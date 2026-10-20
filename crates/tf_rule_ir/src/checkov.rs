//! Execution of imported Checkov value checks. Paths address Checkov's
//! dict-of-lists configuration, not Terraform's evaluated object shape.
//! The projection retains abstract values and provenance, and the common
//! truth lattice lifts the predicate over alternatives.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tf_eval::{Kind, Known, Map, Truth, Value, Verdict, truth};
use tf_semantic::{Body, Resource};

use crate::py::{self, Network};
use crate::{pyliteral, pyre};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeOp {
    Exists,
    NotExists,
    Equals,
    NotEquals,
    EqualsIgnoreCase,
    NotEqualsIgnoreCase,
    Within,
    NotWithin,
    Contains,
    NotContains,
    StartingWith,
    NotStartingWith,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    IsEmpty,
    IsNotEmpty,
    IsTrue,
    IsFalse,
    NumberOfWordsNotEquals,
    LengthGreaterThan,
    LengthLessThanOrEqual,
    Subset,
    EndingWith,
    NotEndingWith,
    RegexMatch,
    NotRegexMatch,
    Intersects,
    NotIntersects,
    NotSubset,
    Any,
    LengthEquals,
    LengthNotEquals,
    LengthGreaterThanOrEqual,
    LengthLessThan,
    NumberOfWordsEquals,
    NumberOfWordsGreaterThan,
    NumberOfWordsGreaterThanOrEqual,
    NumberOfWordsLessThan,
    NumberOfWordsLessThanOrEqual,
    CidrRangeSubset,
    CidrRangeNotSubset,
    RangeIncludes,
    RangeNotIncludes,
}

impl AttributeOp {
    /// Operators whose operand is an integer threshold (Checkov `force_int`).
    pub fn is_size(self) -> bool {
        use AttributeOp::*;
        matches!(
            self,
            NumberOfWordsNotEquals
                | LengthGreaterThan
                | LengthLessThanOrEqual
                | LengthEquals
                | LengthNotEquals
                | LengthGreaterThanOrEqual
                | LengthLessThan
                | NumberOfWordsEquals
                | NumberOfWordsGreaterThan
                | NumberOfWordsGreaterThanOrEqual
                | NumberOfWordsLessThan
                | NumberOfWordsLessThanOrEqual
        )
    }
}

/// An operand prepared once, at load time.
#[derive(Debug)]
pub enum Operand {
    Regex(regex::Regex),
    Cidr(Vec<Network>),
    /// Inclusive integer intervals (single values are one-wide).
    Ranges(Vec<(i128, i128)>),
}

/// A value derived from IR fields once, at load time, and not itself part
/// of the IR: ignored by equality, skipped by serde.
#[derive(Clone)]
pub struct Cache<T>(OnceLock<T>);

impl<T> Default for Cache<T> {
    fn default() -> Self {
        Cache(OnceLock::new())
    }
}

impl<T> Cache<T> {
    pub fn get_or_init(&self, f: impl FnOnce() -> T) -> &T {
        self.0.get_or_init(f)
    }
}

impl<T> std::fmt::Debug for Cache<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cache")
    }
}

impl<T> PartialEq for Cache<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

/// The prepared operand of a check, derived from `operator` and `value`.
pub type Prepared = Cache<std::sync::Arc<Operand>>;

fn prepare(operator: AttributeOp, value: &Json) -> Result<Option<Operand>, String> {
    use AttributeOp::*;
    Ok(match operator {
        RegexMatch | NotRegexMatch => {
            if value.is_array() || value.is_object() {
                return Err("regex_match expects a scalar pattern".into());
            }
            let pattern = py::str(value).ok_or("regex_match pattern cannot be rendered")?;
            Some(Operand::Regex(pyre::compile(&pattern, pyre::Mode::Match)?))
        }
        CidrRangeSubset | CidrRangeNotSubset => {
            let items = match value {
                Json::String(_) => vec![value.clone()],
                Json::Array(items) => items.clone(),
                _ => return Err("cidr_range_subset expects a CIDR string or list of CIDRs".into()),
            };
            let nets = items
                .iter()
                .map(|v| py::network(v).ok_or_else(|| format!("{v} is not an IP network")))
                .collect::<Result<_, _>>()?;
            Some(Operand::Cidr(nets))
        }
        RangeIncludes | RangeNotIncludes => {
            let items = match value {
                Json::Array(items) => items.clone(),
                other => vec![other.clone()],
            };
            let mut ranges = Vec::new();
            for v in &items {
                let bad = || {
                    format!("range operand {v} must be an integer or an \"a-b\" string of integers")
                };
                match v {
                    Json::String(s) if s.contains('-') => {
                        let parts: Vec<&str> = s.split('-').collect();
                        let [a, b] = parts[..] else { return Err(bad()) };
                        let (a, b) = py::int_str(a).zip(py::int_str(b)).ok_or_else(bad)?;
                        if a <= b {
                            ranges.push((a, b));
                        }
                    }
                    Json::String(_) | Json::Bool(_) => {
                        let n = py::force_int(v).ok_or_else(bad)?;
                        ranges.push((n, n));
                    }
                    Json::Number(n) if n.is_i64() || n.is_u64() => {
                        let n = py::force_int(v).ok_or_else(bad)?;
                        ranges.push((n, n));
                    }
                    _ => return Err(bad()),
                }
            }
            Some(Operand::Ranges(ranges))
        }
        _ => None,
    })
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributeCheck {
    pub attribute: String,
    pub operator: AttributeOp,
    #[serde(default)]
    pub value: Json,
    #[serde(skip)]
    pub prepared: Prepared,
}

/// Checkov's result filter: Python truthiness followed by `value in operand`.
/// Unlike attribute predicates, a string operand means substring membership.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributeFilter {
    pub attribute: String,
    pub value: Json,
}

impl AttributeFilter {
    pub fn validate(&self) -> Result<(), String> {
        if self.attribute.is_empty()
            || self.attribute.contains(['.', '*', '?', '[', ']', '/'])
            || matches!(
                self.attribute.as_str(),
                "resource_type"
                    | "lifecycle"
                    | "provisioner"
                    | "connection"
                    | "count"
                    | "for_each"
                    | "provider"
                    | "depends_on"
            )
        {
            return Err(
                "graph attribute filter requires a literal top-level configured attribute".into(),
            );
        }
        if !self.value.is_string()
            && !matches!(&self.value, Json::Array(a) if a.iter().all(|x| !x.is_array() && !x.is_object()))
        {
            return Err("graph attribute filter expects a string or list of scalars".into());
        }
        Ok(())
    }

    pub fn evaluate(&self, r: &Resource) -> Verdict {
        let value = resource_graph_configuration(r).field_or_null(&self.attribute);
        truth::map(&value, &|v| {
            let truthy = match v.as_known() {
                Some(Known::Null) => false,
                Some(Known::Bool(b)) => *b,
                Some(Known::Number(n)) => *n != 0.0,
                Some(Known::String(s)) => !s.is_empty(),
                Some(Known::List(l)) => !l.is_empty(),
                Some(Known::Object(o)) => !o.is_empty(),
                Some(Known::Json(_)) => true,
                None => unreachable!("truth::map supplies known values"),
            };
            if !truthy {
                return Verdict::new(Truth::False, Some(v.clone()));
            }
            match &self.value {
                Json::Array(expected) => matches(v, expected),
                Json::String(expected) => match v.as_known() {
                    Some(Known::String(_) | Known::Json(_)) => match v.to_str() {
                        Some(actual) => Verdict::new(
                            Truth::from_bool(expected.contains(actual.as_ref())),
                            Some(v.clone()),
                        ),
                        None => unresolved(v),
                    },
                    // Python raises for truthy nonstrings in a string operand.
                    // An invalid input must not prove that the filter excludes it.
                    _ => unresolved(v),
                },
                _ => unreachable!("validated filter operand"),
            }
        })
    }
}

impl AttributeCheck {
    pub fn validate(&self) -> Result<(), String> {
        if self.attribute.is_empty()
            || self.attribute.contains(['[', ']', '/'])
            || self
                .attribute
                .split('.')
                .any(|s| s.is_empty() || (s != "*" && s.contains('*')))
        {
            return Err(
                "checkov_attribute: expected dotted path with literal or '*' segments".into(),
            );
        }
        self.validate_operand()
    }

    /// The operand's shape for the operator, preparing it for evaluation.
    pub fn validate_operand(&self) -> Result<(), String> {
        use AttributeOp::*;
        let scalar_list = |v: &Json| matches!(v, Json::Array(v) if v.iter().all(|x| !x.is_array() && !x.is_object()));
        match self.operator {
            Within | NotWithin | Subset | NotSubset => {
                if !scalar_list(&self.value) {
                    return Err("checkov_attribute: membership expects a list of scalars".into());
                }
            }
            op if op.is_size() => {
                if self.value.as_i64().is_none() {
                    return Err(
                        "checkov_attribute: size comparison expects an integer threshold".into(),
                    );
                }
            }
            Intersects | NotIntersects => {
                if !self.value.is_string() && !scalar_list(&self.value) {
                    return Err(
                        "checkov_attribute: intersects expects a string or a list of scalars"
                            .into(),
                    );
                }
            }
            EndingWith | NotEndingWith => {
                if !self.value.is_string() {
                    return Err("checkov_attribute: ending_with expects a string".into());
                }
            }
            Any | CidrRangeSubset | CidrRangeNotSubset | RangeIncludes | RangeNotIncludes => {}
            _ => {
                if self.value.is_array() || self.value.is_object() {
                    return Err("checkov_attribute: comparison expects a scalar".into());
                }
            }
        }
        if let Some(operand) =
            prepare(self.operator, &self.value).map_err(|e| format!("checkov_attribute: {e}"))?
        {
            let operand = std::sync::Arc::new(operand);
            self.prepared.get_or_init(|| operand);
        }
        Ok(())
    }

    pub fn evaluate(&self, r: &Resource) -> Verdict {
        let body = resource_graph_configuration(r);
        let values = attribute_values(body, &self.attribute.split('.').collect::<Vec<_>>());
        let all = self.operator == AttributeOp::NotContains;
        if values.is_empty() {
            // Not set: judged as null, witnessed by its absence so a
            // finding names the attribute (a wildcard path names none).
            let absent = if self.attribute.contains('*') {
                Value::null()
            } else {
                r.absent(&self.attribute)
            };
            return self.evaluate_value(&absent);
        }
        values
            .iter()
            .map(|value| self.evaluate_value(value))
            .reduce(|result, next| {
                if all {
                    result.and(next)
                } else {
                    result.or(next)
                }
            })
            .expect("nonempty attribute matches")
    }

    fn operand(&self) -> &Operand {
        self.prepared
            .get_or_init(|| {
                std::sync::Arc::new(
                    prepare(self.operator, &self.value)
                        .ok()
                        .flatten()
                        .expect("operand validated before evaluation"),
                )
            })
            .as_ref()
    }

    pub(crate) fn evaluate_value(&self, value: &Value) -> Verdict {
        use AttributeOp::*;
        if self.operator == Any {
            // AnyResourceSolver: every vertex of the resource types passes.
            return Verdict::new(Truth::True, Some(value.clone()));
        }
        truth::map(value, &|v| {
            let yes = match self.operator {
                Exists | NotExists => !v.is_null(),
                Contains | NotContains => {
                    let result = contains(v, &self.value);
                    return if self.operator == NotContains {
                        result.negate()
                    } else {
                        result
                    };
                }
                StartingWith | NotStartingWith => v
                    .as_str()
                    .zip(self.value.as_str())
                    .is_some_and(|(a, b)| a.starts_with(b)),
                EndingWith | NotEndingWith => v
                    .as_str()
                    .zip(self.value.as_str())
                    .is_some_and(|(a, b)| a.ends_with(b)),
                RegexMatch | NotRegexMatch => {
                    let Operand::Regex(rx) = self.operand() else {
                        unreachable!()
                    };
                    let Some(text) = python_str(v) else {
                        return unresolved(v);
                    };
                    rx.is_match(&text)
                }
                Intersects | NotIntersects => {
                    let result = intersects(v, &self.value);
                    return if self.operator == NotIntersects {
                        result.negate()
                    } else {
                        result
                    };
                }
                NotSubset => return subset(v, self.value.as_array().expect("validated")).negate(),
                CidrRangeSubset | CidrRangeNotSubset => {
                    let Operand::Cidr(allowed) = self.operand() else {
                        unreachable!()
                    };
                    let result = cidr_subset(v, allowed);
                    return if self.operator == CidrRangeNotSubset {
                        result.negate()
                    } else {
                        result
                    };
                }
                RangeIncludes | RangeNotIncludes => {
                    let Operand::Ranges(ranges) = self.operand() else {
                        unreachable!()
                    };
                    let result = range_includes(v, ranges);
                    return if self.operator == RangeNotIncludes {
                        result.negate()
                    } else {
                        result
                    };
                }
                // IsFalseAttributeSolver is `not (attr is True)`.
                IsTrue | IsFalse => matches!(v.as_known(), Some(Known::Bool(true))),
                IsEmpty | IsNotEmpty => match v.as_known() {
                    Some(Known::List(l)) => l.is_empty(),
                    Some(Known::Object(o)) => o.is_empty(),
                    Some(Known::String(s)) => s.is_empty(),
                    _ => false,
                },
                GreaterThan | GreaterThanOrEqual | LessThan | LessThanOrEqual => {
                    if v.is_null() {
                        return Verdict::new(Truth::False, Some(v.clone()));
                    }
                    let Some(actual) = tf_eval::value::to_json(v) else {
                        return unresolved(v);
                    };
                    let a = python_repr(&actual);
                    let b = python_repr(&self.value);
                    let numeric = |v: &Json| {
                        v.as_bool()
                            .map(|b| if b { 1.0 } else { 0.0 })
                            .or_else(|| python_repr(v).parse::<f64>().ok())
                    };
                    let ordering = match (numeric(&actual), numeric(&self.value)) {
                        (Some(a), Some(b)) if a != 0.0 && b != 0.0 => a.partial_cmp(&b),
                        _ => Some(a.cmp(&b)),
                    };
                    ordering.is_some_and(|o| match self.operator {
                        GreaterThan => o.is_gt(),
                        GreaterThanOrEqual => o.is_ge(),
                        LessThan => o.is_lt(),
                        _ => o.is_le(),
                    })
                }
                Within | NotWithin => {
                    let verdict = matches(v, self.value.as_array().expect("validated"));
                    return if self.operator == NotWithin {
                        verdict.negate()
                    } else {
                        verdict
                    };
                }
                op if op.is_size() => {
                    return measure(v, self.operator, self.value.as_i64().expect("validated"));
                }
                Subset => return subset(v, self.value.as_array().expect("validated")),
                _ => {
                    let Some(actual) = tf_eval::value::to_json(v) else {
                        return unresolved(v);
                    };
                    let a = python_repr(&actual);
                    let b = python_repr(&self.value);
                    if matches!(self.operator, EqualsIgnoreCase | NotEqualsIgnoreCase)
                        || actual.is_boolean()
                        || self.value.is_boolean()
                    {
                        a.to_lowercase() == b.to_lowercase()
                    } else {
                        a == b
                    }
                }
            };
            let invert = matches!(
                self.operator,
                NotExists
                    | NotEquals
                    | NotEqualsIgnoreCase
                    | NotStartingWith
                    | IsNotEmpty
                    | NotEndingWith
                    | NotRegexMatch
                    | IsFalse
            );
            Verdict::new(Truth::from_bool(yes != invert), Some(v.clone()))
        })
    }
}

fn measure(value: &Value, operator: AttributeOp, threshold: i64) -> Verdict {
    use AttributeOp::*;
    if matches!(value.as_known(), Some(Known::Json(_))) {
        return match value.to_str() {
            Some(s) => measure(&Value::string(s).child_of(value), operator, threshold),
            None => unresolved(value),
        };
    }
    let words = matches!(
        operator,
        NumberOfWordsNotEquals
            | NumberOfWordsEquals
            | NumberOfWordsGreaterThan
            | NumberOfWordsGreaterThanOrEqual
            | NumberOfWordsLessThan
            | NumberOfWordsLessThanOrEqual
    );
    let size = match (words, value.as_known()) {
        (true, Some(Known::String(s))) => Some(
            s.split(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
                .filter(|word| !word.is_empty())
                .count(),
        ),
        (true, _) => None,
        (_, Some(Known::String(s))) => Some(s.chars().count()),
        (_, Some(Known::List(items))) => Some(items.len()),
        // Checkov treats every dict, including an empty one, as one block.
        (_, Some(Known::Object(_))) => Some(1),
        _ => None,
    };
    let size = size.map(|n| n as i128);
    let t = threshold as i128;
    // A value that is not measurable fails every comparison, so the
    // not-equals operators (negations of equals) pass it.
    let yes = match operator {
        NumberOfWordsNotEquals | LengthNotEquals => size != Some(t),
        NumberOfWordsEquals | LengthEquals => size == Some(t),
        LengthGreaterThan | NumberOfWordsGreaterThan => size.is_some_and(|n| n > t),
        LengthGreaterThanOrEqual | NumberOfWordsGreaterThanOrEqual => size.is_some_and(|n| n >= t),
        LengthLessThan | NumberOfWordsLessThan => size.is_some_and(|n| n < t),
        LengthLessThanOrEqual | NumberOfWordsLessThanOrEqual => size.is_some_and(|n| n <= t),
        _ => unreachable!(),
    };
    Verdict::new(Truth::from_bool(yes), Some(value.clone()))
}

/// Python's `str()` of a known value, as Checkov's regex solver renders it.
fn python_str(v: &Value) -> Option<String> {
    match v.as_known()? {
        Known::String(s) => Some(s.to_string()),
        Known::Number(n) => Some(py::number_str(*n)),
        Known::Json(_) => None,
        _ => py::str(&tf_eval::value::to_json(v)?),
    }
}

/// `IntersectsAttributeSolver`: a string operand is `value in attr`; a list
/// operand is `any(i in value for i in attr)`. Non-iterables never intersect.
fn intersects(v: &Value, operand: &Json) -> Verdict {
    let no = || Verdict::new(Truth::False, Some(v.clone()));
    match (v.as_known(), operand) {
        (Some(Known::String(s)), Json::String(o)) => {
            Verdict::new(Truth::from_bool(s.contains(o.as_str())), Some(v.clone()))
        }
        (Some(Known::String(s)), Json::Array(o)) => Verdict::new(
            Truth::from_bool(s.chars().any(|c| {
                o.iter()
                    .any(|x| x.as_str() == Some(c.encode_utf8(&mut [0; 4])))
            })),
            Some(v.clone()),
        ),
        (Some(Known::List(_)), Json::String(_)) => truth::exists(v, &|x| equal(x, operand)),
        (Some(Known::List(_)), Json::Array(o)) => truth::exists(v, &|x| matches(x, o)),
        (Some(Known::Object(m)), Json::String(o)) => Verdict::new(
            Truth::from_bool(m.contains_key(o.as_str())),
            Some(v.clone()),
        ),
        (Some(Known::Object(m)), Json::Array(o)) => Verdict::new(
            Truth::from_bool(
                m.keys()
                    .any(|k| o.iter().any(|x| x.as_str() == Some(k.as_ref()))),
            ),
            Some(v.clone()),
        ),
        (Some(Known::Json(_)), _) => unresolved(v),
        _ => no(),
    }
}

/// `CIDRRangeSubsetAttributeSolver`. A falsy value fails; a value Python's
/// `ip_network` would raise on leaves the result unresolved.
fn cidr_subset(v: &Value, allowed: &[Network]) -> Verdict {
    let Some(json) = tf_eval::value::to_json(v) else {
        return unresolved(v);
    };
    let falsy = match &json {
        Json::Null => true,
        Json::Bool(b) => !b,
        Json::Number(n) => n.as_f64() == Some(0.0),
        Json::String(s) => s.is_empty(),
        Json::Array(a) => a.is_empty(),
        Json::Object(o) => o.is_empty(),
    };
    if falsy {
        return Verdict::new(Truth::False, Some(v.clone()));
    }
    let nets: Option<Vec<Network>> = match (&json, v.as_known()) {
        (_, Some(Known::Json(_))) => None,
        (Json::String(s), _) => py::network_str(s).map(|n| vec![n]),
        (Json::Array(items), _) => items.iter().map(py::network).collect(),
        _ => None,
    };
    let Some(nets) = nets else {
        return unresolved(v);
    };
    let yes = nets.iter().all(|n| allowed.iter().any(|a| n.subnet_of(a)));
    Verdict::new(Truth::from_bool(yes), Some(v.clone()))
}

/// `RangeIncludesAttributeSolver` against prepared integer intervals.
fn range_includes(v: &Value, ranges: &[(i128, i128)]) -> Verdict {
    let check = |x: &Value| {
        truth::map(x, &|x| {
            let hit = match x.as_known() {
                Some(Known::String(s)) if s.as_ref() == "*" => !ranges.is_empty(),
                Some(Known::String(s)) if s.matches('-').count() == 1 => {
                    let (a, b) = s.split_once('-').expect("one dash");
                    match (py::int_str(a), py::int_str(b)) {
                        (Some(a), Some(b)) => {
                            ranges.iter().any(|(lo, hi)| a.max(*lo) <= b.min(*hi))
                        }
                        _ => false,
                    }
                }
                Some(Known::String(s)) => py::int_str(s)
                    .is_some_and(|n| ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&n))),
                Some(Known::Number(n)) => {
                    n.is_finite() && {
                        let n = n.trunc() as i128;
                        ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&n))
                    }
                }
                Some(Known::Bool(b)) => ranges
                    .iter()
                    .any(|(lo, hi)| (*lo..=*hi).contains(&(*b as i128))),
                Some(Known::Json(_)) => return unresolved(x),
                _ => false,
            };
            Verdict::new(Truth::from_bool(hit), Some(x.clone()))
        })
    };
    match v.as_known() {
        Some(Known::Null) => Verdict::new(Truth::False, Some(v.clone())),
        Some(Known::List(_)) => truth::exists(v, &check),
        _ => check(v),
    }
}

fn subset(value: &Value, expected: &[Json]) -> Verdict {
    match value.as_known() {
        Some(Known::List(items)) => items.iter().fold(
            Verdict::new(Truth::True, Some(value.clone())),
            |result, item| {
                result.and(truth::map(&item.child_of(value), &|v| {
                    if matches!(v.as_known(), Some(Known::List(_) | Known::Object(_))) {
                        // Python cannot hash these set members. Do not certify
                        // a pass for an operand that the reference cannot run.
                        unresolved(v)
                    } else {
                        matches(v, expected)
                    }
                }))
            },
        ),
        Some(Known::Object(items)) => items.keys().fold(
            Verdict::new(Truth::True, Some(value.clone())),
            |result, key| {
                result.and(matches(
                    &Value::string(key.clone()).child_of(value),
                    expected,
                ))
            },
        ),
        _ => matches(value, expected),
    }
}

/// `ContainsAttributeSolver`. A configured string is first JSON-decoded
/// (quotes normalized); a dict matches a key, or `value in v` for its string,
/// list and dict values. Wherever Python's `in` raises (a non-string operand
/// against a string, any operand against a number, bool or decoded `null`),
/// the vertex gets no result, so the verdict is unresolved.
fn contains(value: &Value, expected: &Json) -> Verdict {
    truth::map(value, &|v| match v.as_known() {
        Some(Known::String(s)) => {
            let normalized = s.replace('\'', "\"");
            if matches!(normalized.trim(), "NaN" | "Infinity" | "-Infinity") {
                return unresolved(v);
            }
            match serde_json::from_str::<Json>(&normalized) {
                Ok(json @ (Json::Array(_) | Json::Object(_))) => {
                    contains(&tf_eval::value::from_json(&json, &v.prov), expected)
                }
                Ok(Json::String(decoded)) => substring(v, &decoded, expected),
                Ok(_) => unresolved(v),
                Err(_) => substring(v, s, expected),
            }
        }
        Some(Known::Object(m)) => {
            let mut result = Verdict::new(
                Truth::from_bool(expected.as_str().is_some_and(|s| m.contains_key(s))),
                Some(v.clone()),
            );
            for child in m.values() {
                let child = child.child_of(v);
                result = result.or(truth::map(&child, &|c| match c.as_known() {
                    Some(Known::String(s)) => substring(c, s, expected),
                    Some(Known::List(_)) => truth::exists(c, &|x| equal(x, expected)),
                    Some(Known::Object(m)) => Verdict::new(
                        Truth::from_bool(expected.as_str().is_some_and(|s| m.contains_key(s))),
                        Some(c.clone()),
                    ),
                    Some(Known::Json(_)) => unresolved(c),
                    _ => Verdict::new(Truth::False, Some(c.clone())),
                }));
            }
            result
        }
        Some(Known::List(_)) => truth::exists(v, &|x| equal(x, expected)),
        Some(Known::Json(inner)) => contains(&inner.child_of(v), expected),
        // A missing attribute reads as "{}", which contains nothing.
        Some(Known::Null) => Verdict::new(Truth::False, Some(v.clone())),
        _ => unresolved(v),
    })
}

/// `expected in s` for a string `s`; a non-string operand raises.
fn substring(v: &Value, s: &str, expected: &Json) -> Verdict {
    match expected.as_str() {
        Some(e) => Verdict::new(Truth::from_bool(s.contains(e)), Some(v.clone())),
        None => unresolved(v),
    }
}

/// An attribute value as Checkov's parser leaves it: `clean_parser_types`
/// (`terraform/modules/module_utils.py`) turns the strings `"true"` and
/// `"false"` into booleans at every depth, except under a key named
/// `alias`. Checkov renders variables and locals into the same shape, so
/// this applies to evaluated values, not only to literals.
///
/// Not modelled: the same function also moves a list's strings, sorted,
/// after its other elements.
fn parser_types(value: &Value) -> Value {
    parser_types_changed(value).unwrap_or_else(|| value.clone())
}

/// [`parser_types`], or `None` when nothing changes (the common case,
/// which then costs no allocation).
fn parser_types_changed(value: &Value) -> Option<Value> {
    let changed = |kind: Kind| Value {
        kind,
        prov: value.prov.clone(),
    };
    match &value.kind {
        Kind::Known(Known::String(s)) => match &**s {
            "true" => Some(changed(Kind::Known(Known::Bool(true)))),
            "false" => Some(changed(Kind::Known(Known::Bool(false)))),
            _ => None,
        },
        Kind::Known(Known::List(items)) => {
            let new: Vec<Option<Value>> = items.iter().map(parser_types_changed).collect();
            let any_new = new.iter().any(Option::is_some);
            let items: Vec<Value> = new
                .into_iter()
                .zip(items.iter())
                .map(|(n, old)| n.unwrap_or_else(|| old.clone()))
                .collect();
            // `clean_parser_types_lst` then moves the strings, sorted, after
            // the other elements. An abstract element might be a string or
            // not, so such a list keeps its order.
            let sorted = sort_strings_last(&items);
            (any_new || sorted.is_some()).then(|| {
                changed(Kind::Known(Known::List(std::sync::Arc::new(
                    sorted.unwrap_or(items),
                ))))
            })
        }
        Kind::Known(Known::Object(items)) => {
            let new: Vec<Option<Value>> = items
                .iter()
                .map(|(k, v)| {
                    if &**k == "alias" {
                        None
                    } else {
                        parser_types_changed(v)
                    }
                })
                .collect();
            new.iter().any(Option::is_some).then(|| {
                changed(Kind::Known(Known::Object(std::sync::Arc::new(
                    new.into_iter()
                        .zip(items.iter())
                        .map(|(n, (k, old))| (k.clone(), n.unwrap_or_else(|| old.clone())))
                        .collect(),
                ))))
            })
        }
        Kind::OneOf(o) => {
            let new: Vec<Option<Value>> = o.alternatives.iter().map(parser_types_changed).collect();
            new.iter().any(Option::is_some).then(|| {
                Value::one_of(
                    new.into_iter()
                        .zip(o.alternatives.iter())
                        .map(|(n, old)| n.unwrap_or_else(|| old.clone()))
                        .collect(),
                    o.tainted,
                )
                .child_of(value)
            })
        }
        _ => None,
    }
}

/// The list with its strings moved, sorted, after its other elements, or
/// `None` when that is already its order (or an element is abstract).
fn sort_strings_last(items: &[Value]) -> Option<Vec<Value>> {
    if items.iter().any(|v| !matches!(v.kind, Kind::Known(_))) {
        return None;
    }
    let text = |i: usize| match &items[i].kind {
        Kind::Known(Known::String(s)) => Some(s.clone()),
        _ => None,
    };
    let mut strings: Vec<usize> = (0..items.len()).filter(|&i| text(i).is_some()).collect();
    // A stable sort, as Python's.
    strings.sort_by_key(|&i| text(i));
    let order: Vec<usize> = (0..items.len())
        .filter(|&i| text(i).is_none())
        .chain(strings)
        .collect();
    let moved = order.iter().enumerate().any(|(at, &i)| at != i);
    moved.then(|| order.into_iter().map(|i| items[i].clone()).collect())
}

/// A resource attribute as Checkov's runner leaves it for resource checks
/// (`evaluate_vertices_attributes` writes evaluated values back into the
/// configuration only through the containers it shares with it):
///
/// - a string whose evaluation is a list or dict becomes it (a JSON policy
///   in a heredoc, `"[1, 2]"`);
/// - the elements of a list attribute, and the values of objects inside
///   it, are evaluated: `["-1"]` → `[-1]`, `[{p = "22"}]` → `[{p: 22}]`.
///
/// Other strings (top-level scalars, map values, block attributes) stay as
/// written. Evaluation reads Python literals only ([`pyliteral`]).
fn runner_rendered(value: &Value) -> Value {
    match &value.kind {
        Kind::Known(Known::String(s)) => match pyliteral::container(s) {
            Some(json) => tf_eval::value::from_json(&json, &value.prov),
            None => value.clone(),
        },
        Kind::Known(Known::List(items)) => {
            Value::list(items.iter().map(rendered_element).collect()).child_of(value)
        }
        _ => value.clone(),
    }
}

fn rendered_element(value: &Value) -> Value {
    match &value.kind {
        Kind::Known(Known::String(s)) if s.len() <= 10_000 => match pyliteral::eval(s) {
            Some(json) => tf_eval::value::from_json(&json, &value.prov),
            None => value.clone(),
        },
        Kind::Known(Known::List(items)) => {
            Value::list(items.iter().map(rendered_element).collect()).child_of(value)
        }
        Kind::Known(Known::Object(m)) => Value::object(
            m.iter()
                .map(|(k, v)| (k.clone(), rendered_element(v)))
                .collect(),
        )
        .child_of(value),
        _ => value.clone(),
    }
}

/// Graph vertices unwrap parser lists; blocks still retain their cardinality.
fn graph_configuration(body: &Body) -> Value {
    let mut map: Map = body
        .attrs
        .iter()
        .map(|a| {
            let value = if &*a.name == "alias" {
                a.value.clone()
            } else {
                parser_types(&a.value)
            };
            (a.name.clone(), value)
        })
        .collect();
    for block in &body.blocks {
        if map.contains_key(&block.ty) {
            continue;
        }
        let blocks: Vec<_> = body
            .blocks_of(&block.ty)
            .filter(|b| b.existence != Truth::False)
            .collect();
        let values: Vec<_> = blocks
            .iter()
            .map(|b| graph_configuration(&b.body))
            .collect();
        let value = if values.len() == 1 {
            values[0].clone()
        } else {
            Value::list(values)
        };
        let uncertain = blocks
            .iter()
            .filter(|b| b.existence != Truth::True)
            .map(|b| b.existence)
            .max();
        map.insert(
            block.ty.clone(),
            match uncertain {
                Some(Truth::Tainted) => Value::tainted("dynamic graph block").child_of(&value),
                Some(_) => Value::other("dynamic graph block").child_of(&value),
                None => value,
            },
        );
    }
    Value::object(map)
}

fn attribute_values(value: &Value, path: &[&str]) -> Vec<Value> {
    if path.is_empty() {
        return vec![value.clone()];
    }
    match &value.kind {
        Kind::Known(Known::Object(m)) => {
            // A literal key containing dots takes precedence over traversal.
            if let Some(v) = m.get(path.join(".").as_str()) {
                return vec![v.child_of(value)];
            }
            if path[0] == "*" {
                // Checkov's flattened wildcard regex accepts numeric indices
                // or the path with the wildcard omitted (a singleton block).
                let mut values = attribute_values(value, &path[1..]);
                values.extend(
                    m.iter()
                        .filter(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_digit()))
                        .flat_map(|(_, v)| attribute_values(&v.child_of(value), &path[1..])),
                );
                values
            } else {
                m.get(path[0])
                    .map(|v| attribute_values(&v.child_of(value), &path[1..]))
                    .unwrap_or_default()
            }
        }
        Kind::Known(Known::List(l)) => {
            if path[0] == "*" {
                l.iter()
                    .flat_map(|v| attribute_values(&v.child_of(value), &path[1..]))
                    .collect()
            } else if let Ok(i) = path[0].parse::<usize>() {
                l.get(i)
                    .map(|v| attribute_values(&v.child_of(value), &path[1..]))
                    .unwrap_or_default()
            } else if l.len() == 1 {
                attribute_values(&l[0].child_of(value), path)
            } else {
                Vec::new()
            }
        }
        Kind::Known(Known::Json(v)) => attribute_values(&v.child_of(value), path),
        Kind::OneOf(o) => {
            // Keep alternatives together, so a maybe-absent attribute cannot
            // turn into an existential definite pass.
            let values = o
                .alternatives
                .iter()
                .map(|v| {
                    let mut children = attribute_values(&v.child_of(value), path);
                    if children.is_empty() {
                        Value::null()
                    } else if children.len() == 1 {
                        children.pop().unwrap()
                    } else {
                        Value::one_of(children, o.tainted)
                    }
                })
                .collect();
            vec![Value::one_of(values, o.tainted).child_of(value)]
        }
        Kind::Unknown(_) | Kind::Tainted(_) => vec![value.clone()],
        _ => Vec::new(),
    }
}

fn python_repr(value: &Json) -> String {
    match value {
        Json::Null => "None".into(),
        Json::Bool(b) => if *b { "True" } else { "False" }.into(),
        Json::String(s) => s.clone(),
        Json::Number(n) => n.to_string(),
        // Composite comparisons are not admitted by the importer. Keep their
        // representation distinct from scalar string operands.
        _ => value.to_string(),
    }
}

// `truth::uncertainty` classifies the outer value only. A Known container
// can still contain abstract descendants (including inside jsonencode).
fn unresolved(value: &Value) -> Verdict {
    let tainted = match &value.kind {
        Kind::Known(Known::List(items)) => {
            items.iter().any(|v| unresolved(v).truth == Truth::Tainted)
        }
        Kind::Known(Known::Object(items)) => items
            .values()
            .any(|v| unresolved(v).truth == Truth::Tainted),
        Kind::Known(Known::Json(inner)) => unresolved(inner).truth == Truth::Tainted,
        _ => truth::uncertainty(value) == Truth::Tainted,
    };
    Verdict::new(
        if tainted {
            Truth::Tainted
        } else {
            Truth::Unknown
        },
        Some(value.clone()),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Missing {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueCheck {
    pub path: Vec<String>,
    pub values: Vec<Json>,
    pub negative: bool,
    pub any_value: bool,
    pub missing: Missing,
}

impl ValueCheck {
    pub fn validate(&self) -> Result<(), String> {
        if self.path.is_empty()
            || self
                .path
                .iter()
                .any(|s| s.is_empty() || s.contains(['*', '?', '/']))
        {
            return Err("checkov_value: expected a nonempty literal path".into());
        }
        for segment in &self.path {
            if (segment.starts_with('[') || segment.ends_with(']')) && index(segment).is_none() {
                return Err(format!("checkov_value: invalid index {segment:?}"));
            }
        }
        Ok(())
    }

    /// The verdict on a missing value, witnessed by its absence at the
    /// checked path so a finding names the attribute.
    fn missing(&self, resource: &Resource) -> Verdict {
        match self.missing {
            Missing::Pass => Verdict::FALSE,
            Missing::Fail => Verdict::new(Truth::True, Some(resource.absent(&self.dotted()))),
            Missing::Unknown => Verdict::new(Truth::Unknown, None),
        }
    }

    /// The checked path, dotted, without index segments
    /// (`versioning.enabled` for `versioning/[0]/enabled`).
    pub fn dotted(&self) -> String {
        self.path
            .iter()
            .filter(|s| index(s).is_none() || !s.starts_with('['))
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(".")
    }

    /// The mechanical fix a passing value implies: a positive check of a
    /// top-level attribute against one literal sets it to that literal.
    pub fn fix(&self) -> Option<(String, Json)> {
        let [attribute] = self.path.as_slice() else {
            return None;
        };
        let [value] = self.values.as_slice() else {
            return None;
        };
        let literal = !value.is_array() && !value.is_object() && !value.is_null();
        (!self.negative && !self.any_value && literal).then(|| (attribute.clone(), value.clone()))
    }

    pub fn evaluate(&self, resource: &Resource) -> Verdict {
        // `field(&resource.body, ..)`, from the configuration every Checkov
        // rule of this resource shares.
        let Some(value) = resource_configuration(resource)
            .as_object()
            .and_then(|m| m.get(self.path[0].as_str()))
            .cloned()
        else {
            return self.missing(resource);
        };
        self.walk(resource, &value, &self.path[1..], &|| {
            if self.negative {
                self.missing(resource)
            } else {
                // Checkov's positive base class retries a missing indexed
                // path ignoring indices. A matching value passes; otherwise
                // the declared missing-block result applies.
                let named: Vec<_> = self.path[1..]
                    .iter()
                    .filter(|s| index(s).is_none())
                    .cloned()
                    .collect();
                let pass = self.fallback(&value, &named);
                match pass.truth {
                    Truth::True => Verdict::FALSE,
                    Truth::False => self.missing(resource),
                    _ if self.missing == Missing::Pass => Verdict::FALSE,
                    _ => pass,
                }
            }
        })
    }

    fn walk(
        &self,
        resource: &Resource,
        value: &Value,
        path: &[String],
        missing: &dyn Fn() -> Verdict,
    ) -> Verdict {
        truth::map(value, &|v| {
            let Some((first, rest)) = path.split_first() else {
                return self.leaf(resource, v);
            };
            match &v.kind {
                Kind::Known(Known::Object(m)) => match m.get(first.as_str()) {
                    Some(child) => self.walk(resource, &child.clone().child_of(v), rest, missing),
                    None => missing(),
                },
                Kind::Known(Known::List(l)) => match index(first).and_then(|i| l.get(i)) {
                    Some(child) => self.walk(resource, &child.clone().child_of(v), rest, missing),
                    None => missing(),
                },
                _ => missing(),
            }
        })
    }

    fn fallback(&self, value: &Value, path: &[String]) -> Verdict {
        truth::map(value, &|v| {
            if path.is_empty() {
                return unbox(v, &|x| matches(x, &self.values));
            }
            match &v.kind {
                Kind::Known(Known::List(_)) => truth::exists(v, &|x| self.fallback(x, path)),
                Kind::Known(Known::Object(m)) => {
                    m.get(path[0].as_str()).map_or(Verdict::FALSE, |x| {
                        self.fallback(&x.clone().child_of(v), &path[1..])
                    })
                }
                _ => Verdict::FALSE,
            }
        })
    }

    fn leaf(&self, resource: &Resource, value: &Value) -> Verdict {
        unbox(value, &|v| {
            if v.is_null() || matches!(&v.kind, Kind::Known(Known::List(l)) if l.is_empty()) {
                // Written as null or empty: the value itself, where it is
                // written, is the witness when it has a location.
                let verdict = self.missing(resource);
                return match verdict.witness {
                    Some(_) if !v.prov.is_empty() => Verdict::new(verdict.truth, Some(v.clone())),
                    _ => verdict,
                };
            }
            if self.any_value && (self.negative || v.as_str() != Some("")) {
                return Verdict::new(Truth::from_bool(self.negative), Some(v.clone()));
            }
            let mut matched = matches(v, &self.values);
            if self.negative {
                if matches!(&v.kind, Kind::Known(Known::List(_))) {
                    matched = matched.or(truth::exists(v, &|x| matches(x, &self.values)));
                }
                matched
            } else {
                // Positive checks additionally accept Python's string form
                // of non-string primitives (True, False, and numbers).
                let rendered = match v.as_known() {
                    Some(Known::Bool(b)) => Some(if *b { "True" } else { "False" }.to_string()),
                    Some(Known::Number(n)) => Some(n.to_string()),
                    _ => None,
                };
                if let Some(s) = rendered {
                    matched = matched.or(Verdict::new(
                        Truth::from_bool(self.values.iter().any(|x| x.as_str() == Some(&s))),
                        Some(v.clone()),
                    ));
                }
                matched.negate()
            }
        })
    }
}

fn index(s: &str) -> Option<usize> {
    s.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(s)
        .parse()
        .ok()
}

fn unbox(value: &Value, f: &dyn Fn(&Value) -> Verdict) -> Verdict {
    truth::map(value, &|v| match &v.kind {
        Kind::Known(Known::List(l)) if l.len() == 1 => truth::map(&l[0].clone().child_of(v), f),
        _ => f(v),
    })
}

fn matches(value: &Value, expected: &[Json]) -> Verdict {
    expected
        .iter()
        .fold(Verdict::new(Truth::False, Some(value.clone())), |v, e| {
            v.or(equal(value, e))
        })
}

/// Python equality: bools equal 0/1, strings are not stripped or coerced.
/// Descendants retain their uncertainty when comparing collections.
pub(crate) fn equal(value: &Value, expected: &Json) -> Verdict {
    truth::map(value, &|v| {
        let yes = match (v.as_known(), expected) {
            (Some(Known::List(items)), Json::Array(want)) if items.len() == want.len() => {
                return items
                    .iter()
                    .zip(want)
                    .fold(Verdict::new(Truth::True, Some(v.clone())), |acc, (x, e)| {
                        acc.and(equal(&x.clone().child_of(v), e))
                    });
            }
            (Some(Known::Object(items)), Json::Object(want)) if items.len() == want.len() => {
                return want.iter().fold(
                    Verdict::new(Truth::True, Some(v.clone())),
                    |acc, (k, e)| {
                        acc.and(
                            items
                                .get(k.as_str())
                                .map_or(Verdict::FALSE, |x| equal(&x.clone().child_of(v), e)),
                        )
                    },
                );
            }
            (Some(Known::Bool(b)), Json::Number(n)) => {
                n.as_f64() == Some(if *b { 1.0 } else { 0.0 })
            }
            (Some(Known::Number(n)), Json::Bool(b)) => *n == if *b { 1.0 } else { 0.0 },
            (Some(Known::Json(_)), Json::String(_)) if tf_eval::value::to_json(v).is_none() => {
                return unresolved(v);
            }
            _ => tf_eval::value::to_json(v).as_ref() == Some(expected),
        };
        Verdict::new(Truth::from_bool(yes), Some(v.clone()))
    })
}

/// Checkov-shaped configured field, keeping source evidence and unknowns.
pub fn field(body: &Body, name: &str) -> Option<Value> {
    field_in(body, name, true)
}

/// [`field`] of a resource (`rendered`: as Checkov's runner leaves it,
/// see [`runner_rendered`]) or of a nested block (as parsed).
fn field_in(body: &Body, name: &str, rendered: bool) -> Option<Value> {
    if let Some(a) = body.attr(name) {
        let value = if name == "alias" {
            a.value.clone()
        } else {
            parser_types(&a.value)
        };
        return Some(if a.from_blocks {
            block_values(&value)
        } else {
            Value::list(vec![if rendered {
                runner_rendered(&value)
            } else {
                value
            }])
        });
    }
    let blocks: Vec<_> = body
        .blocks_of(name)
        .filter(|b| b.existence != Truth::False)
        .collect();
    if blocks.is_empty() {
        return None;
    }
    let mut values = Vec::new();
    let mut uncertainty = None;
    for b in blocks {
        values.push(configuration_in(&b.body, false));
        if b.existence != Truth::True {
            uncertainty = Some(uncertainty.map_or(b.existence, |t: Truth| t.or(b.existence)));
        }
    }
    let value = Value::list(values);
    Some(match uncertainty {
        // Unknown cardinality can change every positional lookup. Merely
        // comparing an all-present and all-absent list misses intermediate
        // combinations and can manufacture a definite result.
        Some(Truth::Tainted) => Value::tainted("dynamic Checkov block list").child_of(&value),
        Some(_) => Value::other("dynamic Checkov block list").child_of(&value),
        None => value,
    })
}

fn block_values(value: &Value) -> Value {
    match &value.kind {
        Kind::Known(Known::List(items)) => {
            Value::list(items.iter().map(block_values).collect()).child_of(value)
        }
        Kind::Known(Known::Object(items)) => Value::object(
            items
                .iter()
                .map(|(k, v)| (k.clone(), Value::list(vec![v.clone()])))
                .collect(),
        )
        .child_of(value),
        Kind::OneOf(o) => {
            Value::one_of(o.alternatives.iter().map(block_values).collect(), o.tainted)
                .child_of(value)
        }
        _ => value.clone(),
    }
}

/// Slots of [`tf_semantic::Derived`] this crate fills.
pub(crate) mod slot {
    pub const CONFIGURATION: usize = 0;
    pub const GRAPH_CONFIGURATION: usize = 1;
    pub const VERTEX: usize = 2;
}

/// [`configuration`] of `r`, computed once per resource instance.
pub fn resource_configuration(r: &Resource) -> &Value {
    r.derived
        .get_or_init(slot::CONFIGURATION, || configuration(&r.body))
}

/// The graph view of `r` (see [`graph_configuration`]), computed once.
fn resource_graph_configuration(r: &Resource) -> &Value {
    r.derived
        .get_or_init(slot::GRAPH_CONFIGURATION, || graph_configuration(&r.body))
}

/// A resource's configuration as Checkov's resource checks see it.
pub fn configuration(body: &Body) -> Value {
    configuration_in(body, true)
}

/// A resource's configuration as parsed, before the runner's rendering.
pub fn parsed_configuration(body: &Body) -> Value {
    configuration_in(body, false)
}

fn configuration_in(body: &Body, rendered: bool) -> Value {
    let mut out = Map::new();
    for name in body
        .attrs
        .iter()
        .map(|a| &a.name)
        .chain(body.blocks.iter().map(|b| &b.ty))
    {
        if let Some(v) = field_in(body, name, rendered) {
            out.insert(name.clone(), v);
        }
    }
    Value::object(out)
}

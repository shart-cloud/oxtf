//! Execution of imported Checkov value checks. Paths address Checkov's
//! dict-of-lists configuration, not Terraform's evaluated object shape.
//! The projection retains abstract values and provenance, and the common
//! truth lattice lifts the predicate over alternatives.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tf_eval::{Kind, Known, Map, Truth, Value, Verdict, truth};
use tf_semantic::{Body, Resource};

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
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributeCheck {
    pub attribute: String,
    pub operator: AttributeOp,
    #[serde(default)]
    pub value: Json,
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
        let value = graph_configuration(&r.body).field_or_null(&self.attribute);
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
        if matches!(
            self.operator,
            AttributeOp::Within | AttributeOp::NotWithin | AttributeOp::Subset
        ) {
            if !matches!(&self.value, Json::Array(v) if v.iter().all(|x| !x.is_array() && !x.is_object()))
            {
                return Err("checkov_attribute: membership expects a list of scalars".into());
            }
        } else if matches!(
            self.operator,
            AttributeOp::NumberOfWordsNotEquals
                | AttributeOp::LengthGreaterThan
                | AttributeOp::LengthLessThanOrEqual
        ) {
            if self.value.as_i64().is_none() {
                return Err(
                    "checkov_attribute: size comparison expects an integer threshold".into(),
                );
            }
        } else if self.value.is_array() || self.value.is_object() {
            return Err("checkov_attribute: comparison expects a scalar".into());
        }
        Ok(())
    }

    pub fn evaluate(&self, r: &Resource) -> Verdict {
        let body = graph_configuration(&r.body);
        let values = attribute_values(&body, &self.attribute.split('.').collect::<Vec<_>>());
        let all = self.operator == AttributeOp::NotContains;
        if values.is_empty() {
            return self.evaluate_value(&Value::null());
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

    pub(crate) fn evaluate_value(&self, value: &Value) -> Verdict {
        use AttributeOp::*;
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
                IsTrue => matches!(v.as_known(), Some(Known::Bool(true))),
                IsFalse => matches!(v.as_known(), Some(Known::Bool(false))),
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
                NumberOfWordsNotEquals | LengthGreaterThan | LengthLessThanOrEqual => {
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
                NotExists | NotEquals | NotEqualsIgnoreCase | NotStartingWith | IsNotEmpty
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
    let size = match (operator, value.as_known()) {
        (NumberOfWordsNotEquals, Some(Known::String(s))) => Some(
            s.split(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
                .filter(|word| !word.is_empty())
                .count(),
        ),
        (NumberOfWordsNotEquals, _) => None,
        (_, Some(Known::String(s))) => Some(s.chars().count()),
        (_, Some(Known::List(items))) => Some(items.len()),
        // Checkov treats every dict, including an empty one, as one block.
        (_, Some(Known::Object(_))) => Some(1),
        _ => None,
    };
    let yes = match operator {
        NumberOfWordsNotEquals => size.map(|n| n as i128) != Some(threshold as i128),
        LengthGreaterThan => size.is_some_and(|n| n as i128 > threshold as i128),
        LengthLessThanOrEqual => size.is_some_and(|n| n as i128 <= threshold as i128),
        _ => unreachable!(),
    };
    Verdict::new(Truth::from_bool(yes), Some(value.clone()))
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

fn contains(value: &Value, expected: &Json) -> Verdict {
    truth::map(value, &|v| match v.as_known() {
        Some(Known::List(_)) => truth::exists(v, &|x| equal(x, expected)),
        Some(Known::Object(m)) => {
            let mut result = Verdict::new(
                Truth::from_bool(expected.as_str().is_some_and(|s| m.contains_key(s))),
                Some(v.clone()),
            );
            for child in m.values() {
                if !matches!(
                    child.as_known(),
                    Some(Known::Null | Known::Bool(_) | Known::Number(_))
                ) {
                    result = result.or(contains(&child.child_of(v), expected));
                }
            }
            result
        }
        Some(Known::String(s)) => {
            if let Ok(json) = serde_json::from_str::<Json>(&s.replace('\'', "\""))
                && (json.is_array() || json.is_object())
            {
                return contains(&tf_eval::value::from_json(&json, &v.prov), expected);
            }
            Verdict::new(
                Truth::from_bool(expected.as_str().is_some_and(|e| s.contains(e))),
                Some(v.clone()),
            )
        }
        Some(Known::Json(inner)) => contains(&inner.child_of(v), expected),
        _ => Verdict::new(Truth::False, Some(v.clone())),
    })
}

/// Graph vertices unwrap parser lists; blocks still retain their cardinality.
fn graph_configuration(body: &Body) -> Value {
    let mut map: Map = body
        .attrs
        .iter()
        .map(|a| (a.name.clone(), a.value.clone()))
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

    fn missing(&self) -> Verdict {
        match self.missing {
            Missing::Pass => Verdict::FALSE,
            Missing::Fail => Verdict::new(Truth::True, None),
            Missing::Unknown => Verdict::new(Truth::Unknown, None),
        }
    }

    pub fn evaluate(&self, resource: &Resource) -> Verdict {
        let Some(value) = field(&resource.body, &self.path[0]) else {
            return self.missing();
        };
        self.walk(&value, &self.path[1..], &|| {
            if self.negative {
                self.missing()
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
                    Truth::False => self.missing(),
                    _ if self.missing == Missing::Pass => Verdict::FALSE,
                    _ => pass,
                }
            }
        })
    }

    fn walk(&self, value: &Value, path: &[String], missing: &dyn Fn() -> Verdict) -> Verdict {
        truth::map(value, &|v| {
            let Some((first, rest)) = path.split_first() else {
                return self.leaf(v);
            };
            match &v.kind {
                Kind::Known(Known::Object(m)) => match m.get(first.as_str()) {
                    Some(child) => self.walk(&child.clone().child_of(v), rest, missing),
                    None => missing(),
                },
                Kind::Known(Known::List(l)) => match index(first).and_then(|i| l.get(i)) {
                    Some(child) => self.walk(&child.clone().child_of(v), rest, missing),
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

    fn leaf(&self, value: &Value) -> Verdict {
        unbox(value, &|v| {
            if v.is_null() || matches!(&v.kind, Kind::Known(Known::List(l)) if l.is_empty()) {
                return self.missing();
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
    if let Some(a) = body.attr(name) {
        return Some(if a.from_blocks {
            block_values(&a.value)
        } else {
            Value::list(vec![a.value.clone()])
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
        values.push(configuration(&b.body));
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

pub fn configuration(body: &Body) -> Value {
    let mut out = Map::new();
    for name in body
        .attrs
        .iter()
        .map(|a| &a.name)
        .chain(body.blocks.iter().map(|b| &b.ty))
    {
        if let Some(v) = field(body, name) {
            out.insert(name.clone(), v);
        }
    }
    Value::object(out)
}

//! The admitted subset of Checkov's JSONPath predicates. Paths are
//! compiled at export time; runtime traversal retains abstract values.
use std::cell::Cell;

use crate::checkov::{AttributeCheck, AttributeOp, configuration};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tf_eval::{Kind, Known, Step, StepKind, Truth, Value, Verdict, truth};
use tf_semantic::Resource;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Segment {
    Field(String),
    Select(Selector),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selector {
    Each,
    Filter { predicates: Vec<FilterPredicate> },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterPredicate {
    pub path: Vec<String>,
    pub operator: FilterOp,
    /// A string, or an integer (the matched value is then passed through
    /// Python's `int()` before comparing, as bc_jsonpath_ng does).
    pub value: Json,
    #[serde(skip)]
    regex: crate::checkov::Cache<Option<regex::Regex>>,
}

impl FilterPredicate {
    pub fn new(path: Vec<String>, operator: FilterOp, value: Json) -> Self {
        FilterPredicate {
            path,
            operator,
            value,
            regex: Default::default(),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.path.is_empty() || self.path.iter().any(|s| !field_name(s)) {
            return Err("JSONPath filter requires literal fields".into());
        }
        match (&self.value, self.operator) {
            (Json::String(_), FilterOp::Equals | FilterOp::NotEquals | FilterOp::Regex) => {}
            (Json::Number(n), op) if n.is_i64() && op != FilterOp::Regex => {}
            _ => {
                return Err(
                    "JSONPath filter expects a string (==, !=, =~) or an integer comparison".into(),
                );
            }
        }
        if self.regex().is_none() && self.operator == FilterOp::Regex {
            return Err("JSONPath filter regex is not supported".into());
        }
        Ok(())
    }

    fn regex(&self) -> Option<&regex::Regex> {
        self.regex
            .get_or_init(|| {
                let pattern = self.value.as_str()?;
                crate::pyre::compile(pattern, crate::pyre::Mode::Search).ok()
            })
            .as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Equals,
    NotEquals,
    /// `=~`: Python `re.search(pattern, value)`.
    Regex,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
}

pub(crate) fn field_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonPathCheck {
    pub path: Vec<Segment>,
    /// `jsonpath_<operator>`: the attribute operator, applied to every match.
    pub operator: AttributeOp,
    #[serde(default)]
    pub value: Json,
    #[serde(skip)]
    check: crate::checkov::Cache<AttributeCheck>,
}

impl JsonPathCheck {
    pub fn validate(&self) -> Result<(), String> {
        let Some(Segment::Field(first)) = self.path.first() else {
            return Err("JSONPath requires an initial configured field".into());
        };
        if self.path.iter().any(|segment| match segment {
            Segment::Field(s) => !field_name(s),
            Segment::Select(Selector::Each) => false,
            Segment::Select(Selector::Filter { predicates }) => {
                predicates.is_empty() || predicates.iter().any(|p| p.validate().is_err())
            }
        }) || matches!(
            first.as_str(),
            "lifecycle"
                | "provisioner"
                | "connection"
                | "count"
                | "for_each"
                | "provider"
                | "depends_on"
        ) {
            return Err(
                "JSONPath requires literal fields, array wildcards or string filters without meta-arguments".into(),
            );
        }
        self.check().validate_operand()
    }

    pub fn evaluate(&self, resource: &Resource) -> Verdict {
        let configured = configuration(&resource.body);
        let vertex = Value::object(
            configured
                .as_object()
                .expect("configuration object")
                .iter()
                .map(|(key, value)| (key.clone(), vertex_field(value)))
                .collect(),
        );
        let fields: Option<Vec<String>> = self
            .path
            .iter()
            .map(|s| match s {
                Segment::Field(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        let mut result = if let Some(fields) = fields {
            self.predicate(&lookup(&vertex, &fields, 0, true).unwrap_or_else(Value::null))
        } else {
            let raised = Cell::new(false);
            let matches = self.query(&vertex, &self.path, &raised);
            if raised.get() {
                // An exception anywhere in the query aborts it: no result.
                return Verdict::new(Truth::Unknown, Some(vertex.clone()));
            }
            if self.predicate(&Value::null()).truth == Truth::True {
                matches.all
            } else {
                matches.any.and(matches.all)
            }
        };
        if result.witness.as_ref().is_none_or(|v| v.prov.is_empty()) {
            result.witness = Some(
                result.witness.unwrap_or_else(Value::null).push(
                    Step::new(
                        StepKind::Attribute,
                        resource.body.span,
                        "JSONPath predicate",
                    )
                    .with_resource(resource.address.clone()),
                ),
            );
        }
        result
    }

    /// The operator as an attribute check, prepared once.
    fn check(&self) -> &AttributeCheck {
        self.check.get_or_init(|| AttributeCheck {
            attribute: String::new(),
            operator: self.operator,
            value: self.value.clone(),
            prepared: Default::default(),
        })
    }

    fn predicate(&self, value: &Value) -> Verdict {
        // A JSONPath match is the raw (unflattened) vertex value, so
        // containment uses the one-level semantics below.
        match self.operator {
            AttributeOp::Contains => contains(value, &self.value),
            AttributeOp::NotContains => contains(value, &self.value).negate(),
            _ => self.check().evaluate_value(value),
        }
    }

    fn query(&self, value: &Value, path: &[Segment], raised: &Cell<bool>) -> Matches {
        if let Kind::OneOf(o) = &value.kind {
            let branches: Vec<_> = o
                .alternatives
                .iter()
                .map(|v| self.query(&v.child_of(value), path, raised))
                .collect();
            return Matches {
                any: truth::combine_one_of(
                    branches.iter().map(|m| m.any.clone()).collect(),
                    o.tainted,
                ),
                all: truth::combine_one_of(
                    branches.into_iter().map(|m| m.all).collect(),
                    o.tainted,
                ),
            };
        }
        if path.is_empty() {
            return Matches {
                any: Verdict::new(Truth::True, Some(value.clone())),
                all: self.predicate(value),
            };
        }
        if matches!(&value.kind, Kind::Unknown(_) | Kind::Tainted(_)) {
            let unknown = Verdict::new(truth::uncertainty(value), Some(value.clone()));
            return Matches {
                any: unknown.clone(),
                all: unknown,
            };
        }
        // The Terraform renderer treats jsonencode as its structured argument.
        // Keep symbolic descendants; never round-trip through a JSON string.
        if let Some(Known::Json(inner)) = value.as_known() {
            return self.query(&inner.child_of(value), path, raised);
        }
        if let Some(s) = value.as_str()
            && let Ok(json) = serde_json::from_str::<Json>(s)
            && (json.is_object() || json.is_array())
        {
            // Terraform's renderer also decodes literal JSON policy strings.
            return self.query(&tf_eval::value::from_json(&json, &value.prov), path, raised);
        }
        match &path[0] {
            Segment::Field(name) => value
                .as_object()
                .and_then(|o| o.get(name.as_str()))
                .map_or_else(Matches::empty, |v| {
                    self.query(&v.child_of(value), &path[1..], raised)
                }),
            Segment::Select(selector) => {
                if matches!(selector, Selector::Each)
                    && value.as_number().is_some_and(|n| n.fract() != 0.0)
                {
                    let unknown = Verdict::new(Truth::Unknown, Some(value.clone()));
                    return Matches {
                        any: unknown.clone(),
                        all: unknown,
                    };
                }
                let items: Vec<Value> = match value.as_known() {
                    Some(Known::List(items)) => items.iter().map(|v| v.child_of(value)).collect(),
                    Some(Known::Object(items))
                        if matches!(selector, Selector::Filter { .. }) || !items.is_empty() =>
                    {
                        vec![value.clone()]
                    }
                    Some(Known::String(s))
                        if !s.is_empty() && matches!(selector, Selector::Each) =>
                    {
                        vec![value.clone()]
                    }
                    Some(Known::Bool(true)) if matches!(selector, Selector::Each) => {
                        vec![value.clone()]
                    }
                    Some(Known::Number(n)) if *n != 0.0 && matches!(selector, Selector::Each) => {
                        vec![value.clone()]
                    }
                    _ => Vec::new(),
                };
                items.iter().fold(Matches::empty(), |matches, item| {
                    let eligibility = match selector {
                        Selector::Each => Verdict::new(Truth::True, Some(item.clone())),
                        Selector::Filter { predicates } => predicates.iter().fold(
                            Verdict::new(Truth::True, Some(item.clone())),
                            |result, p| result.and(filter(item, p, &p.path, raised)),
                        ),
                    };
                    let next = match eligibility.truth {
                        Truth::False => Matches::empty(),
                        Truth::True => self.query(item, &path[1..], raised),
                        _ => {
                            let next = self.query(item, &path[1..], raised);
                            Matches {
                                any: eligibility.clone().and(next.any),
                                all: eligibility.negate().or(next.all),
                            }
                        }
                    };
                    Matches {
                        any: matches.any.or(next.any),
                        all: matches.all.and(next.all),
                    }
                })
            }
        }
    }
}

/// Separately track whether a query has matches and whether every match
/// satisfies the predicate. Empty queries use Checkov's missing-value result.
struct Matches {
    any: Verdict,
    all: Verdict,
}

impl Matches {
    fn empty() -> Self {
        Self {
            any: Verdict::FALSE,
            all: Verdict::new(Truth::True, None),
        }
    }
}

fn filter(
    value: &Value,
    predicate: &FilterPredicate,
    path: &[String],
    raised: &Cell<bool>,
) -> Verdict {
    truth::map(value, &|value| {
        if path.is_empty() {
            return filter_leaf(value, predicate, raised);
        }
        if let Some(Known::Json(inner)) = value.as_known() {
            return filter(&inner.child_of(value), predicate, path, raised);
        }
        value
            .as_object()
            .and_then(|o| o.get(path[0].as_str()))
            .map_or(Verdict::FALSE, |v| {
                filter(&v.child_of(value), predicate, &path[1..], raised)
            })
    })
}

/// bc_jsonpath_ng's `Expression.find` on one matched value. Where Python
/// raises (`int()` of a non-scalar, `re.search` on a non-string) the whole
/// query fails, so the result is left unresolved.
fn filter_leaf(value: &Value, predicate: &FilterPredicate, raised: &Cell<bool>) -> Verdict {
    let yes = |b: bool| Verdict::new(Truth::from_bool(b), Some(value.clone()));
    let raises = || {
        raised.set(true);
        Verdict::new(Truth::Unknown, Some(value.clone()))
    };
    match &predicate.value {
        Json::String(expected) => match predicate.operator {
            FilterOp::Regex => match value.as_known() {
                Some(Known::String(s)) => yes(predicate.regex().expect("validated").is_match(s)),
                _ => raises(),
            },
            op => {
                let equal = value.as_str() == Some(expected.as_str());
                yes(equal == (op == FilterOp::Equals))
            }
        },
        Json::Number(n) => {
            let expected = n.as_i64().expect("validated") as i128;
            let actual = match value.as_known() {
                Some(Known::String(s)) => match crate::py::int_str(s) {
                    Some(n) => n,
                    // int() raised ValueError: the item is skipped.
                    None => return yes(false),
                },
                Some(Known::Number(f)) => f.trunc() as i128,
                Some(Known::Bool(b)) => *b as i128,
                _ => return raises(),
            };
            yes(match predicate.operator {
                FilterOp::Equals => actual == expected,
                FilterOp::NotEquals => actual != expected,
                FilterOp::LessThan => actual < expected,
                FilterOp::LessThanOrEqual => actual <= expected,
                FilterOp::GreaterThan => actual > expected,
                FilterOp::GreaterThanOrEqual => actual >= expected,
                FilterOp::Regex => unreachable!("validated"),
            })
        }
        _ => unreachable!("validated"),
    }
}

/// Python membership used by the pinned containment solver. Object values are
/// inspected one level deep; invalid scalar operands remain indeterminate.
fn membership(value: &Value, expected: &Json) -> Verdict {
    truth::map(value, &|v| match v.as_known() {
        Some(Known::List(_)) => truth::exists(v, &|item| crate::checkov::equal(item, expected)),
        Some(Known::Object(items)) => Verdict::new(
            Truth::from_bool(expected.as_str().is_some_and(|s| items.contains_key(s))),
            Some(v.clone()),
        ),
        Some(Known::String(s)) if expected.is_string() => Verdict::new(
            Truth::from_bool(s.contains(expected.as_str().expect("string"))),
            Some(v.clone()),
        ),
        _ => Verdict::new(Truth::Unknown, Some(v.clone())),
    })
}

fn contains(value: &Value, expected: &Json) -> Verdict {
    truth::map(value, &|v| {
        if v.is_null() {
            return Verdict::new(Truth::False, Some(v.clone()));
        }
        if let Some(Known::Json(inner)) = v.as_known() {
            return contains(&inner.child_of(v), expected);
        }
        if let Some(s) = v.as_str()
            && let Ok(json) = serde_json::from_str::<Json>(&s.replace('\'', "\""))
        {
            let parsed = tf_eval::value::from_json(&json, &v.prov);
            return contains_parsed(&parsed, expected);
        }
        contains_parsed(v, expected)
    })
}

fn contains_parsed(value: &Value, expected: &Json) -> Verdict {
    let mut result = membership(value, expected);
    if let Some(items) = value.as_object() {
        for item in items.values() {
            let child = item.child_of(value);
            let candidate = truth::map(&child, &|v| match v.as_known() {
                Some(Known::String(_) | Known::List(_) | Known::Object(_)) => {
                    membership(v, expected)
                }
                _ => Verdict::FALSE,
            });
            result = result.or(candidate);
        }
    }
    result
}

/// TerraformBlock expands object attributes and blocks before building its
/// graph vertex. Plain top-level attribute lists retain their cardinality.
fn vertex_field(value: &Value) -> Value {
    match &value.kind {
        Kind::Known(Known::Object(_)) => inner(value, true),
        Kind::Known(Known::List(items)) => {
            if items
                .first()
                .is_some_and(|v| matches!(v.as_known(), Some(Known::Object(_))))
            {
                inner(value, true)
            } else if items.len() == 1 {
                // The parser's outer attribute wrapper, not the Terraform list.
                let child = items[0].child_of(value);
                match &child.kind {
                    Kind::OneOf(o) => Value::one_of(
                        o.alternatives
                            .iter()
                            .map(|a| vertex_field(&Value::list(vec![a.child_of(&child)])))
                            .collect(),
                        o.tainted,
                    )
                    .child_of(value),
                    _ => child,
                }
            } else {
                value.clone()
            }
        }
        Kind::OneOf(o) => {
            Value::one_of(o.alternatives.iter().map(vertex_field).collect(), o.tainted)
                .child_of(value)
        }
        _ => value.clone(),
    }
}

/// Checkov strips one singleton list at each recursively projected field.
/// A block attribute list has an extra parser wrapper, so it stays a list.
fn inner(value: &Value, strip: bool) -> Value {
    if strip
        && let Some(items) = value.as_list()
        && items.len() == 1
    {
        return inner(&items[0].child_of(value), false);
    }
    match &value.kind {
        Kind::Known(Known::Object(items)) => Value::object(
            items
                .iter()
                .filter(|(k, _)| !k.is_empty())
                .map(|(k, v)| (k.clone(), inner(v, true)))
                .collect(),
        )
        .child_of(value),
        Kind::Known(Known::List(items)) => {
            Value::list(items.iter().map(|v| inner(v, true)).collect()).child_of(value)
        }
        Kind::OneOf(o) => Value::one_of(
            o.alternatives.iter().map(|v| inner(v, strip)).collect(),
            o.tainted,
        )
        .child_of(value),
        _ => value.clone(),
    }
}

/// Literal JSONPath has at most one match. If it has none, Checkov falls back
/// to the flattened attribute key. get_attribute_dict expands nested fields a
/// second time, adding keys below singleton lists. Resolve that fallback only
/// when an existing flattened key cannot supply the value, per alternative.
fn lookup(value: &Value, path: &[String], depth: usize, fallback: bool) -> Option<Value> {
    if path.is_empty() {
        return Some(value.clone());
    }
    match &value.kind {
        Kind::Known(Known::Object(items)) => {
            let mut candidates = Vec::new();
            if let Some(v) = items.get(path.join(".").as_str()) {
                candidates.push(v.child_of(value));
            }
            for end in (1..path.len()).rev() {
                if let Some(v) = items.get(path[..end].join(".").as_str())
                    && let Some(found) =
                        lookup(&v.child_of(value), &path[end..], depth + end, fallback)
                {
                    candidates.push(found);
                }
            }
            match candidates.len() {
                0 => None,
                1 => candidates.pop(),
                // Terraform maps do not retain source insertion order. When
                // dotted keys collide with nested fields, either upstream
                // flattening order is possible. Keep both deciding values.
                _ => Some(Value::one_of(candidates, true).child_of(value)),
            }
        }
        Kind::Known(Known::List(items)) if fallback && depth > 1 && items.len() == 1 => {
            lookup(&inner(value, true), path, depth, false)
        }
        Kind::OneOf(o) => Some(
            Value::one_of(
                o.alternatives
                    .iter()
                    .map(|v| {
                        lookup(&v.child_of(value), path, depth, fallback)
                            .unwrap_or_else(|| Value::null().child_of(value))
                    })
                    .collect(),
                o.tainted,
            )
            .child_of(value),
        ),
        Kind::Unknown(_) | Kind::Tainted(_) => Some(value.clone()),
        _ => None,
    }
}

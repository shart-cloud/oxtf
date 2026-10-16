//! The admitted subset of Checkov's JSONPath predicates. Paths are
//! compiled at export time; runtime traversal retains abstract values.
use crate::checkov::{AttributeCheck, AttributeOp, configuration};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tf_eval::{Kind, Known, Step, StepKind, Truth, Value, Verdict, truth};
use tf_semantic::Resource;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonPathOp {
    Exists,
    NotExists,
    Equals,
    NotEquals,
    NotContains,
}

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
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Equals,
    NotEquals,
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
    pub operator: JsonPathOp,
    #[serde(default)]
    pub value: Json,
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
                predicates.is_empty()
                    || predicates
                        .iter()
                        .any(|p| p.path.is_empty() || p.path.iter().any(|s| !field_name(s)))
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
        if self.value.is_array() || self.value.is_object() {
            return Err("JSONPath comparison expects a scalar".into());
        }
        Ok(())
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
            let matches = self.query(&vertex, &self.path);
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

    fn predicate(&self, value: &Value) -> Verdict {
        if self.operator == JsonPathOp::NotContains {
            return contains(value, &self.value).negate();
        }
        AttributeCheck {
            attribute: String::new(),
            operator: match self.operator {
                JsonPathOp::Exists => AttributeOp::Exists,
                JsonPathOp::NotExists => AttributeOp::NotExists,
                JsonPathOp::Equals => AttributeOp::Equals,
                JsonPathOp::NotEquals => AttributeOp::NotEquals,
                JsonPathOp::NotContains => AttributeOp::NotContains,
            },
            value: self.value.clone(),
        }
        .evaluate_value(value)
    }

    fn query(&self, value: &Value, path: &[Segment]) -> Matches {
        if let Kind::OneOf(o) = &value.kind {
            let branches: Vec<_> = o
                .alternatives
                .iter()
                .map(|v| self.query(&v.child_of(value), path))
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
            return self.query(&inner.child_of(value), path);
        }
        if let Some(s) = value.as_str()
            && let Ok(json) = serde_json::from_str::<Json>(s)
            && (json.is_object() || json.is_array())
        {
            // Terraform's renderer also decodes literal JSON policy strings.
            return self.query(&tf_eval::value::from_json(&json, &value.prov), path);
        }
        match &path[0] {
            Segment::Field(name) => value
                .as_object()
                .and_then(|o| o.get(name.as_str()))
                .map_or_else(Matches::empty, |v| {
                    self.query(&v.child_of(value), &path[1..])
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
                            |result, p| result.and(filter(item, p, &p.path)),
                        ),
                    };
                    let next = match eligibility.truth {
                        Truth::False => Matches::empty(),
                        Truth::True => self.query(item, &path[1..]),
                        _ => {
                            let next = self.query(item, &path[1..]);
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

fn filter(value: &Value, predicate: &FilterPredicate, path: &[String]) -> Verdict {
    truth::map(value, &|value| {
        if path.is_empty() {
            let equal = value.as_str() == Some(predicate.value.as_str());
            return Verdict::new(
                Truth::from_bool(equal == (predicate.operator == FilterOp::Equals)),
                Some(value.clone()),
            );
        }
        if let Some(Known::Json(inner)) = value.as_known() {
            return filter(&inner.child_of(value), predicate, path);
        }
        value
            .as_object()
            .and_then(|o| o.get(path[0].as_str()))
            .map_or(Verdict::FALSE, |v| {
                filter(&v.child_of(value), predicate, &path[1..])
            })
    })
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

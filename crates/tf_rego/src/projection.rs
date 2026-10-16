//! Known-only projection of a resource instance for foreign policies.
//!
//! Rego never sees an abstract value. Every Unknown, Tainted or OneOf value
//! in the resource's configured attributes is left out of the projected
//! document and recorded on the **abstraction list** with its attribute
//! path; the adapter classifies any finding on the resource from that list.
//! Known containers are projected recursively, so an abstract element deep
//! inside a known list or object is listed too (and the list keeps its
//! other elements).

use serde_json::{Map as JsonMap, Value as Json, json};
use tf_eval::value::to_json;
use tf_eval::{Kind, Known, Truth, Value, truth};
use tf_semantic::{Body, Resource};

/// The input document shape a foreign policy family expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// `terraform show -json` plan: `resource_changes[*].change.after` and
    /// `planned_values.root_module.resources[*].values`.
    Plan,
    /// HCL as JSON (Conftest's hcl2 parser, i.e. hcl2json): every block body,
    /// resources and nested blocks alike, is wrapped in a list:
    /// `resource.<type>.<name>[0]`.
    Hcl,
}

impl std::str::FromStr for Shape {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "plan" => Ok(Shape::Plan),
            "hcl" => Ok(Shape::Hcl),
            _ => Err(format!("unknown policy input shape {s:?} (plan, hcl)")),
        }
    }
}

/// A configured value the policy did not see.
#[derive(Clone, Debug)]
pub struct Abstraction {
    /// Attribute path, e.g. `encryption_settings[0].enabled`.
    pub path: String,
    /// `Tainted` or `Unknown`, by [`truth::uncertainty`].
    pub truth: Truth,
    /// The value itself, for provenance.
    pub value: Value,
}

#[derive(Clone, Debug, Default)]
pub struct Projection {
    /// The resource's configured attributes and nested blocks, Known parts only.
    pub attributes: JsonMap<String, Json>,
    pub abstractions: Vec<Abstraction>,
}

impl Projection {
    /// The one classification rule for foreign findings: Definite only when
    /// every input the policy could have read was Known.
    pub fn certainty(&self) -> tf_linter::Severity {
        use tf_linter::Severity::*;
        if self.abstractions.iter().any(|a| a.truth == Truth::Tainted) {
            Conditional
        } else if self.abstractions.is_empty() {
            Definite
        } else {
            Indeterminate
        }
    }

    /// The abstraction that decides the certainty (a Tainted one first).
    pub fn deciding(&self) -> Option<&Abstraction> {
        self.abstractions
            .iter()
            .find(|a| a.truth == Truth::Tainted)
            .or_else(|| self.abstractions.first())
    }
}

/// Project a resource instance's body for `shape`.
pub fn project(r: &Resource, shape: Shape) -> Projection {
    let mut p = Projection::default();
    let _ = shape; // both shapes share one body projection; they differ in the envelope
    project_body(&r.body, "", &mut p);
    p
}

fn project_body(body: &Body, prefix: &str, p: &mut Projection) {
    for a in &body.attrs {
        let path = format!("{prefix}{}", a.name);
        if let Some(j) = project_value(&a.value, &path, p) {
            p.attributes.insert(a.name.to_string(), j);
        }
    }
    // Nested blocks that are not attributes-as-blocks: lists of objects.
    for b in &body.blocks {
        let path = format!("{prefix}{}", b.ty);
        if b.existence != Truth::True {
            p.abstractions.push(Abstraction {
                path,
                truth: b.existence,
                value: Value::other("dynamic block"),
            });
            continue;
        }
        let mut child = Projection::default();
        let index = p
            .attributes
            .get(&*b.ty)
            .and_then(Json::as_array)
            .map_or(0, Vec::len);
        project_body(&b.body, &format!("{path}[{index}]."), &mut child);
        p.abstractions.extend(child.abstractions);
        let obj = Json::Object(child.attributes);
        match p.attributes.get_mut(&*b.ty) {
            Some(Json::Array(list)) => list.push(obj),
            _ => {
                p.attributes.insert(b.ty.to_string(), json!([obj]));
            }
        }
    }
}

/// `None` when the value is abstract (recorded), else its JSON with abstract
/// descendants removed (objects) or recorded and dropped (lists).
pub(crate) fn project_value(v: &Value, path: &str, p: &mut Projection) -> Option<Json> {
    match &v.kind {
        Kind::Known(Known::Object(m)) => {
            let mut out = JsonMap::new();
            for (k, x) in m.iter() {
                if let Some(j) = project_value(x, &format!("{path}.{k}"), p) {
                    out.insert(k.to_string(), j);
                }
            }
            Some(Json::Object(out))
        }
        Kind::Known(Known::List(l)) => Some(Json::Array(
            l.iter()
                .enumerate()
                .filter_map(|(i, x)| project_value(x, &format!("{path}[{i}]"), p))
                .collect(),
        )),
        Kind::Known(Known::Json(inner)) => match to_json(inner) {
            Some(j) => Some(Json::String(j.to_string())),
            None => {
                record(v, path, p);
                None
            }
        },
        Kind::Known(_) => to_json(v),
        _ => {
            record(v, path, p);
            None
        }
    }
}

fn record(v: &Value, path: &str, p: &mut Projection) {
    p.abstractions.push(Abstraction {
        path: path.to_string(),
        truth: truth::uncertainty(v),
        value: v.clone(),
    });
}

/// A single value, Known parts only (abstract descendants dropped).
pub fn known_part(v: &Value) -> Json {
    let mut scratch = Projection::default();
    project_value(v, "", &mut scratch).unwrap_or(Json::Null)
}

/// The policy input document for one resource instance.
pub fn input(r: &Resource, p: &Projection, shape: Shape) -> Json {
    let attrs = Json::Object(p.attributes.clone());
    match shape {
        Shape::Hcl => json!({ "resource": { &*r.ty: { &*r.name: [attrs] } } }),
        Shape::Plan => {
            let after_unknown: JsonMap<String, Json> = p
                .abstractions
                .iter()
                .filter(|a| !a.path.contains(['.', '[']))
                .map(|a| (a.path.clone(), Json::Bool(true)))
                .collect();
            let index = r.key.as_deref().map(Json::from).unwrap_or(Json::Null);
            let module_address = (!r.module.is_empty()).then(|| Json::from(&*r.module));
            json!({
                "format_version": "1.2",
                "resource_changes": [{
                    "address": &*r.address,
                    "module_address": module_address,
                    "mode": "managed",
                    "type": &*r.ty,
                    "name": &*r.name,
                    "index": index,
                    "change": {
                        "actions": ["create"],
                        "before": null,
                        "after": attrs,
                        "after_unknown": after_unknown,
                    }
                }],
                "planned_values": { "root_module": { "resources": [{
                    "address": &*r.address,
                    "mode": "managed",
                    "type": &*r.ty,
                    "name": &*r.name,
                    "index": index,
                    "values": attrs,
                }]}}
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    #[test]
    fn known_parts_are_projected_and_abstract_parts_listed() {
        let v = obj(vec![
            ("enabled", Value::bool(false)),
            ("name", Value::tainted("n")),
            (
                "cidrs",
                Value::list(vec![Value::string("0.0.0.0/0"), Value::other("computed")]),
            ),
            (
                "nested",
                obj(vec![(
                    "deep",
                    Value::one_of(vec![Value::number(1.0), Value::number(2.0)], true),
                )]),
            ),
        ]);
        let mut p = Projection::default();
        let j = project_value(&v, "root", &mut p).unwrap();
        assert_eq!(
            j,
            json!({"enabled": false, "cidrs": ["0.0.0.0/0"], "nested": {}})
        );
        let mut paths: Vec<_> = p.abstractions.iter().map(|a| (a.path.as_str(), a.truth)).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                ("root.cidrs[1]", Truth::Unknown),
                ("root.name", Truth::Tainted),
                ("root.nested.deep", Truth::Tainted),
            ]
        );
        assert_eq!(p.certainty(), tf_linter::Severity::Conditional);
        assert_eq!(p.deciding().unwrap().path, "root.name");
    }

    #[test]
    fn certainty_is_definite_only_when_nothing_was_hidden() {
        let mut p = Projection::default();
        assert_eq!(p.certainty(), tf_linter::Severity::Definite);
        record(&Value::other("x"), "a", &mut p);
        assert_eq!(p.certainty(), tf_linter::Severity::Indeterminate);
        record(&Value::one_of(vec![Value::bool(true)], false), "b", &mut p);
        assert_eq!(p.certainty(), tf_linter::Severity::Indeterminate);
        record(&Value::tainted("t"), "c", &mut p);
        assert_eq!(p.certainty(), tf_linter::Severity::Conditional);
        assert_eq!(p.deciding().unwrap().path, "c");
    }
}

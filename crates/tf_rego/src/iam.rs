use super::*;
use tf_eval::{Known, value::from_json};

#[derive(Clone, Copy)]
enum Shape {
    Policy,
    Document,
    Statements,
    Statement,
    Wildcard,
    Atom,
}
impl Evidence {
    fn iam_value(&mut self, value: Value, shape: Shape) -> Json {
        if let Kind::OneOf(o) = &value.kind {
            return json!({"kind":"one_of", "tainted":o.tainted,
                "alternatives":o.alternatives.iter().map(|a| self.iam_value(a.child_of(&value), shape)).collect::<Vec<_>>()});
        }
        let mut tag = self.tag(Some(value.clone()));
        if let Kind::Known(k) = &value.kind {
            tag["text"] = json!(value.to_str().map(|s| s.trim().to_string()));
            tag["string"] = json!(value.as_str());
            let field = |name: &str| match k {
                Known::Object(m) => m
                    .get(name)
                    .map(|v| v.child_of(&value))
                    .unwrap_or_else(Value::null),
                Known::Null => Value::null(),
                _ => value.get_attr(name),
            };
            match shape {
                Shape::Policy => {
                    let doc = match k {
                        Known::Json(inner) => Some(inner.child_of(&value)),
                        Known::String(s) => serde_json::from_str::<Json>(s)
                            .ok()
                            .map(|j| from_json(&j, &value.prov)),
                        _ => None,
                    };
                    tag["document"] = doc
                        .map(|d| self.iam_value(d, Shape::Document))
                        .unwrap_or(Json::Null);
                }
                Shape::Document => {
                    tag["statements"] = self.iam_value(field("Statement"), Shape::Statements)
                }
                Shape::Statements | Shape::Wildcard => {
                    let inner = if matches!(shape, Shape::Statements) {
                        Shape::Statement
                    } else {
                        Shape::Atom
                    };
                    if let Known::List(elements) = k {
                        tag["elements"] = json!(
                            elements
                                .iter()
                                .map(|v| self.iam_value(v.child_of(&value), inner))
                                .collect::<Vec<_>>()
                        );
                    } else if !matches!(k, Known::Null) {
                        tag["single"] = self.iam_value(value.clone(), inner);
                    }
                }
                Shape::Statement => {
                    tag["action"] = self.iam_value(field("Action"), Shape::Wildcard);
                    tag["resource"] = self.iam_value(field("Resource"), Shape::Wildcard);
                    tag["effect"] = self.iam_value(field("Effect"), Shape::Atom);
                }
                Shape::Atom => {}
            }
        }
        tag
    }
    pub(super) fn iam_input(&mut self, r: &Resource) -> Json {
        json!({"policy":self.iam_value(r.value("policy").unwrap_or_else(Value::null), Shape::Policy)})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_eval::truth;
    fn field(v: &Value, n: &str) -> Value {
        match &v.kind {
            Kind::Known(Known::Object(m)) => {
                m.get(n).map(|x| x.child_of(v)).unwrap_or_else(Value::null)
            }
            Kind::Known(Known::Null) => Value::null(),
            _ => v.get_attr(n),
        }
    }
    fn native(v: &Value) -> Verdict {
        truth::map(v, &|p| {
            let doc = match &p.kind {
                Kind::Known(Known::Json(d)) => Some(d.child_of(p)),
                Kind::Known(Known::String(s)) => serde_json::from_str::<Json>(s)
                    .ok()
                    .map(|j| from_json(&j, &p.prov)),
                _ => None,
            };
            doc.map(|d| {
                truth::map(&d, &|d| {
                    truth::exists(&field(d, "Statement"), &|s| {
                        truth::map(s, &|s| {
                            let wild = |v: &Value| {
                                truth::exists(v, &|v| {
                                    truth::test(v, &|v| v.to_str().is_some_and(|s| s.trim() == "*"))
                                })
                            };
                            wild(&field(s, "Action"))
                                .and(wild(&field(s, "Resource")))
                                .and(truth::test(&field(s, "Effect"), &|v| {
                                    v.as_str() == Some("Allow")
                                }))
                        })
                    })
                })
            })
            .unwrap_or(Verdict::FALSE)
        })
    }
    #[test]
    fn document_shapes_uncertainty_and_witnesses_match_native() {
        let policy = NativeRule::Iam.prepare().unwrap();
        let base = [
            Value::string("*"),
            Value::string(" scoped "),
            Value::null(),
            Value::tainted("x"),
            Value::other("computed"),
        ];
        let mut fields = base.to_vec();
        for a in &base {
            for b in &base {
                fields.push(Value::list(vec![a.clone(), b.clone()]));
                fields.push(Value::one_of(vec![a.clone(), b.clone()], true));
                fields.push(Value::one_of(vec![a.clone(), b.clone()], false));
            }
        }
        let mut cases = vec![
            Value::string("invalid JSON"),
            Value::string("null"),
            Value::string("42"),
            Value::tainted("policy"),
            Value::other("policy"),
        ];
        for field_value in fields {
            for effect in [
                Value::string("Allow"),
                Value::string("Deny"),
                Value::tainted("effect"),
                Value::other("effect"),
            ] {
                let stmt = Value::object(
                    [
                        ("Action".into(), field_value.clone()),
                        ("Resource".into(), Value::string("*")),
                        ("Effect".into(), effect),
                    ]
                    .into(),
                );
                for statements in [
                    stmt.clone(),
                    Value::list(vec![stmt.clone()]),
                    Value::one_of(vec![stmt, Value::null()], true),
                ] {
                    let doc = Value::object([("Statement".into(), statements)].into());
                    if let Some(json) = tf_eval::value::to_json(&doc) {
                        cases.push(Value::string(json.to_string()));
                    }
                    cases.push(Value::json(doc.clone()));
                    cases.push(Value::json(Value::one_of(vec![doc, Value::null()], false)));
                }
            }
        }
        for case in cases {
            let mut evidence = Evidence::default();
            let input = json!({"policy":evidence.iam_value(case.clone(), Shape::Policy)});
            let actual = evaluate(&policy, &input, &evidence.0).unwrap();
            let expected = native(&case);
            assert_eq!(actual.truth, expected.truth, "{case:?}");
            assert_eq!(
                format!("{:?}", actual.witness),
                format!("{:?}", expected.witness),
                "{case:?}"
            );
        }
    }
}

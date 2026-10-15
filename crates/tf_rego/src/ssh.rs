//! Context-specific projections keep container traversal in Rego non-recursive.
//! Each extracted child retains the native parent provenance before registration.
use super::*;
use tf_eval::Known;

#[derive(Clone, Copy)]
enum Shape {
    Atom,
    Cidrs,
    Inline,
    Ingress,
}

impl Evidence {
    fn ssh_value(&mut self, value: Value, shape: Shape) -> Json {
        if let Kind::OneOf(o) = &value.kind {
            let alternatives: Vec<_> = o
                .alternatives
                .iter()
                .map(|a| self.ssh_value(a.child_of(&value), shape))
                .collect();
            return json!({"kind":"one_of", "tainted":o.tainted, "alternatives":alternatives});
        }
        let mut tag = self.tag(Some(value.clone()));
        if let Kind::Known(_) = &value.kind {
            tag["text"] = json!(value.to_str().map(|s| s.trim().to_string()));
            tag["string"] = json!(value.as_str());
            // Rust's numeric conversion preserves Terraform numeric strings.
            tag["number"] = json!(value.as_number());
            // JSON has no infinities, but native numeric-string conversion does.
            tag["negative_infinity"] = json!(value.as_number() == Some(f64::NEG_INFINITY));
            tag["positive_infinity"] = json!(value.as_number() == Some(f64::INFINITY));
            match shape {
                Shape::Atom => {}
                Shape::Cidrs | Shape::Ingress => {
                    if let Kind::Known(Known::List(elements)) = &value.kind {
                        let child_shape = if matches!(shape, Shape::Cidrs) {
                            Shape::Atom
                        } else {
                            Shape::Inline
                        };
                        tag["elements"] = json!(
                            elements
                                .iter()
                                .map(|v| self.ssh_value(v.child_of(&value), child_shape))
                                .collect::<Vec<_>>()
                        );
                    } else if matches!(shape, Shape::Ingress) {
                        self.ssh_fields(&mut tag, &value);
                    }
                }
                Shape::Inline => self.ssh_fields(&mut tag, &value),
            }
        }
        tag
    }

    fn ssh_fields(&mut self, tag: &mut Json, value: &Value) {
        let get = |name: &str| match &value.kind {
            Kind::Known(Known::Object(m)) => m
                .get(name)
                .map(|v| v.child_of(value))
                .unwrap_or_else(Value::null),
            Kind::Known(Known::Null) => Value::null(),
            _ => value.get_attr(name),
        };
        tag["fields"] = self.ssh_field_values(get, "protocol");
    }

    fn ssh_field_values(&mut self, get: impl Fn(&str) -> Value, protocol: &str) -> Json {
        let mut fields = serde_json::Map::new();
        for name in ["cidr_blocks", "ipv6_cidr_blocks"] {
            fields.insert(name.into(), self.ssh_value(get(name), Shape::Cidrs));
        }
        for name in ["cidr_ipv4", "cidr_ipv6", "type", "from_port", "to_port"] {
            fields.insert(name.into(), self.ssh_value(get(name), Shape::Atom));
        }
        fields.insert(
            "protocol".into(),
            self.ssh_value(get(protocol), Shape::Atom),
        );
        Json::Object(fields)
    }

    pub(super) fn ssh_input(&mut self, r: &Resource) -> Json {
        let mut input = json!({"target":{"address":r.address,"resource_type":r.ty}});
        if r.ty.as_ref() == "aws_security_group" {
            input["ingress"] = self.ssh_value(
                r.value("ingress").unwrap_or_else(Value::null),
                Shape::Ingress,
            );
        } else {
            let protocol = if r.ty.as_ref() == "aws_vpc_security_group_ingress_rule" {
                "ip_protocol"
            } else {
                "protocol"
            };
            input["fields"] =
                self.ssh_field_values(|name| r.value(name).unwrap_or_else(Value::null), protocol);
        }
        input
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_eval::{Step, StepKind};

    fn mark(v: Value, label: &str) -> Value {
        v.push(Step::new(StepKind::Other, Default::default(), label))
    }
    fn rule(cidr: Value, protocol: Value, from: Value, to: Value) -> Value {
        mark(
            Value::object(
                [
                    ("cidr_blocks".into(), mark(cidr, "cidrs")),
                    ("protocol".into(), mark(protocol, "protocol")),
                    ("from_port".into(), mark(from, "from")),
                    ("to_port".into(), mark(to, "to")),
                ]
                .into(),
            ),
            "rule",
        )
    }

    #[test]
    fn nested_values_match_native_truth_and_exact_witness() {
        let policy = NativeRule::Ssh.prepare().unwrap();
        let open = mark(Value::string("0.0.0.0/0"), "open");
        let closed = mark(Value::string("10.0.0.0/8"), "closed");
        let scalar_values = vec![
            open.clone(),
            closed.clone(),
            Value::null(),
            Value::tainted("cidr"),
            Value::other("computed"),
        ];
        let mut cidrs = scalar_values.clone();
        for a in &scalar_values {
            for b in &scalar_values {
                cidrs.push(Value::list(vec![a.clone(), b.clone()]));
                for tainted in [false, true] {
                    cidrs.push(Value::one_of(vec![a.clone(), b.clone()], tainted));
                    cidrs.push(Value::one_of(
                        vec![Value::list(vec![a.clone()]), Value::list(vec![b.clone()])],
                        tainted,
                    ));
                }
            }
        }
        let protocols = [
            Value::string(" tcp "),
            Value::number(-1.0),
            Value::string("udp"),
            Value::tainted("protocol"),
            Value::other("protocol"),
        ];
        let mut rules = vec![
            Value::null(),
            Value::bool(true),
            Value::other("rule"),
            Value::tainted("rule"),
        ];
        for cidr in cidrs {
            for protocol in &protocols {
                rules.push(rule(
                    cidr.clone(),
                    protocol.clone(),
                    Value::string(" 22 "),
                    Value::number(22.0),
                ));
            }
        }
        for port in [
            Value::null(),
            Value::tainted("port"),
            Value::other("port"),
            Value::number(23.0),
            Value::string("NaN"),
        ] {
            rules.push(rule(open.clone(), Value::string("tcp"), port.clone(), port));
        }
        for (from, to) in [("-inf", "22"), ("22", "inf"), ("-inf", "inf")] {
            rules.push(rule(
                open.clone(),
                Value::string("tcp"),
                Value::string(from),
                Value::string(to),
            ));
        }
        let good = rule(
            open,
            Value::string("tcp"),
            Value::number(22.0),
            Value::number(22.0),
        );
        let mut cases = vec![Value::list(vec![])];
        for r in rules {
            cases.push(r.clone());
            cases.push(Value::list(vec![r.clone(), good.clone()]));
            for tainted in [false, true] {
                cases.push(Value::one_of(
                    vec![Value::list(vec![r.clone()]), Value::null()],
                    tainted,
                ));
                cases.push(Value::list(vec![Value::one_of(
                    vec![r.clone(), good.clone()],
                    tainted,
                )]));
            }
        }
        for value in cases {
            let value = mark(value, "ingress");
            let mut evidence = Evidence::default();
            let input = json!({"target":{"resource_type":"aws_security_group"}, "ingress":evidence.ssh_value(value.clone(), Shape::Ingress)});
            let actual = evaluate(&policy, &input, &evidence.0).unwrap();
            let expected = AwsSgOpenSsh::ingress_verdict(&value);
            assert_eq!(actual.truth, expected.truth, "{value:?}");
            assert_eq!(
                format!("{:?}", actual.witness),
                format!("{:?}", expected.witness),
                "{value:?}"
            );
        }
    }
}

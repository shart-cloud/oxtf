use super::*;
use tf_semantic::references::{ReferenceMatch, match_resource_reference};
impl Evidence {
    pub(super) fn s3_input(&mut self, bucket: &Resource, module: &Module) -> Json {
        let candidates: Vec<_> = module
            .resources_of("aws_s3_bucket_public_access_block")
            .filter(|p| p.existence != Truth::False)
            .filter_map(|p| {
                let reference = p.value("bucket")?;
                let matched =
                    match match_resource_reference(&reference, bucket, "bucket", &["id", "bucket"])
                    {
                        ReferenceMatch::Yes => "yes",
                        ReferenceMatch::Maybe => "maybe",
                        ReferenceMatch::No => "no",
                    };
                let flags: Vec<_> = [
                    "block_public_acls",
                    "block_public_policy",
                    "ignore_public_acls",
                    "restrict_public_buckets",
                ]
                .iter()
                .filter_map(|f| p.value_or_default(f))
                .map(|v| self.tag(Some(v)))
                .collect();
                Some(json!({"address":p.address,"match":matched,"flags":flags,
                    "existence":if p.existence == Truth::Tainted {"tainted"} else {"other"}}))
            })
            .collect();
        json!({"target":{"address":bucket.address},"candidates":candidates})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_eval::truth;
    #[test]
    fn candidate_order_matches_native_minimum_and_witness() {
        let policy = NativeRule::S3.prepare().unwrap();
        let values = [
            Value::bool(false),
            Value::bool(true),
            Value::tainted("flag"),
            Value::other("computed"),
            Value::one_of(vec![Value::bool(true), Value::bool(false)], true),
        ];
        for a in &values {
            for b in &values {
                for matches in [
                    ["yes", "yes"],
                    ["yes", "maybe"],
                    ["maybe", "no"],
                    ["no", "no"],
                ] {
                    for tainted in [false, true] {
                        let mut evidence = Evidence::default();
                        let candidates: Vec<_> = [a,b].into_iter().zip(matches).map(|(v, m)| json!({"match":m,"flags":[evidence.tag(Some(v.clone()))],"existence":if tainted {"tainted"} else {"other"}})).collect();
                        let actual =
                            evaluate(&policy, &json!({"candidates":candidates}), &evidence.0)
                                .unwrap();
                        let mut best: Option<Verdict> = None;
                        for (v, m) in [a, b].into_iter().zip(matches) {
                            if m != "yes" {
                                continue;
                            }
                            let mut verdict =
                                Verdict::FALSE.or(truth::test(v, &|v| v.as_bool() != Some(true)));
                            if tainted {
                                verdict = verdict.or(Verdict::new(Truth::Tainted, None));
                            }
                            best = Some(best.map(|b| b.and(verdict.clone())).unwrap_or(verdict));
                        }
                        let expected = best.unwrap_or_else(|| {
                            if matches.contains(&"maybe") {
                                Verdict::FALSE
                            } else {
                                Verdict::new(Truth::True, None)
                            }
                        });
                        assert_eq!(actual.truth, expected.truth);
                        assert_eq!(
                            format!("{:?}", actual.witness),
                            format!("{:?}", expected.witness)
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn structural_reasons_are_scoped_and_validated() {
        for (entry, result) in [
            (
                "data.oxtf.iam.result",
                r#"{"rank":3,"evidence":null,"reason":"missing_protection"}"#,
            ),
            (
                "data.oxtf.s3.result",
                r#"{"rank":1,"evidence":null,"reason":"pab_existence"}"#,
            ),
            ("data.oxtf.s3.result", r#"{"rank":3,"evidence":null}"#),
            (
                "data.oxtf.s3.result",
                r#"{"rank":3,"evidence":null,"reason":"anything"}"#,
            ),
        ] {
            assert!(decode(regorus::Value::from_json_str(result).unwrap(), &[], entry).is_err());
        }
    }
}

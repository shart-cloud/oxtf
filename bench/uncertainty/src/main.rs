use serde_json::{Value as J, json};
use std::path::Path;
use tf_eval::{Kind, Truth, Value, Verdict, truth};
use tf_linter::{Category, Finding, Level, Linter, RuleInfo};
use tf_semantic::references::{ReferenceMatch, match_resource_reference};
use tf_semantic::{Analysis, AnalyzeOptions, FileTable, analyze_module};

struct Case {
    name: &'static str,
    lhs: Value,
    rhs: Value,
    op: &'static str,
    predicate: &'static str,
    existence: Truth,
    display_tainted: bool,
}

fn project(v: &Value) -> J {
    match &v.kind {
        Kind::Known(_) => json!({"kind":"known", "value":tf_eval::value::to_json(v).unwrap()}),
        Kind::Unknown(_) => json!({"kind":"unknown"}),
        Kind::Tainted(_) => json!({"kind":"tainted"}),
        Kind::OneOf(o) => json!({"kind":"one_of", "tainted":o.tainted,
            "alternatives":o.alternatives.iter().map(|v| tf_eval::value::to_json(v).unwrap()).collect::<Vec<_>>() }),
    }
}

fn plain(v: &Value) -> J {
    tf_eval::value::to_json(v).unwrap_or(J::Null)
}
fn predicate(v: &Value, p: &str) -> Verdict {
    truth::test(v, &|v| match p {
        "not_true" => v.as_bool() != Some(true),
        "equals_true" => v.as_bool() == Some(true),
        _ => unreachable!(),
    })
}
fn native(c: &Case) -> Verdict {
    let a = predicate(&c.lhs, c.predicate);
    match c.op {
        "single" => a,
        "and" => a.and(predicate(&c.rhs, c.predicate)),
        "or" => a.or(predicate(&c.rhs, c.predicate)),
        _ => unreachable!(),
    }
}
fn truth_from_rank(rank: u64) -> Truth {
    Truth::from_rank(u8::try_from(rank).expect("truth rank")).expect("invalid truth rank")
}

// Use production finding construction for existence gating and certainty.
fn probe_info(name: &str, category: Category) -> RuleInfo {
    RuleInfo {
        name: name.into(),
        category,
        level: Level::High,
        description: "Experiment only".into(),
        resource_types: Vec::new(),
        runs_on_module: false,
    }
}
fn outcome(analysis: &Analysis, verdict: Verdict) -> J {
    let info = probe_info("uncertainty-experiment", Category::Encryption);
    let findings: Vec<_> = analysis
        .modules
        .iter()
        .flat_map(|m| m.resources.iter())
        .filter(|r| &*r.ty == "aws_db_instance" && r.mode == tf_semantic::Mode::Managed)
        .filter_map(|r| Finding::from_verdict(&info, r, &verdict, "experiment", &analysis.root_dir))
        .collect();
    json!(
        findings
            .iter()
            .map(|f| f.severity.as_str())
            .collect::<Vec<_>>()
    )
}

fn cases() -> Vec<Case> {
    let mut rows = Vec::new();
    let mut add = |name, lhs, rhs, op, predicate, existence, display_tainted| {
        rows.push(Case {
            name,
            lhs,
            rhs,
            op,
            predicate,
            existence,
            display_tainted,
        })
    };
    for (name, value) in [
        ("known_false", Value::bool(false)),
        ("known_true", Value::bool(true)),
        ("known_null", Value::null()),
        ("provider_unknown", Value::other("provider")),
        ("unconstrained_input", Value::tainted("encrypt")),
        (
            "one_of_tainted",
            Value::one_of(vec![Value::bool(false), Value::bool(true)], true),
        ),
        (
            "one_of_unknown",
            Value::one_of(vec![Value::bool(false), Value::bool(true)], false),
        ),
        (
            "all_alternatives_unsafe",
            Value::one_of(vec![Value::bool(false), Value::null()], true),
        ),
    ] {
        add(
            name,
            value,
            Value::bool(true),
            "single",
            "not_true",
            Truth::True,
            false,
        );
    }
    add(
        "missing_boolean_result",
        Value::tainted("encrypt"),
        Value::bool(true),
        "single",
        "equals_true",
        Truth::True,
        false,
    );
    add(
        "unrelated_display_taint",
        Value::bool(false),
        Value::bool(true),
        "single",
        "not_true",
        Truth::True,
        true,
    );
    add(
        "false_and_tainted",
        Value::bool(true),
        Value::tainted("encrypt"),
        "and",
        "not_true",
        Truth::True,
        false,
    );
    add(
        "true_or_tainted",
        Value::bool(false),
        Value::tainted("encrypt"),
        "or",
        "not_true",
        Truth::True,
        false,
    );
    add(
        "tainted_and_unknown",
        Value::tainted("encrypt"),
        Value::other("provider"),
        "and",
        "not_true",
        Truth::True,
        false,
    );
    add(
        "tainted_or_unknown",
        Value::tainted("encrypt"),
        Value::other("provider"),
        "or",
        "not_true",
        Truth::True,
        false,
    );
    for (name, existence) in [
        ("existence_false", Truth::False),
        ("existence_unknown", Truth::Unknown),
        ("existence_tainted", Truth::Tainted),
    ] {
        add(
            name,
            Value::bool(false),
            Value::bool(true),
            "single",
            "not_true",
            existence,
            false,
        );
    }
    rows
}

fn experiment() -> J {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let files = FileTable::new();
    let base = analyze_module(
        &repo.join("fixtures/rules/aws-rds-unencrypted/fail_explicit_false"),
        &AnalyzeOptions::default(),
        &files,
    );
    assert!(base.diagnostics.is_empty());
    let mut engine = regorus::Engine::new();
    engine
        .add_policy(
            "uncertainty.rego".into(),
            include_str!("../policy.rego").into(),
        )
        .unwrap();
    let mut rows = Vec::new();
    for c in cases() {
        let input = json!({"op":c.op,"predicate":c.predicate,"lhs":project(&c.lhs),"rhs":project(&c.rhs),
            "plain":{"lhs":plain(&c.lhs),"rhs":plain(&c.rhs)},"display_tainted":c.display_tainted});
        engine.set_input(regorus::Value::from_json_str(&input.to_string()).unwrap());
        let result = engine.eval_rule("data.experiment.result".into()).unwrap();
        let result: J = serde_json::from_str(&result.to_json_str().unwrap()).unwrap();
        let mut analysis = base.clone();
        analysis.modules[0].resources[0].existence = c.existence;
        let expected = native(&c);
        let expected_truth = expected.truth as u64;
        let expected_outcome = outcome(&analysis, expected);
        let mut strategies = serde_json::Map::new();
        for strategy in ["path", "evidence", "tagged"] {
            let rank = result[strategy].as_u64().unwrap();
            let got = outcome(&analysis, Verdict::new(truth_from_rank(rank), None));
            strategies.insert(
                strategy.into(),
                json!({"truth_rank":rank,"findings":got,
                "truth_matches":rank==expected_truth,"findings_match":got==expected_outcome}),
            );
        }
        rows.push(json!({"case":c.name,"input":input,"existence":format!("{:?}",c.existence),
            "native":{"truth_rank":expected_truth,"findings":expected_outcome},"strategies":strategies}));
    }
    json!({"version":1,"regorus":"0.12.0","features":["std","arc"],"cases":rows})
}

fn main() {
    let mut report = experiment();
    report["evidence_probes"] = evidence_probes();
    report["two_pass_probe"] = two_pass_probe();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tagged_policy_preserves_native_truth_and_existence_semantics() {
        let result = experiment();
        let rows = result["cases"].as_array().unwrap();
        assert_eq!(rows.len(), 17);
        for row in rows {
            assert_eq!(row["strategies"]["tagged"]["truth_matches"], true, "{row}");
            assert_eq!(row["strategies"]["tagged"]["findings_match"], true, "{row}");
        }
        for (name, strategy) in [
            ("provider_unknown", "path"),
            ("unconstrained_input", "path"),
            ("unrelated_display_taint", "path"),
            ("missing_boolean_result", "evidence"),
            ("true_or_tainted", "evidence"),
            ("tainted_or_unknown", "evidence"),
        ] {
            let row = rows.iter().find(|r| r["case"] == name).unwrap();
            assert_eq!(
                row["strategies"][strategy]["findings_match"], false,
                "{row}"
            );
        }
    }
}

fn evaluate(query: &str, input: &J) -> J {
    let mut e = regorus::Engine::new();
    e.add_policy(
        "uncertainty.rego".into(),
        include_str!("../policy.rego").into(),
    )
    .unwrap();
    e.set_input(regorus::Value::from_json_str(&input.to_string()).unwrap());
    serde_json::from_str(&e.eval_rule(query.into()).unwrap().to_json_str().unwrap()).unwrap()
}

fn evidence_probes() -> J {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let files = FileTable::new();
    let options = AnalyzeOptions::default();
    let mut rows = Vec::new();
    for (case, root, target_type, evidence_type, attribute) in [
        (
            "cross_resource_taint",
            "fixtures/rules/aws-s3-public-access-block/conditional_unconstrained_variable",
            "aws_s3_bucket",
            "aws_s3_bucket_public_access_block",
            "block_public_policy",
        ),
        (
            "tfvars_chain",
            "fixtures/rules/aws-sg-open-ssh/fail_tfvars_through_local",
            "aws_security_group",
            "aws_security_group",
            "ingress",
        ),
        (
            "absent_default",
            "fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default",
            "aws_db_instance",
            "aws_db_instance",
            "storage_encrypted",
        ),
        (
            "explicit_null_default",
            "fixtures/uncertainty/explicit-null",
            "aws_db_instance",
            "aws_db_instance",
            "storage_encrypted",
        ),
    ] {
        let a = analyze_module(&repo.join(root), &options, &files);
        assert!(a.diagnostics.is_empty());
        let target = a.modules[0].resources_of(target_type).next().unwrap();
        let owner = a.modules[0].resources_of(evidence_type).next().unwrap();
        let mut value = owner.value_or_default(attribute).unwrap();
        if case == "tfvars_chain" {
            value = value
                .index(&Value::number(0.0))
                .get_attr("cidr_blocks")
                .index(&Value::number(0.0));
        }
        if case == "cross_resource_taint" {
            assert_eq!(
                match_resource_reference(
                    &owner.value("bucket").unwrap(),
                    target,
                    "bucket",
                    &["id", "bucket"]
                ),
                ReferenceMatch::Yes
            );
        }
        let native = predicate(&value, "not_true");
        // The handle table belongs to this evaluation. Display and evidence
        // identities are separate; retain the original Value and its provenance.
        let handle = "evidence-0";
        let mut tagged = project(&value);
        tagged["handle"] = json!(handle);
        let response = evaluate("data.experiment.probe", &json!({"value":tagged}));
        let mut evidence = std::collections::HashMap::new();
        evidence.insert(handle.to_string(), value.clone());
        let resolve = |response: &J| -> Result<Value, &'static str> {
            evidence
                .get(response["evidence"].as_str().ok_or("invalid handle")?)
                .cloned()
                .ok_or("unknown evidence handle")
        };
        assert!(resolve(&json!({"evidence":"forged-handle"})).is_err());
        let reconstructed = Verdict::new(
            truth_from_rank(response["truth_rank"].as_u64().unwrap()),
            Some(resolve(&response).unwrap()),
        );
        let probe = probe_info("evidence-probe", Category::Storage);
        let run = |v: Verdict| -> Vec<Finding> {
            Finding::from_verdict(&probe, target, &v, "probe", &a.root_dir)
                .into_iter()
                .collect()
        };
        let expected = run(native);
        let actual = run(reconstructed);
        let encode = |findings: &[tf_linter::Finding]| {
            findings
                .iter()
                .map(|f| tf_linter::render::finding_json(&files, f))
                .collect::<Vec<_>>()
        };
        assert_eq!(encode(&expected), encode(&actual));
        assert_eq!(actual.len(), 1);
        let finding = &actual[0];
        let kinds: Vec<_> = finding.provenance.iter().map(|s| s.kind.as_str()).collect();
        match case {
            "tfvars_chain" => assert_eq!(kinds, ["tfvars", "variable", "local", "attribute"]),
            "cross_resource_taint" => {
                assert_eq!(finding.severity, tf_linter::Severity::Conditional);
                assert_ne!(target.address, owner.address);
                assert_eq!(finding.primary, target.span);
            }
            "absent_default" | "explicit_null_default" => assert_eq!(kinds, ["default"]),
            _ => unreachable!(),
        }
        rows.push(json!({"case":case,"target":target.address,"evidence_owner":owner.address,
            "attribute":attribute,"configured":owner.value(attribute).is_some(),
            "configured_value":owner.value(attribute).as_ref().map(project).unwrap_or(json!({"kind":"missing"})),
            "effective_evidence_value":project(&value),"severity":finding.severity.as_str(),
            "provenance_kinds":kinds,"native_finding_matches":true,"forged_handle_rejected":true}));
    }
    json!(rows)
}

fn two_pass_probe() -> J {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let files = FileTable::new();
    let a = analyze_module(
        &repo.join("fixtures/uncertainty/two-inputs"),
        &AnalyzeOptions::default(),
        &files,
    );
    assert!(a.diagnostics.is_empty());
    let findings = Linter::with_seed_rules().run(&a);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, tf_linter::Severity::Conditional);
    let mut rows = Vec::new();
    for left in [false, true] {
        for right in [false, true] {
            let hit = evaluate("data.experiment.different", &json!({"a":left,"b":right}));
            assert_eq!(hit, json!(left != right));
            rows.push(json!({"a":left,"b":right,"finding":hit}));
        }
    }
    json!({"native":"conditional","assignments":rows,
        "uniform_false_and_true_findings":0,"exhaustive_boolean_findings":2})
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    #[test]
    fn evidence_handles_preserve_cross_resource_certainty_and_provenance() {
        evidence_probes();
    }
    #[test]
    fn two_uniform_evaluations_miss_mixed_assignments() {
        two_pass_probe();
    }
}

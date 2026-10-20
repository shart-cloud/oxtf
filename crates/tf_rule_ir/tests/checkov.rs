use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::json;
use tf_eval::Truth;
use tf_semantic::{AnalyzeOptions, FileTable};

fn evaluate(source: &str, condition: serde_json::Value) -> tf_eval::Verdict {
    let rule = json!({
        "version": 2, "name": "CKV_TEST_1", "message": "test", "clauses": [{
            "resource_types": ["aws_db_instance"], "condition": condition
        }]
    });
    let compiled = tf_rule_ir::compile_json(&rule.to_string()).unwrap();
    let files =
        FileTable::with_overlay([(PathBuf::from("checkov-test/main.tf"), Arc::from(source))]);
    let a = tf_semantic::analyze_module(
        Path::new("checkov-test"),
        &AnalyzeOptions::default(),
        &files,
    );
    assert!(a.diagnostics.is_empty(), "{:?}", a.diagnostics);
    compiled[0]
        .verdict(&a.modules[0].resources[0])
        .unwrap()
        .unwrap()
}

fn verdict(
    source: &str,
    path: &[&str],
    values: serde_json::Value,
    negative: bool,
    missing: &str,
    any: bool,
) -> tf_eval::Verdict {
    evaluate(
        source,
        json!({"op":"checkov_value", "path":path, "values":values,
                    "negative":negative,"missing":missing,"any_value":any}
        ),
    )
}

#[test]
fn configured_missing_and_null_follow_upstream_policy() {
    for expr in ["", "storage_encrypted = null", "storage_encrypted = []"] {
        let src = format!("resource \"aws_db_instance\" \"db\" {{ {expr} }}");
        assert_eq!(
            verdict(
                &src,
                &["storage_encrypted"],
                json!([true]),
                false,
                "pass",
                false
            )
            .truth,
            Truth::False
        );
        assert_eq!(
            verdict(
                &src,
                &["storage_encrypted"],
                json!([true]),
                false,
                "fail",
                false
            )
            .truth,
            Truth::True
        );
    }
}

#[test]
fn paths_traverse_blocks_maps_and_attribute_lists() {
    for (body, path, expected) in [
        (
            "settings { encrypted = true }",
            vec!["settings", "[0]", "encrypted"],
            json!([true]),
        ),
        (
            "tags = { Owner = \"me\" }",
            vec!["tags", "[0]", "Owner"],
            json!(["me"]),
        ),
        (
            "logs = [\"audit\", \"error\"]",
            vec!["logs", "[0]"],
            json!([["audit", "error"]]),
        ),
    ] {
        let src = format!("resource \"aws_db_instance\" \"db\" {{ {body} }}");
        assert_eq!(
            verdict(&src, &path, expected, false, "fail", false).truth,
            Truth::False,
            "{body}"
        );
    }
}

#[test]
fn abstract_values_and_alternatives_keep_certainty_and_evidence() {
    for (expr, truth) in [
        ("var.encrypted", Truth::Tainted),
        ("var.encrypted ? true : false", Truth::Tainted),
        ("true", Truth::False),
        ("false", Truth::True),
    ] {
        let src = format!(
            "variable \"encrypted\" {{ type = bool }}\nresource \"aws_db_instance\" \"db\" {{ storage_encrypted = {expr} }}"
        );
        let v = verdict(
            &src,
            &["storage_encrypted"],
            json!([true]),
            false,
            "fail",
            false,
        );
        assert_eq!(v.truth, truth);
        if v.holds() {
            assert!(!v.witness.unwrap().prov.is_empty(), "{expr}");
        }
    }
    let src = "resource \"aws_db_instance\" \"db\" { storage_encrypted = aws_db_instance.db.id }";
    assert_eq!(
        verdict(
            src,
            &["storage_encrypted"],
            json!([true]),
            false,
            "fail",
            false
        )
        .truth,
        Truth::Unknown
    );
}

#[test]
fn python_equality_any_value_and_negative_list_membership() {
    for (expr, values, negative, any, expected) in [
        ("true", json!([1]), false, false, Truth::False),
        ("\" true \"", json!(["true"]), false, false, Truth::True),
        ("true", json!(["True"]), false, false, Truth::False),
        ("\"\"", json!([]), false, true, Truth::True),
        ("false", json!([]), false, true, Truth::False),
        ("\"\"", json!([]), true, true, Truth::True),
        ("[\"a\", \"b\"]", json!(["b"]), true, false, Truth::True),
    ] {
        let src = format!("resource \"aws_db_instance\" \"db\" {{ custom = {expr} }}");
        assert_eq!(
            verdict(&src, &["custom"], values, negative, "fail", any).truth,
            expected,
            "{expr}"
        );
    }
}

#[test]
fn positive_base_check_retries_missing_indices() {
    let src = "resource \"aws_db_instance\" \"db\" { settings { encrypted = true } }";
    assert_eq!(
        verdict(
            src,
            &["settings", "[8]", "encrypted"],
            json!([true]),
            false,
            "fail",
            false
        )
        .truth,
        Truth::False
    );
    assert_eq!(
        verdict(
            src,
            &["settings", "[8]", "encrypted"],
            json!([true]),
            true,
            "fail",
            false
        )
        .truth,
        Truth::True
    );
}

#[test]
fn checkov_predicates_are_validated() {
    for (version, condition, error) in [
        (
            2,
            json!({"op":"checkov_value", "path":[], "values":[], "negative":false, "any_value":true, "missing":"fail"}),
            "nonempty",
        ),
        (
            2,
            json!({"op":"checkov_attribute", "attribute":"enabled", "operator":"exists", "typo":true}),
            "unknown field",
        ),
    ] {
        let rule = json!({"version":version, "name":"test", "message":"test",
            "clauses":[{"resource_types":["aws_db_instance"], "condition":condition}]});
        let err = tf_rule_ir::compile_json(&rule.to_string()).unwrap_err();
        assert!(err.contains(error), "{err}");
    }
}

#[test]
fn graph_boolean_predicates_keep_abstract_descendants() {
    for (expr, expected) in [
        ("false", Truth::True),
        ("\"False\"", Truth::True),
        ("true", Truth::False),
        ("var.enabled", Truth::Tainted),
        ("[var.enabled]", Truth::Tainted),
        ("[aws_db_instance.db.id]", Truth::Unknown),
    ] {
        let source = format!(
            "variable \"enabled\" {{ type = bool }}\nresource \"aws_db_instance\" \"db\" {{ storage_encrypted = {expr} }}"
        );
        let result = evaluate(
            &source,
            json!({"op":"not", "arg":{
            "op":"checkov_attribute", "attribute":"storage_encrypted", "operator":"equals", "value":true}}),
        );
        assert_eq!(result.truth, expected, "{expr}");
    }
}

#[test]
fn jsonencode_and_dynamic_block_cardinality_do_not_manufacture_certainty() {
    let source = "variable \"enabled\" { type = bool }\nresource \"aws_db_instance\" \"db\" { custom = jsonencode({ enabled = var.enabled }) }";
    assert_eq!(
        verdict(source, &["custom"], json!(["{}"]), false, "fail", false).truth,
        Truth::Tainted
    );
    let source = "variable \"items\" { type = list(string) }\nresource \"aws_db_instance\" \"db\" { dynamic \"settings\" { for_each = var.items\ncontent { encrypted = true } } }";
    assert_eq!(
        verdict(
            source,
            &["settings", "[0]", "encrypted"],
            json!([true]),
            false,
            "fail",
            false
        )
        .truth,
        Truth::Tainted
    );
}

#[test]
fn forbidden_collection_keeps_the_attribute_witness() {
    let source = "resource \"aws_db_instance\" \"db\" { custom = [\"a\", \"b\"] }";
    let result = verdict(
        source,
        &["custom"],
        json!([["a", "b"]]),
        true,
        "pass",
        false,
    );
    assert_eq!(result.truth, Truth::True);
    assert!(!result.witness.unwrap().prov.is_empty());
}

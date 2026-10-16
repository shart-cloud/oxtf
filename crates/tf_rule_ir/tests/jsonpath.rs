use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tf_eval::{Truth, Verdict};
use tf_rule_ir::jsonpath::JsonPathCheck;
use tf_semantic::{AnalyzeOptions, FileTable, analyze_module};

fn evaluate(body: &str, path: &[&str], operator: &str, value: Value) -> Verdict {
    evaluate_query(body, json!(path), operator, value)
}

fn evaluate_query(body: &str, path: Value, operator: &str, value: Value) -> Verdict {
    let source = format!(
        "variable \"input\" {{}}\nvariable \"choice\" {{ type = bool }}\nresource \"test_node\" \"n\" {{\n{body}\n}}"
    );
    let files = FileTable::with_overlay([(PathBuf::from("jsonpath/main.tf"), Arc::from(source))]);
    let analysis = analyze_module(Path::new("jsonpath"), &AnalyzeOptions::default(), &files);
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let check: JsonPathCheck =
        serde_json::from_value(json!({"path":path,"operator":operator,"value":value})).unwrap();
    check.validate().unwrap();
    check.evaluate(&analysis.modules[0].resources[0])
}

#[test]
fn filtered_matches_preserve_selection_certainty_and_deciding_values() {
    use Truth::*;
    let path = json!(["settings", {"kind":"filter", "predicates":[
        {"path":["name"],"operator":"equals","value":"Allow"}
    ]}, "value", {"kind":"each"}]);
    for (body, expected) in [
        ("settings = [{name=var.input, value=\"*\"}]", Tainted),
        ("settings = [{name=test_node.n.id, value=\"*\"}]", Unknown),
        ("settings = [{name=var.input, value=\"safe\"}]", True),
        ("settings = [{name=\"Deny\", value=var.input}]", True),
        ("settings = [{name=\"Allow\", value=var.input}]", Tainted),
        (
            "settings = [{name=\"Allow\", value=test_node.n.id}]",
            Unknown,
        ),
        (
            "settings = [{name=\"Allow\", value=\"*\"}, {name=var.input, value=\"safe\"}]",
            False,
        ),
        (
            "settings = var.choice ? [{name=\"Allow\", value=\"safe\"}] : []",
            True,
        ),
        (
            "settings = var.choice ? [{name=\"Allow\", value=\"*\"}] : []",
            Tainted,
        ),
        (
            "settings = jsonencode([{name=\"Allow\", value=var.input}])",
            Tainted,
        ),
        (
            "dynamic \"settings\" { for_each = var.input\ncontent { name = \"Allow\"\nvalue = \"*\" }\n}",
            Tainted,
        ),
    ] {
        let result = evaluate_query(body, path.clone(), "not_equals", json!("*"));
        assert_eq!(result.truth, expected, "{body}");
        if expected != True {
            assert!(!result.witness.unwrap().prov.is_empty(), "{body}");
        }
    }
    let bad = evaluate_query(
        "settings = [{name=\"Allow\", value=[\"safe\", \"*\"]}]",
        path,
        "not_equals",
        json!("*"),
    );
    assert_eq!(bad.truth, False);
    assert_eq!(bad.witness.unwrap().as_str(), Some("*"));
}

#[test]
fn invalid_jsonpath_operands_remain_indeterminate() {
    let path = json!(["settings", {"kind":"each"}]);
    for expr in ["[true]", "[1]", "[\"123\"]", "[\"null\"]"] {
        let verdict = evaluate_query(
            &format!("settings = {expr}"),
            path.clone(),
            "not_contains",
            json!("bad"),
        );
        assert_eq!(verdict.truth, Truth::Unknown, "{expr}");
        assert!(!verdict.witness.unwrap().prov.is_empty());
    }
    assert_eq!(
        evaluate_query("settings=1.5", path.clone(), "exists", Value::Null).truth,
        Truth::Unknown
    );
    assert_eq!(
        evaluate_query(
            "settings=[{outer={inner=\"bad\"}}]",
            path,
            "not_contains",
            json!("bad")
        )
        .truth,
        Truth::True
    );
}

#[test]
fn compound_filters_keep_missing_paths_distinct_from_null() {
    use Truth::*;
    let path = json!(["settings", {"kind":"filter", "predicates":[
        {"path":["name"],"operator":"equals","value":"Allow"},
        {"path":["value"],"operator":"not_equals","value":"off"}
    ]}]);
    for (body, expected) in [
        ("settings = [{name=\"Allow\"}]", False),
        ("settings = [{name=\"Allow\", value=null}]", True),
        ("settings = [{name=\"Deny\", value=var.input}]", False),
        ("settings = [{name=\"Allow\", value=var.input}]", Tainted),
        (
            "settings = [{name=\"Allow\", value=var.input}, {name=\"Allow\", value=\"on\"}]",
            True,
        ),
    ] {
        assert_eq!(
            evaluate_query(body, path.clone(), "exists", Value::Null).truth,
            expected,
            "{body}"
        );
    }
}

#[test]
fn jsonpath_preserves_unknowns_alternatives_and_evidence() {
    use Truth::*;
    for (body, expected) in [
        ("settings = var.input", Tainted),
        ("settings = test_node.n.id", Unknown),
        ("settings = { value = var.input }", Tainted),
        ("settings { value = test_node.n.id }", Unknown),
        (
            "settings = var.choice ? { value = true } : { value = false }",
            Tainted,
        ),
        (
            "settings = var.choice ? { value = true } : { value = \"true\" }",
            True,
        ),
        ("settings = var.choice ? { value = false } : {}", False),
        ("settings { value = var.choice ? true : false }", Tainted),
        (
            "dynamic \"settings\" { for_each = var.input\ncontent { value = true }\n}",
            Tainted,
        ),
    ] {
        let result = evaluate(body, &["settings", "value"], "equals", json!(true));
        assert_eq!(result.truth, expected, "{body}");
        if matches!(expected, Tainted | Unknown) {
            assert!(!result.witness.unwrap().prov.is_empty(), "{body}");
        }
    }
    for op in ["exists", "not_exists"] {
        assert_eq!(
            evaluate(
                "settings = var.input",
                &["settings", "value"],
                op,
                Value::Null
            )
            .truth,
            Tainted
        );
        assert_eq!(
            evaluate(
                "settings = test_node.n.id",
                &["settings", "value"],
                op,
                Value::Null
            )
            .truth,
            Unknown
        );
    }
    for (expr, truth) in [
        (
            "var.choice ? [{ value = true }] : [{ value = false }]",
            Tainted,
        ),
        (
            "var.choice ? [{ value = true }] : [{ value = \"true\" }]",
            True,
        ),
    ] {
        let body = format!("wrapper {{ settings = {expr} }}");
        assert_eq!(
            evaluate(
                &body,
                &["wrapper", "settings", "value"],
                "equals",
                json!(true)
            )
            .truth,
            truth
        );
    }
}

#[test]
fn jsonpath_does_not_search_lists_or_decode_strings() {
    for body in [
        "settings = [{ value = true }]",
        "settings { value = true }\nsettings { value = false }",
        "settings = jsonencode({ value = true })",
    ] {
        assert_eq!(
            evaluate(body, &["settings", "value"], "exists", Value::Null).truth,
            Truth::False,
            "{body}"
        );
    }
    for body in [
        "settings = { nested = [{ value = true }] }",
        "settings { nested { value = true }\n}",
        "settings = { \"nested.value\" = true }",
    ] {
        assert_eq!(
            evaluate(
                body,
                &["settings", "nested", "value"],
                "equals",
                json!(true)
            )
            .truth,
            Truth::True,
            "{body}"
        );
    }
}

#[test]
fn jsonpath_ir_rejects_unsupported_paths_and_operands() {
    for (path, value) in [
        (json!([]), Value::Null),
        (json!([""]), Value::Null),
        (json!(["settings", "*"]), Value::Null),
        (json!(["settings[0]"]), Value::Null),
        (json!(["settings.value"]), Value::Null),
        (json!(["lifecycle", "enabled"]), Value::Null),
        (json!(["settings"]), json!([])),
        (json!([{"kind":"each"}]), Value::Null),
        (
            json!(["settings", {"kind":"filter", "predicates":[]}]),
            Value::Null,
        ),
        (
            json!(["settings", {"kind":"filter", "predicates":[{"path":[],"operator":"equals","value":"on"}]}]),
            Value::Null,
        ),
        (
            json!(["settings", {"kind":"filter", "predicates":[{"path":["value"],"operator":"equals","value":true}]}]),
            Value::Null,
        ),
    ] {
        let rule = json!({"version":3,"name":"test","message":"test","clauses":[{"resource_types":["test_node"],"condition":{"op":"checkov_graph","definition":{"kind":"jsonpath","resource_types":["test_node"],"check":{"path":path,"operator":"equals","value":value}}}}]});
        assert!(
            tf_rule_ir::compile_json(&rule.to_string()).is_err(),
            "{rule}"
        );
    }
}

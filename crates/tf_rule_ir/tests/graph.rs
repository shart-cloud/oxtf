use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tf_linter::{Certainty, Linter};
use tf_semantic::{AnalyzeOptions, FileTable, analyze_module};

fn connection(operator: &str) -> Value {
    json!({"kind":"connection", "resource_types":["test_node"], "connected_resource_types":["test_link"], "operator":operator})
}
fn attribute() -> Value {
    json!({"kind":"attribute", "resource_types":["test_link"], "check":{"attribute":"enabled", "operator":"equals", "value":true}})
}
fn policy(definition: Value) -> Value {
    json!({"version":3,"name":"graph","message":"graph test","clauses":[{"resource_types":["*"],"condition":{"op":"checkov_graph","definition":definition}}]})
}
fn filtered(definition: Value) -> Value {
    json!({"kind":"and","args":[definition,{"kind":"filter","resource_types":["test_node"]}]})
}
fn scan(source: &str, definition: Value) -> Vec<(String, Certainty)> {
    let files = FileTable::with_overlay([(PathBuf::from("graph-rule/main.tf"), Arc::from(source))]);
    let analysis = analyze_module(Path::new("graph-rule"), &AnalyzeOptions::default(), &files);
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let rules = tf_rule_ir::compile_json(&policy(definition).to_string()).unwrap();
    let result = Linter::new(
        rules
            .into_iter()
            .map(|r| Box::new(r) as Box<dyn tf_linter::DynRule>)
            .collect(),
    )
    .run(&analysis);
    assert!(result.rule_errors.is_empty());
    result
        .findings
        .into_iter()
        .map(|f| (f.address.to_string(), f.certainty))
        .collect()
}

#[test]
fn connections_are_bidirectional_and_filter_only_output() {
    let source = r#"
resource "test_node" "linked" {}
resource "test_node" "missing" {}
resource "test_link" "l" { target = test_node.linked.id }
resource "test_link" "orphan" {}
"#;
    assert_eq!(
        scan(source, filtered(connection("exists"))),
        vec![("test_node.missing".into(), Certainty::Definite)]
    );
    assert_eq!(
        scan(source, filtered(connection("not_exists"))),
        vec![("test_node.linked".into(), Certainty::Definite)]
    );
    assert_eq!(scan(source, connection("exists")).len(), 2);
}

#[test]
fn endpoint_attributes_and_multiple_connections_follow_checkov() {
    let source = r#"
resource "test_node" "n" {}
resource "test_link" "bad" { target = test_node.n.id
 enabled = false }
resource "test_link" "good" { target = test_node.n.id
 enabled = true }
"#;
    let definition = |op| filtered(json!({"kind":"and", "args":[attribute(),connection(op)]}));
    assert_eq!(
        scan(source, definition("exists")),
        vec![("test_node.n".into(), Certainty::Definite)]
    );
    assert!(scan(source, definition("one_exists")).is_empty());
}

#[test]
fn nested_or_and_not_keep_resource_scope() {
    let source = r#"resource "test_node" "n" {}"#;
    assert!(
        scan(
            source,
            filtered(json!({"kind":"or", "args":[connection("exists"),connection("not_exists")]}))
        )
        .is_empty()
    );
    assert!(
        scan(
            source,
            filtered(json!({"kind":"not", "arg":connection("exists")}))
        )
        .is_empty()
    );
}

#[test]
fn unknown_instance_index_and_dynamic_existence_are_conditional() {
    let source = r#"
variable "key" { type = string }
resource "test_node" "n" { for_each = toset(["a", "b"]) }
resource "test_link" "l" { target = test_node.n[var.key].id }
"#;
    let result = scan(source, filtered(connection("exists")));
    assert_eq!(result.len(), 2);
    assert!(result.iter().all(|(_, s)| *s == Certainty::Conditional));
}

#[test]
fn flattened_wildcards_include_singleton_blocks_and_numeric_keys() {
    let source = r#"
resource "test_node" "object" { origin = { custom_origin_config = {} } }
resource "test_node" "block" {
 origin { custom_origin_config {} }
}
resource "test_node" "numbered" { origin = { "0" = {custom_origin_config = {}} } }
resource "test_node" "named" { origin = { example = {custom_origin_config = {}} } }
resource "test_node" "missing" { origin = {} }
"#;
    let definition = json!({"kind":"attribute", "resource_types":["test_node"], "check":{
        "attribute":"origin.*.custom_origin_config", "operator":"not_exists"}});
    let mut results = scan(source, definition);
    results.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        results,
        vec![
            ("test_node.block".into(), Certainty::Definite),
            ("test_node.numbered".into(), Certainty::Definite),
            ("test_node.object".into(), Certainty::Definite),
        ]
    );
}

#[test]
fn nested_wildcard_negative_predicate_checks_every_element() {
    let source = r#"
resource "test_node" "n" {}
resource "test_link" "l" {
 target = test_node.n.id
 ingress { cidrs = ["10.0.0.0/8"] }
 ingress { cidrs = ["0.0.0.0/0"] }
}
"#;
    let attr = json!({"kind":"attribute","resource_types":["test_link"],"check":{"attribute":"ingress.*.cidrs","operator":"not_contains","value":"0.0.0.0/0"}});
    assert_eq!(
        scan(
            source,
            filtered(json!({"kind":"and","args":[connection("exists"),attr]}))
        ),
        vec![("test_node.n".into(), Certainty::Definite)]
    );
}

#[test]
fn graph_ir_is_the_complete_clause_condition() {
    let mut rule = policy(connection("exists"));
    rule["clauses"][0]["condition"] =
        json!({"op":"not", "arg":rule["clauses"][0]["condition"].clone()});
    assert!(
        tf_rule_ir::compile_json(&rule.to_string())
            .unwrap_err()
            .contains("complete clause")
    );
}

#[test]
fn data_sources_can_be_the_subject_of_graph_findings() {
    let definition = json!({"kind":"and","args":[
        {"kind":"connection","resource_types":["data.test_node"],"connected_resource_types":["test_link"],"operator":"exists"},
        {"kind":"filter","resource_types":["data.test_node"]}
    ]});
    assert_eq!(
        scan(r#"data "test_node" "missing" {}"#, definition),
        vec![("data.test_node.missing".into(), Certainty::Definite)]
    );
}

#[test]
fn mixed_resource_and_graph_clauses_emit_one_finding() {
    let files = FileTable::with_overlay([(
        PathBuf::from("graph-mixed/main.tf"),
        Arc::from(r#"resource "test_node" "n" {}"#),
    )]);
    let analysis = analyze_module(Path::new("graph-mixed"), &AnalyzeOptions::default(), &files);
    let mut rule = policy(connection("exists"));
    rule["clauses"]
        .as_array_mut()
        .unwrap()
        .push(json!({"resource_types":["test_node"],"condition":{"op":"lit","value":true}}));
    let rules = tf_rule_ir::compile_json(&rule.to_string()).unwrap();
    let result = Linter::new(
        rules
            .into_iter()
            .map(|r| Box::new(r) as Box<dyn tf_linter::DynRule>)
            .collect(),
    )
    .run(&analysis);
    assert_eq!(result.findings.len(), 1);
}

#[test]
fn attribute_only_boolean_tree_tests_resource_types_per_leaf() {
    let a = json!({"kind":"attribute","resource_types":["test_node"],"check":{"attribute":"enabled","operator":"equals","value":true}});
    let b = attribute();
    let source = r#"resource "test_node" "n" { enabled = true }
resource "test_link" "l" { enabled = true }"#;
    assert_eq!(scan(source, json!({"kind":"and","args":[a,b]})).len(), 2);
    assert!(
        scan(
            source,
            json!({"kind":"or","args":[{"kind":"not","arg":a},b]})
        )
        .iter()
        .all(|(r, _)| r == "test_node.n")
    );
}

#[test]
fn filters_exclude_resources_in_attribute_only_policies() {
    let definition = filtered(
        json!({"kind":"attribute","resource_types":["test_node","test_link"],"check":{"attribute":"enabled","operator":"equals","value":true}}),
    );
    let source = r#"resource "test_node" "n" { enabled = false }
resource "test_link" "l" { enabled = false }"#;
    assert_eq!(
        scan(source, definition),
        vec![("test_node.n".into(), Certainty::Definite)]
    );
}

fn attribute_verdict(expr: &str, operator: &str, expected: Value) -> tf_eval::Verdict {
    let source = format!(
        "variable \"input\" {{}}\nvariable \"choice\" {{ type = bool }}\nresource \"test_node\" \"n\" {{ value = {expr} }}"
    );
    let files =
        FileTable::with_overlay([(PathBuf::from("graph-attribute/main.tf"), Arc::from(source))]);
    let analysis = analyze_module(
        Path::new("graph-attribute"),
        &AnalyzeOptions::default(),
        &files,
    );
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let check: tf_rule_ir::checkov::AttributeCheck =
        serde_json::from_value(json!({"attribute":"value", "operator":operator, "value":expected}))
            .unwrap();
    check.validate().unwrap();
    check.evaluate(&analysis.modules[0].resources[0])
}

#[test]
fn graph_measurements_and_subsets_preserve_abstract_values_and_evidence() {
    use tf_eval::Truth::*;
    for (op, expected) in [
        ("number_of_words_not_equals", json!(0)),
        ("length_greater_than", json!(0)),
        ("length_less_than_or_equal", json!(0)),
        ("subset", json!(["s3"])),
    ] {
        for (expr, want) in [("var.input", Tainted), ("test_node.n.id", Unknown)] {
            let result = attribute_verdict(expr, op, expected.clone());
            assert_eq!(result.truth, want, "{op} {expr}");
            assert!(!result.witness.unwrap().prov.is_empty(), "{op} {expr}");
        }
    }
    for (expr, op, expected, want) in [
        (
            "var.choice ? \"\" : \"present\"",
            "number_of_words_not_equals",
            json!(0),
            Tainted,
        ),
        (
            "var.choice ? [] : [1]",
            "length_greater_than",
            json!(0),
            Tainted,
        ),
        (
            "var.choice ? \"s3\" : \"bad\"",
            "subset",
            json!(["s3"]),
            Tainted,
        ),
        ("[var.input]", "length_greater_than", json!(0), True),
        ("{ s3 = var.input }", "subset", json!(["s3"]), True),
        ("[\"s3\", var.input]", "subset", json!(["s3"]), Tainted),
        ("[\"bad\", var.input]", "subset", json!(["s3"]), False),
        ("[\"s3\", test_node.n.id]", "subset", json!(["s3"]), Unknown),
        (
            "jsonencode({ key = var.input })",
            "length_greater_than",
            json!(0),
            Tainted,
        ),
        (
            "jsonencode({ key = test_node.n.id })",
            "number_of_words_not_equals",
            json!(0),
            Unknown,
        ),
        ("[]", "subset", json!([]), True),
        ("{}", "length_greater_than", json!(0), True),
        ("null", "length_less_than_or_equal", json!(0), False),
        ("null", "number_of_words_not_equals", json!(0), True),
        ("[[]]", "subset", json!(["s3"]), Unknown),
    ] {
        let result = attribute_verdict(expr, op, expected);
        assert_eq!(result.truth, want, "{op} {expr}");
        assert!(!result.witness.unwrap().prov.is_empty(), "{op} {expr}");
    }
}

#[test]
fn graph_size_and_subset_operands_are_validated() {
    for (operator, value) in [
        ("subset", json!("s3")),
        ("subset", json!([["s3"]])),
        ("length_greater_than", json!("0")),
        ("number_of_words_not_equals", json!(null)),
        ("length_less_than_or_equal", json!(0.5)),
    ] {
        let rule = policy(json!({"kind":"attribute", "resource_types":["test_node"],
            "check":{"attribute":"value","operator":operator,"value":value}}));
        assert!(
            tf_rule_ir::compile_json(&rule.to_string()).is_err(),
            "{operator}"
        );
    }
}

fn attribute_filter(attribute: &str, value: Value) -> Value {
    json!({"kind":"attribute_filter", "check":{"attribute":attribute,"value":value}})
}

#[test]
fn attribute_filters_restrict_results_after_both_and_and_or() {
    let source = r#"
resource "test_node" "included" { engine = "post" }
resource "test_node" "excluded" { engine = "mysql" }
resource "test_node" "missing" {}
resource "test_node" "empty" { engine = "" }
resource "test_node" "connected" { engine = "postgres" }
resource "test_link" "l" { target = test_node.connected.id }
"#;
    for kind in ["and", "or"] {
        let definition = json!({"kind":kind,"args":[connection("exists"),
            {"kind":"filter","resource_types":["test_node"]},
            attribute_filter("engine",json!("postgres"))]});
        // The connected endpoint has no engine. A result filter must not
        // remove it before the connection is evaluated.
        assert_eq!(
            scan(source, definition),
            vec![("test_node.included".into(), Certainty::Definite)]
        );
    }
}

#[test]
fn unknown_filter_eligibility_keeps_uncertainty_and_source_evidence() {
    use tf_eval::Truth::*;
    for (expr, expected) in [
        ("var.input", Tainted),
        ("test_node.n.id", Unknown),
        ("var.choice ? \"postgres\" : \"mysql\"", Tainted),
        ("var.choice ? \"post\" : \"postgres\"", False),
        ("true", Unknown), // Python raises for a truthy nonstring in a string.
    ] {
        let source = format!(
            "variable \"input\" {{}}\nvariable \"choice\" {{type=bool}}\nresource \"test_node\" \"n\" {{engine={expr}}}"
        );
        let files = FileTable::with_overlay([(PathBuf::from("filter/main.tf"), Arc::from(source))]);
        let analysis = analyze_module(Path::new("filter"), &AnalyzeOptions::default(), &files);
        assert!(analysis.diagnostics.is_empty());
        let graph =
            tf_semantic::graph::ResourceGraph::new(&analysis).expect("graph within default limits");
        let definition: tf_rule_ir::graph::GraphExpr = serde_json::from_value(
            json!({"kind":"and","args":[connection("exists"),attribute_filter("engine",json!("postgres"))]}),
        ).unwrap();
        definition.validate().unwrap();
        let result = definition.evaluate(&graph).remove(0).unwrap();
        assert_eq!(result.truth, expected, "{expr}");
        if matches!(expected, Tainted | Unknown) {
            assert!(!result.witness.unwrap().prov.is_empty(), "{expr}");
        }
    }
    let source = r#"
variable "engine" {}
resource "test_node" "n" { engine = var.engine }
resource "test_link" "l" { target = test_node.n.id }
"#;
    assert!(
        scan(
            source,
            filtered(json!({"kind":"and","args":[
        connection("exists"),attribute_filter("engine",json!("postgres"))]}))
        )
        .is_empty()
    );
}

#[test]
fn nested_filters_remain_local_and_multiple_filters_intersect() {
    let source = r#"
resource "test_node" "included" { engine = "postgres"
 tier = "prod" }
resource "test_node" "excluded" { engine = "postgres"
 tier = "dev" }
"#;
    let branch = json!({"kind":"and","args":[connection("exists"),
        attribute_filter("engine",json!(["postgres"])),attribute_filter("tier",json!(["prod"]))]});
    assert_eq!(
        scan(source, branch.clone()),
        vec![("test_node.included".into(), Certainty::Definite)]
    );
    // A sibling passing branch still passes the included vertex.
    assert!(
        scan(
            source,
            json!({"kind":"or","args":[branch,connection("not_exists")]})
        )
        .is_empty()
    );
}

#[test]
fn attribute_filters_reject_unsupported_scope_paths_and_operands() {
    let filter = attribute_filter("engine", json!("postgres"));
    for definition in [
        filter.clone(),
        json!({"kind":"not","arg":filter}),
        json!({"kind":"and","args":[filter,attribute()]}),
        json!({"kind":"and","args":[filter,{"kind":"filter","resource_types":["test_node"]}]}),
    ] {
        assert!(tf_rule_ir::compile_json(&policy(definition).to_string()).is_err());
    }
    for (name, value) in [
        ("engine.name", json!("x")),
        ("resource_type", json!("x")),
        ("depends_on", json!(["x"])),
        ("engine", json!(true)),
        ("engine", json!([["x"]])),
    ] {
        let definition =
            json!({"kind":"and","args":[connection("exists"),attribute_filter(name,value)]});
        assert!(tf_rule_ir::compile_json(&policy(definition).to_string()).is_err());
    }
}

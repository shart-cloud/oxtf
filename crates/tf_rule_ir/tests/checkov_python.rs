//! `checkov_python`: Checkov checks' own Python, interpreted natively.
//!
//! Programs are written here in the importer's JSON form; conformance with
//! Checkov itself is `bench/checkov/python_compare.py`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value as J, json};
use tf_eval::Truth;
use tf_semantic::{AnalyzeOptions, FileTable};

fn c(v: J) -> J {
    json!({"e": "const", "v": v})
}
fn name(id: &str) -> J {
    json!({"e": "name", "id": id})
}
fn result(r: &str) -> J {
    c(json!({"result": r}))
}
fn ret(e: J) -> J {
    json!({"s": "return", "value": e})
}
fn get(obj: J, key: &str) -> J {
    json!({"e": "call", "func": {"method": "get", "obj": obj}, "args": [c(json!(key))], "kwargs": []})
}
fn sub(v: J, i: J) -> J {
    json!({"e": "sub", "value": v, "index": i})
}
fn cmp(l: J, op: &str, r: J) -> J {
    json!({"e": "cmp", "left": l, "ops": [op], "comparators": [r]})
}
fn if_(test: J, body: Vec<J>, orelse: Vec<J>) -> J {
    json!({"s": "if", "test": test, "body": body, "orelse": orelse})
}
fn list(items: Vec<J>) -> J {
    json!({"list": items})
}

/// Run `body` as `scan_resource_conf(self, conf)` on the only resource of
/// `source`.
fn run(source: &str, body: Vec<J>) -> tf_eval::Verdict {
    let program = json!({
        "version": 1, "entry": "Check.scan_resource_conf", "self": {"evaluated_keys": {"list": []}},
        "functions": {"Check.scan_resource_conf": {"params": ["conf"], "defaults": [null], "body": body}},
    });
    let rule = json!({
        "version": 4, "name": "CKV_TEST_1", "message": "test", "clauses": [{
            "resource_types": ["test_resource"],
            "condition": {"op": "checkov_python", "program": program},
        }]
    });
    let compiled = tf_rule_ir::compile_json(&rule.to_string()).unwrap();
    let files = FileTable::with_overlay([(PathBuf::from("py-test/main.tf"), Arc::from(source))]);
    let a = tf_semantic::analyze_module(Path::new("py-test"), &AnalyzeOptions::default(), &files);
    let r = a.modules[0]
        .resources
        .iter()
        .find(|r| &*r.ty == "test_resource")
        .expect("a test_resource");
    compiled[0].verdict(r).unwrap_or(tf_eval::Verdict::FALSE)
}

fn truth(source: &str, body: Vec<J>) -> Truth {
    run(source, body).truth
}

/// `if conf.get(attr) == expected: FAILED else PASSED`.
fn fails_when_equal(attr: &str, expected: J) -> Vec<J> {
    vec![
        if_(
            cmp(get(name("conf"), attr), "eq", c(expected)),
            vec![ret(result("FAILED"))],
            vec![],
        ),
        ret(result("PASSED")),
    ]
}

#[test]
fn attributes_are_wrapped_in_a_list_as_checkov_parses_them() {
    let src = r#"resource "test_resource" "r" { a = "x" }"#;
    assert_eq!(
        truth(src, fails_when_equal("a", list(vec![json!("x")]))),
        Truth::True
    );
    // A bare string is not equal to the one-element list.
    assert_eq!(truth(src, fails_when_equal("a", json!("x"))), Truth::False);
}

#[test]
fn python_truthiness_and_membership() {
    let src = r#"resource "test_resource" "r" {
  flags = [false]
  name  = "prod-db"
}"#;
    // [[False]] is truthy: the list is not empty.
    let flags = get(name("conf"), "flags");
    assert_eq!(
        truth(
            src,
            vec![
                if_(flags, vec![ret(result("FAILED"))], vec![]),
                ret(result("PASSED"))
            ]
        ),
        Truth::True
    );
    // `in` on a string is a substring test.
    let name0 = sub(get(name("conf"), "name"), c(json!(0)));
    let body = vec![
        if_(
            cmp(c(json!("prod")), "in", name0),
            vec![ret(result("FAILED"))],
            vec![],
        ),
        ret(result("PASSED")),
    ];
    assert_eq!(truth(src, body), Truth::True);
}

#[test]
fn an_abstract_value_decides_only_when_inspected() {
    let src = r#"variable "v" {}
resource "test_resource" "r" {
  a = var.v
  b = "fixed"
}"#;
    // Inspecting the unconstrained variable: conditional.
    assert_eq!(
        truth(src, fails_when_equal("a", list(vec![json!("x")]))),
        Truth::Tainted
    );
    // Never inspecting it: decided by the known attribute.
    assert_eq!(
        truth(src, fails_when_equal("b", list(vec![json!("fixed")]))),
        Truth::True
    );
    // An unresolvable reference is Unknown: no finding.
    let src = r#"resource "test_resource" "r" { a = aws_s3_bucket.missing.id }"#;
    assert_eq!(
        truth(src, fails_when_equal("a", list(vec![json!("x")]))),
        Truth::Unknown
    );
}

#[test]
fn a_conditional_value_is_resolved_per_alternative() {
    // Both alternatives fail: definite. One fails: conditional (the
    // condition depends on an unconstrained variable).
    let both = r#"variable "on" { type = bool }
resource "test_resource" "r" { a = var.on ? "x" : "x" }"#;
    assert_eq!(
        truth(both, fails_when_equal("a", list(vec![json!("x")]))),
        Truth::True
    );
    let one = r#"variable "on" { type = bool }
resource "test_resource" "r" { a = var.on ? "x" : "y" }"#;
    assert_eq!(
        truth(one, fails_when_equal("a", list(vec![json!("x")]))),
        Truth::Tainted
    );
}

#[test]
fn exceptions_are_caught_or_mean_no_result() {
    let src = r#"resource "test_resource" "r" { a = "x" }"#;
    let missing = sub(name("conf"), c(json!("missing")));
    let caught = vec![
        json!({"s": "try", "body": [{"s": "expr", "value": missing.clone()}],
               "handlers": [{"types": ["KeyError"], "name": null, "body": [ret(result("FAILED"))]}],
               "orelse": [], "finally": []}),
        ret(result("PASSED")),
    ];
    assert_eq!(truth(src, caught), Truth::True);
    // LookupError catches KeyError; ValueError does not.
    let wrong = vec![
        json!({"s": "try", "body": [{"s": "expr", "value": missing.clone()}],
               "handlers": [{"types": ["ValueError"], "name": null, "body": [ret(result("PASSED"))]}],
               "orelse": [], "finally": []}),
        ret(result("FAILED")),
    ];
    assert_eq!(truth(src, wrong), Truth::Unknown);
}

#[test]
fn heredoc_json_and_list_elements_are_rendered_as_checkov_runs_them() {
    let src = r#"resource "test_resource" "r" {
  policy = <<EOF
{"Statement": [{"Effect": "Allow", "Principal": "*",}]}
EOF
  ports   = ["22", "x", "-1"]
  scalar  = "-1"
}"#;
    // The heredoc is a Python literal with a trailing comma: a dict.
    let statement = sub(
        sub(
            sub(get(name("conf"), "policy"), c(json!(0))),
            c(json!("Statement")),
        ),
        c(json!(0)),
    );
    let principal = sub(statement, c(json!("Principal")));
    let body = vec![
        if_(
            cmp(principal, "eq", c(json!("*"))),
            vec![ret(result("FAILED"))],
            vec![],
        ),
        ret(result("PASSED")),
    ];
    assert_eq!(truth(src, body), Truth::True);
    // List elements are evaluated, and strings sort after other elements.
    assert_eq!(
        truth(
            src,
            fails_when_equal(
                "ports",
                list(vec![list(vec![json!(-1), json!(22), json!("x")])])
            )
        ),
        Truth::True
    );
    // A top-level scalar stays as written.
    assert_eq!(
        truth(src, fails_when_equal("scalar", list(vec![json!("-1")]))),
        Truth::True
    );
}

#[test]
fn a_runaway_program_is_unknown() {
    let src = r#"resource "test_resource" "r" { a = "x" }"#;
    // for _ in range(10**7): pass
    let range = json!({"e": "call", "func": {"builtin": "range"}, "args": [c(json!(10_000_000))], "kwargs": []});
    let body = vec![
        json!({"s": "for", "target": {"t": "name", "id": "_"}, "iter": range, "body": [{"s": "pass"}], "orelse": []}),
        ret(result("FAILED")),
    ];
    assert_eq!(truth(src, body), Truth::Unknown);
}

/// Classes of inlined modules (cloudsplaining's policy documents):
/// `__init__` sets attributes, properties and methods read them.
#[test]
fn objects_of_inlined_classes() {
    let src = r#"resource "test_resource" "r" { a = "x" }"#;
    let attr = |obj: J, a: &str| json!({"e": "attr", "value": obj, "attr": a});
    let program = json!({
        "version": 1, "entry": "Check.scan_resource_conf", "self": {"evaluated_keys": {"list": []}},
        "classes": {"m.Doc": {
            "methods": {"__init__": "m.Doc.__init__", "has": "m.Doc.has"},
            "properties": {"first": "m.Doc.first"},
            "attrs": {"KIND": "doc"},
        }},
        "functions": {
            "Check.scan_resource_conf": {"params": ["conf"], "defaults": [null], "body": [
                {"s": "assign", "targets": [{"t": "name", "id": "d"}],
                 "value": {"e": "call", "func": {"class": "m.Doc"}, "args": [get(name("conf"), "a")], "kwargs": []}},
                if_(cmp(attr(name("d"), "first"), "eq", c(json!("x"))), vec![
                    if_(json!({"e": "call", "func": {"method": "has", "obj": name("d")}, "args": [c(json!("x"))], "kwargs": []}),
                        vec![if_(cmp(attr(name("d"), "KIND"), "eq", c(json!("doc"))), vec![ret(result("FAILED"))], vec![])], vec![]),
                ], vec![]),
                ret(result("PASSED")),
            ]},
            "m.Doc.__init__": {"params": ["self", "items"], "defaults": [null, null], "body": [
                {"s": "assign", "targets": [{"t": "attr", "value": name("self"), "attr": "items"}], "value": name("items")},
            ]},
            "m.Doc.first": {"params": ["self"], "defaults": [null], "body": [
                ret(sub(attr(name("self"), "items"), c(json!(0)))),
            ]},
            "m.Doc.has": {"params": ["self", "x"], "defaults": [null, null], "body": [
                ret(cmp(name("x"), "in", attr(name("self"), "items"))),
            ]},
        },
    });
    let rule = json!({"version": 4, "name": "CKV_TEST_2", "message": "test", "clauses": [{
        "resource_types": ["test_resource"], "condition": {"op": "checkov_python", "program": program}}]});
    let compiled = tf_rule_ir::compile_json(&rule.to_string()).unwrap();
    let files = FileTable::with_overlay([(PathBuf::from("py-test/main.tf"), Arc::from(src))]);
    let a = tf_semantic::analyze_module(Path::new("py-test"), &AnalyzeOptions::default(), &files);
    let v = compiled[0].verdict(&a.modules[0].resources[0]).unwrap();
    assert_eq!(v.truth, Truth::True);
}

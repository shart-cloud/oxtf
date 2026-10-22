use std::path::{Path, PathBuf};

use serde_json::{Value as Json, json};
use tf_eval::Truth;
use tf_linter::{RuleBudget, ScanStatus};
use tf_rule_ir::CompiledRule;
use tf_scan::{Catalog, Limits, ScanRequest, scan};
use tf_semantic::{Analysis, AnalyzeOptions, FileTable, Resource};

fn budget(steps: u64) -> RuleBudget {
    RuleBudget::new(Limits::default().with_rule_steps(steps).unwrap())
}

fn compile(condition: Json) -> CompiledRule {
    tf_rule_ir::compile_json(
        &json!({
            "name": "test-budget", "message": "test", "clauses": [{
                "resource_types": ["test_resource"], "condition": condition
            }]
        })
        .to_string(),
    )
    .unwrap()
    .remove(0)
}

fn analysis(source: &str) -> Analysis {
    let files = FileTable::with_overlay([("/nonexistent/rules/main.tf".into(), source.into())]);
    tf_semantic::analyze_module(
        Path::new("/nonexistent/rules"),
        &AnalyzeOptions::default(),
        &files,
    )
}

fn assert_boundary(rule: &CompiledRule, resource: &Resource, truth: Truth) -> u64 {
    let large = budget(1_000_000);
    assert_eq!(
        rule.verdict_with_budget(resource, &large)
            .unwrap()
            .unwrap()
            .truth,
        truth
    );
    let cost = large.used();
    assert!(cost > 1);
    for allowance in [cost - 1, cost, cost + 1] {
        let budget = budget(allowance);
        let result = rule.verdict_with_budget(resource, &budget);
        if allowance < cost {
            assert!(result.unwrap_err().contains("rule_steps"));
            assert!(budget.exhaustion().is_some());
        } else {
            assert_eq!(result.unwrap().unwrap().truth, truth);
            assert_eq!(budget.used(), cost);
        }
    }
    cost
}

#[test]
fn ir_traversal_has_an_exact_boundary_and_repeated_calls_share_the_allowance() {
    let a = analysis("resource \"test_resource\" \"r\" { values = [1, 2, 3, 4] }");
    let resource = &a.modules[0].resources[0];
    let rule = compile(
        json!({"op": "list_all", "list": {"op": "col", "path": ["values"]},
        "pred": {"op": "cmp", "cmp": "gt", "left": {"op": "element"},
                 "right": {"op": "lit", "value": 0}}}),
    );
    let cost = assert_boundary(&rule, resource, Truth::True);
    let budget = budget(cost * 2 - 1);
    assert!(rule.verdict_with_budget(resource, &budget).is_ok());
    assert!(
        rule.verdict_with_budget(resource, &budget)
            .unwrap_err()
            .contains("rule_steps")
    );
    assert!(rule.verdict_with_budget(resource, &budget).is_err());
}

#[test]
fn short_circuited_ir_does_not_spend_the_unvisited_branch_allowance() {
    let a = analysis("resource \"test_resource\" \"r\" {}");
    let false_ = json!({"op": "lit", "value": false});
    let expensive = json!({"op": "is_in", "expr": {"op": "lit", "value": -1},
        "values": (0..1000).collect::<Vec<_>>()});
    let short = compile(json!({"op": "and", "args": [false_, expensive]}));
    let long = compile(json!({"op": "and", "args": [expensive, false_]}));
    let cost = assert_boundary(&short, &a.modules[0].resources[0], Truth::False);
    assert!(
        long.verdict_with_budget(&a.modules[0].resources[0], &budget(cost))
            .is_err()
    );
}

#[test]
fn for_each_charges_visits_even_when_elements_are_unknown() {
    let rule = tf_rule_ir::compile_json(
        &json!({
            "name": "unknown-elements", "message": "test", "clauses": [{
                "resource_types": ["test_resource"],
                "for_each": {"op": "col", "path": ["values"]},
                "condition": {"op": "lit", "value": true}
            }]
        })
        .to_string(),
    )
    .unwrap()
    .remove(0);
    let a = analysis(
        "resource \"test_resource\" \"r\" {\n\
        values = [missing.a, missing.b, missing.c, missing.d]\n}",
    );
    let cost = assert_boundary(&rule, &a.modules[0].resources[0], Truth::Unknown);
    let one = analysis("resource \"test_resource\" \"r\" { values = [missing.a] }");
    let one_cost = assert_boundary(&rule, &one.modules[0].resources[0], Truth::Unknown);
    assert_eq!(cost - one_cost, 3);
}

fn python(body: Vec<Json>) -> CompiledRule {
    compile(json!({"op": "checkov_python", "program": {
        "version": 1, "entry": "check", "self": {}, "functions": {
            "check": {"params": ["conf"], "defaults": [null], "body": body}
        }
    }}))
}

fn result(value: &str) -> Json {
    json!({"s": "return", "value": {"e": "const", "v": {"result": value}}})
}

fn loop_work() -> Json {
    json!({"s": "for", "target": {"t": "name", "id": "i"}, "iter": {
        "e": "call", "func": {"builtin": "range"},
        "args": [{"e": "const", "v": 100}], "kwargs": []
    }, "body": [{"s": "pass"}], "orelse": []})
}

#[test]
fn interpreted_exception_handlers_cannot_hide_root_exhaustion() {
    let a = analysis("resource \"test_resource\" \"r\" {}");
    let rule = python(vec![
        json!({"s": "try", "body": [loop_work()], "handlers": [{
        "types": ["Exception"], "name": null, "body": [result("PASSED")]
    }], "orelse": [], "finally": []}),
        result("FAILED"),
    ]);
    assert_boundary(&rule, &a.modules[0].resources[0], Truth::True);
}

#[test]
fn alternative_runs_spend_the_same_root_allowance() {
    let rule = python(vec![
        json!({"s": "if", "test": {"e": "sub", "value": {
        "e": "sub", "value": {"e": "name", "id": "conf"},
        "index": {"e": "const", "v": "flag"}
    }, "index": {"e": "const", "v": 0}}, "body": [loop_work()],
    "orelse": [loop_work()]}),
        result("FAILED"),
    ]);
    let known = analysis("resource \"test_resource\" \"r\" { flag = true }");
    let forked = analysis(
        "variable \"on\" {}\n\
        resource \"test_resource\" \"r\" { flag = var.on ? true : false }",
    );
    let one = assert_boundary(&rule, &known.modules[0].resources[0], Truth::True);
    let all = assert_boundary(&rule, &forked.modules[0].resources[0], Truth::True);
    assert!(all > 2 * one);
    assert!(
        rule.verdict_with_budget(&forked.modules[0].resources[0], &budget(one))
            .is_err()
    );
}

#[test]
fn new_root_runs_do_not_reuse_mutable_interpreter_state() {
    let a = analysis("resource \"test_resource\" \"r\" {}");
    let state = json!({"e": "static", "key": "Test.visits", "v": {"list": []}});
    let rule = python(vec![
        json!({"s": "if", "test": state, "body": [result("PASSED")], "orelse": []}),
        json!({"s": "expr", "value": {"e": "call", "func": {
            "method": "append", "obj": state
        }, "args": [{"e": "const", "v": 1}], "kwargs": []}}),
        loop_work(),
        result("FAILED"),
    ]);
    let resource = &a.modules[0].resources[0];
    let cost = assert_boundary(&rule, resource, Truth::True);
    let shared = budget(cost * 2);
    assert_eq!(
        rule.verdict_with_budget(resource, &shared)
            .unwrap()
            .unwrap()
            .truth,
        Truth::True
    );
    assert_eq!(
        rule.verdict_with_budget(resource, &shared)
            .unwrap()
            .unwrap()
            .truth,
        Truth::False
    );
    assert!(
        rule.verdict_with_budget(resource, &budget(cost - 1))
            .is_err()
    );
    assert_boundary(&rule, resource, Truth::True);
}

fn request(root: PathBuf, allowance: u64) -> ScanRequest {
    let mut request = ScanRequest::dirs(vec![root.clone()], false);
    request.catalog = Catalog::seed();
    request.selection = Some(vec!["aws-rds-unencrypted".into()]);
    request.limits = Limits::default().with_rule_steps(allowance).unwrap();
    request.overlay.push((
        root.join("main.tf"),
        "resource \"aws_db_instance\" \"a\" { storage_encrypted = false }\n\
         resource \"aws_db_instance\" \"b\" { storage_encrypted = false }"
            .into(),
    ));
    request
}

#[test]
fn exhausted_rules_preserve_prior_findings_but_cannot_verify_fixes() {
    let limited = request("/nonexistent/rule-scan".into(), 1);
    let out = scan(limited.try_clone().unwrap()).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Failed);
    assert_eq!(out.result.findings.len(), 1);
    assert_eq!(out.result.rule_errors.len(), 1);
    assert!(out.result.rule_errors[0].message.contains("rule_steps"));
    let fix = tf_scan::fix(limited, &out.record().findings[0].fingerprint, None).unwrap();
    assert!(!fix.verified);
    assert!(
        fix.verification_errors
            .iter()
            .any(|e| e.contains("rule_steps"))
    );
    let complete = scan(request("/nonexistent/rule-scan".into(), 2)).unwrap();
    assert_eq!(complete.result.status(), ScanStatus::Complete);
    assert_eq!(complete.result.findings.len(), 2);
}

#[test]
fn rule_allowances_are_per_root_with_one_or_many_workers() {
    for allowance in [1, 2] {
        let mut base = request("/nonexistent/rule-workers/0".into(), allowance);
        let source = base.overlay[0].1.clone();
        let roots = (0..4)
            .map(|i| PathBuf::from(format!("/nonexistent/rule-workers/{i}")))
            .collect::<Vec<_>>();
        base.overlay = roots
            .iter()
            .map(|r| (r.join("main.tf"), source.clone()))
            .collect();
        base.input = tf_scan::ScanInput::Dirs {
            paths: roots,
            recursive: false,
        };
        let mut records = Vec::new();
        for threads in [1, 4] {
            let mut request = base.try_clone().unwrap();
            request.threads = Some(threads);
            let out = scan(request).unwrap();
            assert_eq!(out.result.findings.len(), allowance as usize * 4);
            assert_eq!(
                out.result.rule_errors.len(),
                if allowance == 1 { 4 } else { 0 }
            );
            records.push((
                serde_json::to_value(out.record().findings).unwrap(),
                serde_json::to_value(out.record().rule_errors).unwrap(),
            ));
        }
        assert_eq!(records[0], records[1]);
    }
}

#[test]
fn lazy_bundled_rules_borrow_the_root_allowance() {
    let mut request = request("/nonexistent/rule-bundled".into(), 1);
    request.catalog = Catalog::standard();
    request.selection = Some(vec!["CKV_AWS_16".into()]);
    let stopped = scan(request.try_clone().unwrap()).unwrap();
    assert_eq!(stopped.result.status(), ScanStatus::Failed);
    assert!(stopped.result.findings.is_empty());
    assert_eq!(stopped.result.rule_errors.len(), 1);
    assert!(stopped.result.rule_errors[0].message.contains("rule_steps"));
    request.limits = Limits::default();
    let complete = scan(request).unwrap();
    assert_eq!(complete.result.status(), ScanStatus::Complete);
    assert_eq!(complete.result.findings.len(), 2);
}

#[test]
fn graph_rules_reserve_resource_work_before_emitting_findings() {
    let a = analysis(
        "resource \"test_resource\" \"a\" { enabled = false }\n\
        resource \"test_resource\" \"b\" { enabled = false }",
    );
    let rule = compile(json!({"op": "checkov_graph", "definition": {
        "kind": "attribute", "resource_types": ["test_resource"], "check": {
            "attribute": "enabled", "operator": "equals", "value": true
        }
    }}));
    let linter = tf_linter::Linter::new(vec![Box::new(rule)]);
    let cost = linter.run(&a).rule_steps;
    for allowance in [1, 2, cost - 1, cost] {
        let out = linter.run_with_limits(
            &a,
            None,
            Limits::default().with_rule_steps(allowance).unwrap(),
        );
        assert_eq!(out.rule_errors.len(), usize::from(allowance < cost));
        assert_eq!(out.rule_exhaustion.is_some(), allowance < cost);
        if allowance < 3 {
            assert!(out.findings.is_empty());
        }
        if allowance == cost {
            assert_eq!(out.findings.len(), 2);
        }
    }
}

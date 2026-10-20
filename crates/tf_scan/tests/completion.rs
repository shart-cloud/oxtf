//! A missing finding is only meaningful when analysis completed.
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use tf_linter::ScanStatus;
use tf_scan::{ScanRequest, scan};

fn request(source: &str) -> ScanRequest {
    let root = PathBuf::from("/nonexistent/oxtf-completion");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.threads = Some(1);
    req.overlay = vec![(root.join("main.tf"), Arc::from(source))];
    req
}

fn error_when_encrypted() -> String {
    json!({
        "version": 4, "name": "execution-check", "message": "test",
        "clauses": [{
            "resource_types": ["aws_db_instance"],
            "condition": {"op": "checkov_python", "program": {
                "version": 1, "entry": "check", "self": {},
                "functions": {"check": {
                    "params": ["conf"], "defaults": [null],
                    "body": [
                        {"s": "if", "test": {
                            "e": "sub", "value": {
                                "e": "sub", "value": {"e": "name", "id": "conf"},
                                "index": {"e": "const", "v": "storage_encrypted"}
                            }, "index": {"e": "const", "v": 0}
                        }, "body": [{"s": "raise", "type": "ValueError"}], "orelse": []},
                        {"s": "return", "value": {"e": "const", "v": {"result": "PASSED"}}}
                    ]
                }}
            }}
        }]
    })
    .to_string()
}

#[test]
fn parse_errors_survive_every_record_format() {
    let out = scan(request("broken = )\n")).unwrap();
    assert!(out.result.findings.is_empty());
    assert_eq!(out.result.status(), ScanStatus::Failed);
    let record = out.record();
    assert_eq!(serde_json::to_value(&record).unwrap()["status"], "failed");
    let ndjson = tf_linter::formats::ndjson(&record);
    let summary: serde_json::Value = serde_json::from_str(ndjson.lines().last().unwrap()).unwrap();
    assert_eq!(summary["status"], "failed");
    let sarif = tf_linter::formats::sarif(&record);
    let invocation = &sarif["runs"][0]["invocations"][0];
    assert_eq!(invocation["executionSuccessful"], false);
    assert!(
        invocation["toolExecutionNotifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["descriptor"]["id"] == "parse-error")
    );
}

#[test]
fn interpreter_failure_is_a_rule_error_and_does_not_stop_other_rules() {
    let mut req = request(
        "resource \"aws_db_instance\" \"db\" { storage_encrypted = true }\nresource \"aws_db_instance\" \"other\" { storage_encrypted = false }\n",
    );
    req.catalog.rule_json.push(error_when_encrypted());
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Failed);
    assert_eq!(out.result.rule_errors.len(), 1);
    let error = &out.result.rule_errors[0];
    assert_eq!(error.rule, "execution-check");
    assert_eq!(error.resource.as_deref(), Some("aws_db_instance.db"));
    assert!(error.message.contains("ValueError"));
    assert!(
        out.result
            .findings
            .iter()
            .any(|f| &*f.address == "aws_db_instance.other")
    );
}

#[test]
fn fix_cannot_verify_when_the_rescan_fails() {
    let mut req = request("resource \"aws_db_instance\" \"db\" { storage_encrypted = false }\n");
    req.catalog.rule_json.push(error_when_encrypted());
    let before = scan(req.try_clone().unwrap()).unwrap();
    assert_eq!(before.result.status(), ScanStatus::Complete);
    let fp = &before.record().findings[0].fingerprint;
    let outcome = tf_scan::fix(req, fp, None).unwrap();
    assert!(outcome.edit.text.contains("storage_encrypted = true"));
    assert!(!outcome.verified);
    assert!(
        outcome
            .verification_errors
            .iter()
            .any(|e| e.contains("after edit: execution-check"))
    );
}

#[test]
fn fix_cannot_verify_an_initially_broken_configuration() {
    let req =
        request("broken = )\nresource \"aws_db_instance\" \"db\" { storage_encrypted = false }\n");
    let before = scan(req.try_clone().unwrap()).unwrap();
    let fp = &before.record().findings[0].fingerprint;
    let outcome = tf_scan::fix(req, fp, None).unwrap();
    assert!(!outcome.verified);
    assert!(
        outcome
            .verification_errors
            .iter()
            .any(|e| e.starts_with("before edit: parse-error"))
    );
}

#[test]
fn unknown_input_is_distinct_from_execution_failure() {
    let mut req = request(
        "resource \"aws_db_instance\" \"db\" { storage_encrypted = data.example.value.encrypted }\n",
    );
    req.catalog.rule_json.push(error_when_encrypted());
    let out = scan(req).unwrap();
    assert!(out.result.rule_errors.is_empty());
    assert!(out.result.findings.is_empty());
}

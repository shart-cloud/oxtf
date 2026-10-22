use std::path::PathBuf;

use tf_linter::ScanStatus;
use tf_scan::{Catalog, Limits, ScanRequest, scan};

fn request(results: u64) -> ScanRequest {
    let root = PathBuf::from("/nonexistent/results-scan");
    let mut request = ScanRequest::dirs(vec![root.clone()], false);
    request.catalog = Catalog::seed();
    request.selection = Some(vec!["aws-rds-unencrypted".into()]);
    request.limits = Limits::default().with_results(results).unwrap();
    request.overlay.push((
        root.join("main.tf"),
        "resource \"aws_db_instance\" \"a\" { storage_encrypted = false }\n\
         resource \"aws_db_instance\" \"b\" { storage_encrypted = false }"
            .into(),
    ));
    request
}

#[test]
fn truncated_results_are_reported_and_cannot_verify_fixes() {
    let complete = scan(request(2)).unwrap();
    assert_eq!(complete.result.status(), ScanStatus::Complete);
    assert_eq!(complete.result.findings.len(), 2);

    let limited = request(1);
    let out = scan(limited.try_clone().unwrap()).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Incomplete);
    assert_eq!(out.result.findings.len(), 1);
    assert!(out.result.rule_errors.is_empty());
    let terminal: Vec<_> = out
        .result
        .diagnostics
        .iter()
        .filter(|d| d.code == "coverage-results")
        .collect();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].message, "results exceeds scan allowance 1");
    assert!(!out.result.completion_issues().is_empty());
    let fingerprint = out.record().findings[0].fingerprint.clone();
    let fix = tf_scan::fix(limited, &fingerprint, None).unwrap();
    assert!(!fix.verified);
    assert!(
        fix.verification_errors
            .iter()
            .any(|e| e.contains("coverage-results")),
        "{:?}",
        fix.verification_errors
    );
}

#[test]
fn the_results_allowance_is_part_of_the_strict_wire_format() {
    let limits = tf_scan::limits::from_json(r#"{"results": 7}"#).unwrap();
    assert_eq!(limits.results(), 7);
    assert!(tf_scan::limits::from_json(r#"{"results": 0}"#).is_err());
    assert!(tf_scan::limits::from_json(r#"{"results": null}"#).is_err());
    assert_eq!(
        tf_scan::limits::from_json("{}").unwrap().results(),
        tf_limits::RESULTS_DEFAULT
    );
}

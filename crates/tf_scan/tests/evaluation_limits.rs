//! Resource limits remain visible through scan status, records, and fix verification.
use std::path::PathBuf;
use std::sync::Arc;

use tf_linter::ScanStatus;
use tf_scan::{Catalog, ScanRequest, scan};

fn request(expression: &str) -> ScanRequest {
    let root = PathBuf::from("/nonexistent/oxtf-evaluation-limits");
    let mut request = ScanRequest::dirs(vec![root.clone()], false);
    request.catalog = Catalog::seed();
    request.threads = Some(1);
    request.overlay = vec![(
        root.join("main.tf"),
        Arc::from(format!(
            "variable \"enabled\" {{}}\nresource \"aws_db_instance\" \"db\" {{\n\
         storage_encrypted = false\nallocated_storage = {expression}\n}}\n"
        )),
    )];
    request
}

#[test]
fn exhausted_evaluation_never_reports_a_complete_scan() {
    for expression in [
        "length(setproduct(range(1024), range(1024)))",
        "length(try(indent(1e100, \"a\\nb\"), \"fallback\"))",
        "can(indent(1e100, \"a\\nb\")) ? 20 : 20",
        "length([for x in range(5) : x if var.enabled])",
    ] {
        let output = scan(request(expression)).unwrap();
        assert_eq!(
            output.result.status(),
            ScanStatus::Incomplete,
            "{expression}"
        );
        assert!(
            output
                .result
                .diagnostics
                .iter()
                .any(|d| d.code == "coverage-evaluation")
        );
        let record = serde_json::to_value(output.record()).unwrap();
        assert_eq!(record["status"], "incomplete");
    }
}

#[test]
fn a_fix_cannot_verify_while_evaluation_is_limited() {
    let request = request("length(setproduct(range(1024), range(1024)))");
    let output = scan(request.try_clone().unwrap()).unwrap();
    let fingerprint = &output.record().findings[0].fingerprint;
    let outcome = tf_scan::fix(request, fingerprint, None).unwrap();
    assert!(!outcome.verified);
    assert!(!outcome.target_resolved);
    assert!(
        outcome
            .verification_errors
            .iter()
            .any(|error| error.contains("coverage-evaluation"))
    );
}

//! Root work is independent of worker scheduling and survives adapter/fix copies.
use std::path::PathBuf;
use std::sync::Arc;

use tf_linter::ScanStatus;
use tf_scan::{Catalog, Limits, ScanRequest, scan};

fn request(source: &str, allowance: u64) -> ScanRequest {
    let root = PathBuf::from("/nonexistent/oxtf-budget");
    let mut request = ScanRequest::dirs(vec![root.clone()], false);
    request.catalog = Catalog::seed();
    request.limits = Limits::new(allowance).unwrap();
    request
        .overlay
        .push((root.join("main.tf"), Arc::from(source)));
    request
}

const RESOURCE: &str = "resource \"aws_db_instance\" \"db\" {\n\
    storage_encrypted = false\nallocated_storage = 1 + 2\n}\n";

#[test]
fn root_boundary_is_exact_and_request_clones_retain_limits() {
    let complete = scan(request(RESOURCE, 100)).unwrap();
    assert_eq!(complete.result.status(), ScanStatus::Complete);
    let used = complete.analyses[0].stats.evaluation_steps;
    assert!(used > 1);
    for allowance in [used - 1, used, used + 1] {
        let request = request(RESOURCE, allowance);
        let copy = request.try_clone().unwrap();
        assert_eq!(request.limits, copy.limits);
        let output = scan(copy).unwrap();
        let expected = if allowance < used {
            ScanStatus::Incomplete
        } else {
            ScanStatus::Complete
        };
        assert_eq!(output.result.status(), expected);
        if allowance < used {
            let diag = output
                .result
                .diagnostics
                .iter()
                .find(|d| d.code == "coverage-budget")
                .unwrap();
            assert!(diag.message.contains(&format!("allowance {allowance}")));
            assert!(diag.at.is_some());
        }
    }
}

#[test]
fn roots_get_equal_allowances_with_one_or_many_workers() {
    let mut base = request(RESOURCE, 3);
    base.input = tf_scan::ScanInput::Dirs {
        paths: vec!["/nonexistent/oxtf-budget".into()],
        recursive: true,
    };
    base.overlay.push((
        "/nonexistent/oxtf-budget/second/main.tf".into(),
        RESOURCE.into(),
    ));
    let mut counts = Vec::new();
    for workers in [1, 4] {
        let mut request = base.try_clone().unwrap();
        request.threads = Some(workers);
        let output = scan(request).unwrap();
        assert_eq!(output.result.status(), ScanStatus::Incomplete);
        assert_eq!(output.analyses.len(), 2);
        counts.push(
            output
                .analyses
                .iter()
                .map(|a| a.stats.evaluation_steps)
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            output
                .result
                .diagnostics
                .iter()
                .filter(|d| d.code == "coverage-budget")
                .count(),
            2
        );
    }
    assert_eq!(counts[0], counts[1]);
    assert_eq!(counts[0], [3, 3]);
}

#[test]
fn locals_child_modules_and_templatefiles_consume_the_same_root_budget() {
    let mut base = request(
        "locals { n = 1 + 2 }\nmodule \"child\" { source = \"./child\" }\n\
         resource \"aws_db_instance\" \"db\" { allocated_storage = local.n }",
        1000,
    );
    base.overlay.extend([
        (
            "/nonexistent/oxtf-budget/child/main.tf".into(),
            Arc::from(
                "resource \"aws_db_instance\" \"child\" {\n\
             allocated_storage = templatefile(\"value.tftpl\", { n = 1 + 2 })\n}",
            ),
        ),
        (
            "/nonexistent/oxtf-budget/value.tftpl".into(),
            Arc::from("${n + 4}"),
        ),
    ]);
    let complete = scan(base.try_clone().unwrap()).unwrap();
    assert_eq!(complete.result.status(), ScanStatus::Complete);
    let used = complete.analyses[0].stats.evaluation_steps;
    base.limits = Limits::new(used - 1).unwrap();
    let limited = scan(base).unwrap();
    assert_eq!(limited.result.status(), ScanStatus::Incomplete);
    assert_eq!(limited.analyses[0].stats.evaluation_steps, used - 1);
    assert!(
        limited
            .result
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-budget")
    );
}

#[test]
fn dropped_limit_values_and_failed_inputs_never_look_complete() {
    let source = "resource \"aws_db_instance\" \"db\" {\n\
        allocated_storage = length([indent(1e100, \"a\\nb\")])\n}";
    assert_eq!(
        scan(request(source, 100)).unwrap().result.status(),
        ScanStatus::Incomplete
    );
    let source = format!("broken = )\n{RESOURCE}");
    assert_eq!(
        scan(request(&source, 1)).unwrap().result.status(),
        ScanStatus::Failed
    );
}

#[test]
fn both_fix_scans_keep_the_configured_allowance() {
    let original = request(RESOURCE, 3);
    let output = scan(original.try_clone().unwrap()).unwrap();
    let fingerprint = &output.record().findings[0].fingerprint;
    let outcome = tf_scan::fix(original, fingerprint, None).unwrap();
    assert!(!outcome.verified);
    assert!(!outcome.target_resolved);
    assert!(
        outcome
            .verification_errors
            .iter()
            .any(|e| e.contains("coverage-budget"))
    );
    let complete = request(RESOURCE, 100);
    let outcome = tf_scan::fix(complete, fingerprint, None).unwrap();
    assert!(outcome.verified, "{:?}", outcome.verification_errors);
}

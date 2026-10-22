use std::path::PathBuf;

use tf_linter::ScanStatus;
use tf_scan::{Catalog, Limits, ScanRequest, scan};

const ROOT: &str = "/nonexistent/oxtf-input-scan";

fn request() -> ScanRequest {
    let root = PathBuf::from(ROOT);
    let mut request = ScanRequest::dirs(vec![root.clone()], false);
    request.catalog = Catalog::seed();
    request.overlay.extend([
        (
            root.join("main.tf"),
            "variable \"value\" {\n type = list(object({x=optional(number,7)}))\n}\n\
        resource \"aws_db_instance\" \"db\" {\n storage_encrypted = false\n\
        allocated_storage = try(length(var.value), 0)\n}"
                .into(),
        ),
        (root.join("override.tf"), "".into()),
        (
            root.join("terraform.tfvars.json"),
            r#"{"value":[{},{},{}]}"#.into(),
        ),
    ]);
    request
}

#[test]
fn stopped_input_conversion_cannot_be_caught_or_verify_a_fix() {
    let base = request();
    let complete = scan(base.try_clone().unwrap()).unwrap();
    assert_eq!(complete.result.status(), ScanStatus::Complete);
    let fingerprint = complete.record().findings[0].fingerprint.clone();
    let mut limited = base.try_clone().unwrap();
    limited.limits = Limits::new(complete.analyses[0].stats.evaluation_steps - 1).unwrap();
    let result = scan(limited.try_clone().unwrap()).unwrap();
    assert_eq!(result.result.status(), ScanStatus::Incomplete);
    assert_eq!(
        result
            .result
            .diagnostics
            .iter()
            .filter(|d| d.code == "coverage-budget")
            .count(),
        1
    );
    let outcome = tf_scan::fix(limited, &fingerprint, None).unwrap();
    assert!(!outcome.verified);
    assert!(
        outcome
            .verification_errors
            .iter()
            .any(|e| e.contains("coverage-budget"))
    );
    assert!(tf_scan::fix(base, &fingerprint, None).unwrap().verified);
}

#[test]
fn runtime_input_allowances_are_independent_of_worker_scheduling() {
    let cost = scan(request()).unwrap().analyses[0].stats.evaluation_steps;
    let mut base = request();
    let first = base.overlay.clone();
    let roots = (0..4)
        .map(|i| PathBuf::from(ROOT).join(format!("root{i}")))
        .collect::<Vec<_>>();
    base.overlay.clear();
    for root in &roots {
        for (path, source) in &first {
            base.overlay
                .push((root.join(path.file_name().unwrap()), source.clone()));
        }
    }
    base.input = tf_scan::ScanInput::Dirs {
        paths: roots,
        recursive: false,
    };
    for allowance in [cost - 1, cost] {
        base.limits = Limits::new(allowance).unwrap();
        let mut snapshots = Vec::new();
        for threads in [1, 4] {
            let mut request = base.try_clone().unwrap();
            request.threads = Some(threads);
            let result = scan(request).unwrap();
            assert_eq!(
                result.result.status(),
                if allowance < cost {
                    ScanStatus::Incomplete
                } else {
                    ScanStatus::Complete
                }
            );
            snapshots.push((
                result
                    .analyses
                    .iter()
                    .map(|a| a.stats.evaluation_steps)
                    .collect::<Vec<_>>(),
                serde_json::to_value(result.record().diagnostics).unwrap(),
            ));
        }
        assert_eq!(snapshots[0], snapshots[1]);
    }
}

#[test]
fn existing_failures_still_win_over_input_conversion_exhaustion() {
    let mut request = request();
    request.limits = Limits::new(10).unwrap();
    request
        .overlay
        .push((PathBuf::from(ROOT).join("broken.tf"), "broken = )".into()));
    let result = scan(request).unwrap();
    assert_eq!(result.result.status(), ScanStatus::Failed);
    assert!(
        result
            .result
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-budget")
    );
    assert!(
        result
            .result
            .diagnostics
            .iter()
            .any(|d| d.code == "parse-error")
    );
}

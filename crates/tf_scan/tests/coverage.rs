use std::path::PathBuf;
use std::sync::Arc;

use tf_linter::ScanStatus;
use tf_scan::{ScanRequest, scan};

fn request(files: &[(&str, &str)], recursive: bool) -> ScanRequest {
    let root = PathBuf::from("/nonexistent/oxtf-coverage");
    let mut req = ScanRequest::dirs(vec![root.clone()], recursive);
    req.catalog = tf_scan::Catalog::seed();
    req.overlay = files
        .iter()
        .map(|(path, text)| (root.join(path), Arc::from(*text)))
        .collect();
    req
}

#[test]
fn json_only_roots_are_discovered_and_evaluated() {
    let out = scan(request(&[("child/main.tf.json", "{}")], true)).unwrap();
    assert_eq!(out.result.stats.roots, 1);
    assert_eq!(out.result.status(), ScanStatus::Complete);
}

#[test]
fn overrides_are_composed_before_findings() {
    let req = request(
        &[
            (
                "main.tf",
                "resource \"aws_db_instance\" \"db\" { storage_encrypted = false }\n",
            ),
            (
                "test_override.tf",
                "resource \"aws_db_instance\" \"db\" { storage_encrypted = true }\n",
            ),
            ("terraform.tfvars.json", "{}"),
        ],
        false,
    );
    let out = scan(req).unwrap();
    assert_eq!(
        out.result.stats.resources, 1,
        "override is not a second declaration"
    );
    assert_eq!(out.result.status(), ScanStatus::Complete);
    assert!(out.record().findings.is_empty());
}

#[test]
fn remote_modules_report_coverage_except_when_disabled() {
    for (count, status) in [
        ("", ScanStatus::Incomplete),
        ("\ncount = 0", ScanStatus::Complete),
    ] {
        let source = format!("module \"remote\" {{\nsource = \"example/remote/aws\"{count}\n}}\n");
        let out = scan(request(&[("main.tf", &source)], false)).unwrap();
        assert_eq!(out.result.status(), status);
    }
}

#[test]
fn evaluation_and_expansion_limits_are_visible() {
    for (source, code) in [
        (
            "resource \"test\" \"r\" { value = not_implemented(1) }",
            "coverage-evaluation",
        ),
        (
            "resource \"test\" \"r\" { value = range(1000000) }",
            "coverage-evaluation",
        ),
        ("resource \"test\" \"r\" { count = 65 }", "coverage-count"),
        (
            "resource \"test\" \"r\" { for_each = range(65) }",
            "coverage-expansion",
        ),
        (
            "resource \"test\" \"r\" {\ndynamic \"x\" {\nfor_each = range(65)\ncontent { value = true }\n}\n}",
            "coverage-expansion",
        ),
    ] {
        let out = scan(request(&[("main.tf", source)], false)).unwrap();
        assert_eq!(out.result.status(), ScanStatus::Incomplete, "{source}");
        assert!(
            out.result.diagnostics.iter().any(|d| d.code == code),
            "{source}"
        );
    }
}

#[test]
fn errored_or_unrecognized_plans_are_incomplete() {
    for source in [
        r#"{"format_version":"1.2","errored":true,"resource_changes":[]}"#,
        r#"{"format_version":"2.0","resource_changes":[]}"#,
    ] {
        let path = PathBuf::from("/nonexistent/oxtf-coverage/plan.json");
        let mut req = ScanRequest::plan(path.clone(), None);
        req.overlay = vec![(path, Arc::from(source))];
        assert_eq!(scan(req).unwrap().result.status(), ScanStatus::Incomplete);
    }
}

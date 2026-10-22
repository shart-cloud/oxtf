//! Oversized syntax trees are coverage limits through every source frontend.
use std::path::PathBuf;
use std::sync::Arc;

use tf_linter::ScanStatus;
use tf_scan::{Catalog, ScanRequest, scan};

fn request(files: &[(&str, String)]) -> ScanRequest {
    let root = PathBuf::from("/nonexistent/oxtf-depth");
    let mut request = ScanRequest::dirs(vec![root.clone()], false);
    request.catalog = Catalog::seed();
    request.threads = Some(1);
    request.overlay = files
        .iter()
        .map(|(name, source)| (root.join(name), Arc::from(source.as_str())))
        .collect();
    request
}

#[test]
fn depth_limits_have_coverage_diagnostics_instead_of_syntax_errors() {
    let nested = format!("{}true", "!".repeat(1000));
    let json = format!("{{\"v\":{}0{}}}", "[".repeat(1000), "]".repeat(1000));
    let template = format!(
        "{}text{}",
        "%{ if true }".repeat(1000),
        "%{ endif }".repeat(1000)
    );
    let normal =
        "variable \"v\" {}\nresource \"aws_db_instance\" \"db\" { storage_encrypted = false }\n";
    for (name, content) in [
        ("deep.tf", format!("v = {nested}\n")),
        ("terraform.tfvars", format!("v = {nested}\n")),
        ("terraform.tfvars.json", json.clone()),
        ("deep.tf.json", json),
        (
            "deep.tf.json",
            serde_json::json!({"locals": {"v": format!("${{{nested}}}")}}).to_string(),
        ),
        ("deep.tf", "b {\n".repeat(1000) + &"}\n".repeat(1000)),
        ("deep.tf", format!("v = <<-EOT\n{template}\nEOT\n")),
    ] {
        let output = scan(request(&[("main.tf", normal.into()), (name, content)])).unwrap();
        assert_eq!(output.result.status(), ScanStatus::Incomplete, "{name}");
        let diagnostics = &output.result.diagnostics;
        assert!(
            diagnostics.iter().any(|d| d.code == "coverage-parse-limit"),
            "{diagnostics:?}"
        );
        assert!(
            !diagnostics.iter().any(|d| d.code == "parse-error"),
            "{diagnostics:?}"
        );
        assert_eq!(
            serde_json::to_value(output.record()).unwrap()["status"],
            "incomplete"
        );
    }
}

#[test]
fn templatefile_depth_limit_is_not_catchable_and_prevents_fix_verification() {
    let template = "%{ if true }".repeat(1000) + "text" + &"%{ endif }".repeat(1000);
    let config = r#"resource "aws_db_instance" "db" {
      storage_encrypted = false
      allocated_storage = length(try(templatefile("deep.tftpl", {}), "fallback"))
    }"#;
    let request = request(&[("main.tf", config.into()), ("deep.tftpl", template)]);
    let output = scan(request.try_clone().unwrap()).unwrap();
    assert_eq!(output.result.status(), ScanStatus::Incomplete);
    assert!(
        output
            .result
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-evaluation")
    );
    let fingerprint = &output.record().findings[0].fingerprint;
    let outcome = tf_scan::fix(request, fingerprint, None).unwrap();
    assert!(!outcome.verified);
}

#[test]
fn workers_are_validated_before_catalog_or_input_loading() {
    for workers in [0, tf_linter::scan::WORKERS_MAX + 1, usize::MAX] {
        let mut request = ScanRequest::dirs(vec!["/nonexistent".into()], false);
        request.threads = Some(workers);
        let error = match scan(request) {
            Ok(_) => panic!("invalid workers accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, tf_scan::ScanError::Execution(_)));
        assert!(error.to_string().contains("worker count"));
    }
    let mut request = ScanRequest::dirs(Vec::new(), false);
    request.threads = Some(tf_linter::scan::WORKERS_MAX);
    request.catalog = Catalog::seed();
    let output = scan(request).unwrap();
    assert_eq!(output.result.status(), ScanStatus::Incomplete);
    assert_eq!(output.result.stats.roots, 0);
}

#[test]
fn existing_syntax_errors_keep_precedence_over_a_depth_limit() {
    let source = format!("invalid = ]\nv = {}true\n", "!".repeat(1000));
    let output = scan(request(&[("main.tf", source)])).unwrap();
    assert_eq!(output.result.status(), ScanStatus::Failed);
    assert!(
        output
            .result
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-parse-limit")
    );
    assert!(
        output
            .result
            .diagnostics
            .iter()
            .any(|d| d.code == "parse-error")
    );
}

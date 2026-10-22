//! Rust convenience constructors use the same shipped rules as CLI/Python.
use std::path::Path;

use tf_scan::{Catalog, ScanRequest, scan};

fn requests() -> [ScanRequest; 2] {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = root.join("fixtures/rules/aws-rds-unencrypted/fail_explicit_false");
    [
        ScanRequest::dirs(vec![source.clone()], false),
        ScanRequest::plan(
            root.join("fixtures/plans/aws-rds-unencrypted/fail_explicit_false.json"),
            Some(source),
        ),
    ]
}

#[test]
fn directory_and_plan_defaults_run_seed_and_bundled_rules() {
    for mut request in requests() {
        let out = scan(request.try_clone().unwrap()).unwrap();
        assert!(out.result.rule_errors.is_empty());
        for rule in ["aws-rds-unencrypted", "CKV_AWS_16"] {
            assert!(
                out.result.findings.iter().any(|f| &*f.rule == rule),
                "missing {rule}"
            );
        }

        request.selection = Some(vec!["CKV_AWS_16".into()]);
        let out = scan(request).unwrap();
        assert_eq!(out.result.findings.len(), 1);
        assert_eq!(&*out.result.findings[0].rule, "CKV_AWS_16");
    }
}

#[test]
fn seed_rules_remain_an_explicit_opt_in() {
    for mut request in requests() {
        request.catalog = Catalog::seed();
        let out = scan(request).unwrap();
        assert!(out.result.rule_errors.is_empty());
        assert_eq!(out.result.findings.len(), 1);
        assert_eq!(&*out.result.findings[0].rule, "aws-rds-unencrypted");
    }
}

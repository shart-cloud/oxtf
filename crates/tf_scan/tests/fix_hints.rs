//! Fix hints, applied and rescanned: every source of hints (seed rules,
//! Checkov predicates, a Rego policy's `fix`) yields an edit that makes the
//! finding go away, and policies whose predicate implies no single fix carry
//! none.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tf_scan::{ScanOutput, ScanRequest, apply_fix, scan};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(
    dir: &Path,
    configure: &dyn Fn(&mut ScanRequest),
    overlay: Vec<(PathBuf, Arc<str>)>,
) -> ScanOutput {
    let mut req = ScanRequest::dirs(vec![dir.to_path_buf()], false);
    req.catalog = tf_scan::Catalog::seed();
    configure(&mut req);
    req.overlay = overlay;
    let out = scan(req).unwrap();
    assert!(
        out.result.rule_errors.is_empty(),
        "{:?}",
        out.result.rule_errors
    );
    out
}

/// Scan, apply the one finding's hint, rescan with the edit: the rule
/// passes. Returns the edited text.
fn fixes(dir: &Path, rule: &str, configure: &dyn Fn(&mut ScanRequest)) -> String {
    let before = run(dir, configure, Vec::new());
    let found: Vec<_> = before
        .result
        .findings
        .iter()
        .filter(|f| &*f.rule == rule)
        .collect();
    assert_eq!(found.len(), 1, "{rule} in {}: {found:?}", dir.display());
    assert!(found[0].fix_hint.is_some(), "{rule}: no fix hint");
    let edit = apply_fix(&before, found[0]).unwrap();
    let after = run(
        dir,
        configure,
        vec![(edit.file.clone(), Arc::from(edit.text.as_str()))],
    );
    assert!(
        !after.result.findings.iter().any(|f| &*f.rule == rule),
        "{rule} still fails in {} after:\n{}",
        dir.display(),
        edit.text
    );
    edit.text
}

fn checkov(req: &mut ScanRequest) {
    req.catalog.builtin = false;
    req.catalog.rule_files = vec![repo().join("fixtures/fix_hints/policies")];
}

#[test]
fn checkov_predicates_imply_fixes_that_pass() {
    let cases = repo().join("fixtures/fix_hints");
    let inserted = fixes(&cases.join("equals_insert"), "CKV2_FIX_EQUALS", &checkov);
    assert!(
        inserted.contains("  storage_encrypted = true\n}"),
        "{inserted}"
    );
    let replaced = fixes(&cases.join("equals_replace"), "CKV2_FIX_EQUALS", &checkov);
    assert!(
        replaced.contains("storage_encrypted = true") && !replaced.contains("false"),
        "{replaced}"
    );
    let one_line = fixes(&cases.join("equals_one_line"), "CKV2_FIX_EQUALS", &checkov);
    assert_eq!(
        one_line,
        "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted = true\n}\n"
    );
    fixes(&cases.join("is_false"), "CKV2_FIX_IS_FALSE", &checkov);
    let acl = fixes(&cases.join("within_one"), "CKV2_FIX_WITHIN", &checkov);
    assert!(acl.contains("  acl    = \"private\"\n"), "{acl}");
}

#[test]
fn ambiguous_predicates_imply_no_fix() {
    let out = run(
        &repo().join("fixtures/fix_hints/equals_insert"),
        &checkov,
        Vec::new(),
    );
    for rule in ["CKV2_FIX_NONE_EXISTS", "CKV2_FIX_NONE_TWO"] {
        let f = out
            .result
            .findings
            .iter()
            .find(|f| &*f.rule == rule)
            .unwrap();
        assert!(f.fix_hint.is_none(), "{rule}");
    }
}

#[test]
fn seed_rule_and_rego_fixes_pass() {
    let rules = repo().join("fixtures/rules");
    for (case, rule) in [
        (
            "aws-rds-unencrypted/fail_explicit_false",
            "aws-rds-unencrypted",
        ),
        (
            "aws-rds-unencrypted/fail_absent_uses_default",
            "aws-rds-unencrypted",
        ),
    ] {
        fixes(&rules.join(case), rule, &|_| {});
    }
    fixes(
        &repo().join("fixtures/rego/ports_tf/known"),
        "PORT-AWS-RDS-UNENCRYPTED",
        &|req| {
            req.catalog.builtin = false;
            req.catalog.rule_files = vec![repo().join("fixtures/rego/ports")];
            req.catalog.policies.entries = vec!["data.ports.rds.deny".into()];
            req.catalog.policies.shape = Some(tf_scan::Shape::Plan);
        },
    );
}

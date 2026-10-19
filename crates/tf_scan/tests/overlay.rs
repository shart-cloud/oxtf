//! In-memory files shadow the disk: the shape a patch-verify step and an
//! editor integration need, with no checkout touched.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tf_linter::record::fingerprint;
use tf_scan::{ScanRequest, scan};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const FIXED: &str = r#"resource "aws_db_instance" "db" {
  identifier        = "db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = true
}
"#;

/// A proposed edit is verified by re-scanning with the edit as an overlay:
/// the finding's fingerprint is gone, and the disk is unchanged.
#[test]
fn overlay_verifies_a_fix_without_writing() {
    let dir = repo().join("fixtures/rules/aws-rds-unencrypted/fail_explicit_false");
    let before = scan(ScanRequest::dirs(vec![dir.clone()], false)).unwrap();
    let f = &before.result.findings[0];
    let fp = fingerprint(
        &f.rule,
        "fixtures/rules/aws-rds-unencrypted/fail_explicit_false/main.tf",
        "aws_db_instance.db",
        f.attribute.as_deref(),
    );
    assert_eq!(before.record().findings[0].fingerprint, fp);

    let mut req = ScanRequest::dirs(vec![dir.clone()], false);
    req.overlay = vec![(dir.join("main.tf"), Arc::from(FIXED))];
    let after = scan(req).unwrap();
    assert!(after.result.findings.is_empty());
    assert!(after.record().findings.iter().all(|f| f.fingerprint != fp));
    assert_eq!(after.result.stats.files, 1);
    assert!(
        std::fs::read_to_string(dir.join("main.tf"))
            .unwrap()
            .contains("= false")
    );
}

/// A fingerprint names the file relative to its repository, so scanning
/// the same directory spelled another way (or from elsewhere) keeps it.
#[test]
fn fingerprints_do_not_depend_on_how_the_path_is_spelled() {
    let canonical = repo()
        .canonicalize()
        .unwrap()
        .join("fixtures/rules/aws-rds-unencrypted/fail_explicit_false");
    let dotted = repo().join("crates/../fixtures/rules/aws-rds-unencrypted/fail_explicit_false");
    let fps = |dir: PathBuf| -> Vec<String> {
        let out = scan(ScanRequest::dirs(vec![dir], false)).unwrap();
        out.record()
            .findings
            .into_iter()
            .map(|f| f.fingerprint)
            .collect()
    };
    let a = fps(canonical);
    assert!(!a.is_empty());
    assert_eq!(a, fps(dotted));
}

/// A module that exists only in memory: the directory need not exist.
#[test]
fn overlay_only_module_in_a_directory_that_does_not_exist() {
    let dir = PathBuf::from("/nonexistent/oxtf-overlay/mod");
    let mut req = ScanRequest::dirs(vec![dir.clone()], false);
    req.overlay = vec![
        (
            dir.join("main.tf"),
            Arc::from(r#"resource "aws_db_instance" "db" { storage_encrypted = var.enc }"#),
        ),
        (
            dir.join("vars.tf"),
            Arc::from(r#"variable "enc" { type = bool }"#),
        ),
        (dir.join("terraform.tfvars"), Arc::from("enc = false\n")),
    ];
    let out = scan(req).unwrap();
    let rec = out.record();
    assert_eq!(rec.findings.len(), 1, "{:?}", rec.diagnostics);
    let f = &rec.findings[0];
    assert_eq!(f.certainty, tf_linter::Certainty::Definite);
    assert_eq!(f.location.file, dir.join("main.tf").display().to_string());
    assert!(
        f.provenance
            .iter()
            .any(|s| s.location.file.ends_with("terraform.tfvars")),
        "{:?}",
        f.provenance
    );
    assert_eq!(out.result.stats.files, 3);
    // Without the overlay the same path is refused.
    let err = scan(ScanRequest::dirs(vec![dir], false)).err().unwrap();
    assert!(err.to_string().contains("not a directory"));
}

/// Recursive discovery sees overlay-only roots beside disk roots.
#[test]
fn recursive_discovery_includes_overlay_only_roots() {
    let base = repo().join("fixtures/rules/aws-rds-unencrypted");
    let on_disk = scan(ScanRequest::dirs(vec![base.clone()], true)).unwrap();
    let mut req = ScanRequest::dirs(vec![base.clone()], true);
    req.overlay = vec![
        (
            base.join("zz_memory/main.tf"),
            Arc::from(r#"resource "aws_db_instance" "m" { storage_encrypted = false }"#),
        ),
        // An existing root with its file replaced by a clean one.
        (base.join("fail_explicit_false/main.tf"), Arc::from(FIXED)),
    ];
    let with = scan(req).unwrap();
    assert_eq!(with.result.stats.roots, on_disk.result.stats.roots + 1);
    assert_eq!(with.result.stats.findings, on_disk.result.stats.findings);
    assert!(
        with.result
            .findings
            .iter()
            .any(|f| f.root.ends_with("zz_memory"))
    );
    assert!(
        !with
            .result
            .findings
            .iter()
            .any(|f| f.root.ends_with("fail_explicit_false"))
    );
}

//! A finding is one rule failing on one resource declaration: the module
//! scanned as its own root, each example that calls it, and each
//! `for_each` instance are occurrences of it, not findings of their own.
use std::path::PathBuf;
use std::sync::Arc;

use tf_linter::Certainty;
use tf_linter::record::SubjectRecord;
use tf_scan::{ScanRequest, scan};

const MODULE: &str = r#"
variable "encrypted" {
  type    = bool
  default = false
}
resource "aws_db_instance" "db" {
  for_each          = toset(["x", "y"])
  storage_encrypted = var.encrypted
}
"#;

fn repo_in_memory() -> (PathBuf, Vec<(PathBuf, Arc<str>)>) {
    let base = PathBuf::from("/nonexistent/oxtf-grouping");
    let overlay = vec![
        (base.join("modules/db/main.tf"), Arc::from(MODULE)),
        (
            base.join("examples/a/main.tf"),
            Arc::from(r#"module "db" { source = "../../modules/db" }"#),
        ),
        (
            base.join("examples/b/main.tf"),
            Arc::from(
                r#"module "db" {
  source    = "../../modules/db"
  encrypted = var.enc
}
variable "enc" { type = bool }
"#,
            ),
        ),
        // Sets the variable securely: not an occurrence.
        (
            base.join("examples/c/main.tf"),
            Arc::from(
                r#"module "db" {
  source    = "../../modules/db"
  encrypted = true
}"#,
            ),
        ),
    ];
    (base, overlay)
}

#[test]
fn roots_and_instances_are_occurrences_of_one_finding() {
    let (base, overlay) = repo_in_memory();
    let mut req = ScanRequest::dirs(vec![base], true);
    req.overlay = overlay;
    let out = scan(req).unwrap();
    // Per-instance findings: two instances in each of three roots.
    assert_eq!(out.result.findings.len(), 6);

    let rec = out.record();
    assert_eq!(rec.findings.len(), 1, "{:#?}", rec.findings);
    assert_eq!((rec.stats.findings, rec.stats.occurrences), (1, 6));
    let f = &rec.findings[0];
    // The most certain occurrence decides; the module's own root is the
    // representative (no module path).
    assert_eq!(f.certainty, Certainty::Definite);
    assert!(f.root.ends_with("modules/db"), "{}", f.root);
    let SubjectRecord::Resource(r) = &f.subject else {
        panic!("a resource finding")
    };
    assert_eq!(r.module, "");
    let occurrences: Vec<(&str, &str, Certainty)> = f
        .occurrences
        .iter()
        .map(|o| (o.root.rsplit('/').next().unwrap(), &*o.address, o.certainty))
        .collect();
    assert_eq!(
        occurrences,
        [
            (
                "a",
                "module.db.aws_db_instance.db[\"x\"]",
                Certainty::Definite
            ),
            (
                "a",
                "module.db.aws_db_instance.db[\"y\"]",
                Certainty::Definite
            ),
            (
                "b",
                "module.db.aws_db_instance.db[\"x\"]",
                Certainty::Conditional
            ),
            (
                "b",
                "module.db.aws_db_instance.db[\"y\"]",
                Certainty::Conditional
            ),
            ("db", "aws_db_instance.db[\"x\"]", Certainty::Definite),
            ("db", "aws_db_instance.db[\"y\"]", Certainty::Definite),
        ]
    );
    assert!(f.occurrences.iter().all(|o| o.location.is_none()));
    assert_eq!(
        rec.rules.keys().collect::<Vec<_>>(),
        ["aws-rds-unencrypted"]
    );
}

#[test]
fn ndjson_has_a_line_per_finding_and_a_summary() {
    let (base, overlay) = repo_in_memory();
    let mut req = ScanRequest::dirs(vec![base], true);
    req.overlay = overlay;
    let rec = scan(req).unwrap().record();
    let lines: Vec<serde_json::Value> = tf_linter::formats::ndjson(&rec)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["type"], "finding");
    assert_eq!(lines[0]["occurrences"], 6);
    assert_eq!(
        lines[0]["fingerprint"],
        rec.findings[0].fingerprint.as_str()
    );
    assert_eq!(lines[1]["type"], "summary");
    assert_eq!(lines[1]["findings"], 1);

    let sarif = tf_linter::formats::sarif(&rec);
    let run = &sarif["runs"][0];
    assert_eq!(
        run["tool"]["driver"]["rules"][0]["id"],
        "aws-rds-unencrypted"
    );
    let result = &run["results"][0];
    assert_eq!(result["ruleIndex"], 0);
    assert_eq!(result["level"], "error");
    assert_eq!(
        result["partialFingerprints"]["oxtf/v1"],
        rec.findings[0].fingerprint.as_str()
    );
}

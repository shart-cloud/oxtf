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

/// A bundled value check that fails on an absent attribute names the
/// attribute, carries a fix hint that inserts it, and the edited file
/// scans clean under the same fingerprint check.
#[test]
fn absent_attribute_findings_name_it_and_fix_it() {
    let dir = PathBuf::from("/nonexistent/oxtf-absent");
    let main = dir.join("main.tf");
    let text = "resource \"aws_instance\" \"web\" {\n  ami           = \"ami-123\"\n  instance_type = \"t3.micro\"\n}\n";
    let request = |text: &str| {
        let mut req = ScanRequest::dirs(vec![dir.clone()], false);
        req.catalog = tf_scan::Catalog::standard();
        req.selection = Some(vec!["CKV_AWS_126".into()]);
        req.overlay = vec![(main.clone(), Arc::from(text))];
        req
    };
    let before = scan(request(text)).unwrap();
    let rec = before.record();
    let [f] = rec.findings.as_slice() else {
        panic!("{:#?}", rec.findings)
    };
    assert_eq!(f.attribute.as_deref(), Some("monitoring"));
    assert_eq!(f.provenance[0].kind, "absent");
    let hint = before.result.findings[0].fix_hint.clone().unwrap();
    assert_eq!(
        (hint.attribute.as_str(), &hint.value),
        ("monitoring", &serde_json::json!(true))
    );
    assert!(hint.site.is_none());

    let edit = tf_scan::apply_fix(&before, &hint).unwrap();
    assert!(
        edit.text.contains("  monitoring = true\n}"),
        "{}",
        edit.text
    );
    let after = scan(request(&edit.text)).unwrap().record();
    assert!(
        after
            .findings
            .iter()
            .all(|g| g.fingerprint != f.fingerprint),
        "{:#?}",
        after.findings
    );
}

/// A bundled Python check that fails on a missing attribute names it from
/// its `evaluated_keys`.
#[test]
fn python_check_findings_name_a_missing_attribute() {
    let dir = PathBuf::from("/nonexistent/oxtf-python-attribute");
    let text = r#"resource "google_compute_subnetwork" "s" {
  name          = "s"
  ip_cidr_range = "10.0.0.0/24"
  network       = "n"
}
"#;
    let mut req = ScanRequest::dirs(vec![dir.clone()], false);
    req.catalog = tf_scan::Catalog::standard();
    req.selection = Some(vec!["CKV_GCP_74".into()]);
    req.overlay = vec![(dir.join("main.tf"), Arc::from(text))];
    let rec = scan(req).unwrap().record();
    let [f] = rec.findings.as_slice() else {
        panic!("{:#?}", rec.findings)
    };
    assert_eq!(f.attribute.as_deref(), Some("private_ip_google_access"));
    assert_eq!(f.provenance.last().unwrap().kind, "absent");
}

/// A Python check that reports no `evaluated_keys` is located by its
/// lookups: the last key it read, at the line it is written when it was
/// found, as an absence at the header when it was not.
#[test]
fn python_check_findings_are_located_by_their_lookups() {
    // if conf.get("enabled") == [True]: return PASSED
    // return FAILED
    let rule = serde_json::json!({
        "version": 4, "name": "PY_TRACE", "message": "not enabled",
        "clauses": [{"resource_types": ["test_thing"], "condition": {
            "op": "checkov_python",
            "program": {"version": 1, "entry": "f", "self": {}, "functions": {"f": {
                "params": ["conf"], "defaults": [null], "body": [
                    {"s": "if", "test": {"e": "cmp",
                        "left": {"e": "call", "func": {"method": "get", "obj": {"e": "name", "id": "conf"}},
                                 "args": [{"e": "const", "v": "enabled"}], "kwargs": []},
                        "ops": ["eq"],
                        "comparators": [{"e": "list", "elts": [{"e": "const", "v": true}]}]},
                     "body": [{"s": "return", "value": {"e": "const", "v": {"result": "PASSED"}}}],
                     "orelse": []},
                    {"s": "return", "value": {"e": "const", "v": {"result": "FAILED"}}}
                ]}}}}}]
    });
    let dir = PathBuf::from("/nonexistent/oxtf-python-trace");
    let text = "resource \"test_thing\" \"off\" {\n  name    = \"a\"\n  enabled = false\n}\nresource \"test_thing\" \"unset\" {\n  name = \"b\"\n}\n";
    let mut req = ScanRequest::dirs(vec![dir.clone()], false);
    req.catalog = tf_scan::Catalog {
        rule_json: vec![rule.to_string()],
        ..tf_scan::Catalog::default()
    };
    req.overlay = vec![(dir.join("main.tf"), Arc::from(text))];
    let rec = scan(req).unwrap().record();
    let mut got: Vec<(&str, Option<&str>, u32, &str)> = rec
        .findings
        .iter()
        .map(|f| {
            let SubjectRecord::Resource(r) = &f.subject else {
                panic!("a resource finding")
            };
            (
                r.name.as_str(),
                f.attribute.as_deref(),
                f.location.line,
                f.provenance.last().map_or("", |s| s.kind.as_str()),
            )
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("off", Some("enabled"), 3, "attribute"),
            ("unset", Some("enabled"), 5, "absent"),
        ]
    );
}

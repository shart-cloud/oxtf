//! One `--rule-file` for every format: rule IR, Checkov policies and Rego
//! in one directory, each detected by its content, with the common
//! metadata model (engine, source file and line, guideline, category).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tf_scan::{Catalog, ScanRequest, scan};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn mixed() -> Catalog {
    Catalog {
        rule_files: vec![repo().join("fixtures/rules_mixed/policies")],
        ..Catalog::default()
    }
}

#[test]
fn a_mixed_directory_loads_every_format() {
    let resolved = mixed().resolve().unwrap();
    // The mock JSON next to the Rego is data, not a broken rule.
    assert!(resolved.warnings.is_empty(), "{:?}", resolved.warnings);
    type Row = (String, String, String, Option<String>, Option<u32>);
    let rows: Vec<Row> = resolved
        .rules
        .iter()
        .map(|r| r.info())
        .map(|i| {
            (
                i.name.to_string(),
                i.source.engine.as_str().to_string(),
                i.category.as_str().to_string(),
                i.guideline.as_deref().map(str::to_string),
                i.source.line,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                "CKV2_MIXED_1".into(),
                "checkov".into(),
                "other".into(),
                Some("https://example.com/guidelines/s3-versioning".into()),
                Some(2)
            ),
            (
                "py-sg-open-ssh".into(),
                "ir".into(),
                "network".into(),
                None,
                None
            ),
            (
                "MIXED_OWNER_TAG".into(),
                "conftest".into(),
                "other".into(),
                Some("https://example.com/guidelines/owner-tag".into()),
                Some(13)
            ),
        ]
    );
}

#[test]
fn findings_carry_the_rule_source() {
    let mut req = ScanRequest::dirs(vec![repo().join("fixtures/rules_mixed/tf")], false);
    req.catalog = mixed();
    req.catalog.builtin = false;
    let out = scan(req).unwrap();
    let record = serde_json::to_value(out.record()).unwrap();
    let mut rules: Vec<(String, Value)> = record["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                record["rules"][f["rule"].as_str().unwrap()]["source"]["engine"].clone(),
            )
        })
        .collect();
    rules.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        rules,
        [
            ("CKV2_MIXED_1".to_string(), json!("checkov")),
            ("MIXED_OWNER_TAG".to_string(), json!("conftest")),
            ("py-sg-open-ssh".to_string(), json!("ir")),
        ]
    );
    assert!(record["rule_errors"].as_array().unwrap().is_empty());
}

/// A rule file that does not load is a `rule-skipped` warning located in
/// the rule file, whatever its format.
#[test]
fn skipped_rule_files_are_located() {
    let dir = std::env::temp_dir().join(format!("oxtf-rule-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("a_bad.yaml"),
        "metadata:\n  id: BAD_1\n  name: n\n  category: c\ndefinition:\n  cond_type: attribute\n  resource_types: [aws_s3_bucket]\n  attribute: acl\n  operator: frobnicate\n  value: x\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("b_bad.json"),
        "{\n  \"name\": \"x\",\n  \"message\": \"m\",\n  \"clauses\": [{\"resource_types\": [\"a\"], \"condition\": {\"op\": \"nope\"}}]\n}\n",
    )
    .unwrap();
    let mut req = ScanRequest::dirs(vec![repo().join("fixtures/rules_mixed/tf")], false);
    req.catalog.rule_files = vec![dir.clone()];
    let out = scan(req).unwrap();
    let record = serde_json::to_value(out.record()).unwrap();
    let locations: Vec<(String, Value, Value)> = record["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["code"] == "rule-skipped")
        .map(|d| {
            let loc = &d["location"];
            (
                Path::new(loc["file"].as_str().unwrap())
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                loc["line"].clone(),
                loc["column"].clone(),
            )
        })
        .collect();
    assert_eq!(
        locations,
        [
            ("a_bad.yaml".to_string(), json!(9), json!(13)),
            ("b_bad.json".to_string(), json!(4), json!(66)),
        ]
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// `checkov:skip` lines suppress Checkov-sourced rules as Checkov does:
/// inside the resource's block or an enclosing module call, by ID, and the
/// suppression is reported (fixtures/checkov_skip; Checkov 3.2.328 skips
/// and fails the same resources).
#[test]
fn checkov_skip_comments_suppress_checkov_rules() {
    let base = repo().join("fixtures/checkov_skip");
    let mut req = ScanRequest::dirs(vec![base.join("tf")], false);
    req.catalog.builtin = false;
    req.catalog.rule_files = vec![base.join("policies")];
    let out = scan(req).unwrap();
    let record = serde_json::to_value(out.record()).unwrap();
    let mut failed: Vec<&str> = record["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["subject"]["address"].as_str().unwrap())
        .collect();
    failed.sort();
    assert_eq!(
        failed,
        [
            "aws_db_instance.other_id",
            "aws_db_instance.outside",
            "module.child2.aws_db_instance.inner"
        ]
    );
    let mut suppressed: Vec<(String, String, Value)> = record["suppressed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["resource"].as_str().unwrap().to_string(),
                s["comment"].as_str().unwrap().to_string(),
                s["location"]["line"].clone(),
            )
        })
        .collect();
    suppressed.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        suppressed,
        [
            (
                "aws_db_instance.bare_skip".to_string(),
                "No comment provided".to_string(),
                json!(12)
            ),
            (
                "aws_db_instance.skipped".to_string(),
                "encrypted by the platform".to_string(),
                json!(2)
            ),
            (
                "module.child.aws_db_instance.inner".to_string(),
                "module-wide".to_string(),
                json!(22)
            ),
        ]
    );
}

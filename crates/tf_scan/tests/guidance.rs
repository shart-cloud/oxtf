//! Severity and remediation describe the evidence a rule actually establishes.
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tf_linter::{Level, Profile};
use tf_scan::{ScanRequest, scan};

#[test]
fn guardrails_endpoints_and_administrative_grants_have_distinct_severity() {
    let mut catalog = tf_scan::Catalog::standard();
    catalog.profiles = Some(tf_scan::ALL_PROFILES.to_vec());
    let rules = catalog.resolve().unwrap().rules;
    for (id, level, profile) in [
        ("aws-rds-unencrypted", Level::Medium, Profile::Security),
        (
            "aws-s3-public-access-block",
            Level::Medium,
            Profile::Security,
        ),
        (
            "aws-iam-wildcard-policy",
            Level::Critical,
            Profile::Security,
        ),
        ("CKV_AWS_16", Level::Medium, Profile::Security),
        ("CKV_AWS_17", Level::High, Profile::Security),
        ("CKV_AWS_61", Level::Medium, Profile::Security),
        ("CKV_AWS_355", Level::Medium, Profile::Security),
        ("CKV_AZURE_190", Level::Medium, Profile::Security),
        ("CKV_AWS_145", Level::Low, Profile::Hygiene),
        ("CKV_AWS_158", Level::Low, Profile::Hygiene),
        ("CKV2_GCP_18", Level::Low, Profile::Hygiene),
        ("CKV_GCP_25", Level::Medium, Profile::Security),
        ("CKV_GCP_64", Level::Medium, Profile::Security),
        ("CKV_GCP_40", Level::Medium, Profile::Security),
        ("CKV_GCP_49", Level::Medium, Profile::Security),
        ("CKV_GCP_41", Level::High, Profile::Security),
    ] {
        let rule = rules
            .iter()
            .map(|r| r.info())
            .find(|r| &*r.name == id)
            .unwrap();
        assert_eq!((rule.level, rule.profile), (level, profile), "{id}");
        assert!(rule.rationale.is_some(), "{id}");
        assert!(rule.remediation.is_some(), "{id}");
    }
}

#[test]
fn gke_guidance_explains_the_actual_presence_and_dataplane_predicates() {
    let root = PathBuf::from("/nonexistent/oxtf-guidance-gke");
    for (body, expected) in [
        ("", vec!["CKV_GCP_12", "CKV_GCP_25", "CKV_GCP_64"]),
        (
            "private_cluster_config { enable_private_nodes = false }",
            vec!["CKV_GCP_12"],
        ),
        (
            "datapath_provider = \"ADVANCED_DATAPATH\"",
            vec!["CKV_GCP_12", "CKV_GCP_25", "CKV_GCP_64"],
        ),
        (
            "datapath_provider = \"ADVANCED_DATAPATH\"\nnetwork_policy { enabled = false }",
            vec!["CKV_GCP_25", "CKV_GCP_64"],
        ),
    ] {
        let mut req = ScanRequest::dirs(vec![root.clone()], false);
        req.overlay = vec![(
            root.join("main.tf"),
            Arc::from(format!(
                "resource \"google_container_cluster\" \"r\" {{\n{body}\n}}"
            )),
        )];
        req.selection = Some(
            ["CKV_GCP_12", "CKV_GCP_25", "CKV_GCP_64"]
                .map(String::from)
                .to_vec(),
        );
        let out = scan(req).unwrap().record();
        assert_eq!(out.status, tf_linter::ScanStatus::Complete);
        let mut ids: Vec<_> = out.findings.iter().map(|f| f.rule.as_str()).collect();
        ids.sort();
        assert_eq!(ids, expected, "{body}");
        for rule in out.rules.values() {
            assert!(rule.remediation.is_some());
            assert!(rule.rationale.is_some());
        }
    }
}

#[test]
fn guidance_survives_scanning_json_ndjson_sarif_and_text() {
    let root = PathBuf::from("/nonexistent/oxtf-guidance");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.overlay = vec![(
        root.join("main.tf"),
        Arc::from("resource \"aws_db_instance\" \"db\" { storage_encrypted = false }\n"),
    )];
    req.selection = Some(vec!["aws-rds-unencrypted".into(), "CKV_AWS_16".into()]);
    let out = scan(req).unwrap();
    let record = out.record();
    assert_eq!(record.findings.len(), 2);
    for f in &record.findings {
        assert_eq!(f.level, Level::Medium);
        let info = &record.rules[&f.rule];
        assert!(info.remediation.as_ref().unwrap().contains("snapshot"));
        assert!(
            info.rationale
                .as_ref()
                .unwrap()
                .contains("does not establish public")
        );
    }
    let json = serde_json::to_value(&record).unwrap();
    let ndjson = tf_linter::formats::ndjson(&record);
    let summary: Value = serde_json::from_str(ndjson.lines().last().unwrap()).unwrap();
    assert_eq!(summary["rules"], json["rules"]);
    let sarif = tf_linter::formats::sarif(&record);
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
    {
        let id = rule["id"].as_str().unwrap();
        assert_eq!(rule["help"]["text"], json["rules"][id]["remediation"]);
        assert_eq!(
            rule["properties"]["rationale"],
            json["rules"][id]["rationale"]
        );
        assert_eq!(rule["helpUri"], json["rules"][id]["guideline"]);
    }
    let text = tf_linter::render::render_finding(&out.result.files, &out.result.findings[0], false);
    assert!(text.contains("remediation:"), "{text}");
    assert!(text.contains("snapshot"), "{text}");
}

#[test]
fn account_trust_is_described_as_delegation_in_actual_findings() {
    let root = PathBuf::from("/nonexistent/oxtf-guidance-trust");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.overlay = vec![(
        root.join("main.tf"),
        Arc::from(
            r#"
resource "aws_iam_role" "delegated" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::123456789012:root" }, Action = "sts:AssumeRole" }]
  })
}
"#,
        ),
    )];
    req.selection = Some(vec!["CKV_AWS_61".into()]);
    let out = scan(req).unwrap().record();
    assert_eq!(out.findings.len(), 1);
    assert_eq!(
        out.findings[0].message,
        "IAM role trust delegates to an AWS account principal"
    );
    assert_eq!(out.findings[0].level, Level::Medium);
}

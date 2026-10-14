use serde_json::Value;
use std::{path::Path, process::Command};

fn scan(args: &[String], rego: bool) -> Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxtf"));
    cmd.args(["scan", "--format", "json", "--threads", "4"]);
    cmd.args(args);
    if rego {
        cmd.arg("--rego-native");
    }
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut result: Value = serde_json::from_slice(&output.stdout).unwrap();
    result["stats"]
        .as_object_mut()
        .unwrap()
        .remove("elapsed_ms");
    for key in ["findings", "diagnostics"] {
        result[key]
            .as_array_mut()
            .unwrap()
            .sort_by_key(Value::to_string);
    }
    result
}

fn visit(path: &Path, cases: &mut usize) {
    if path.join("main.tf").is_file() {
        let args = vec![path.to_string_lossy().into_owned()];
        assert_eq!(scan(&args, true), scan(&args, false), "{}", path.display());
        *cases += 1;
    }
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            visit(&path, cases);
        } else if path.extension().is_some_and(|e| e == "json")
            && path.file_name().unwrap() != "native.json"
        {
            let args = vec!["--plan".into(), path.to_string_lossy().into_owned()];
            assert_eq!(scan(&args, true), scan(&args, false), "{}", path.display());
            *cases += 1;
        }
    }
}

#[test]
fn full_source_and_plan_outputs_match_native() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cases = 0;
    for dir in ["rules", "plans", "baseline", "parity", "uncertainty"] {
        visit(&repo.join("fixtures").join(dir), &mut cases);
    }
    assert!(cases >= 74, "only {cases} fixture scans");
}

#[test]
fn parallel_roots_match_native() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let args = vec![
        repo.join("fixtures/rules").to_string_lossy().into_owned(),
        "--recursive".into(),
    ];
    assert_eq!(scan(&args, true), scan(&args, false));
}

#[test]
fn existence_and_module_tfvars_provenance_match_native() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rego/rds");
    let args = vec![root.to_string_lossy().into_owned()];
    let actual = scan(&args, true);
    assert_eq!(actual, scan(&args, false));
    let findings = actual["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 3);
    assert!(
        findings
            .iter()
            .any(|f| f["address"] == "module.db.aws_db_instance.db")
    );
    assert!(actual["findings"].to_string().contains("terraform.tfvars"));
    assert_eq!(
        findings
            .iter()
            .filter(|f| f["severity"] == "conditional")
            .count(),
        2
    );
}

#[test]
fn rds_flag_and_rule_selection_remain_compatible() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rules");
    let args = vec![root.to_string_lossy().into_owned(), "--recursive".into()];
    let mut legacy = args.clone();
    legacy.push("--rego-rds".into());
    assert_eq!(scan(&legacy, false), scan(&args, false));
    assert_eq!(scan(&legacy, true), scan(&args, true));
    for rule in [
        "aws-rds-unencrypted",
        "gcp-storage-uniform-access",
        "aws-sg-open-ssh",
        "aws-iam-wildcard-policy",
        "aws-s3-public-access-block",
    ] {
        let mut selected = args.clone();
        selected.extend(["--rule".into(), rule.into()]);
        let actual = scan(&selected, true);
        assert_eq!(actual, scan(&selected, false));
        assert!(!actual["findings"].as_array().unwrap().is_empty());
        assert!(
            actual["findings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|f| f["rule"] == rule)
        );
    }
}

#[test]
fn gcp_defaults_uncertainty_and_provenance_match_native() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rego/gcp");
    let args = vec![root.to_string_lossy().into_owned()];
    let actual = scan(&args, true);
    assert_eq!(actual, scan(&args, false));
    let findings = actual["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 6);
    assert!(
        findings
            .iter()
            .any(|f| f["address"] == "module.bucket.google_storage_bucket.bucket")
    );
    assert!(actual["findings"].to_string().contains("terraform.tfvars"));
    assert_eq!(
        findings
            .iter()
            .filter(|f| f["severity"] == "conditional")
            .count(),
        3
    );
}

#[test]
fn ssh_container_witnesses_and_resource_variants_match_native() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rego/ssh");
    let args = vec![root.to_string_lossy().into_owned()];
    let actual = scan(&args, true);
    assert_eq!(actual, scan(&args, false));
    let findings = actual["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 5);
    assert_eq!(
        findings
            .iter()
            .filter(|f| f["severity"] == "conditional")
            .count(),
        3
    );
    let module = findings
        .iter()
        .find(|f| f["address"] == "module.network.aws_security_group.ssh")
        .unwrap();
    assert_eq!(
        module["message"],
        "ingress allows SSH (port 22) from 0.0.0.0/0"
    );
    assert!(module.to_string().contains("terraform.tfvars"));
}

#[test]
fn iam_documents_and_s3_module_joins_match_native() {
    for (fixture, count, conditional) in [("iam", 3, 1), ("s3", 2, 1)] {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/rego")
            .join(fixture);
        let args = vec![root.to_string_lossy().into_owned()];
        let actual = scan(&args, true);
        assert_eq!(actual, scan(&args, false));
        let findings = actual["findings"].as_array().unwrap();
        assert_eq!(findings.len(), count, "{fixture}");
        assert_eq!(
            findings
                .iter()
                .filter(|f| f["severity"] == "conditional")
                .count(),
            conditional
        );
        if fixture == "iam" {
            let module = findings
                .iter()
                .find(|f| f["address"] == "module.policy.aws_iam_role_policy.policy")
                .unwrap();
            assert!(module.to_string().contains("terraform.tfvars"));
        } else {
            assert!(
                findings
                    .iter()
                    .any(|f| f["address"] == "aws_s3_bucket.b[\"c\"]")
            );
            assert!(
                findings
                    .iter()
                    .any(|f| f["message"].as_str().unwrap().contains("may not exist"))
            );
        }
    }
}

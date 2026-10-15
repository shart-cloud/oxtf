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
fn rule_selection_applies_to_native_tier_policies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rules");
    let args = vec![root.to_string_lossy().into_owned(), "--recursive".into()];
    for rule in ["aws-rds-unencrypted", "gcp-storage-uniform-access"] {
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

/// The exit check for the foreign-policy seam: an unmodified public Conftest
/// policy over the HCL-shaped projection yields each certainty class.
#[test]
fn unmodified_conftest_policy_yields_each_certainty_class() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = repo.join("fixtures/rego/foreign");
    let policy = root.join("conftest_hcl2_deny.rego");
    let args = vec![
        root.to_string_lossy().into_owned(),
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--policy-shape".into(),
        "hcl".into(),
    ];
    let result = scan(&args, false);
    let findings = result["findings"].as_array().unwrap();
    let mut rows: Vec<(String, String, String)> = findings
        .iter()
        .map(|f| {
            (
                f["address"].as_str().unwrap().to_string(),
                f["severity"].as_str().unwrap().to_string(),
                f["message"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    rows.sort();
    assert!(findings.iter().all(|f| f["rule"] == "rego:conftest_hcl2_deny"));
    // hcl2json renders every block body as a list, so the policy's
    // `not disk.encryption_settings.enabled` is true for any disk that has the
    // block at all: the encrypted `ok` disk is flagged too. That is what the
    // policy does under Conftest; the seam reproduces it faithfully.
    let expect = [
        (
            "azurerm_managed_disk.from_data",
            "indeterminate",
            "Azure disk `from_data` is not encrypted (cannot be confirmed: encryption_settings[0].enabled computed at apply time)",
        ),
        (
            "azurerm_managed_disk.from_var",
            "conditional",
            "Azure disk `from_var` is not encrypted (depends on unconstrained variable var.encrypt)",
        ),
        ("azurerm_managed_disk.ok", "definite", "Azure disk `ok` is not encrypted"),
        ("azurerm_managed_disk.plain", "definite", "Azure disk `plain` is not encrypted"),
    ];
    let expect: Vec<(String, String, String)> = expect
        .iter()
        .map(|(a, s, m)| (a.to_string(), s.to_string(), m.to_string()))
        .collect();
    assert_eq!(rows, expect);
    assert_eq!(result["stats"]["indeterminate"], 1);
    assert_eq!(result["stats"]["conditional"], 1);
    assert_eq!(result["stats"]["definite"], 2);
    // The conditional finding points at the variable through provenance.
    let cond = findings.iter().find(|f| f["severity"] == "conditional").unwrap();
    assert!(cond["provenance"].to_string().contains("variable"), "{cond}");
}

/// regorus does not implement Go's `%q` format verb, which the public
/// policy's required-tags rule uses. That is an engine gap, and it must
/// surface as a failed scan, never as a missing violation.
#[test]
fn unsupported_builtin_in_a_foreign_policy_fails_loudly() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = repo.join("fixtures/rego/foreign_sprintf");
    let policy = repo.join("fixtures/rego/foreign/conftest_hcl2_deny.rego");
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "--format",
            "json",
            root.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--policy-shape",
            "hcl",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("aws_security_group_rule.open") && err.contains("%q"), "{err}");
    assert!(out.stdout.is_empty());
}

#[test]
fn foreign_policy_errors_refuse_the_scan() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = repo.join("fixtures/rego/foreign");
    let dir = std::env::temp_dir().join(format!("oxtf-rego-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.rego");
    std::fs::write(&bad, "package main\nimport rego.v1\ndeny contains msg if { msg := 1 / 0 }").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args(["scan", "--format", "json", root.to_str().unwrap(), "--policy", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("bad"));
    assert!(out.stdout.is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

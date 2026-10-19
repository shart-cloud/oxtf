//! The Rego backend through the scan request: the foreign-policy seam,
//! Conftest conventions and catalog shadowing.
use std::path::{Path, PathBuf};

use serde_json::Value;
use tf_scan::{Catalog, ScanError, ScanInput, ScanRequest, Shape, scan};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn request(input: ScanInput) -> ScanRequest {
    let mut req = ScanRequest::dirs(vec![], false);
    req.input = input;
    req.threads = Some(4);
    req
}

/// Record JSON with timing removed and finding order made immaterial.
fn run(req: ScanRequest) -> Value {
    let out = scan(req).unwrap();
    assert!(
        out.result.rule_errors.is_empty(),
        "{:?}",
        out.result.rule_errors
    );
    let mut result = serde_json::to_value(out.record()).unwrap();
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

fn dirs(paths: Vec<PathBuf>, recursive: bool) -> ScanInput {
    ScanInput::Dirs { paths, recursive }
}

#[test]
fn existence_and_module_tfvars_provenance() {
    let actual = run(request(dirs(vec![repo().join("fixtures/rego/rds")], false)));
    let findings = actual["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 3);
    assert!(
        findings
            .iter()
            .any(|f| f["subject"]["address"] == "module.db.aws_db_instance.db")
    );
    assert!(actual["findings"].to_string().contains("terraform.tfvars"));
    assert_eq!(
        findings
            .iter()
            .filter(|f| f["certainty"] == "conditional")
            .count(),
        2
    );
}

#[test]
fn gcp_defaults_uncertainty_and_provenance() {
    let actual = run(request(dirs(vec![repo().join("fixtures/rego/gcp")], false)));
    let findings = actual["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 6);
    assert!(
        findings
            .iter()
            .any(|f| f["subject"]["address"] == "module.bucket.google_storage_bucket.bucket")
    );
    assert!(actual["findings"].to_string().contains("terraform.tfvars"));
    assert_eq!(
        findings
            .iter()
            .filter(|f| f["certainty"] == "conditional")
            .count(),
        3
    );
}

fn foreign(root: &str, policy: &Path, shape: Shape) -> ScanRequest {
    let mut req = ScanRequest::dirs(vec![repo().join(root)], false);
    req.catalog.policies.foreign = vec![policy.to_path_buf()];
    req.catalog.policies.shape = Some(shape);
    req
}

/// The exit check for the foreign-policy seam: an unmodified public Conftest
/// policy, evaluated per file as Conftest does, yields each certainty class
/// (one file per class: certainty is decided over the whole file).
#[test]
fn unmodified_conftest_policy_yields_each_certainty_class() {
    let policy = repo().join("fixtures/rego/foreign/conftest_hcl2_deny.rego");
    let result = run(foreign("fixtures/rego/foreign", &policy, Shape::Hcl));
    let findings = result["findings"].as_array().unwrap();
    let mut rows: Vec<(String, String, String)> = findings
        .iter()
        .map(|f| {
            (
                f["subject"]["address"].as_str().unwrap().to_string(),
                f["certainty"].as_str().unwrap().to_string(),
                f["message"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    rows.sort();
    assert!(
        findings
            .iter()
            .all(|f| f["rule"] == "rego:conftest_hcl2_deny")
    );
    // hcl2json renders every block body as a list, so the policy's
    // `not disk.encryption_settings.enabled` is true for any disk that has the
    // block at all: the encrypted `ok` disk is flagged too. That is what the
    // policy does under Conftest; the seam reproduces it faithfully.
    let expect = [
        (
            "azurerm_managed_disk.from_data",
            "indeterminate",
            "Azure disk `from_data` is not encrypted (cannot be confirmed: resource.azurerm_managed_disk.from_data.encryption_settings[0].enabled computed at apply time)",
        ),
        (
            "azurerm_managed_disk.from_var",
            "conditional",
            "Azure disk `from_var` is not encrypted (depends on unconstrained variable var.encrypt)",
        ),
        (
            "azurerm_managed_disk.ok",
            "definite",
            "Azure disk `ok` is not encrypted",
        ),
        (
            "azurerm_managed_disk.plain",
            "definite",
            "Azure disk `plain` is not encrypted",
        ),
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
    let cond = findings
        .iter()
        .find(|f| f["certainty"] == "conditional")
        .unwrap();
    assert!(
        cond["provenance"].to_string().contains("variable"),
        "{cond}"
    );
}

/// A builtin that fails at runtime (`to_number("tcp")`, an error in OPA
/// with --strict-builtin-errors too) must surface as a rule error naming
/// the file (Conftest's unit), never as a missing violation; the rest of
/// the scan still completes.
#[test]
fn runtime_error_in_a_foreign_policy_is_a_rule_error() {
    let policy = repo().join("fixtures/rego/runtime_error/protocol_number.rego");
    let out = scan(foreign(
        "fixtures/rego/foreign_runtime_error",
        &policy,
        Shape::Hcl,
    ))
    .unwrap();
    let errors = &out.result.rule_errors;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].rule, "rego:protocol_number");
    assert_eq!(errors[0].resource, None);
    assert!(
        errors[0].message.contains("foreign_runtime_error/main.tf"),
        "{}",
        errors[0].message
    );
    assert!(
        errors[0].message.contains("to_number"),
        "{}",
        errors[0].message
    );
    assert_eq!(out.record().rule_errors.len(), 1);
}

/// The public policy's required-tags rule formats with Go's `%q` verb,
/// which regorus 0.12 lacked. Its violation is reported as OPA words it.
#[test]
fn go_quoted_strings_in_a_foreign_policy_match_opa() {
    let policy = repo().join("fixtures/rego/foreign/conftest_hcl2_deny.rego");
    let out = scan(foreign(
        "fixtures/rego/foreign_sprintf",
        &policy,
        Shape::Hcl,
    ))
    .unwrap();
    assert!(
        out.result.rule_errors.is_empty(),
        "{:?}",
        out.result.rule_errors
    );
    let messages: Vec<_> = out
        .result
        .findings
        .iter()
        .map(|f| f.message.as_str())
        .collect();
    assert!(
        messages.contains(
            &r#"AWS resource: "aws_security_group_rule" named "open" is missing required tags: {"environment", "owner"}"#
        ),
        "{messages:?}"
    );
}

#[test]
fn foreign_policy_compile_errors_refuse_the_scan() {
    let dir = std::env::temp_dir().join(format!("oxtf-rego-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.rego");
    std::fs::write(
        &bad,
        "package main\nimport rego.v1\ndeny contains msg if { msg := 1 / 0 }",
    )
    .unwrap();
    let err = scan(foreign("fixtures/rego/foreign", &bad, Shape::Plan))
        .err()
        .unwrap();
    assert!(matches!(err, ScanError::Policy(_)), "{err}");
    assert!(err.to_string().contains("bad"));
    let missing = scan(foreign(
        "fixtures/rego/foreign",
        &dir.join("none.rego"),
        Shape::Plan,
    ))
    .err()
    .unwrap();
    assert!(missing.to_string().contains("none.rego"), "{missing}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_later_catalog_source_shadows_by_name() {
    // A loaded rule carrying a seed rule's name replaces it: one rule runs,
    // not two. This rule never fires, so the seed rule's finding is gone.
    let shadow = r#"{"name": "aws-rds-unencrypted", "message": "never",
        "clauses": [{"resource_types": ["aws_db_instance"],
                     "condition": {"op": "lit", "value": false}}]}"#;
    let mut req = ScanRequest::dirs(
        vec![repo().join("fixtures/rules/aws-rds-unencrypted/fail_explicit_false")],
        false,
    );
    req.catalog.rule_json.push(shadow.into());
    let out = scan(req).unwrap();
    assert_eq!(out.result.findings.len(), 0);
    let names: Vec<String> = Catalog {
        builtin: true,
        rule_json: vec![shadow.into()],
        ..Default::default()
    }
    .resolve()
    .unwrap()
    .rules
    .iter()
    .map(|r| r.info().name.to_string())
    .collect();
    assert_eq!(
        names.iter().filter(|n| *n == "aws-rds-unencrypted").count(),
        1
    );
    assert_eq!(names.len(), 5);
}

#[test]
fn selection_covers_the_whole_catalog() {
    let policy = repo().join("fixtures/rego/foreign/conftest_hcl2_deny.rego");
    let mut req = foreign("fixtures/rego/foreign", &policy, Shape::Hcl);
    req.selection = Some(vec!["rego:conftest_hcl2_deny".into()]);
    let out = scan(req).unwrap();
    assert_eq!(out.result.findings.len(), 4);
    let mut req = foreign("fixtures/rego/foreign", &policy, Shape::Hcl);
    req.selection = Some(vec!["rego:nope".into()]);
    let err = scan(req).err().unwrap();
    assert!(matches!(err, ScanError::Selection(_)), "{err}");
}

fn ports(root: &str, shape: Shape) -> ScanRequest {
    let mut req = ScanRequest::dirs(vec![repo().join(root)], false);
    req.catalog.builtin = false;
    req.catalog.policies.foreign = vec![repo().join("fixtures/rego/ports")];
    req.catalog.policies.entries = vec![
        "data.ports.rds.deny".into(),
        "data.ports.s3_public_access_block.deny".into(),
    ];
    req.catalog.policies.shape = Some(shape);
    req
}

/// The seed-rule ports: IDs and levels from `# METADATA`, a module-input
/// policy joining buckets to public access blocks across the root, and a
/// `path` in the violation pointing the finding at the attribute.
#[test]
fn ported_policies_use_metadata_module_input_and_paths() {
    let known = run(ports("fixtures/rego/ports_tf/known", Shape::Plan));
    let rows: Vec<(String, String, String, String, Value)> = known["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().into(),
                f["level"].as_str().unwrap().into(),
                f["subject"]["address"].as_str().unwrap().into(),
                f["certainty"].as_str().unwrap().into(),
                f["location"]["line"].clone(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                "PORT-AWS-RDS-UNENCRYPTED".into(),
                "high".into(),
                "aws_db_instance.db".into(),
                "definite".into(),
                // `storage_encrypted = false`, from the violation's `path`.
                serde_json::json!(20)
            ),
            (
                "PORT-AWS-S3-PUBLIC-ACCESS-BLOCK".into(),
                "high".into(),
                "aws_s3_bucket.exposed".into(),
                "definite".into(),
                serde_json::json!(13)
            ),
        ]
    );
    let tainted = run(ports("fixtures/rego/ports_tf/tainted", Shape::Plan));
    let f = &tainted["findings"][0];
    assert_eq!(tainted["findings"].as_array().unwrap().len(), 1);
    assert_eq!(f["subject"]["address"], "aws_s3_bucket.named");
    assert_eq!(f["certainty"], "conditional");
    assert!(f["message"].as_str().unwrap().contains("var.name"), "{f}");
    assert_eq!(f["hidden"][0]["path"], "aws_s3_bucket.named.bucket");
    // Module input is defined for the plan shape only.
    let err = scan(ports("fixtures/rego/ports_tf/known", Shape::Hcl))
        .err()
        .unwrap();
    assert!(
        err.to_string().contains("needs the plan input shape"),
        "{err}"
    );
}

/// Conftest conventions, per file: `deny_`/`warn_` rules discovered in
/// `main`, results no resource reproduces reported on the file, a join
/// attributed to the bucket by ablation, and an exception keyed on
/// `data.conftest.file` (fixtures/rego/conftest; `conftest test` agrees).
#[test]
fn conftest_conventions_files_ablation_and_exceptions() {
    let mut req = ScanRequest::dirs(vec![repo().join("fixtures/rego/conftest/tf")], false);
    req.catalog.builtin = false;
    req.catalog.policies.foreign = vec![repo().join("fixtures/rego/conftest/policy")];
    let result = run(req);
    let mut rows: Vec<(String, String, Value, String)> = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().into(),
                f["level"].as_str().unwrap().into(),
                f["subject"].clone(),
                f["certainty"].as_str().unwrap().into(),
            )
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let file = serde_json::json!({
        "kind": "file",
        "file": tf_semantic::source::normalize(&repo().join("fixtures/rego/conftest/tf/main.tf"))
            .display()
            .to_string(),
        "module": "",
    });
    assert_eq!(
        rows,
        [
            (
                "rego:main.deny_unpinned_module".to_string(),
                "medium".to_string(),
                file.clone(),
                "definite".to_string()
            ),
            (
                "rego:main.deny_unversioned".to_string(),
                "medium".to_string(),
                serde_json::json!({
                    "kind": "resource",
                    "address": "aws_s3_bucket.a",
                    "base_address": "aws_s3_bucket.a",
                    "module": "",
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "name": "a",
                    "key": null,
                }),
                "definite".to_string()
            ),
            (
                "rego:main.warn_provider_region".to_string(),
                "low".to_string(),
                file,
                "definite".to_string()
            ),
        ]
    );
    let f = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["subject"]["kind"] == "file")
        .unwrap();
    assert_eq!(f["resource"], Value::Null);
}

/// `oxtf rules test` (Conftest's `verify`): `test_*` rules pass when true,
/// `todo_test_*` is skipped, and Conftest's `parse_config` and
/// `parse_config_file` builtins work. `conftest verify` gives the same.
#[test]
fn policy_tests_run_as_conftest_verify() {
    let catalog = Catalog {
        rule_files: vec![repo().join("fixtures/rego/conftest/policy")],
        ..Catalog::default()
    };
    let outcomes = tf_scan::verify_policies(&catalog).unwrap();
    let got: Vec<(String, tf_scan::TestResult)> =
        outcomes.into_iter().map(|o| (o.rule, o.result)).collect();
    use tf_scan::TestResult::*;
    assert_eq!(
        got,
        [
            ("data.main.test_unpinned_module_is_denied".to_string(), Pass),
            ("data.main.test_pinned_module_passes".to_string(), Pass),
            ("data.main.test_a_failing_test_fails".to_string(), Fail),
            ("data.main.todo_test_regions".to_string(), Skip),
        ]
    );
}

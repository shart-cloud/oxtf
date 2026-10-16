//! The Rego backend through the scan request: native-tier parity with the
//! seed rules on every fixture, and the foreign-policy seam.
use std::path::{Path, PathBuf};

use serde_json::Value;
use tf_scan::{Catalog, ScanError, ScanInput, ScanRequest, Shape, scan};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn request(input: ScanInput, rego_native: bool) -> ScanRequest {
    let mut req = ScanRequest::dirs(vec![], false);
    req.input = input;
    req.catalog.policies.native = rego_native;
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

fn both(input: ScanInput, selection: Option<Vec<String>>) -> (Value, Value) {
    let mut rego = request(input.clone(), true);
    rego.selection = selection.clone();
    let mut native = request(input, false);
    native.selection = selection;
    (run(rego), run(native))
}

fn visit(path: &Path, cases: &mut usize) {
    if path.join("main.tf").is_file() {
        let (r, n) = both(dirs(vec![path.to_path_buf()], false), None);
        assert_eq!(r, n, "{}", path.display());
        *cases += 1;
    }
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            visit(&path, cases);
        } else if path.extension().is_some_and(|e| e == "json")
            && path.file_name().unwrap() != "native.json"
        {
            let input = ScanInput::Plan {
                plan: path.clone(),
                source: None,
            };
            let (r, n) = both(input, None);
            assert_eq!(r, n, "{}", path.display());
            *cases += 1;
        }
    }
}

#[test]
fn full_source_and_plan_outputs_match_native() {
    let mut cases = 0;
    for dir in ["rules", "plans", "baseline", "parity", "uncertainty"] {
        visit(&repo().join("fixtures").join(dir), &mut cases);
    }
    assert!(cases >= 74, "only {cases} fixture scans");
}

#[test]
fn parallel_roots_match_native() {
    let (r, n) = both(dirs(vec![repo().join("fixtures/rules")], true), None);
    assert_eq!(r, n);
}

#[test]
fn existence_and_module_tfvars_provenance_match_native() {
    let (actual, native) = both(dirs(vec![repo().join("fixtures/rego/rds")], false), None);
    assert_eq!(actual, native);
    let findings = actual["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 3);
    assert!(
        findings
            .iter()
            .any(|f| f["resource"]["address"] == "module.db.aws_db_instance.db")
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
    for rule in ["aws-rds-unencrypted", "gcp-storage-uniform-access"] {
        let (actual, native) = both(
            dirs(vec![repo().join("fixtures/rules")], true),
            Some(vec![rule.into()]),
        );
        assert_eq!(actual, native);
        assert!(!actual["findings"].as_array().unwrap().is_empty());
        assert!(
            actual["findings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|f| f["rule"]["id"] == rule)
        );
    }
}

#[test]
fn gcp_defaults_uncertainty_and_provenance_match_native() {
    let (actual, native) = both(dirs(vec![repo().join("fixtures/rego/gcp")], false), None);
    assert_eq!(actual, native);
    let findings = actual["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 6);
    assert!(
        findings
            .iter()
            .any(|f| f["resource"]["address"] == "module.bucket.google_storage_bucket.bucket")
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

fn foreign(root: &str, policy: &Path, shape: Shape) -> ScanRequest {
    let mut req = ScanRequest::dirs(vec![repo().join(root)], false);
    req.catalog.policies.foreign = vec![policy.to_path_buf()];
    req.catalog.policies.shape = Some(shape);
    req
}

/// The exit check for the foreign-policy seam: an unmodified public Conftest
/// policy over the HCL-shaped projection yields each certainty class.
#[test]
fn unmodified_conftest_policy_yields_each_certainty_class() {
    let policy = repo().join("fixtures/rego/foreign/conftest_hcl2_deny.rego");
    let result = run(foreign("fixtures/rego/foreign", &policy, Shape::Hcl));
    let findings = result["findings"].as_array().unwrap();
    let mut rows: Vec<(String, String, String)> = findings
        .iter()
        .map(|f| {
            (
                f["resource"]["address"].as_str().unwrap().to_string(),
                f["severity"].as_str().unwrap().to_string(),
                f["message"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    rows.sort();
    assert!(
        findings
            .iter()
            .all(|f| f["rule"]["id"] == "rego:conftest_hcl2_deny")
    );
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
        .find(|f| f["severity"] == "conditional")
        .unwrap();
    assert!(
        cond["provenance"].to_string().contains("variable"),
        "{cond}"
    );
}

/// regorus does not implement Go's `%q` format verb, which the public
/// policy's required-tags rule uses. That is an engine gap, and it must
/// surface as a rule error naming the resource, never as a missing
/// violation; the rest of the scan still completes.
#[test]
fn unsupported_builtin_in_a_foreign_policy_is_a_rule_error() {
    let policy = repo().join("fixtures/rego/foreign/conftest_hcl2_deny.rego");
    let out = scan(foreign(
        "fixtures/rego/foreign_sprintf",
        &policy,
        Shape::Hcl,
    ))
    .unwrap();
    let errors = &out.result.rule_errors;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].rule, "rego:conftest_hcl2_deny");
    assert_eq!(
        errors[0].resource.as_deref(),
        Some("aws_security_group_rule.open")
    );
    assert!(errors[0].message.contains("%q"), "{}", errors[0].message);
    assert_eq!(out.record().rule_errors.len(), 1);
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
    // The native-tier RDS policy carries the seed rule's name: one rule
    // runs, not two, so findings are not doubled.
    let mut req = ScanRequest::dirs(
        vec![repo().join("fixtures/rules/aws-rds-unencrypted/fail_explicit_false")],
        false,
    );
    req.catalog.policies.native = true;
    let out = scan(req).unwrap();
    assert_eq!(out.result.findings.len(), 1);
    let names: Vec<String> = Catalog {
        builtin: true,
        policies: tf_rego::Policies {
            native: true,
            ..Default::default()
        },
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
                f["rule"]["id"].as_str().unwrap().into(),
                f["rule"]["level"].as_str().unwrap().into(),
                f["resource"]["address"].as_str().unwrap().into(),
                f["severity"].as_str().unwrap().into(),
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
    assert_eq!(f["resource"]["address"], "aws_s3_bucket.named");
    assert_eq!(f["severity"], "conditional");
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

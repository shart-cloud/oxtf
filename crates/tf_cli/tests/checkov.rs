//! Portable Checkov packs use the same catalog for discovery and execution.
use std::process::Command;

#[test]
fn imported_check_can_be_listed_and_selected_without_checkov_installed() {
    let dir = std::env::temp_dir().join(format!("oxtf-checkov-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pack = dir.join("rules.json");
    std::fs::write(&pack, r#"[{"version":2,"name":"CKV_AWS_16","description":"RDS encryption","message":"RDS encryption","clauses":[{"resource_types":["aws_db_instance"],"condition":{"op":"checkov_value","path":["storage_encrypted"],"values":[true],"negative":false,"any_value":false,"missing":"fail"}}]}]"#).unwrap();
    std::fs::write(dir.join("main.tf"), "resource \"aws_db_instance\" \"bad\" { storage_encrypted = false }\nresource \"aws_db_instance\" \"good\" { storage_encrypted = true }\n").unwrap();
    let list = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args(["rules", "--rule-file"])
        .arg(&pack)
        .output()
        .unwrap();
    assert!(list.status.success(), "{:?}", list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("CKV_AWS_16"));
    let scan = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .arg("scan")
        .arg(&dir)
        .args(["--format", "json", "--rule", "CKV_AWS_16", "--rule-file"])
        .arg(&pack)
        .output()
        .unwrap();
    assert!(scan.status.success(), "{:?}", scan);
    let result: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let findings = result["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule"]["id"], "CKV_AWS_16");
    assert_eq!(findings[0]["resource"]["address"], "aws_db_instance.bad");
    assert_eq!(findings[0]["severity"], "definite");
    assert!(!findings[0]["provenance"].as_array().unwrap().is_empty());
    assert!(result["rule_errors"].as_array().unwrap().is_empty());
}

#[test]
fn graph_policy_runs_through_cli_for_source_and_plan() {
    let dir = std::env::temp_dir().join(format!("oxtf-graph-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pack = dir.join("rules.json");
    let rule = serde_json::json!({"version":3,"name":"GRAPH_FLOW_LOGS","message":"VPC needs flow logs","clauses":[{"resource_types":["*"],"condition":{"op":"checkov_graph","definition":{"kind":"and","args":[
        {"kind":"connection","resource_types":["aws_vpc"],"connected_resource_types":["aws_flow_log"],"operator":"exists"},
        {"kind":"filter","resource_types":["aws_vpc"]}
    ]}}}]});
    std::fs::write(&pack, rule.to_string()).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        r#"
resource "aws_vpc" "good" {}
resource "aws_vpc" "bad" {}
resource "aws_flow_log" "log" { vpc_id = aws_vpc.good.id }
"#,
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .arg("scan")
        .arg(&dir)
        .args([
            "--format",
            "json",
            "--rule",
            "GRAPH_FLOW_LOGS",
            "--rule-file",
        ])
        .arg(&pack)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["findings"].as_array().unwrap().len(), 1);
    assert_eq!(result["findings"][0]["resource"]["address"], "aws_vpc.bad");
    assert!(result["rule_errors"].as_array().unwrap().is_empty());

    let plan_dir = dir.join("plan");
    std::fs::create_dir_all(&plan_dir).unwrap();
    let plan_path = plan_dir.join("plan.json");
    let resource = |ty: &str, name: &str, after| serde_json::json!({"address":format!("{ty}.{name}"),"mode":"managed","type":ty,"name":name,"change":{"actions":["create"],"after":after}});
    let mut plan = serde_json::json!({"format_version":"1.2","resource_changes":[
        resource("aws_vpc","good",serde_json::json!({"id":"vpc-good"})),
        resource("aws_vpc","bad",serde_json::json!({"id":"vpc-bad"})),
        resource("aws_flow_log","log",serde_json::json!({"vpc_id":"vpc-good"}))
    ],"configuration":{"root_module":{"resources":[
        {"address":"aws_vpc.good"},{"address":"aws_vpc.bad"},
        {"address":"aws_flow_log.log","expressions":{"vpc_id":{"references":["aws_vpc.good.id","aws_vpc.good"]}}}
    ]}}});
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .arg("scan")
            .arg("--plan")
            .arg(&plan_path)
            .args([
                "--format",
                "json",
                "--rule",
                "GRAPH_FLOW_LOGS",
                "--rule-file",
            ])
            .arg(&pack)
            .output()
            .unwrap()
    };
    std::fs::write(&plan_path, plan.to_string()).unwrap();
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["findings"].as_array().unwrap().len(), 1);
    assert_eq!(result["findings"][0]["resource"]["address"], "aws_vpc.bad");
    plan.as_object_mut().unwrap().remove("configuration");
    std::fs::write(&plan_path, plan.to_string()).unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["rule_errors"].as_array().unwrap().len(), 1);
    assert!(
        result["rule_errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("dependencies unavailable")
    );
}

/// A Checkov custom policy in YAML runs as written: no export step, no
/// Python, with values resolved by oxtf (the bucket's ACL comes from a
/// variable default, which Checkov's own loader would compare as text).
#[test]
fn yaml_policy_runs_without_export() {
    let dir = std::env::temp_dir().join(format!("oxtf-checkov-yaml-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("policies")).unwrap();
    std::fs::write(
        dir.join("policies/private_acl.yaml"),
        r#"
metadata:
  id: CKV2_CUSTOM_ACL
  name: S3 buckets must be private
  category: GENERAL_SECURITY
  severity: HIGH
definition:
  cond_type: attribute
  resource_types: [aws_s3_bucket]
  attribute: acl
  operator: equals
  value: private
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.tf"),
        r#"
variable "acl" { default = "public-read" }
resource "aws_s3_bucket" "bad" { acl = var.acl }
resource "aws_s3_bucket" "good" { acl = "private" }
"#,
    )
    .unwrap();
    let list = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args(["rules", "--rule-file"])
        .arg(dir.join("policies"))
        .output()
        .unwrap();
    assert!(list.status.success(), "{:?}", list);
    assert!(String::from_utf8_lossy(&list.stdout).contains("CKV2_CUSTOM_ACL"));
    let scan = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .arg("scan")
        .arg(&dir)
        .args([
            "--format",
            "json",
            "--rule",
            "CKV2_CUSTOM_ACL",
            "--rule-file",
        ])
        .arg(dir.join("policies"))
        .output()
        .unwrap();
    assert!(scan.status.success(), "{:?}", scan);
    let result: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let findings = result["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0]["rule"]["id"], "CKV2_CUSTOM_ACL");
    assert_eq!(findings[0]["rule"]["level"], "high");
    assert_eq!(findings[0]["resource"]["address"], "aws_s3_bucket.bad");

    // An unsupported policy in a directory is skipped with a warning that
    // points into the policy file; the rest of the directory still runs.
    std::fs::write(
        dir.join("policies/regex.yaml"),
        "metadata: {id: CKV2_RE, name: n, category: c}\ndefinition:\n  cond_type: attribute\n  resource_types: [aws_s3_bucket]\n  attribute: acl\n  operator: regex_match\n  value: '^p'\n",
    )
    .unwrap();
    let scan = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .arg("scan")
        .arg(&dir)
        .args(["--format", "json", "--no-diagnostics", "--rule-file"])
        .arg(dir.join("policies"))
        .output()
        .unwrap();
    assert!(scan.status.success(), "{:?}", scan);
    let stderr = String::from_utf8_lossy(&scan.stderr);
    assert!(stderr.contains("warning: skipped rule file"), "{stderr}");
    assert!(
        stderr.contains("regex.yaml:6:13: CKV2_RE: unsupported graph operator: regex_match"),
        "{stderr}"
    );
    let result: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let skipped: Vec<_> = result["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["code"] == "rule-skipped")
        .collect();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["severity"], "warning");
    assert!(
        result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule"]["id"] == "CKV2_CUSTOM_ACL")
    );

    // Named directly, the same file is still a load error.
    let scan = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .arg("scan")
        .arg(&dir)
        .arg("--rule-file")
        .arg(dir.join("policies/regex.yaml"))
        .output()
        .unwrap();
    assert_eq!(scan.status.code(), Some(2), "{:?}", scan);
    std::fs::remove_dir_all(&dir).unwrap();
}

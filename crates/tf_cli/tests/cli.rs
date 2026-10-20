//! `oxtf scan` end-to-end: the W4 exit output (finding + full provenance
//! chain) and the JSON format. These run the seed rules alone
//! (`--no-bundled`); the bundled Checkov catalog has its own tests below.

use std::process::Command;

#[test]
fn json_configuration_and_override_fixes_share_the_cli_pipeline() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-json-overrides-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("main.tf.json"),
        r#"{"resource":{"aws_db_instance":{"db":{"storage_encrypted":false}}}}"#,
    )
    .unwrap();
    let scan = || {
        let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args(["scan", "--no-bundled", "-f", "json"])
            .arg(&dir)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(record["status"], "complete");
        record
    };
    let json = scan();
    assert!(json["findings"][0]["fix_hint"].is_null());
    std::fs::write(
        dir.join("override.tf"),
        r#"resource "aws_db_instance" "db" { storage_encrypted = false }"#,
    )
    .unwrap();
    let merged = scan();
    let finding = &merged["findings"][0];
    assert!(
        finding["location"]["file"]
            .as_str()
            .unwrap()
            .ends_with("override.tf")
    );
    let fixed = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "fix",
            finding["fingerprint"].as_str().unwrap(),
            "--no-bundled",
            "-f",
            "json",
        ])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        fixed.status.success(),
        "{}",
        String::from_utf8_lossy(&fixed.stderr)
    );
    let fixed: serde_json::Value = serde_json::from_slice(&fixed.stdout).unwrap();
    assert_eq!(fixed["verified"], true);
    assert!(fixed["file"].as_str().unwrap().ends_with("override.tf"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn installed_modules_and_json_vars_work_from_disk_with_custom_data_dir() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-installed-{}", std::process::id()));
    let cache = dir.join("cache/modules/db");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        r#"
variable "encrypted" { default = true }
module "db" {
  source = "acme/db/aws"
  encrypted = var.encrypted
}
"#,
    )
    .unwrap();
    std::fs::write(dir.join("terraform.tfvars.json"), r#"{"encrypted":false}"#).unwrap();
    std::fs::write(cache.join("main.tf"), "variable \"encrypted\" {}\nresource \"aws_db_instance\" \"db\" { storage_encrypted = var.encrypted }\n").unwrap();
    let manifest = dir.join("cache/modules/modules.json");
    std::fs::write(&manifest, r#"{"Modules":[{"Key":"db","Source":"acme/db/aws","Version":"1.2.3","Dir":"cache/modules/db"}]}"#).unwrap();
    for path in [".", dir.to_str().unwrap()] {
        let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .current_dir(&dir)
            .args([
                "scan",
                path,
                "--recursive",
                "--data-dir",
                "cache",
                "--no-bundled",
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(out.status.code(), Some(1), "{record}");
        assert_eq!(record["status"], "complete");
        assert_eq!(record["stats"]["roots"], 1);
        assert_eq!(record["findings"][0]["package"]["file"], "main.tf");
        assert!(record["findings"][0]["fix_hint"].is_null());
    }
    std::fs::remove_file(manifest).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .current_dir(&dir)
        .args([
            "scan",
            ".",
            "--data-dir",
            "cache",
            "--no-bundled",
            "--format",
            "json",
            "--fail-on",
            "never",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    std::fs::remove_dir_all(dir).unwrap();
}

fn fixture(p: &str) -> String {
    format!("{}/../../fixtures/rules/{p}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn scan_prints_provenance_chain() {
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "--no-bundled",
            &fixture("aws-sg-open-ssh/fail_tfvars_through_local"),
        ])
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    // A definite finding fails the default --fail-on.
    assert_eq!(out.status.code(), Some(1));
    assert!(s.contains("aws-sg-open-ssh [definite]"), "{s}");
    assert!(
        s.contains("aws_security_group.admin: ingress allows SSH (port 22) from 0.0.0.0/0"),
        "{s}"
    );
    for step in [
        "[1/4] terraform.tfvars: admin_cidr = \"0.0.0.0/0\"",
        "[2/4] variable admin_cidr",
        "[3/4] local.ssh_sources",
        "[4/4] aws_security_group.admin ingress.cidr_blocks",
    ] {
        assert!(s.contains(step), "missing {step:?} in\n{s}");
    }
}

#[test]
fn scan_json_and_recursive() {
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "--no-bundled",
            "--recursive",
            "--format",
            "json",
            &fixture("aws-rds-unencrypted"),
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["stats"]["roots"], 6);
    let sev: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["certainty"].as_str().unwrap())
        .collect();
    assert_eq!(sev.iter().filter(|s| **s == "definite").count(), 3);
    assert_eq!(sev.iter().filter(|s| **s == "conditional").count(), 2);
}

#[test]
fn var_file_wins_over_terraform_tfvars() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-varfile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let vf = dir.join("open.tfvars");
    std::fs::write(&vf, "admin_cidr = \"0.0.0.0/0\"\n").unwrap();
    let case = fixture("aws-sg-open-ssh/pass_tfvars_overrides_open_default");
    let run = |extra: &[&str]| {
        let mut args = vec!["scan", "--no-bundled", "--format", "json", case.as_str()];
        args.extend_from_slice(extra);
        let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args(&args)
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["findings"].as_array().unwrap().len()
    };
    assert_eq!(run(&[]), 0);
    assert_eq!(run(&["--var-file", vf.to_str().unwrap()]), 1);
}

#[test]
fn current_directory_scan_loads_terraform_tfvars() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-cwd-tfvars-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.tf"), "variable \"encrypt\" { default = true }\nresource \"aws_db_instance\" \"db\" { storage_encrypted = var.encrypt }\n").unwrap();
    std::fs::write(dir.join("terraform.tfvars"), "encrypt = false\n").unwrap();
    for path in [None, Some("."), Some("./"), dir.to_str()] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxtf"));
        cmd.current_dir(&dir)
            .args(["scan", "--no-bundled", "--format", "json"]);
        if let Some(path) = path {
            cmd.arg(path);
        }
        let out = cmd.output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["stats"]["files"], 2, "{path:?}: {v}");
        assert_eq!(v["findings"].as_array().unwrap().len(), 1, "{path:?}: {v}");
        assert_eq!(v["findings"][0]["certainty"], "definite");
        assert_eq!(v["findings"][0]["effective"]["value"], false);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// `--rule-file`: a rule written with the Python expression API (rule IR
/// JSON) runs with no Python runtime and matches the built-in rule.
#[test]
fn scan_rule_file() {
    let rules = format!(
        "{}/../tfscan_py/rules/sg_open_ssh.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let run = |rule: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args([
                "scan",
                "--no-bundled",
                &fixture("aws-sg-open-ssh/conditional_unconstrained_variable"),
                "--rule-file",
                &rules,
                "--rule",
                rule,
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["subject"]["address"].clone(),
                    f["certainty"].clone(),
                    f["message"].clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let ir = run("py-sg-open-ssh");
    assert_eq!(ir.len(), 1);
    assert_eq!(ir, run("aws-sg-open-ssh"));
    let bad = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "--no-bundled",
            ".",
            "--rule-file",
            "/nonexistent.json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

/// W5: `oxtf scan --plan` maps a plan finding back to the source span.
#[test]
fn scan_plan_maps_to_source() {
    let plan = format!(
        "{}/../../fixtures/plans/aws-s3-public-access-block/fail_permissive_block.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "--no-bundled",
            "--plan",
            &plan,
            "--source",
            &fixture("aws-s3-public-access-block/fail_permissive_block"),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let f = &j["findings"][0];
    assert_eq!(f["subject"]["address"], "aws_s3_bucket.data");
    assert_eq!(f["certainty"], "definite");
    assert!(
        f["location"]["file"]
            .as_str()
            .unwrap()
            .ends_with("fail_permissive_block/main.tf"),
        "{f}"
    );
    assert_eq!(f["location"]["line"], 1);
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args(["scan", "--no-bundled", "--plan", &plan, "."])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn unknown_rule_ids_are_errors_even_with_valid_ids() {
    for ids in [
        vec!["aws-rds-unencryptd"],
        vec!["aws-rds-unencrypted", "aws-rds-unencryptd"],
    ] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxtf"));
        cmd.args([
            "scan",
            "--no-bundled",
            &fixture("aws-rds-unencrypted/fail_absent_uses_default"),
            "--format",
            "json",
        ]);
        for id in ids {
            cmd.args(["--rule", id]);
        }
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("aws-rds-unencryptd"));
        assert!(out.stdout.is_empty());
    }
}

/// A policy that fails on one resource at runtime: the scan completes,
/// the record carries the rule error, stderr names it, and the exit code
/// is 1 so a caller cannot read the output as clean.
#[test]
fn rule_errors_exit_one_with_output() {
    let repo = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "--no-bundled",
            "--format",
            "json",
            &format!("{repo}/fixtures/rego/foreign_runtime_error"),
            "--policy",
            &format!("{repo}/fixtures/rego/runtime_error/protocol_number.rego"),
            "--policy-shape",
            "hcl",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    // Conftest evaluates the whole file, so the error names the file.
    assert!(
        err.contains("foreign_runtime_error/main.tf") && err.contains("to_number"),
        "{err}"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["rule_errors"][0]["resource"], serde_json::Value::Null);
    // No finding from the policy whose evaluation failed.
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| !f["rule"].as_str().unwrap().starts_with("rego:"))
    );
}

/// A policy that does not compile refuses the scan: exit 2, no output.
#[test]
fn policy_compile_errors_exit_two() {
    let repo = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let dir = std::env::temp_dir().join(format!("oxtf-cli-rego-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.rego");
    std::fs::write(
        &bad,
        "package main\nimport rego.v1\ndeny contains msg if { msg := 1 / 0 }",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "--no-bundled",
            "--format",
            "json",
            &format!("{repo}/fixtures/rego/foreign"),
            "--policy",
            bad.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("bad"));
    assert!(out.stdout.is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

/// `--overlay PATH=-`: stdin stands in for a file, so an editor buffer or
/// a candidate patch is scanned with nothing written to disk.
#[test]
fn overlay_from_stdin_shadows_the_file() {
    use std::io::Write;
    let case = fixture("aws-rds-unencrypted/fail_explicit_false");
    let mut child = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "--no-bundled",
            "--format",
            "json",
            &case,
            "--overlay",
            &format!("{case}/main.tf=-"),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"resource \"aws_db_instance\" \"db\" { storage_encrypted = true }\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["stats"]["findings"], 0);
    assert_eq!(v["stats"]["files"], 1);
    let bad = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args(["scan", "--no-bundled", &case, "--overlay", "nope"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn current_directory_scan_discovers_new_overlay_files_once() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-cwd-overlay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("patch.txt"),
        "resource \"aws_db_instance\" \"db\" { storage_encrypted = false }\n",
    )
    .unwrap();
    for with_disk_root in [false, true] {
        if with_disk_root {
            std::fs::write(
                dir.join("existing.tf"),
                "resource \"aws_db_instance\" \"existing\" { storage_encrypted = true }\n",
            )
            .unwrap();
        }
        for path in [None, Some("."), Some("./"), dir.to_str()] {
            for recursive in [false, true] {
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxtf"));
                cmd.current_dir(&dir)
                    .args(["scan", "--no-bundled", "--format", "json"]);
                if let Some(path) = path {
                    cmd.arg(path);
                }
                if recursive {
                    cmd.arg("--recursive");
                }
                let prefix = path.unwrap_or(".");
                cmd.args(["--overlay", &format!("{prefix}/new.tf=patch.txt")]);
                cmd.args(["--overlay", &format!("{prefix}/nested/new.tf=patch.txt")]);
                let out = cmd.output().unwrap();
                assert_eq!(
                    out.status.code(),
                    Some(1),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                let roots = if recursive { 2 } else { 1 };
                assert_eq!(
                    v["stats"]["roots"], roots,
                    "{path:?}, recursive={recursive}, disk={with_disk_root}: {v}"
                );
                assert_eq!(
                    v["stats"]["resources"],
                    roots + usize::from(with_disk_root),
                    "{v}"
                );
                assert_eq!(v["stats"]["findings"], roots, "{v}");
                assert_eq!(v["stats"]["definite"], roots, "{v}");
                assert_eq!(v["diagnostics"], serde_json::json!([]), "{v}");
                assert_eq!(v["rule_errors"], serde_json::json!([]), "{v}");
            }
        }
    }
    assert!(!dir.join("new.tf").exists());
    assert!(!dir.join("nested").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

/// With no flags a scan runs the bundled Checkov catalog next to the seed
/// rules; its findings carry the upstream check file and the same
/// provenance as a seed rule's.
#[test]
fn default_scan_runs_the_bundled_checkov_catalog() {
    let run = |extra: &[&str]| {
        let case = fixture("aws-rds-unencrypted/fail_explicit_false");
        let mut args = vec!["scan", "--format", "json", case.as_str()];
        args.extend_from_slice(extra);
        let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args(&args)
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                let id = f["rule"].as_str().unwrap().to_string();
                let mut f = f.clone();
                f["rule"] = v["rules"][&id].clone();
                (id, f)
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let all = run(&[]);
    let ckv = &all["CKV_AWS_16"];
    assert_eq!(ckv["rule"]["source"]["engine"], "checkov");
    assert_eq!(
        ckv["rule"]["source"]["file"],
        "checkov/terraform/checks/resource/aws/RDSEncryption.py"
    );
    assert_eq!(ckv["attribute"], "storage_encrypted");
    assert!(all.contains_key("aws-rds-unencrypted"));
    let seed = run(&["--no-bundled"]);
    assert_eq!(seed.keys().collect::<Vec<_>>(), ["aws-rds-unencrypted"]);
    assert!(run(&["--no-builtin"]).is_empty());
    // A rule selection reaches the bundled catalog.
    assert_eq!(
        run(&["--rule", "CKV_AWS_16"]).keys().collect::<Vec<_>>(),
        ["CKV_AWS_16"]
    );
}

#[test]
fn rules_lists_the_bundled_catalog() {
    let count = |extra: &[&str]| {
        let mut args = vec!["rules", "-f", "json"];
        args.extend_from_slice(extra);
        let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args(&args)
            .output()
            .unwrap();
        assert!(out.status.success());
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v.as_array().unwrap().len()
    };
    assert_eq!(count(&["--no-bundled"]), 5);
    // gcp-storage-uniform-access replaces CKV_GCP_29, its alias.
    assert_eq!(count(&[]), 5 + 1079 - 1);
    assert_eq!(count(&["--no-builtin"]), 0);
}

/// Exit codes: 1 when a finding is at least as certain as `--fail-on`
/// (default: definite), 0 otherwise; `never` never fails on findings.
#[test]
fn fail_on_sets_the_exit_code() {
    let code = |case: &str, extra: &[&str]| {
        let case = fixture(case);
        let mut args = vec!["scan", "--no-bundled", "-q", case.as_str()];
        args.extend_from_slice(extra);
        Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args(&args)
            .output()
            .unwrap()
            .status
            .code()
    };
    let definite = "aws-rds-unencrypted/fail_explicit_false";
    let conditional = "aws-rds-unencrypted/conditional_unconstrained_variable";
    assert_eq!(code(definite, &[]), Some(1));
    assert_eq!(code(definite, &["--fail-on", "never"]), Some(0));
    assert_eq!(code(conditional, &[]), Some(0));
    assert_eq!(code(conditional, &["--fail-on", "conditional"]), Some(1));
    assert_eq!(code(conditional, &["--fail-on", "indeterminate"]), Some(1));
    assert_eq!(code(definite, &["--fail-on", "bogus"]), Some(2));
}

#[test]
fn parse_errors_fail_even_when_findings_are_disabled_or_diagnostics_hidden() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "/nonexistent/oxtf-cli-parse",
            "--no-builtin",
            "--overlay",
            "/nonexistent/oxtf-cli-parse/main.tf=-",
            "--fail-on",
            "never",
            "--no-diagnostics",
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"broken = )\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(record["status"], "failed");
    assert_eq!(record["findings"], serde_json::json!([]));
}

/// NDJSON: a line per finding and a closing summary; SARIF: one run whose
/// results carry the record's fingerprints.
#[test]
fn ndjson_and_sarif_formats() {
    let run = |format: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args([
                "scan",
                "--no-bundled",
                "--recursive",
                "--format",
                format,
                &fixture("aws-rds-unencrypted"),
            ])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    let lines: Vec<serde_json::Value> = run("ndjson")
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let (summary, findings) = lines.split_last().unwrap();
    assert_eq!(summary["type"], "summary");
    assert_eq!(summary["findings"], findings.len());
    assert!(findings.iter().all(|f| f["type"] == "finding"));
    let sarif: serde_json::Value = serde_json::from_str(&run("sarif")).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), findings.len());
    for (r, f) in results.iter().zip(findings) {
        assert_eq!(r["partialFingerprints"]["oxtf/v1"], f["fingerprint"]);
    }
}

/// `oxtf fix`: the diff of a verified fix (exit 0), written only with
/// `--write`; exit 2 for an unknown fingerprint or a finding with no fix
/// hint.
#[test]
fn fix_prints_writes_and_refuses() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-fix-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let main = dir.join("main.tf");
    let original = "resource \"aws_instance\" \"web\" {\n  ami = \"ami-123\"\n}\n";
    std::fs::write(&main, original).unwrap();
    let oxtf = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args(args)
            .arg(&dir)
            .args(["--rule", "CKV_AWS_126"])
            .output()
            .unwrap()
    };
    let scan = oxtf(&["scan", "-f", "ndjson"]);
    let first: serde_json::Value = serde_json::from_str(
        String::from_utf8_lossy(&scan.stdout)
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    let fp = first["fingerprint"].as_str().unwrap().to_string();

    let out = oxtf(&["fix", &fp]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let diff = String::from_utf8(out.stdout).unwrap();
    assert!(diff.contains("+  monitoring = true\n"), "{diff}");
    assert_eq!(std::fs::read_to_string(&main).unwrap(), original);

    let out = oxtf(&["fix", &fp, "-f", "json", "--write"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (v["verified"].clone(), v["written"].clone()),
        (true.into(), true.into())
    );
    assert!(
        std::fs::read_to_string(&main)
            .unwrap()
            .contains("monitoring = true")
    );
    assert_eq!(oxtf(&["scan", "-q"]).status.code(), Some(0));

    let out = oxtf(&["fix", "0000000000000000"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no finding has fingerprint"));
    std::fs::remove_dir_all(&dir).unwrap();

    // A finding no edit is known for.
    let case = fixture("aws-s3-public-access-block/fail_missing_block");
    let scan = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args(["scan", "--no-bundled", "-f", "ndjson", &case])
        .output()
        .unwrap();
    let first: serde_json::Value = serde_json::from_str(
        String::from_utf8_lossy(&scan.stdout)
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "fix",
            first["fingerprint"].as_str().unwrap(),
            "--no-bundled",
            &case,
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("has no fix hint"),
        "{out:?}"
    );
}

/// A default scan runs the security profile of the shipped rules; hygiene
/// rules run with `--profile hygiene` or `all`, or when selected.
#[test]
fn profiles_pick_the_shipped_rules() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-profile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        "resource \"aws_instance\" \"web\" {\n  ami = \"ami-123\"\n}\n",
    )
    .unwrap();
    let rules = |extra: &[&str]| -> std::collections::BTreeSet<String> {
        let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args(["scan", "-f", "json", "--fail-on", "never"])
            .arg(&dir)
            .args(extra)
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["rules"].as_object().unwrap().keys().cloned().collect()
    };
    let default = rules(&[]);
    assert!(!default.contains("CKV_AWS_126"), "{default:?}");
    assert!(rules(&["--profile", "hygiene"]).contains("CKV_AWS_126"));
    let all = rules(&["--profile", "all"]);
    assert!(all.contains("CKV_AWS_126") && default.is_subset(&all));
    assert_eq!(
        rules(&["--rule", "CKV_AWS_126"])
            .into_iter()
            .collect::<Vec<_>>(),
        ["CKV_AWS_126"]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn explicit_fetch_enables_offline_counted_module_scans() {
    let base = std::env::temp_dir().join(format!("oxtf-cli-fetch-{}", std::process::id()));
    let package = base.join("package");
    let root = base.join("root");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        package.join("main.tf"),
        "resource \"aws_db_instance\" \"db\" { storage_encrypted = false }\n",
    )
    .unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "fixture",
        ],
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(&package)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    }
    std::fs::write(
        root.join("main.tf"),
        format!(
            "module \"m\" {{\nsource = \"git::file://{}\"\ncount = 2\n}}\n",
            package.display()
        ),
    )
    .unwrap();
    let scan = || {
        Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args(["scan", "--no-bundled", "-f", "json", "--data-dir", ".data"])
            .arg(&root)
            .output()
            .unwrap()
    };
    assert_eq!(scan().status.code(), Some(3));
    let fetched = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .arg("fetch")
        .arg(&root)
        .args(["--data-dir", ".data"])
        .output()
        .unwrap();
    assert!(
        fetched.status.success(),
        "{}",
        String::from_utf8_lossy(&fetched.stderr)
    );
    std::fs::rename(&package, base.join("offline-package")).unwrap();
    let result = scan();
    assert_eq!(result.status.code(), Some(1));
    let record: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(record["status"], "complete");
    assert_eq!(
        record["findings"][0]["occurrences"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        record["findings"][0]["package"]["revision"]
            .as_str()
            .is_some()
    );
    assert!(record["findings"][0]["fix_hint"].is_null());
}

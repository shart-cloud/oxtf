//! `oxtf scan` end-to-end: the W4 exit output (finding + full provenance
//! chain) and the JSON format. These run the seed rules alone
//! (`--no-bundled`); the bundled Checkov catalog has its own tests below.

use std::process::Command;

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
    assert!(out.status.success());
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
        .map(|f| f["severity"].as_str().unwrap())
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
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["stats"]["files"], 2, "{path:?}: {v}");
        assert_eq!(v["findings"].as_array().unwrap().len(), 1, "{path:?}: {v}");
        assert_eq!(v["findings"][0]["severity"], "definite");
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
                    f["resource"]["address"].clone(),
                    f["severity"].clone(),
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
    assert!(out.status.success());
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let f = &j["findings"][0];
    assert_eq!(f["resource"]["address"], "aws_s3_bucket.data");
    assert_eq!(f["severity"], "definite");
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
            &format!("{repo}/fixtures/rego/foreign_sprintf"),
            "--policy",
            &format!("{repo}/fixtures/rego/foreign/conftest_hcl2_deny.rego"),
            "--policy-shape",
            "hcl",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    // Conftest evaluates the whole file, so the error names the file.
    assert!(
        err.contains("foreign_sprintf/main.tf") && err.contains("%q"),
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
            .all(|f| !f["rule"]["id"].as_str().unwrap().starts_with("rego:"))
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
                assert!(
                    out.status.success(),
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
            .map(|f| (f["rule"]["id"].as_str().unwrap().to_string(), f.clone()))
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
    assert_eq!(count(&[]), 5 + 1064 - 1);
    assert_eq!(count(&["--no-builtin"]), 0);
}

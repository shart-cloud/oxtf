//! `oxtf scan` end-to-end: the W4 exit output (finding + full provenance
//! chain) and the JSON format.

use std::process::Command;

fn fixture(p: &str) -> String {
    format!("{}/../../fixtures/rules/{p}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn scan_prints_provenance_chain() {
    let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
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
        let mut args = vec!["scan", "--format", "json", case.as_str()];
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
                    f["address"].clone(),
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
        .args(["scan", ".", "--rule-file", "/nonexistent.json"])
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
    assert_eq!(f["address"], "aws_s3_bucket.data");
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
        .args(["scan", "--plan", &plan, "."])
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

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
    assert_eq!(v["stats"]["roots"], 5);
    let sev: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["severity"].as_str().unwrap())
        .collect();
    assert_eq!(sev.iter().filter(|s| **s == "definite").count(), 3);
    assert_eq!(sev.iter().filter(|s| **s == "conditional").count(), 1);
}

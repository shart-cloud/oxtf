use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn oversized_stdin_is_refused_during_bounded_overlay_read() {
    let config = std::env::temp_dir().join(format!("oxtf-stdin-limit-{}.json", std::process::id()));
    std::fs::write(&config, r#"{"input_bytes":8}"#).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "/nonexistent/oxtf-cli-input",
            "--no-bundled",
            "--limits",
        ])
        .arg(&config)
        .args([
            "--overlay",
            "/nonexistent/oxtf-cli-input/main.tf=-",
            "--fail-on",
            "never",
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
        .write_all(b"locals { x = 1 }")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    std::fs::remove_file(config).unwrap();
    assert_eq!(output.status.code(), Some(3));
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("coverage-storage: input_bytes"),
        "{message}"
    );
    assert!(!message.contains("panicked"));
}

#[test]
fn excessive_depth_is_incomplete_even_when_diagnostics_are_hidden() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "/nonexistent/oxtf-cli-depth",
            "--no-builtin",
            "--no-bundled",
            "--overlay",
            "/nonexistent/oxtf-cli-depth/main.tf=-",
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
    let source = format!("v = {}true\n", "!".repeat(1000));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["status"], "incomplete");
    assert!(
        record["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "coverage-parse-limit")
    );
}

#[test]
fn invalid_workers_are_an_ordinary_cli_error() {
    for count in ["0", "65"] {
        let output = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args(["scan", "/nonexistent", "--threads", count, "--no-bundled"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains("worker count"), "{message}");
        assert!(!message.contains("panicked"), "{message}");
    }
}

#[test]
fn configured_budget_controls_completion_and_fix_verification() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-budget-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("limits.json"), r#"{"evaluation_steps":3}"#).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        "resource \"aws_db_instance\" \"db\" {\n\
        storage_encrypted = false\nallocated_storage = 1 + 2\n}",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "scan",
            "--no-bundled",
            "--format",
            "json",
            "--fail-on",
            "never",
        ])
        .arg(&dir)
        .arg("--limits")
        .arg(dir.join("limits.json"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["status"], "incomplete");
    assert!(
        record["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "coverage-budget")
    );
    let fix = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .args([
            "fix",
            record["findings"][0]["fingerprint"].as_str().unwrap(),
            "--no-bundled",
            "--format",
            "json",
        ])
        .arg(&dir)
        .arg("--limits")
        .arg(dir.join("limits.json"))
        .output()
        .unwrap();
    let fixed: serde_json::Value = serde_json::from_slice(&fix.stdout).unwrap();
    assert_eq!(fixed["verified"], false);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_limits_fail_before_reading_overlays_or_resolving_inputs() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-invalid-budget-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for json in [
        r#"{"evaluation_steps":0}"#,
        r#"{"loader_steps":0}"#,
        r#"{"rule_steps":0}"#,
        r#"{"arena_bytes":0}"#,
        r#"{"ast_nodes":0}"#,
        r#"{"text_bytes":0}"#,
        r#"{"unexpected":3}"#,
    ] {
        std::fs::write(dir.join("limits.json"), json).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args([
                "scan",
                "/nonexistent",
                "--overlay",
                "main.tf=/nonexistent/buffer",
                "--limits",
            ])
            .arg(dir.join("limits.json"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains("invalid limits"), "{message}");
        assert!(
            !message.lines().next().unwrap().contains("--overlay"),
            "{message}"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn loader_budget_is_configurable_and_never_silently_complete() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-loader-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        "variable \"v\" { default = [1, 2, 3] }",
    )
    .unwrap();
    std::fs::write(dir.join("override.tf"), "").unwrap();
    for (allowance, expected_code, expected_status) in [(1, 3, "incomplete"), (1000, 0, "complete")]
    {
        std::fs::write(
            dir.join("limits.json"),
            format!(r#"{{"loader_steps":{allowance}}}"#),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args([
                "scan",
                "--no-bundled",
                "--format",
                "json",
                "--no-diagnostics",
            ])
            .arg(&dir)
            .arg("--limits")
            .arg(dir.join("limits.json"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected_code));
        let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["status"], expected_status);
        if allowance == 1 {
            assert!(
                record["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|d| d["code"] == "coverage-budget"
                        && d["message"].as_str().unwrap().contains("loader_steps"))
            );
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cached_input_conversion_uses_the_runtime_budget() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-input-budget-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        "variable \"value\" {\n type = list(number)\n default = [1,2,3]\n}",
    )
    .unwrap();
    std::fs::write(dir.join("override.tf"), "").unwrap();
    for (allowance, code, status) in [(2, 3, "incomplete"), (1000, 0, "complete")] {
        std::fs::write(
            dir.join("limits.json"),
            format!(r#"{{"evaluation_steps":{allowance}}}"#),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args([
                "scan",
                "--no-bundled",
                "--format",
                "json",
                "--no-diagnostics",
            ])
            .arg(&dir)
            .arg("--limits")
            .arg(dir.join("limits.json"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code));
        let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["status"], status);
        if allowance == 2 {
            assert!(
                record["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|d| d["code"] == "coverage-budget"
                        && d["message"].as_str().unwrap().contains("evaluation_steps"))
            );
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn exhausted_rule_budget_is_failed_even_with_fail_on_never() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-rule-budget-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        "resource \"aws_db_instance\" \"a\" { storage_encrypted = false }\n\
         resource \"aws_db_instance\" \"b\" { storage_encrypted = false }",
    )
    .unwrap();
    for (allowance, code, status) in [(1, 3, "failed"), (2, 0, "complete")] {
        std::fs::write(
            dir.join("limits.json"),
            format!(r#"{{"rule_steps":{allowance}}}"#),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args([
                "scan",
                "--no-bundled",
                "--rule",
                "aws-rds-unencrypted",
                "--format",
                "json",
                "--no-diagnostics",
                "--fail-on",
                "never",
            ])
            .arg(&dir)
            .arg("--limits")
            .arg(dir.join("limits.json"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["status"], status);
        assert_eq!(record["findings"].as_array().unwrap().len(), allowance);
        if allowance == 1 {
            assert_eq!(record["rule_errors"].as_array().unwrap().len(), 1);
            assert!(
                record["rule_errors"][0]["message"]
                    .as_str()
                    .unwrap()
                    .contains("rule_steps")
            );
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn storage_refusal_is_incomplete_even_with_hidden_diagnostics() {
    let dir = std::env::temp_dir().join(format!("oxtf-cli-arena-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        "locals { value = reverse([\"text\", 2, 3]) }",
    )
    .unwrap();
    for field in ["arena_bytes", "ast_nodes", "text_bytes", "collection_bytes"] {
        std::fs::write(dir.join("limits.json"), format!(r#"{{"{field}":1}}"#)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args([
                "scan",
                "--no-bundled",
                "--no-diagnostics",
                "--fail-on",
                "never",
                "--format",
                "json",
            ])
            .arg(&dir)
            .arg("--limits")
            .arg(dir.join("limits.json"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(3),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["status"], "incomplete");
        assert!(
            record["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["code"] == "coverage-storage"
                    && d["message"].as_str().unwrap().contains(field))
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

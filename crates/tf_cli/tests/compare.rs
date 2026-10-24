use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Workspace(PathBuf);
impl Workspace {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("oxtf-compare-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn snapshot(&self, name: &str, source: &str) -> PathBuf {
        std::fs::write(self.0.join("main.tf"), source).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_oxtf"))
            .args([
                "scan",
                "--no-bundled",
                "--rule",
                "aws-rds-unencrypted",
                "-f",
                "json",
            ])
            .arg(&self.0)
            .output()
            .unwrap();
        assert!(matches!(out.status.code(), Some(0 | 1 | 3 | 4)), "{out:?}");
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap();
        let path = self.0.join(format!("{name}.json"));
        std::fs::write(&path, out.stdout).unwrap();
        path
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn compare(before: &Path, after: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .arg("compare")
        .arg(before)
        .arg(after)
        .args(args)
        .output()
        .unwrap()
}
const BAD: &str = "resource \"aws_db_instance\" \"db\" { storage_encrypted = false }";
const GOOD: &str = "resource \"aws_db_instance\" \"db\" { storage_encrypted = true }";

#[test]
fn saved_scans_compare_fixes_regressions_and_failed_analysis() {
    let w = Workspace::new("workflow");
    let before = w.snapshot("before", BAD);
    let after = w.snapshot("after", GOOD);
    let fixed = compare(&before, &after, &[]);
    assert_eq!(fixed.status.code(), Some(0), "{fixed:?}");
    let json: serde_json::Value = serde_json::from_slice(&fixed.stdout).unwrap();
    assert_eq!(json["comparable"], true);
    assert_eq!(json["resolved"].as_array().unwrap().len(), 1);
    let regressed = compare(&after, &before, &["-f", "text"]);
    assert_eq!(regressed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&regressed.stdout).contains("1 added"));
    let failed = w.snapshot("failed", "broken = )");
    let diff = compare(&before, &failed, &[]);
    assert_eq!(diff.status.code(), Some(4));
    let json: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    assert_eq!(json["comparable"], false);
    assert_eq!(json["resolved"], serde_json::json!([]));
    assert_eq!(json["unverified_removed"].as_array().unwrap().len(), 1);
}

#[test]
fn old_records_remain_readable_but_cannot_verify_resolution() {
    let w = Workspace::new("legacy");
    let before = w.snapshot("before", BAD);
    let after = w.snapshot("after", GOOD);
    let mut old: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&before).unwrap()).unwrap();
    old.as_object_mut().unwrap().remove("coverage");
    old.as_object_mut().unwrap().remove("input_kind");
    for root in old["roots"].as_array_mut().unwrap() {
        root.as_object_mut().unwrap().remove("coverage");
    }
    std::fs::write(&before, old.to_string()).unwrap();
    let out = compare(&before, &after, &[]);
    assert_eq!(out.status.code(), Some(4), "{out:?}");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        json["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i.as_str().unwrap().contains("lacks rule coverage"))
    );
}

#[test]
fn bad_snapshots_and_inconsistent_accounting_are_input_errors() {
    let w = Workspace::new("invalid");
    let before = w.snapshot("before", BAD);
    let after = w.snapshot("after", GOOD);
    let valid: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&before).unwrap()).unwrap();
    let mut wrong_schema = valid.clone();
    wrong_schema["schema"] = 999.into();
    let mut wrong_counts = valid.clone();
    wrong_counts["coverage"]["rules"]["aws-rds-unencrypted"]["executed"] = 99.into();
    let mut duplicate = valid.clone();
    duplicate["findings"]
        .as_array_mut()
        .unwrap()
        .push(valid["findings"][0].clone());
    for json in [wrong_schema, wrong_counts, duplicate] {
        std::fs::write(&before, json.to_string()).unwrap();
        let out = compare(&before, &after, &[]);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        assert!(out.stdout.is_empty());
    }
    std::fs::write(&before, "not json").unwrap();
    assert_eq!(compare(&before, &after, &[]).status.code(), Some(2));
    assert_eq!(
        compare(&after, &after, &["--unknown"]).status.code(),
        Some(2)
    );
}

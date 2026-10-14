//! Stable native output before adding foreign rule engines.
//! Regenerate explicitly with OXTF_UPDATE_BASELINE=1 cargo test -p tf_cli --test native_baseline.
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    paths
}

fn normalize(value: &mut Value, repo: &str) {
    match value {
        Value::String(s) => *s = s.replace(&format!("{repo}/"), ""),
        Value::Array(values) => values.iter_mut().for_each(|v| normalize(v, repo)),
        Value::Object(values) => values.values_mut().for_each(|v| normalize(v, repo)),
        _ => {}
    }
}

fn scan(repo: &Path, args: &[String]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_oxtf"))
        .current_dir(repo)
        .args(["scan", "--format", "json", "--threads", "1"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "{args:?}: unexpected stderr");
    let mut result: Value = serde_json::from_slice(&output.stdout).unwrap();
    // Runtime and absolute checkout location are not semantic output.
    result["stats"]
        .as_object_mut()
        .unwrap()
        .remove("elapsed_ms")
        .unwrap();
    normalize(&mut result, repo.to_str().unwrap());
    // Preserve duplicates; order between independent findings is immaterial.
    for key in ["findings", "diagnostics"] {
        result[key]
            .as_array_mut()
            .unwrap()
            .sort_by_key(Value::to_string);
    }
    result
}

#[test]
fn native_findings_match_baseline() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut cases = serde_json::Map::new();
    for rule in entries(&repo.join("fixtures/rules")) {
        if !rule.is_dir() {
            continue;
        }
        for case in entries(&rule) {
            if !case.is_dir() {
                continue;
            }
            assert!(case.join("EXPECT").is_file());
            let path = case.strip_prefix(&repo).unwrap().to_str().unwrap();
            cases.insert(format!("source:{path}"), scan(&repo, &[path.into()]));
        }
    }
    assert_eq!(
        cases.len(),
        34,
        "seed fixture inventory changed; review the baseline coverage"
    );
    let mut plans = 0;
    for rule in entries(&repo.join("fixtures/plans")) {
        if !rule.is_dir() {
            continue;
        }
        for plan in entries(&rule) {
            if plan.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let path = plan.strip_prefix(&repo).unwrap().to_str().unwrap();
            let stem = plan
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .split("__")
                .next()
                .unwrap();
            let source = format!(
                "fixtures/rules/{}/{stem}",
                rule.file_name().unwrap().to_str().unwrap()
            );
            assert!(repo.join(&source).is_dir());
            cases.insert(
                format!("plan:{path}"),
                scan(
                    &repo,
                    &["--plan".into(), path.into(), "--source".into(), source],
                ),
            );
            plans += 1;
        }
    }
    assert_eq!(
        plans, 34,
        "plan inventory changed; review the baseline coverage"
    );
    for case in entries(&repo.join("fixtures/baseline")) {
        if !case.is_dir() {
            continue;
        }
        let path = case.strip_prefix(&repo).unwrap().to_str().unwrap();
        let result = scan(&repo, &[path.into()]);
        let expected = if case.ends_with("transformed") {
            vec!["aws_s3_bucket.b[\"a\"]", "aws_s3_bucket.b[\"b\"]"]
        } else {
            vec!["aws_s3_bucket.b[\"b\"]"]
        };
        let addresses: Vec<_> = result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["address"].as_str().unwrap())
            .collect();
        assert_eq!(addresses, expected, "{path}");
        assert_eq!(result["diagnostics"], json!([]));
        cases.insert(format!("source:{path}"), result);
        if case.join("plan.json").is_file() {
            let plan_path = format!("{path}/plan.json");
            let result = scan(
                &repo,
                &[
                    "--plan".into(),
                    plan_path.clone(),
                    "--source".into(),
                    path.into(),
                ],
            );
            let addresses: Vec<_> = result["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["address"].as_str().unwrap())
                .collect();
            assert_eq!(addresses, expected, "{plan_path}");
            cases.insert(format!("plan:{plan_path}"), result);
        }
    }
    assert_eq!(cases.len(), 74);
    let actual = json!({"version": 1, "backend": "native", "cases": cases});
    let baseline = repo.join("fixtures/baseline/native.json");
    if std::env::var("OXTF_UPDATE_BASELINE").as_deref() == Ok("1") {
        std::fs::write(
            &baseline,
            format!("{}\n", serde_json::to_string_pretty(&actual).unwrap()),
        )
        .unwrap();
    }
    let expected: Value = serde_json::from_slice(
        &std::fs::read(&baseline)
            .expect("baseline missing; regenerate explicitly with OXTF_UPDATE_BASELINE=1"),
    )
    .unwrap();
    assert_eq!(actual["version"], expected["version"]);
    assert_eq!(actual["backend"], expected["backend"]);
    let expected = expected["cases"].as_object().unwrap();
    let actual = actual["cases"].as_object().unwrap();
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (case, result) in actual {
        assert_eq!(
            result, &expected[case],
            "native baseline changed for {case}; review semantics before regenerating"
        );
    }
}

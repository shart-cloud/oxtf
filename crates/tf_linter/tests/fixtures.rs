//! Walks fixtures/rules/<rule>/<case>/, scans each case directory, and
//! compares the (rule, address, severity) set for the rule under test with
//! the case's EXPECT file.

use std::collections::BTreeSet;
use std::path::Path;

use tf_linter::{ScanOptions, scan_dir};

#[test]
fn seed_rule_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rules");
    let mut rules: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    rules.sort();
    let mut cases = 0;
    let mut failures = Vec::new();
    let mut table = Vec::new();
    for rule_dir in rules {
        let rule = rule_dir.file_name().unwrap().to_string_lossy().to_string();
        let mut case_dirs: Vec<_> = std::fs::read_dir(&rule_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        case_dirs.sort();
        for case in case_dirs {
            cases += 1;
            let expect_text = std::fs::read_to_string(case.join("EXPECT")).unwrap();
            let expected: BTreeSet<(String, String, String)> = expect_text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| {
                    let p: Vec<&str> = l.split_whitespace().collect();
                    assert_eq!(p.len(), 3, "bad EXPECT line {l:?} in {}", case.display());
                    (p[0].to_string(), p[1].to_string(), p[2].to_string())
                })
                .collect();
            let r = scan_dir(&case, &ScanOptions::default()).unwrap();
            let errors: Vec<_> = r
                .diagnostics
                .iter()
                .filter(|d| d.severity == tf_semantic::DiagSeverity::Error)
                .collect();
            assert!(errors.is_empty(), "{}: {errors:?}", case.display());
            let got: BTreeSet<(String, String, String)> = r
                .findings
                .iter()
                .filter(|f| *f.rule == *rule)
                .map(|f| {
                    (
                        f.rule.to_string(),
                        f.address.to_string(),
                        f.severity.as_str().to_string(),
                    )
                })
                .collect();
            let ok = got == expected;
            let case_name = case.file_name().unwrap().to_string_lossy().to_string();
            table.push(format!(
                "| {rule} | {case_name} | {} | {} | {} |",
                if expected.is_empty() {
                    "none".to_string()
                } else {
                    expected
                        .iter()
                        .map(|e| format!("{} {}", e.1, e.2))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                if got.is_empty() {
                    "none".to_string()
                } else {
                    got.iter()
                        .map(|e| format!("{} {}", e.1, e.2))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                if ok { "pass" } else { "FAIL" }
            ));
            if !ok {
                failures.push(format!(
                    "{}: expected {expected:?}, got {got:?}",
                    case.display()
                ));
            }
        }
    }
    println!(
        "| rule | case | expected | got | result |\n|---|---|---|---|---|\n{}",
        table.join("\n")
    );
    println!("{} cases, {} failures", cases, failures.len());
    // 29 original cases + 2 added in W4 (aws_iam_policy_document data source)
    // + 3 added after the independent review (GCP variable and conditional,
    // IAM dynamic statement in a policy document) + 1 for count with a
    // tainted alternative (added before the lattice unification).
    assert_eq!(cases, 35, "expected 34 fixture cases");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

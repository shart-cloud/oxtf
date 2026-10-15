//! W5 exit test: the five seed rules on plan JSON.
//!
//! For every committed plan `fixtures/plans/<rule>/<case>[__<variant>].json`
//! (generated from `fixtures/rules/<rule>/<case>/` by
//! `fixtures/plans/generate.sh`), scan the plan with the source directory as
//! the span index and compare (rule, address, severity) for the rule under
//! test with the source scan of the same case:
//!
//! - ordinary cases: plan findings == source findings == EXPECT;
//! - `conditional_*__fail` (planned with an insecure `-var`): the source's
//!   conditional finding, now `definite`;
//! - `conditional_*__pass` (planned with a secure `-var`): no finding.
//!
//! Every finding's primary location and every provenance step must point
//! into a `.tf` file of the case's source directory (not the plan JSON).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use tf_linter::{Linter, ScanOptions, scan_dir};
use tf_plan::{PlanOptions, scan_plan};

type Row = (String, String, String);

fn rows(r: &tf_linter::ScanResult, rule: &str) -> BTreeSet<Row> {
    r.findings
        .iter()
        .filter(|f| *f.rule == *rule)
        .map(|f| {
            (
                f.rule.to_string(),
                f.address.to_string(),
                f.severity.as_str().to_string(),
            )
        })
        .collect()
}

fn fmt(s: &BTreeSet<Row>) -> String {
    if s.is_empty() {
        return "none".into();
    }
    s.iter()
        .map(|e| format!("{} {}", e.1, e.2))
        .collect::<Vec<_>>()
        .join(", ")
}

fn expect_rows(case: &Path) -> BTreeSet<Row> {
    std::fs::read_to_string(case.join("EXPECT"))
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            (p[0].to_string(), p[1].to_string(), p[2].to_string())
        })
        .collect()
}

#[test]
fn plan_fixtures_match_source() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let plans_root = repo.join("fixtures/plans");
    let linter = Linter::with_seed_rules();
    let mut plans: Vec<PathBuf> = Vec::new();
    for rd in std::fs::read_dir(&plans_root)
        .unwrap()
        .filter_map(|e| e.ok())
    {
        if rd.path().is_dir() {
            for f in std::fs::read_dir(rd.path()).unwrap().filter_map(|e| e.ok()) {
                if f.path().extension().is_some_and(|x| x == "json") {
                    plans.push(f.path());
                }
            }
        }
    }
    plans.sort();
    let mut table = Vec::new();
    let mut failures = Vec::new();
    for plan in &plans {
        let rule = plan
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let stem = plan.file_stem().unwrap().to_string_lossy().to_string();
        let (case, variant) = match stem.split_once("__") {
            Some((c, v)) => (c.to_string(), Some(v.to_string())),
            None => (stem.clone(), None),
        };
        let case_dir = repo.join("fixtures/rules").join(&rule).join(&case);
        let src = scan_dir(&case_dir, &ScanOptions::default());
        let src_rows = rows(&src, &rule);
        assert_eq!(src_rows, expect_rows(&case_dir), "source scan of {case}");
        let expected: BTreeSet<Row> = match variant.as_deref() {
            None => src_rows.clone(),
            Some("fail") => src_rows
                .iter()
                .map(|(r, a, _)| (r.clone(), a.clone(), "definite".to_string()))
                .collect(),
            Some("pass") => BTreeSet::new(),
            Some(v) => panic!("unknown variant {v}"),
        };
        let r = scan_plan(
            &linter,
            plan,
            &PlanOptions {
                source: Some(case_dir.clone()),
            },
        )
        .unwrap_or_else(|e| panic!("{}: {e}", plan.display()));
        let got = rows(&r, &rule);
        let mut ok = got == expected;
        let errors: Vec<_> = r
            .diagnostics
            .iter()
            .filter(|d| d.severity == tf_semantic::DiagSeverity::Error || d.code == "plan-unmapped")
            .collect();
        if !errors.is_empty() {
            failures.push(format!("{}: diagnostics {errors:?}", plan.display()));
            ok = false;
        }
        // Spans: primary and every provenance step in a .tf file of the case.
        for f in &r.findings {
            let mut spans = vec![f.primary];
            spans.extend(f.provenance.iter().map(|s| s.at));
            for s in spans {
                let file = r.files.get(s.file);
                let in_case = file.path.extension().is_some_and(|x| x == "tf")
                    && file
                        .path
                        .starts_with(tf_semantic::source::normalize(&case_dir));
                if !in_case {
                    ok = false;
                    failures.push(format!(
                        "{}: {} span in {}",
                        plan.display(),
                        f.address,
                        file.path.display()
                    ));
                }
            }
        }
        let primary = r
            .findings
            .iter()
            .filter(|f| *f.rule == *rule)
            .map(|f| {
                let loc = tf_semantic::source::normalize(&case_dir);
                let p = r.files.location(f.primary);
                p.strip_prefix(&format!("{}/", loc.display()))
                    .unwrap_or(&p)
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(", ");
        table.push(format!(
            "| {rule} | {stem} | {} | {} | {} | {} |",
            fmt(&src_rows),
            fmt(&got),
            if primary.is_empty() {
                "-".into()
            } else {
                primary
            },
            if ok { "pass" } else { "FAIL" }
        ));
        if variant.is_none() {
            let msgs = |r: &tf_linter::ScanResult| -> BTreeSet<(String, String)> {
                r.findings
                    .iter()
                    .filter(|f| *f.rule == *rule)
                    .map(|f| (f.address.to_string(), f.message.clone()))
                    .collect()
            };
            // Known, intended difference: the plan carries the provider's
            // planned value for an attribute left unset, where the source
            // scan falls back to the defaults overlay.
            let allowed = ["aws-s3-public-access-block/fail_block_attrs_absent_default_false"];
            if msgs(&src) != msgs(&r) && !allowed.contains(&format!("{rule}/{stem}").as_str()) {
                ok = false;
                failures.push(format!(
                    "{}: messages differ: source {:?} plan {:?}",
                    plan.display(),
                    msgs(&src),
                    msgs(&r)
                ));
            }
        }
        if got != expected {
            failures.push(format!(
                "{}: expected {expected:?}, got {got:?}",
                plan.display()
            ));
        }
    }
    println!(
        "| rule | plan | source findings | plan findings | plan primary location | result |\n|---|---|---|---|---|---|\n{}",
        table.join("\n")
    );
    println!("{} plans, {} failures", plans.len(), failures.len());
    // The 31 rule fixture cases that existed in W5; the 3 conditional_* cases
    // are planned twice. The 3 cases added after the review are source-only.
    assert_eq!(plans.len(), 34, "expected 34 plan fixtures");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Without a source directory, findings still come out, located in the plan
/// JSON (and an info diagnostic says the resource was not mapped).
#[test]
fn plan_without_source_points_into_plan_json() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let plan =
        repo.join("fixtures/plans/aws-s3-public-access-block/fail_block_for_other_bucket.json");
    let r = scan_plan(&Linter::with_seed_rules(), &plan, &PlanOptions::default()).unwrap();
    let addrs: Vec<&str> = r.findings.iter().map(|f| &*f.address).collect();
    assert_eq!(addrs, ["aws_s3_bucket.b"]);
    let f = &r.findings[0];
    let file = r.files.get(f.primary.file);
    assert!(file.path.ends_with("fail_block_for_other_bucket.json"));
    assert_eq!(
        f.primary.span.source_text(&file.text),
        "\"address\": \"aws_s3_bucket.b\""
    );
    assert!(r.diagnostics.iter().any(|d| d.code == "plan-unmapped"));
}

/// Plan-only case: local child module with `for_each`, `count`, a sensitive
/// variable. The source directory is found next to the plan (no
/// `PlanOptions::source`).
#[test]
fn plan_case_module_count_sensitive() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let case = repo.join("fixtures/plan_cases/module_count_sensitive");
    let plan = case.join("plan.json");
    let r = scan_plan(&Linter::with_seed_rules(), &plan, &PlanOptions::default()).unwrap();
    let got: BTreeSet<Row> = r
        .findings
        .iter()
        .map(|f| {
            (
                f.rule.to_string(),
                f.address.to_string(),
                f.severity.as_str().to_string(),
            )
        })
        .collect();
    assert_eq!(got, expect_rows(&case));
    assert!(
        !r.diagnostics.iter().any(|d| d.code == "plan-unmapped"),
        "{:?}",
        r.diagnostics
    );
    // Child-module findings point into the child module's file.
    for f in r
        .findings
        .iter()
        .filter(|f| f.module.starts_with("module.store"))
    {
        let file = r.files.get(f.primary.file);
        assert!(
            file.path.ends_with("modules/store/main.tf"),
            "{} -> {}",
            f.address,
            file.path.display()
        );
    }

    // The model: join origin from configuration references, sensitive label.
    let files = tf_semantic::FileTable::new();
    let a = tf_plan::load_plan(&plan, &PlanOptions::default(), &files).unwrap();
    let store = a
        .modules
        .iter()
        .find(|m| &*m.address == "module.store")
        .unwrap();
    let pab = store
        .resources
        .iter()
        .find(|r| &*r.address == "module.store.aws_s3_bucket_public_access_block.b[\"a\"]")
        .unwrap();
    match pab.value("bucket").unwrap().origin() {
        Some(tf_eval::Origin::Computed {
            resource,
            key,
            attr,
        }) => {
            assert_eq!(&**resource, "module.store.aws_s3_bucket.b");
            // Plan JSON records `aws_s3_bucket.b[each.key].id` as
            // ["aws_s3_bucket.b", "each.key"]; attribute and key come from
            // the source model of the same instance.
            assert_eq!(key.as_deref(), Some("a"));
            assert_eq!(&**attr, "id");
        }
        other => panic!("{other:?}"),
    }
    let db = a.modules[0]
        .resources
        .iter()
        .find(|r| &*r.address == "aws_db_instance.db")
        .unwrap();
    let pw = db.value("password").unwrap();
    let labels: Vec<String> = pw
        .prov
        .steps()
        .iter()
        .map(|s| s.label.to_string())
        .collect();
    assert!(
        labels.iter().any(|l| l.ends_with("password (sensitive)")),
        "{labels:?}"
    );
    assert!(
        !labels.iter().any(|l| l.contains("not-a-real-password")),
        "{labels:?}"
    );
    // Computed-only attributes not set in configuration are absent, as in
    // the HCL model.
    assert!(db.value("arn").is_none());
}

/// Synthetic plan adapter coverage: dependencies listed in configuration are
/// explanation metadata, not proof that the resulting value names a resource.
#[test]
fn known_plan_names_do_not_join_via_dependency_provenance() {
    use serde_json::json;
    let dir = std::env::temp_dir().join(format!("oxtf-plan-identity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, expected) in [
        ("example-a", vec!["aws_s3_bucket.b[\"b\"]"]),
        (
            "example-a-other",
            vec!["aws_s3_bucket.b[\"a\"]", "aws_s3_bucket.b[\"b\"]"],
        ),
    ] {
        let mut resources = Vec::new();
        for key in ["a", "b"] {
            resources.push(json!({"address": format!("aws_s3_bucket.b[\"{key}\"]"),
                "mode":"managed", "type":"aws_s3_bucket", "name":"b", "index":key,
                "values":{"bucket":format!("example-{key}")}}));
        }
        resources.push(json!({"address":"aws_s3_bucket_public_access_block.p",
            "mode":"managed", "type":"aws_s3_bucket_public_access_block", "name":"p",
            "values":{"bucket":name,"block_public_acls":true,"block_public_policy":true,
                "ignore_public_acls":true,"restrict_public_buckets":true}}));
        let changes: Vec<_> = resources
            .iter()
            .map(|r| {
                let mut change = r.clone();
                change["change"] = json!({"actions":["create"], "after":r["values"]});
                change
            })
            .collect();
        let plan = json!({"format_version":"1.2",
        "resource_changes":changes,
        "planned_values":{"root_module":{"resources":resources}},
        "configuration":{"root_module":{"resources":[{
            "address":"aws_s3_bucket_public_access_block.p",
            "expressions":{"bucket":{"references":["aws_s3_bucket.b[\"a\"].bucket", "aws_s3_bucket.b"]}}
        }]}}});
        let path = dir.join("plan.json");
        std::fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
        let result = scan_plan(&Linter::with_seed_rules(), &path, &PlanOptions::default()).unwrap();
        let got: Vec<_> = result.findings.iter().map(|f| f.address.as_ref()).collect();
        assert_eq!(got, expected, "{name}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

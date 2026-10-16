//! The native Checkov policy front-end against the Python importer.
//!
//! `pinned_catalog_matches_python_importer` needs a Checkov 3.2.328 install
//! and a pack exported from it by `scripts/import_checkov.py`:
//!
//! ```sh
//! CHECKOV_GRAPH_CHECKS=.../site-packages/checkov/terraform/checks/graph_checks \
//! CHECKOV_PACK=bench/results/out/checkov-3.2.328 \
//!   cargo test -p tf_rule_ir --test checkov_policy -- --include-ignored
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value as Json, json};
use tf_rule_ir::checkov_policy::{self, Blocker, PolicySource};
use tf_rule_ir::{Expr, RuleSpec, load_rules_file};

fn translate_yaml(text: &str) -> Result<RuleSpec, String> {
    let path = Path::new("policy.yaml");
    let source = PolicySource::parse(path, text)?;
    checkov_policy::translate_source(path, &source)
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

#[test]
#[ignore = "needs CHECKOV_GRAPH_CHECKS and CHECKOV_PACK"]
fn pinned_catalog_matches_python_importer() {
    let (Ok(checks), Ok(pack)) = (
        std::env::var("CHECKOV_GRAPH_CHECKS"),
        std::env::var("CHECKOV_PACK"),
    ) else {
        panic!("set CHECKOV_GRAPH_CHECKS and CHECKOV_PACK");
    };
    let pack = Path::new(&pack);
    let golden: Vec<RuleSpec> =
        serde_json::from_str(&std::fs::read_to_string(pack.join("rules.json")).unwrap()).unwrap();
    let golden: BTreeMap<_, _> = golden.into_iter().map(|r| (r.name.clone(), r)).collect();
    let manifest: Json =
        serde_json::from_str(&std::fs::read_to_string(pack.join("manifest.json")).unwrap())
            .unwrap();
    let unsupported: BTreeMap<&str, &Json> = manifest["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "graph" && c["status"] == "unsupported")
        .map(|c| (c["id"].as_str().unwrap(), &c["blockers"]))
        .collect();

    let mut paths = Vec::new();
    files(Path::new(&checks), &mut paths);
    let (mut translated, mut rejected) = (0, 0);
    for path in paths {
        let text = std::fs::read_to_string(&path).unwrap();
        let source = PolicySource::parse(&path, &text).unwrap();
        let id = source.value["metadata"]["id"].as_str().unwrap().to_string();
        match checkov_policy::translate(&source.value) {
            Ok(rule) => {
                translated += 1;
                let expected = &golden[&id];
                let graph: Vec<_> = expected
                    .clauses
                    .iter()
                    .filter(|c| matches!(c.condition, Expr::CheckovGraph { .. }))
                    .cloned()
                    .collect();
                assert_eq!(rule.clauses, graph, "{id}: clauses differ");
                if graph.len() == expected.clauses.len() {
                    // Not merged with a value check of the same ID.
                    assert_eq!(&rule, expected, "{id}: rule differs");
                }
            }
            Err(blockers) => {
                rejected += 1;
                let expected = unsupported
                    .get(id.as_str())
                    .unwrap_or_else(|| panic!("{id}: unexpectedly rejected: {blockers:?}"));
                let ours: Vec<Json> = blockers
                    .iter()
                    .map(|b: &Blocker| json!({"path": b.path, "code": b.code, "reason": b.reason}))
                    .collect();
                assert_eq!(&Json::Array(ours), *expected, "{id}: blockers differ");
            }
        }
    }
    assert_eq!((translated, rejected), (184, 2));
}

#[test]
fn custom_yaml_policy() {
    let rule = translate_yaml(
        r#"
metadata:
  id: CKV2_CUSTOM_1
  name: "Buckets have {versioning}"
  category: GENERAL_SECURITY
  severity: high
scope:
  provider: aws
definition:
  and:
    - cond_type: attribute
      resource_types: aws_s3_bucket
      attribute: versioning.enabled
      operator: equals
      value: on            # PyYAML: a boolean
    - cond_type: connection
      resource_types: [aws_s3_bucket]
      connected_resource_types: [aws_s3_bucket_public_access_block]
      operator: exists
    - cond_type: attribute
      resource_types: aws_s3_bucket
      attribute: lifecycle_rule
      operator: length_greater_than
      value: "1_0"         # Python int(): 10
"#,
    )
    .unwrap();
    let expected: RuleSpec = serde_json::from_value(json!({
        "version": 3, "name": "CKV2_CUSTOM_1", "description": "Buckets have {versioning}",
        "message": "Buckets have {{versioning}}", "category": "other", "level": "high",
        "clauses": [{
            "resource_types": ["aws_s3_bucket", "aws_s3_bucket_public_access_block"],
            "condition": {"op": "checkov_graph", "definition": {"kind": "and", "args": [
                {"kind": "attribute", "resource_types": ["aws_s3_bucket"],
                 "check": {"attribute": "versioning.enabled", "operator": "equals", "value": true}},
                {"kind": "connection", "resource_types": ["aws_s3_bucket"],
                 "connected_resource_types": ["aws_s3_bucket_public_access_block"], "operator": "exists"},
                {"kind": "attribute", "resource_types": ["aws_s3_bucket"],
                 "check": {"attribute": "lifecycle_rule", "operator": "length_greater_than", "value": 10}},
            ]}},
        }],
    }))
    .unwrap();
    assert_eq!(rule, expected);
}

#[test]
fn unsupported_policies_fail_with_positions() {
    let err = translate_yaml(
        "metadata:\n  id: X\n  name: n\n  category: c\ndefinition:\n  cond_type: attribute\n  resource_types: all\n  attribute: tags\n  operator: regex_match\n  value: x\n",
    )
    .unwrap_err();
    assert_eq!(
        err,
        "policy.yaml:9:13: X: unsupported graph operator: regex_match [attribute_operator] at /definition/operator\n\
         policy.yaml:7:19: X: graph resource type `all` expands from Checkov's provider table, which is not supported [resource_selector] at /definition/resource_types"
    );
    let err = translate_yaml("metadata:\n  id: X\n  name: n\ndefinition: {}\n").unwrap_err();
    assert!(err.contains("requires metadata.category"), "{err}");
}

#[test]
fn rule_files_detect_format_and_walk_directories() {
    let dir = std::env::temp_dir().join(format!("oxtf-checkov-policy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    let policy = |id: &str| {
        format!(
            "metadata: {{id: {id}, name: n, category: c}}\ndefinition: {{cond_type: attribute, resource_types: [aws_s3_bucket], attribute: acl, operator: equals, value: private}}\n"
        )
    };
    std::fs::write(dir.join("a.yaml"), policy("CKV2_A")).unwrap();
    std::fs::write(dir.join("nested/b.yml"), policy("CKV2_B")).unwrap();
    std::fs::write(
        dir.join("c.json"),
        r#"{"metadata": {"id": "CKV2_C", "name": "n", "category": "c"}, "definition": {"cond_type": "attribute", "resource_types": "aws_s3_bucket", "attribute": "acl", "operator": "exists"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("ir.json"),
        r#"{"name": "ir-rule", "message": "m", "clauses": [{"resource_types": ["aws_s3_bucket"], "condition": {"op": "lit", "value": true}}]}"#,
    )
    .unwrap();
    std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
    let loaded = load_rules_file(&dir).unwrap();
    let mut names: Vec<_> = loaded.rules.into_iter().map(|r| r.name).collect();
    names.sort();
    assert_eq!(names, ["CKV2_A", "CKV2_B", "CKV2_C", "ir-rule"]);
    assert!(loaded.skipped.is_empty());

    // Bad files in a directory are skipped, one report per file; a later
    // duplicate loses to the first definition, as in Checkov.
    std::fs::write(dir.join("dup.yaml"), policy("CKV2_A")).unwrap();
    std::fs::write(dir.join("bad.yaml"), "metadata: [\n").unwrap();
    std::fs::write(
        dir.join("regex.yaml"),
        "metadata: {id: CKV2_RE, name: n, category: c}\ndefinition: {cond_type: attribute, resource_types: [x], attribute: a, operator: regex_match, value: v}\n",
    )
    .unwrap();
    let loaded = load_rules_file(&dir).unwrap();
    assert_eq!(loaded.rules.len(), 4);
    let skipped: Vec<_> = loaded
        .skipped
        .iter()
        .map(|s| {
            (
                s.path.file_name().unwrap().to_str().unwrap(),
                s.reason.as_str(),
            )
        })
        .collect();
    assert_eq!(skipped.len(), 3, "{skipped:#?}");
    assert_eq!(skipped[0].0, "bad.yaml");
    assert_eq!(skipped[1].0, "dup.yaml");
    assert!(
        skipped[1].1.contains("rule CKV2_A is already defined in"),
        "{}",
        skipped[1].1
    );
    assert_eq!(skipped[2].0, "regex.yaml");
    assert!(skipped[2].1.contains("regex.yaml:2:"), "{}", skipped[2].1);

    // A file named directly still fails.
    assert!(load_rules_file(&dir.join("regex.yaml")).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

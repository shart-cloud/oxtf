//! The bundled Checkov catalog (`data/checkov/`).
//!
//! `bundled_catalog_is_current` regenerates it from a Checkov 3.2.328
//! install and fails on any difference, so the embedded IR cannot drift
//! from what the front-ends produce today:
//!
//! ```sh
//! "$CHECKOV_PYTHON" -I scripts/import_checkov.py --output /tmp/pack
//! CHECKOV_PACK=/tmp/pack \
//! CHECKOV_GRAPH_CHECKS=.../site-packages/checkov/terraform/checks/graph_checks \
//!   cargo test -p tf_rule_ir --test bundled -- --include-ignored
//! ```

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value as Json;
use tf_rule_ir::bundled;

fn manifest() -> Json {
    serde_json::from_str(bundled::CHECKOV_MANIFEST_JSON).unwrap()
}

#[test]
fn bundled_catalog_compiles_and_matches_its_manifest() {
    let specs = bundled::checkov().unwrap();
    let manifest = manifest();
    assert_eq!(manifest["source_version"], bundled::CHECKOV_VERSION);
    assert_eq!(manifest["rules"], specs.len());

    let names: BTreeSet<String> = specs.iter().map(|s| s.name.clone()).collect();
    assert_eq!(names.len(), specs.len(), "duplicate rule names");
    for spec in &specs {
        let file = spec.origin.0.file.as_ref().unwrap().to_string_lossy();
        assert!(file.starts_with("checkov/terraform/checks/"), "{file}");
        assert_eq!(spec.origin.0.engine, tf_linter::Engine::Checkov);
    }
    // Every translated check is a rule, and every rule is a translated check.
    let translated: BTreeSet<String> = manifest["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["status"] == "translated")
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(translated, names);
    for c in manifest["checks"].as_array().unwrap() {
        if c["status"] == "unsupported" {
            assert!(c["reason"].as_str().is_some_and(|r| !r.is_empty()), "{c}");
        }
    }

    let compiled = specs
        .into_iter()
        .map(tf_rule_ir::compile)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(compiled.len(), names.len());
}

/// The lazy rules a scan uses report, before compiling, what their
/// compiled rules would.
#[test]
fn lazy_rules_match_their_compiled_rules() {
    use tf_linter::DynRule;

    let lazy = bundled::rules().unwrap();
    let specs = bundled::checkov().unwrap();
    assert_eq!(lazy.len(), specs.len());
    for (lazy, spec) in lazy.iter().zip(specs) {
        let compiled = tf_rule_ir::compile(spec).unwrap();
        let (l, c) = (lazy.info(), compiled.info());
        assert_eq!(l.name, c.name);
        assert_eq!(l.category, c.category, "{}", c.name);
        assert_eq!(l.level, c.level, "{}", c.name);
        assert_eq!(l.description, c.description, "{}", c.name);
        assert_eq!(l.resource_types, c.resource_types, "{}", c.name);
        assert_eq!(l.runs_on_module, c.runs_on_module, "{}", c.name);
        assert_eq!(l.guideline, c.guideline, "{}", c.name);
        assert_eq!(l.rationale, c.rationale, "{}", c.name);
        assert_eq!(l.remediation, c.remediation, "{}", c.name);
        assert_eq!(l.source, c.source, "{}", c.name);
        assert_eq!(lazy.needs_graph(), compiled.needs_graph(), "{}", c.name);
        assert_eq!(lazy.needs_files(), compiled.needs_files(), "{}", c.name);
    }
}

#[test]
fn curation_changes_metadata_without_expanding_or_rewriting_predicates() {
    let raw: bundled::Bundle = serde_json::from_str(bundled::CHECKOV_RULES_JSON).unwrap();
    let curated = bundled::checkov().unwrap();
    assert_eq!(raw.rules.len(), curated.len());
    for (original, reviewed) in raw.rules.iter().zip(curated) {
        assert_eq!(original.rule.name, reviewed.name);
        assert_eq!(original.rule.clauses, reviewed.clauses, "{}", reviewed.name);
    }
    for rule in bundled::rules().unwrap() {
        let info = rule.info();
        if info.profile != tf_linter::Profile::Unreviewed {
            assert!(
                info.rationale
                    .as_ref()
                    .is_some_and(|s| !s.trim().is_empty()),
                "{}",
                info.name
            );
        }
        if let Some(remediation) = &info.remediation {
            assert!(!remediation.trim().is_empty(), "{}", info.name);
            let url = info.guideline.as_deref().unwrap();
            assert!(
                url.starts_with("https://docs.aws.amazon.com/")
                    || url.starts_with("https://docs.cloud.google.com/")
                    || url.starts_with("https://learn.microsoft.com/"),
                "{}: {url}",
                info.name
            );
        }
    }
}

#[test]
#[ignore = "needs CHECKOV_PACK and CHECKOV_GRAPH_CHECKS"]
fn bundled_catalog_is_current() {
    let (Ok(pack), Ok(graph)) = (
        std::env::var("CHECKOV_PACK"),
        std::env::var("CHECKOV_GRAPH_CHECKS"),
    ) else {
        panic!("set CHECKOV_PACK and CHECKOV_GRAPH_CHECKS");
    };
    let generated = bundled::generate(Path::new(&pack), Path::new(&graph)).unwrap();
    assert!(
        generated.rules_json == bundled::CHECKOV_RULES_JSON,
        "data/checkov/rules.json is stale: run examples/bundle_checkov.rs"
    );
    assert!(
        generated.manifest_json == bundled::CHECKOV_MANIFEST_JSON,
        "data/checkov/manifest.json is stale: run examples/bundle_checkov.rs"
    );
    let iam = std::fs::read_to_string(Path::new(&pack).join("iam.ndjson")).unwrap();
    assert!(
        iam == tf_rule_ir::checkov_python::iam::COMPACT,
        "data/checkov/iam.ndjson is stale: run examples/bundle_checkov.rs"
    );
}

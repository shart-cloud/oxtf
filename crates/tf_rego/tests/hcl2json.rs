//! `tf_rego::hcl2json::raw` against Conftest v0.71.0's `conftest parse`.
//! The corpus-wide comparison is `bench/rego/hcl2json_compare.py`.

use std::path::Path;

#[test]
fn raw_rendering_matches_conftest_parse() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rego/hcl2json");
    let text = std::fs::read_to_string(dir.join("tricky.tf")).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("tricky.conftest.json")).unwrap())
            .unwrap();
    let alloc = tf_allocator::Allocator::new();
    let parsed = tf_parser::parse(&alloc, &text);
    assert!(parsed.errors.is_empty());
    let file = alloc.alloc(parsed.file).unwrap();
    assert_eq!(tf_rego::hcl2json::raw(file, &text).unwrap(), expected);
}

#[test]
fn evaluated_overrides_render_syntax_and_settings_from_their_original_files() {
    use std::{path::PathBuf, sync::Arc};
    let root = PathBuf::from("/nonexistent/oxtf-render-overrides");
    let files = tf_semantic::FileTable::with_overlay([
        (
            root.join("main.tf"),
            Arc::from("resource \"test\" \"r\" {}\nprovider \"aws\" {}"),
        ),
        (
            root.join("override.tf.json"),
            Arc::from(
                r#"{
          "//": "Padding makes offsets in this file exceed the entire base file.",
          "resource":{"test":{"r":{"lifecycle":{"ignore_changes":["\u0074ags"]}}}},
          "provider":{"aws":{"region":"us-west-2"}}
        }"#,
            ),
        ),
    ]);
    let store = tf_semantic::ModuleStore::new();
    let options = tf_semantic::AnalyzeOptions {
        whole_files: true,
        ..Default::default()
    };
    let analysis = tf_semantic::analyze::analyze_module_shared(&root, &options, &files, &store);
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let definition = store.module(&files, &root).unwrap();
    let (source, ast) = definition
        .files
        .iter()
        .find(|(sf, _)| sf.path.ends_with("main.tf"))
        .unwrap();
    let doc = tf_rego::hcl2json::evaluated(&tf_linter::ConfigFile {
        module: &analysis.modules[0],
        definition,
        source: source.clone(),
        ast,
        run: 0,
    })
    .unwrap()
    .doc;
    assert_eq!(doc["provider"]["aws"][0]["region"], "us-west-2");
    assert_eq!(
        doc["resource"]["test"]["r"][0]["lifecycle"][0]["ignore_changes"],
        serde_json::json!(["${tags}"])
    );
}

#[test]
fn json_provider_nested_blocks_match_hcl_policy_input() {
    use std::{path::PathBuf, sync::Arc};
    let root = PathBuf::from("/nonexistent/oxtf-provider-json");
    for local in ["aws", "myaws"] {
        let mut docs = Vec::new();
        for (filename, text) in [
            (
                "main.tf",
                r#"provider "aws" {
  region = "us-east-1"
  assume_role { role_arn = "arn:aws:iam::123456789012:role/example" }
}"#,
            ),
            (
                "main.tf.json",
                r#"{"provider":{"aws":{"region":"us-east-1",
          "assume_role":{"role_arn":"arn:aws:iam::123456789012:role/example"}}}}"#,
            ),
        ] {
            let files = tf_semantic::FileTable::with_overlay([
                (
                    root.join(filename),
                    Arc::from(text.replace("\"aws\"", &format!("\"{local}\""))),
                ),
                (
                    root.join("requirements.tf"),
                    Arc::from(format!(
                        "terraform {{\nrequired_providers {{\n{local} = {{ source = \"hashicorp/google\" }}\n}}\n}}"
                    )),
                ),
                (
                    root.join("requirements_override.tf.json"),
                    Arc::from(format!(
                        r#"{{"terraform":{{"required_providers":{{"{local}":{{"source":"hashicorp/aws"}}}}}}}}"#
                    )),
                ),
            ]);
            let store = tf_semantic::ModuleStore::new();
            let analysis = tf_semantic::analyze::analyze_module_shared(
                &root,
                &tf_semantic::AnalyzeOptions {
                    whole_files: true,
                    ..Default::default()
                },
                &files,
                &store,
            );
            assert!(
                analysis.diagnostics.is_empty(),
                "{:?}",
                analysis.diagnostics
            );
            let definition = store.module(&files, &root).unwrap();
            let (source, ast) = &definition.files[0];
            docs.push(
                tf_rego::hcl2json::evaluated(&tf_linter::ConfigFile {
                    module: &analysis.modules[0],
                    definition,
                    source: source.clone(),
                    ast,
                    run: 0,
                })
                .unwrap()
                .doc,
            );
        }
        assert_eq!(docs[0], docs[1]);
        assert!(docs[1]["provider"][local][0]["assume_role"][0]["role_arn"].is_string());
    }
}

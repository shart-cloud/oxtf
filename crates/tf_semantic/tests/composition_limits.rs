use std::path::Path;
use std::sync::Arc;

use tf_limits::{Limits, Resource};
use tf_semantic::{FileTable, ModuleStore};

const ROOT: &str = "/nonexistent/oxtf-composition";

fn files(case: &[(&str, &str)], allowance: u64) -> FileTable {
    FileTable::with_overlay_and_limits(
        case.iter()
            .map(|(name, text)| (Path::new(ROOT).join(name), Arc::from(*text))),
        Limits::default().with_collection_bytes(allowance).unwrap(),
    )
}

const CASES: &[&[(&str, &str)]] = &[
    &[
        (
            "main.tf",
            r#"variable "v" {
            type = object({x=optional(number, 1)})
            default = {}
        }
        locals { a=var.v.x }
        resource "test_node" "r" { x=local.a
            child { y=1 } }"#,
        ),
        (
            "override.tf",
            r#"variable "v" { type=any }
            locals { a=7 }
            resource "test_node" "r" { x=var.v.x
                child { y=2 } }"#,
        ),
    ],
    &[
        (
            "main.tf",
            r#"terraform { required_providers { aws={source="hashicorp/aws"} } }
            locals { v=1 }"#,
        ),
        ("other.tf", r#"terraform { backend "s3" { bucket="old" } }"#),
        (
            "override.tf",
            r#"terraform { required_providers { aws={version="1.0"} }
            backend "s3" { bucket="new" } }
            provider "aws" { region="us-east-1" }"#,
        ),
    ],
    &[
        (
            "main.tf.json",
            r#"{"variable":{"v":{"default":{"x":1}}},
            "locals":{"a":"${var.v}"},"output":{"o":{"value":"${local.a}"}}}"#,
        ),
        (
            "override.tf.json",
            r#"{"variable":{"v":{"default":{"x":2}}},
            "locals":{"a":"${var.v.x}"}}"#,
        ),
    ],
];

#[test]
fn composition_storage_boundaries_discard_partial_ownership_defaults_and_references() {
    for case in CASES {
        let full = files(case, 1_000_000);
        let store = ModuleStore::new();
        let definition = store.module(&full, Path::new(ROOT)).unwrap();
        assert!(
            definition.parse_errors.is_empty(),
            "{:?}",
            definition.parse_errors
        );
        let count =
            definition.variables.len() + definition.locals.len() + definition.resources.len();
        assert!(count > 0);
        let cost = full.input_budget().stats().collection_bytes;
        for allowance in (1..cost).step_by(16).chain([cost - 1, cost, cost + 1]) {
            let files = files(case, allowance);
            let store = ModuleStore::new();
            if let Ok(def) = store.module(&files, Path::new(ROOT)) {
                assert!(
                    def.parse_errors.is_empty(),
                    "{allowance}/{cost}: {:?}",
                    def.parse_errors
                );
                let actual = def.variables.len() + def.locals.len() + def.resources.len();
                assert_eq!(actual, if allowance < cost { 0 } else { count });
                if allowance < cost {
                    assert!(def.references.is_empty());
                }
            }
            assert_eq!(
                files.input_budget().exhaustion().is_some(),
                allowance < cost
            );
            let consumed = files.input_budget().stats();
            assert!(consumed.collection_bytes <= allowance);
            let _ = store.module(&files, Path::new(ROOT));
            assert_eq!(files.input_budget().stats(), consumed);
        }
    }
}

#[test]
fn every_composition_byte_boundary_keeps_observed_errors() {
    let case = [
        ("main.tf", "locals { a=1\n a=2\n b=local.a }"),
        ("override.tf", ""),
    ];
    let full = files(&case, 100_000);
    let store = ModuleStore::new();
    assert!(
        !store
            .module(&full, Path::new(ROOT))
            .unwrap()
            .parse_errors
            .is_empty()
    );
    let cost = full.input_budget().stats().collection_bytes;
    let mut observed_error = false;
    for allowance in 1..=cost {
        let files = files(&case, allowance);
        let store = ModuleStore::new();
        if let Ok(def) = store.module(&files, Path::new(ROOT)) {
            if !def.parse_errors.is_empty() {
                observed_error = true;
            } else {
                assert!(
                    !observed_error,
                    "observed error disappeared at {allowance}/{cost}"
                );
            }
            if allowance < cost {
                assert!(def.locals.is_empty());
                assert!(def.references.is_empty());
            }
        }
        if allowance < cost {
            assert_eq!(
                files.input_budget().exhaustion().unwrap().resource,
                Resource::CollectionBytes
            );
        }
    }
    assert!(observed_error);
}

#[test]
fn overridden_reference_spans_still_point_to_the_original_source_file() {
    let case = [
        (
            "main.tf",
            "variable \"v\" {}\nresource \"test_node\" \"r\" { x=1\n y=var.v }",
        ),
        ("override.tf", "resource \"test_node\" \"r\" { x=var.v }"),
    ];
    let files = files(&case, 100_000);
    let store = ModuleStore::new();
    let def = store.module(&files, Path::new(ROOT)).unwrap();
    let resource = &def.resources[0];
    for name in ["x", "y"] {
        let attribute = resource.block.body.find_attribute(name).unwrap();
        let file = def.origins.file(attribute, resource.file);
        let source = files.get(file);
        assert!(source.path.ends_with(if name == "x" {
            "override.tf"
        } else {
            "main.tf"
        }));
        assert!(
            def.references
                .iter()
                .any(|r| r.at.file == file && r.to == tf_semantic::SymbolRef::Variable("v".into()))
        );
    }
    let consumed = files.input_budget().stats();
    let warm = store.module(&files, Path::new(ROOT)).unwrap();
    assert!(Arc::ptr_eq(&def.references, &warm.references));
    assert_eq!(files.input_budget().stats(), consumed);
}

use std::path::Path;
use std::sync::Arc;

use tf_limits::{Limits, Resource};
use tf_semantic::{FileTable, ModuleStore};

const ROOT: &str = "/nonexistent/oxtf-metadata";
const SOURCE: &str = r#"
variable "v" { default = 1 }
locals { a = var.v
         b = 2 }
resource "test_node" "r" { x = local.a }
data "test_node" "d" {}
module "child" { source = "./child" }
output "o" { value = local.b }
"#;

#[test]
fn provider_index_refusal_discards_json_preparation_without_syntax_errors() {
    let overlay = || {
        [
            (
                Path::new(ROOT).join("main.tf"),
                Arc::from(
                    "terraform { required_providers { amazon = { source = \"hashicorp/aws\" } } }",
                ),
            ),
            (
                Path::new(ROOT).join("extra.tf.json"),
                Arc::from(r#"{"locals":{"x":1}}"#),
            ),
        ]
    };
    let full = FileTable::with_overlay(overlay());
    let store = ModuleStore::new();
    let def = store.module(&full, Path::new(ROOT)).unwrap();
    assert_eq!(def.locals.len(), 1);
    assert!(def.parse_errors.is_empty());
    let cost = full.input_budget().stats().collection_bytes;
    for allowance in 1..=cost {
        let files = FileTable::with_overlay_and_limits(
            overlay(),
            Limits::default().with_collection_bytes(allowance).unwrap(),
        );
        let store = ModuleStore::new();
        if let Ok(def) = store.module(&files, Path::new(ROOT)) {
            assert!(def.parse_errors.is_empty());
            assert_eq!(def.locals.len(), usize::from(allowance == cost));
        }
        assert_eq!(
            files.input_budget().exhaustion().is_some(),
            allowance < cost
        );
        assert!(files.input_budget().stats().collection_bytes <= allowance);
    }
}

fn files(source: &str, allowance: u64) -> FileTable {
    FileTable::with_overlay_and_limits(
        [(Path::new(ROOT).join("main.tf"), Arc::from(source))],
        Limits::default().with_collection_bytes(allowance).unwrap(),
    )
}

#[test]
fn every_definition_metadata_boundary_discards_all_partial_indexes() {
    let full = files(SOURCE, 100_000);
    ModuleStore::new().module(&full, Path::new(ROOT)).unwrap();
    let cost = full.input_budget().stats().collection_bytes;
    for allowance in 1..=cost + 1 {
        let files = files(SOURCE, allowance);
        let store = ModuleStore::new();
        let first = store.module(&files, Path::new(ROOT));
        match first {
            Err(error) => {
                assert_eq!(error.resource, Resource::CollectionBytes);
                assert!(store.is_empty());
                assert_eq!(files.input_budget().stats().ast_nodes, 0);
            }
            Ok(def) if allowance < cost => {
                assert!(def.variables.is_empty());
                assert!(def.locals.is_empty());
                assert!(def.resources.is_empty());
                assert!(def.module_calls.is_empty());
                assert!(def.outputs.is_empty());
                assert!(def.references.is_empty());
                assert!(def.variable("v").is_none());
                assert!(def.local("a").is_none());
                assert!(def.module_call("child").is_none());
                assert!(def.output("o").is_none());
                assert!(def.parse_errors.is_empty());
            }
            Ok(def) => {
                assert_eq!(def.variables.len(), 1);
                assert_eq!(def.locals.len(), 2);
                assert_eq!(def.resources.len(), 2);
                assert_eq!(def.module_calls.len(), 1);
                assert_eq!(def.outputs.len(), 1);
            }
        }
        let consumed = files.input_budget().stats();
        assert!(consumed.collection_bytes <= allowance);
        assert_eq!(
            files.input_budget().exhaustion().is_some(),
            allowance < cost
        );
        match (first, store.module(&files, Path::new(ROOT))) {
            (Ok(a), Ok(b)) => assert!(std::ptr::eq(a, b)),
            (Err(a), Err(b)) => assert_eq!(a, b),
            _ => panic!("cache outcome changed"),
        }
        assert_eq!(files.input_budget().stats(), consumed);
    }
}

#[test]
fn concurrent_definition_admission_matches_one_serial_load() {
    let serial = files(SOURCE, 100_000);
    ModuleStore::new().module(&serial, Path::new(ROOT)).unwrap();
    let cost = serial.input_budget().stats();
    for allowance in [1, cost.collection_bytes - 1, cost.collection_bytes] {
        let files = files(SOURCE, allowance);
        let store = ModuleStore::new();
        let barrier = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        store
                            .module(&files, Path::new(ROOT))
                            .map(|def| std::ptr::from_ref(def) as usize)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(results.iter().all(|r| r == &results[0]));
        assert_eq!(store.len(), usize::from(results[0].is_ok()));
        if allowance == cost.collection_bytes {
            assert_eq!(files.input_budget().stats(), cost);
        } else {
            assert_eq!(
                files.input_budget().exhaustion().unwrap().resource,
                Resource::CollectionBytes
            );
        }
    }
}

#[test]
fn indexing_refusal_keeps_an_already_observed_duplicate_error() {
    let source = "locals { a = 1\n a = 2\n b = 3 }";
    let full = files(source, 100_000);
    let store = ModuleStore::new();
    let def = store.module(&full, Path::new(ROOT)).unwrap();
    assert!(std::ptr::eq(def.local("a").unwrap(), &def.locals[0]));
    assert_eq!(def.parse_errors.len(), 1);
    let cost = full.input_budget().stats().collection_bytes;
    let limited = files(source, cost - 1);
    let store = ModuleStore::new();
    let def = store.module(&limited, Path::new(ROOT)).unwrap();
    assert!(def.locals.is_empty());
    assert!(def.local("a").is_none());
    assert_eq!(def.parse_errors.len(), 1);
    assert!(def.parse_errors[0].1.contains("duplicate local"));
}

#[test]
fn concurrent_variable_file_entries_admit_once_before_parsing() {
    let root = Path::new(ROOT);
    let path = root.join("terraform.tfvars");
    let make_files = |allowance| {
        FileTable::with_overlay_and_limits(
            [(path.clone(), Arc::from("v = 1"))],
            Limits::default().with_collection_bytes(allowance).unwrap(),
        )
    };
    let full = make_files(100_000);
    let sf = full.load(&path).unwrap();
    ModuleStore::new().variable_file(&sf).unwrap();
    let cost = full.input_budget().stats();
    for allowance in [
        cost.collection_bytes - 1,
        cost.collection_bytes,
        cost.collection_bytes + 1,
    ] {
        let files = make_files(allowance);
        let sf = files.load(&path).unwrap();
        let store = ModuleStore::new();
        let barrier = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        match store.variable_file(&sf) {
                            Ok(parsed) => Ok(std::ptr::from_ref(parsed) as usize),
                            Err(tf_semantic::store::FileError::Storage(error)) => Err(error),
                            Err(error) => panic!("{error}"),
                        }
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(results.iter().all(|r| r == &results[0]));
        if allowance < cost.collection_bytes {
            assert_eq!(results[0].unwrap_err().resource, Resource::CollectionBytes);
            assert_eq!(files.input_budget().stats().ast_nodes, 0);
            assert_eq!(files.input_budget().stats().collection_bytes, 0);
        } else {
            assert!(results[0].is_ok());
            assert_eq!(files.input_budget().stats(), cost);
        }
    }
}

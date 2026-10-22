use std::path::PathBuf;
use std::sync::Arc;
use tf_limits::{Limits, Resource};
use tf_semantic::{FileTable, ModuleStore};

struct Scratch(PathBuf);
impl Scratch {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!("oxtf-storage-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

#[test]
fn raw_and_decoded_payloads_are_admitted_before_registration() {
    let scratch = Scratch::new("raw", b"abcd");
    for allowance in [7, 8, 9] {
        let files = FileTable::with_limits(Limits::default().with_source_bytes(allowance).unwrap());
        let source = files.load(&scratch.0);
        if allowance == 7 {
            assert_eq!(
                tf_limits::input::exhaustion(&source.unwrap_err())
                    .unwrap()
                    .resource,
                Resource::SourceBytes
            );
            assert_eq!(files.len(), 0);
            assert_eq!(files.input_budget().stats().source_bytes, 4);
        } else {
            let source = source.unwrap();
            assert_eq!(&*source.text, "abcd");
            assert!(Arc::ptr_eq(&source, &files.load(&scratch.0).unwrap()));
            files.read_bytes(&scratch.0).unwrap();
            assert_eq!(files.input_budget().stats().source_bytes, 8);
            assert_eq!(files.input_budget().stats().file_entries, 2);
        }
    }
}

#[test]
fn lossy_utf8_expansion_is_checked_before_constructing_text() {
    let scratch = Scratch::new("utf8", &[0xff, 0xff]);
    let files = FileTable::with_limits(Limits::default().with_input_bytes(5).unwrap());
    let error = files.load(&scratch.0).unwrap_err();
    assert_eq!(
        tf_limits::input::exhaustion(&error).unwrap().resource,
        Resource::InputBytes
    );
    assert!(files.is_empty());
    assert_eq!(files.input_budget().stats().source_bytes, 2);
    let files = FileTable::with_limits(Limits::default().with_input_bytes(6).unwrap());
    assert_eq!(&*files.load(&scratch.0).unwrap().text, "\u{fffd}\u{fffd}");
    assert_eq!(files.input_budget().stats().source_bytes, 8);
}

#[test]
fn concurrent_source_loads_share_one_snapshot_and_one_reservation() {
    let scratch = Scratch::new("concurrent", b"text");
    let files = FileTable::with_limits(Limits::default().with_source_bytes(8).unwrap());
    let barrier = std::sync::Barrier::new(8);
    let snapshots = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(|| {
                    barrier.wait();
                    files.load(&scratch.0).unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(
        snapshots
            .iter()
            .all(|source| Arc::ptr_eq(source, &snapshots[0]))
    );
    assert_eq!(files.len(), 1);
    assert_eq!(files.input_budget().stats().source_bytes, 8);
    assert_eq!(files.input_budget().exhaustion(), None);
}

#[test]
fn overlay_raw_copy_and_duplicate_paths_do_not_bypass_admission() {
    let path = PathBuf::from("/nonexistent/oxtf-storage/main.tf");
    let files = FileTable::with_overlay_and_limits(
        [
            (path.clone(), Arc::from("abcd")),
            (path.clone(), Arc::from("other")),
        ],
        Limits::default().with_source_bytes(7).unwrap(),
    );
    assert_eq!(&*files.load(&path).unwrap().text, "abcd");
    assert!(files.read_bytes(&path).is_err());
    assert_eq!(files.len(), 1);
    assert_eq!(files.input_budget().stats().source_bytes, 4);
}

#[test]
fn concurrent_module_requests_share_definitions_and_loader_cost() {
    let root = PathBuf::from("/nonexistent/oxtf-storage/module");
    let files = FileTable::with_overlay([
        (
            root.join("main.tf"),
            Arc::from("variable \"v\" { default = [1, 2, 3] }"),
        ),
        (root.join("override.tf"), Arc::from("")),
    ]);
    let store = ModuleStore::new();
    let barrier = std::sync::Barrier::new(8);
    let definitions = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(|| {
                    barrier.wait();
                    std::ptr::from_ref(store.module(&files, &root).unwrap()) as usize
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(definitions.iter().all(|d| *d == definitions[0]));
    assert_eq!(store.len(), 1);
    assert_eq!(files.input_budget().stats().file_entries, 4);
}

#[test]
fn parsed_caches_do_not_cross_input_snapshots_or_recharge_warm_entries() {
    use tf_semantic::{AnalyzeOptions, analyze_module_shared};
    let root = PathBuf::from("/nonexistent/oxtf-storage/snapshots");
    let store = ModuleStore::new();
    for value in [1, 2] {
        let files = FileTable::with_overlay([
            (root.join("main.tf"), Arc::from("variable \"v\" {}")),
            (
                root.join("terraform.tfvars"),
                Arc::from(format!("v = {value}")),
            ),
        ]);
        let options = AnalyzeOptions::default();
        store.module(&files, &root).unwrap();
        let sf = files.load(&root.join("terraform.tfvars")).unwrap();
        store.variable_file(&sf).unwrap();
        let shared = files.input_budget().stats().collection_bytes;
        let first = analyze_module_shared(&root, &options, &files, &store);
        let cost = files.input_budget().stats();
        let second = analyze_module_shared(&root, &options, &files, &store);
        let mut second_cost = files.input_budget().stats();
        assert_eq!(
            second_cost.collection_bytes,
            shared + 2 * (cost.collection_bytes - shared)
        );
        second_cost.collection_bytes = cost.collection_bytes;
        assert_eq!(second_cost, cost);
        assert_eq!(cost.file_entries, 4);
        for analysis in [first, second] {
            assert!(analysis.diagnostics.is_empty());
            assert_eq!(
                tf_eval::value::to_json(&analysis.modules[0].variables[0].value),
                Some(serde_json::json!(value))
            );
        }
    }
    assert_eq!(store.len(), 2);
}

#[test]
#[expect(clippy::too_many_lines)]
fn every_module_construction_boundary_discards_partial_definitions() {
    let root = PathBuf::from("/nonexistent/oxtf-arena-sweep");
    let cases: &[&[(&str, &str)]] = &[
        &[(
            "main.tf",
            "variable \"v\" { default = [1, 2] }\nlocals { x = var.v }",
        )],
        &[(
            "main.tf.json",
            r#"{"variable":{"v":{"default":[1,2]}},"locals":{"x":"${var.v}"}}"#,
        )],
        &[
            (
                "main.tf",
                "variable \"v\" { default = [1, 2] }\nlocals { x = 1 }",
            ),
            (
                "override.tf",
                "variable \"v\" { default = [3, 4] }\nlocals { x = 2 }",
            ),
        ],
        &[
            (
                "main.tf",
                "terraform { required_providers { aws = { source = \"hashicorp/aws\" } } }",
            ),
            (
                "main.tf.json",
                r#"{"resource":{"aws_db_instance":{"db":{"storage_encrypted":false,"tags":{"x":"${1 + 2}"}}}}}"#,
            ),
        ],
    ];
    for case in cases {
        let overlay = || {
            case.iter()
                .map(|(name, source)| (root.join(name), Arc::from(*source)))
        };
        let files = FileTable::with_overlay(overlay());
        let store = ModuleStore::new();
        let definition = store.module(&files, &root).unwrap();
        assert!(
            definition.parse_errors.is_empty(),
            "{:?}",
            definition.parse_errors
        );
        let count = files.input_budget().stats().ast_nodes;
        assert!(count > 1);
        for allowance in 1..count {
            let files = FileTable::with_overlay_and_limits(
                overlay(),
                Limits::default().with_ast_nodes(allowance).unwrap(),
            );
            let store = ModuleStore::new();
            let definition = store.module(&files, &root).unwrap();
            assert!(
                definition.parse_errors.is_empty(),
                "allowance={allowance}: {:?}",
                definition.parse_errors
            );
            assert!(definition.variables.is_empty());
            assert!(definition.locals.is_empty());
            assert!(definition.resources.is_empty());
            assert_eq!(
                files.input_budget().exhaustion().unwrap().resource,
                Resource::AstNodes
            );
            assert!(files.input_budget().stats().ast_nodes <= allowance);
            let cost = files.input_budget().stats();
            store.module(&files, &root).unwrap();
            assert_eq!(files.input_budget().stats(), cost);
        }
    }
}

#[test]
fn failed_variable_file_preparation_is_cached_with_typed_exhaustion() {
    for name in ["terraform.tfvars", "terraform.tfvars.json"] {
        let path = PathBuf::from("/nonexistent/oxtf-arena-vars").join(name);
        let source = if name.ends_with("json") {
            r#"{"v":[1,2,3]}"#
        } else {
            "v = [1, 2, 3]"
        };
        let files = FileTable::with_overlay_and_limits(
            [(path.clone(), Arc::from(source))],
            Limits::default().with_ast_nodes(2).unwrap(),
        );
        let sf = files.load(&path).unwrap();
        let store = ModuleStore::new();
        let tf_semantic::store::FileError::Parse(first) = store.variable_file(&sf).err().unwrap()
        else {
            panic!("expected cached parse failure")
        };
        assert_eq!(
            tf_limits::input::exhaustion(first).unwrap().resource,
            Resource::AstNodes
        );
        let cost = files.input_budget().stats();
        let tf_semantic::store::FileError::Parse(second) = store.variable_file(&sf).err().unwrap()
        else {
            panic!("expected cached parse failure")
        };
        assert!(std::ptr::eq(first, second));
        assert_eq!(files.input_budget().stats(), cost);
    }
}

#[test]
fn independent_low_level_arenas_report_refusal_in_the_module() {
    let root = PathBuf::from("/nonexistent/oxtf-independent-arena");
    for nodes in [1, 4] {
        let files =
            FileTable::with_overlay([(root.join("main.tf"), Arc::from("locals { x = 1 }"))]);
        let arena = tf_allocator::Allocator::with_budget(Arc::new(
            tf_limits::input::InputBudget::new(Limits::default().with_ast_nodes(nodes).unwrap()),
        ));
        let module = tf_semantic::module::load_module(&arena, &files, &root);
        assert!(files.input_budget().exhaustion().is_none());
        assert!(module.locals.is_empty());
        assert_eq!(module.parse_limits.len(), 1);
        assert!(matches!(
            module.parse_limits[0].1.kind,
            tf_parser::DiagnosticKind::Limit(tf_parser::ParseLimit::Storage(_))
        ));
    }
}

#[test]
fn cached_default_text_is_charged_once_and_refusal_discards_composition() {
    let root = PathBuf::from("/nonexistent/oxtf-text-defaults");
    let source = r#"variable "v" { default = ["long string", "another"] }"#;
    for allowance in [1, 1000] {
        let files = FileTable::with_overlay_and_limits(
            [
                (root.join("main.tf"), Arc::from(source)),
                (root.join("override.tf"), Arc::from("")),
            ],
            Limits::default().with_text_bytes(allowance).unwrap(),
        );
        let store = ModuleStore::new();
        let first = store.module(&files, &root).unwrap();
        if allowance == 1 {
            assert!(first.variables.is_empty());
            assert!(first.parse_errors.is_empty());
            assert_eq!(
                files.input_budget().exhaustion().unwrap().resource,
                Resource::TextBytes
            );
        } else {
            assert_eq!(first.variables.len(), 1);
            assert!(files.input_budget().stats().text_bytes > 0);
        }
        let cost = files.input_budget().stats();
        let second = store.module(&files, &root).unwrap();
        assert!(std::ptr::eq(first, second));
        assert_eq!(files.input_budget().stats(), cost);
    }
}

#[test]
fn cached_default_collections_share_admission_and_are_not_charged_twice() {
    let root = PathBuf::from("/nonexistent/oxtf-collection-defaults");
    for allowance in [1, 10_000] {
        let files = FileTable::with_overlay_and_limits(
            [
                (
                    root.join("main.tf"),
                    Arc::from("variable \"v\" { default = reverse([1, 2, 3]) }"),
                ),
                (root.join("override.tf"), Arc::from("")),
            ],
            Limits::default().with_collection_bytes(allowance).unwrap(),
        );
        let store = ModuleStore::new();
        let first = store.module(&files, &root);
        if allowance == 1 {
            assert_eq!(first.err().unwrap().resource, Resource::CollectionBytes);
            assert_eq!(store.len(), 0);
            assert_eq!(
                files.input_budget().exhaustion().unwrap().resource,
                Resource::CollectionBytes
            );
            continue;
        } else {
            assert_eq!(first.as_ref().unwrap().variables.len(), 1);
            // Default inference now also admits its scratch and retained type tree.
            assert!(
                files.input_budget().stats().collection_bytes
                    > 7 * size_of::<tf_eval::Value>() as u64
            );
        }
        let cost = files.input_budget().stats();
        assert!(std::ptr::eq(
            first.unwrap(),
            store.module(&files, &root).unwrap()
        ));
        assert_eq!(files.input_budget().stats(), cost);
    }
}

#[test]
fn semantic_preparation_cache_retains_every_storage_refusal_boundary() {
    let root = PathBuf::from("/nonexistent/oxtf-semantic-preparation");
    let source = r#"variable "v" {
        type = object({x=optional(list(number), [1,2]), y=optional(map(string), {})})
        default = {}
    }"#;
    let overlay = || {
        [
            (root.join("main.tf"), Arc::from(source)),
            (
                root.join("override.tf"),
                Arc::from("variable \"v\" { type = any }"),
            ),
        ]
    };
    let full = FileTable::with_overlay(overlay());
    let store = ModuleStore::new();
    let definition = store.module(&full, &root).unwrap();
    assert!(definition.parse_errors.is_empty());
    assert_eq!(definition.variables.len(), 1);
    let cost = full.input_budget().stats().collection_bytes;
    for allowance in 1..=cost {
        let files = FileTable::with_overlay_and_limits(
            overlay(),
            Limits::default().with_collection_bytes(allowance).unwrap(),
        );
        let store = ModuleStore::new();
        let first = match store.module(&files, &root) {
            Ok(first) => first,
            Err(error) => {
                assert_eq!(error.resource, Resource::CollectionBytes);
                assert!(store.is_empty());
                let consumed = files.input_budget().stats();
                assert_eq!(store.module(&files, &root).err(), Some(error));
                assert_eq!(files.input_budget().stats(), consumed);
                continue;
            }
        };
        assert!(first.parse_errors.is_empty(), "allowance={allowance}");
        if allowance < cost {
            assert!(first.variables.is_empty(), "allowance={allowance}");
            assert_eq!(
                files.input_budget().exhaustion().unwrap().resource,
                Resource::CollectionBytes
            );
        } else {
            assert_eq!(first.variables.len(), 1);
            assert!(files.input_budget().exhaustion().is_none());
        }
        let consumed = files.input_budget().stats();
        assert!(consumed.collection_bytes <= allowance);
        assert!(std::ptr::eq(first, store.module(&files, &root).unwrap()));
        assert_eq!(files.input_budget().stats(), consumed);
    }
}

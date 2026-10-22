use std::path::Path;
use std::sync::Arc;
use tf_limits::{Limits, Resource};
use tf_semantic::{Analysis, AnalyzeOptions, FileTable, ModuleStore, analyze_module_shared};

const ROOT: &str = "/nonexistent/oxtf-model-admission";

fn analyze(source: &str, allowance: u64, whole_files: bool) -> (Analysis, FileTable) {
    let limits = Limits::default().with_collection_bytes(allowance).unwrap();
    let files = FileTable::with_overlay_and_limits(
        [
            (Path::new(ROOT).join("main.tf"), Arc::from(source)),
            (
                Path::new(ROOT).join("child/main.tf"),
                Arc::from("variable \"v\" {}\noutput \"out\" { value = {nested = var.v} }"),
            ),
        ],
        limits,
    );
    let options = AnalyzeOptions {
        limits,
        whole_files,
        ..AnalyzeOptions::default()
    };
    let result = analyze_module_shared(Path::new(ROOT), &options, &files, &ModuleStore::new());
    (result, files)
}

#[test]
fn model_builders_projections_and_expansions_obey_storage_boundaries() {
    let sources = [
        "resource \"test_node\" \"r\" { x = 1\n child { y = 2 } }",
        "resource \"test_node\" \"r\" { count = 2\n x = { a = count.index } }\n\
         output \"all\" { value = test_node.r[*].x.a }\n\
         output \"legacy\" { value = test_node.r.*.x.a }\n\
         output \"object\" { value = test_node.r }",
        "resource \"test_node\" \"r\" { for_each = {a = 1, b = 2}\n x = each.value }\n\
         variable \"key\" {}\noutput \"all\" { value = test_node.r }\n\
         output \"unknown\" { value = test_node.r[var.key].x }",
        "resource \"aws_security_group\" \"r\" {\n\
         dynamic \"ingress\" { for_each = [1, 2]\n content { from_port = ingress.value } }\n\
         egress { from_port = 3 } }",
        "module \"child\" { source = \"./child\"\n count = 2\n v = count.index }\n\
         variable \"key\" {}\noutput \"all\" { value = module.child }\n\
         output \"unknown\" { value = module.child[var.key] }\n\
         locals { used = module.child[0].out }\nprovider \"test\" { x = 1 }",
        "data \"aws_iam_policy_document\" \"p\" {\n\
         source_policy_documents = [jsonencode({Statement=[{Effect=\"Allow\"}]})]\n\
         statement { actions=[\"s3:GetObject\"]\n resources=[\"*\"]\n\
         principals { type=\"AWS\"\n identifiers=[\"*\"] } } }\n\
         output \"policy\" { value = data.aws_iam_policy_document.p.json }",
    ];
    for source in sources {
        for whole in [false, true] {
            let (full, files) = analyze(source, 1_000_000, whole);
            assert!(
                full.diagnostics.is_empty(),
                "{source}: {:?}",
                full.diagnostics
            );
            let cost = files.input_budget().stats().collection_bytes;
            let allowances = (1..cost).step_by(64).chain([cost - 1, cost, cost + 1]);
            for allowance in allowances {
                let (result, files) = analyze(source, allowance, whole);
                let limits: Vec<_> = result
                    .diagnostics
                    .iter()
                    .filter(|d| d.code == "coverage-storage")
                    .collect();
                if allowance < cost {
                    assert_eq!(limits.len(), 1, "{allowance}/{cost}: {source}");
                    assert_eq!(
                        files.input_budget().exhaustion().unwrap().resource,
                        Resource::CollectionBytes
                    );
                } else {
                    assert!(limits.is_empty(), "{allowance}/{cost}: {source}");
                    assert_eq!(result.stats.resources, full.stats.resources);
                    assert_eq!(result.stats.module_instances, full.stats.module_instances);
                }
                assert!(files.input_budget().stats().collection_bytes <= allowance);
                for (index, module) in result.modules.iter().enumerate() {
                    assert!(module.parent.is_none_or(|parent| parent < index));
                }
                assert!(!result.diagnostics.iter().any(|d| d.code == "parse-error"));
            }
        }
    }
}

#[test]
fn every_byte_boundary_keeps_completed_resources_and_discards_incomplete_bodies() {
    let source = "resource \"test_node\" \"first\" { x=1 }\n\
                  resource \"test_node\" \"second\" { x=1\n y=2 }";
    let (_, files) = analyze(source, 100_000, false);
    let cost = files.input_budget().stats().collection_bytes;
    let mut retained_first = false;
    for allowance in 1..=cost {
        let (result, files) = analyze(source, allowance, false);
        for resource in result.modules.iter().flat_map(|m| &m.resources) {
            let count = if &*resource.name == "first" { 1 } else { 2 };
            assert_eq!(resource.body.attrs.len(), count);
            retained_first |= allowance < cost && &*resource.name == "first";
        }
        assert_eq!(
            files.input_budget().exhaustion().is_some(),
            allowance < cost
        );
    }
    assert!(retained_first);
}

#[test]
fn warm_definition_still_charges_each_new_model_and_replays_refusal() {
    let source = "resource \"test_node\" \"r\" { x=1 }";
    let files = FileTable::with_overlay([(Path::new(ROOT).join("main.tf"), Arc::from(source))]);
    let store = ModuleStore::new();
    let options = AnalyzeOptions::default();
    analyze_module_shared(Path::new(ROOT), &options, &files, &store);
    analyze_module_shared(Path::new(ROOT), &options, &files, &store);
    let two_models = files.input_budget().stats().collection_bytes;
    let limits = Limits::default()
        .with_collection_bytes(two_models - 1)
        .unwrap();
    let files = FileTable::with_overlay_and_limits(
        [(Path::new(ROOT).join("main.tf"), Arc::from(source))],
        limits,
    );
    let options = AnalyzeOptions {
        limits,
        ..AnalyzeOptions::default()
    };
    let store = ModuleStore::new();
    let first = analyze_module_shared(Path::new(ROOT), &options, &files, &store);
    assert!(first.diagnostics.is_empty());
    let first_cost = files.input_budget().stats();
    let second = analyze_module_shared(Path::new(ROOT), &options, &files, &store);
    assert!(
        second
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-storage")
    );
    assert_eq!(files.input_budget().stats().ast_nodes, first_cost.ast_nodes);
    let consumed = files.input_budget().stats();
    let third = analyze_module_shared(Path::new(ROOT), &options, &files, &store);
    assert!(third.modules.is_empty());
    assert!(
        third
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-storage")
    );
    assert_eq!(files.input_budget().stats(), consumed);
}

use std::{path::Path, sync::Arc};
use tf_eval::{Truth, Value};
use tf_semantic::{AnalyzeOptions, FileTable, InstanceKey, analyze_module, graph::ResourceGraph};

fn analyze(source: &str, children: &[(&str, &str)], opts: AnalyzeOptions) -> tf_semantic::Analysis {
    let root = Path::new("/nonexistent/count-test");
    let files = FileTable::with_overlay(
        std::iter::once(("main.tf", source))
            .chain(children.iter().copied())
            .map(|(p, s)| (root.join(p), Arc::from(s))),
    );
    analyze_module(root, &opts, &files)
}

#[test]
fn sensitive_indices_mark_resource_and_module_selections_including_errors() {
    let analysis = analyze(
        r#"
variable "choice" {}
resource "test_node" "n" {
  count = 2
  value = "private-${count.index}"
}
module "child" {
  count = 2
  source = "./child"
  value = "private-${count.index}"
}
locals {
  resource_object = test_node.n[sensitive(1)]
  module_object = module.child[sensitive(1)]
}
resource "test_result" "r" {
  direct = test_node.n[sensitive(1)].value
  indirect = local.resource_object.value
  module_direct = module.child[sensitive(1)].value
  module_indirect = local.module_object.value
  alternative = test_node.n[sensitive(var.choice ? 0 : 1)].value
  module_alternative = module.child[sensitive(var.choice ? 0 : 1)].value
  invalid = can(test_node.n[sensitive("invalid")].value)
  missing = can(test_node.n[sensitive(99)].value)
  module_invalid = can(module.child[sensitive("invalid")].value)
  module_missing = can(module.child[sensitive(99)].value)
}
"#,
        &[(
            "child/main.tf",
            "variable \"value\" {}\noutput \"value\" { value = var.value }\n",
        )],
        AnalyzeOptions::default(),
    );
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let result = &analysis.modules[0].resources[2];
    for name in [
        "direct",
        "indirect",
        "module_direct",
        "module_indirect",
        "alternative",
        "module_alternative",
        "invalid",
        "missing",
        "module_invalid",
        "module_missing",
    ] {
        assert!(result.value(name).unwrap().is_sensitive(), "{name}");
    }
    assert_eq!(result.value("direct").unwrap().as_str(), Some("private-1"));
    assert_eq!(
        result.value("module_direct").unwrap().as_str(),
        Some("private-1")
    );
    assert_eq!(result.value("invalid").unwrap().as_bool(), Some(false));
    assert_eq!(
        result.value("module_missing").unwrap().as_bool(),
        Some(false)
    );
}

#[test]
fn count_indices_use_numeric_conversion_and_reject_non_integral_values() {
    let analysis = analyze(
        r#"
resource "test_node" "n" {
  count = 2
  value = count.index
}
module "child" {
  count = 2
  source = "./child"
  value = count.index
}
resource "test_result" "r" {
  resource = [for key in ["1", "1.0", "1e0", " 1 "] : test_node.n[key].value]
  module = [for key in ["1", "1.0", "1e0", " 1 "] : module.child[key].value]
  invalid_resource = [for key in ["1.5", "-1", "NaN", "inf", "18446744073709551616"] : can(test_node.n[key].value)]
  invalid_module = [for key in ["1.5", "-1", "NaN", "inf", "18446744073709551616"] : can(module.child[key].value)]
}
"#,
        &[(
            "child/main.tf",
            "variable \"value\" {}\noutput \"value\" { value = var.value }\n",
        )],
        AnalyzeOptions::default(),
    );
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let result = &analysis.modules[0].resources[2];
    for name in ["resource", "module"] {
        assert_eq!(
            result
                .value(name)
                .unwrap()
                .as_list()
                .unwrap()
                .iter()
                .map(Value::as_number)
                .collect::<Vec<_>>(),
            vec![Some(1.0); 4],
            "{name}",
        );
    }
    for name in ["invalid_resource", "invalid_module"] {
        assert_eq!(
            result
                .value(name)
                .unwrap()
                .as_list()
                .unwrap()
                .iter()
                .map(Value::as_bool)
                .collect::<Vec<_>>(),
            vec![Some(false); 5],
            "{name}",
        );
    }
}

#[test]
fn whole_resource_objects_retain_nested_block_uncertainty() {
    let analysis = analyze(
        r#"
resource "aws_instance" "n" {
  count = 1
  metadata_options { http_tokens = "required" }
}
resource "test_node" "dynamic" {
  dynamic "settings" {
    for_each = [1]
    content { value = settings.value }
  }
}
locals {
  node = aws_instance.n[0]
  nodes = aws_instance.n[*]
  dynamic = test_node.dynamic
}
resource "test_result" "r" {
  direct = aws_instance.n[0].metadata_options
  copied = local.node.metadata_options
  splat = local.nodes[0].metadata_options
  can = can(local.node.metadata_options)
  fallback = try(local.node.metadata_options, "missing")
  dynamic = try(local.dynamic.settings, "missing")
}
"#,
        &[],
        AnalyzeOptions::default(),
    );
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let result = &analysis.modules[0].resources[2];
    for name in ["direct", "copied", "splat", "can", "fallback", "dynamic"] {
        let value = result.value(name).unwrap();
        assert!(value.is_unknown(), "{name}: {value:?}");
        assert!(!value.is_error(), "{name}: {value:?}");
    }
}

#[test]
fn concrete_count_instances_have_numeric_addresses_values_and_exact_edges() {
    let analysis = analyze(
        r#"
resource "test_node" "zero" { count = 0 }
resource "test_node" "one" {
  count = 1
  value = count.index
}

resource "test_node" "many" {
  count = 3
  value = count.index
}
resource "test_link" "links" {
  count = 3
  value = test_node.many[count.index].value
  id = test_node.many[count.index].id
}
"#,
        &[],
        AnalyzeOptions::default(),
    );
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let resources = &analysis.modules[0].resources;
    assert_eq!(resources.len(), 7);
    for (i, resource) in resources.iter().enumerate() {
        let index = if i == 0 { 0 } else { (i - 1) % 3 };
        assert_eq!(resource.id.key, Some(InstanceKey::Index(index as u64)));
        assert!(resource.address.ends_with(&format!("[{index}]")));
        assert_eq!(
            resource.body.value("value").and_then(Value::as_number),
            Some(index as f64)
        );
    }
    let graph = ResourceGraph::new(&analysis).expect("graph within default limits");
    for i in 1..4 {
        assert_eq!(graph.neighbours[i], vec![(i + 3, Truth::True)]);
    }
}

#[test]
fn counted_module_outputs_and_resource_splats_preserve_each_instance() {
    let analysis = analyze(
        r#"
module "child" {
  source = "./child"
  count = 3
  index = count.index
}
resource "test_link" "result" {
  selected = module.child[1].index
  all = module.child[*].index
  legacy = module.child.*.index[2]
  ids = module.child[*].ids
}
"#,
        &[(
            "child/main.tf",
            r#"
variable "index" {}
resource "test_node" "n" {
  count = 2
  value = var.index * 10 + count.index
}
output "index" { value = var.index }
output "ids" { value = test_node.n[*].value }
"#,
        )],
        AnalyzeOptions::default(),
    );
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let r = &analysis.modules[0].resources[0];
    assert_eq!(r.value("selected").unwrap().as_number(), Some(1.0));
    assert_eq!(r.value("legacy").unwrap().as_number(), Some(2.0));
    let all = r.body.value("all").unwrap().as_list().unwrap();
    assert_eq!(
        all.iter().map(Value::as_number).collect::<Vec<_>>(),
        vec![Some(0.0), Some(1.0), Some(2.0)]
    );
    let ids = r.body.value("ids").unwrap().as_list().unwrap();
    for (i, values) in ids.iter().enumerate() {
        assert_eq!(
            values
                .as_list()
                .unwrap()
                .iter()
                .map(Value::as_number)
                .collect::<Vec<_>>(),
            vec![Some((i * 10) as f64), Some((i * 10 + 1) as f64)]
        );
    }
    assert_eq!(analysis.modules[2].address.as_ref(), "module.child[1]");
}

#[test]
fn count_collections_invalid_indices_and_limits_are_explicit() {
    let analysis = analyze(
        r#"
variable "unknown" {}
resource "test_node" "n" {
  count = 2
  value = count.index
}
resource "test_node" "unknown" { count = var.unknown }
resource "test_node" "large" { count = 65 }
resource "test_link" "l" {
  size = length(test_node.n)
  values = [for n in test_node.n : n.value]
  missing = can(test_node.n[2].value)
  invalid = can(test_node.n[-1].value)
}
"#,
        &[],
        AnalyzeOptions::default(),
    );
    let r = analysis.modules[0].resources.last().unwrap();
    assert_eq!(r.value("size").unwrap().as_number(), Some(2.0));
    assert_eq!(r.value("missing").unwrap().as_bool(), Some(false));
    assert_eq!(r.value("invalid").unwrap().as_bool(), Some(false));
    assert_eq!(
        r.body.value("values").unwrap().as_list().unwrap()[1].as_number(),
        Some(1.0)
    );
    assert_eq!(analysis.modules[0].resources.len(), 5);
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-count")
    );
    for count in ["-1", "1.5", "null", "true", "\"bad\""] {
        let source = format!("resource \"test_node\" \"bad\" {{ count = {count} }}");
        let a = analyze(&source, &[], AnalyzeOptions::default());
        assert!(
            a.diagnostics.iter().any(|d| d.code == "invalid-count"),
            "{count}"
        );
    }
}

#[test]
fn nested_expansion_has_a_root_budget() {
    let a = analyze(
        "module \"a\" {\nsource = \"./child\"\ncount = 4\n}",
        &[(
            "child/main.tf",
            "resource \"test_node\" \"n\" { count = 4 }",
        )],
        AnalyzeOptions {
            max_instances: 12,
            ..AnalyzeOptions::default()
        },
    );
    assert!(a.modules.iter().map(|m| m.resources.len()).sum::<usize>() <= 12);
    assert!(a.diagnostics.iter().any(|d| d.code == "coverage-expansion"));
}

#[test]
fn whole_objects_and_collection_selections_keep_exact_instance_dependencies() {
    let a = analyze(
        r#"
resource "test_node" "n" {
  count = 3
  value = count.index
}
locals {
  all = test_node.n
  selected = test_node.n[1]
}
resource "test_link" "l" {
  from_list = local.all[1].value
  from_object = local.selected.value
}
"#,
        &[],
        AnalyzeOptions::default(),
    );
    let r = a.modules[0].resources.last().unwrap();
    assert_eq!(r.value("from_list").unwrap().as_number(), Some(1.0));
    assert_eq!(r.value("from_object").unwrap().as_number(), Some(1.0));
    let g = ResourceGraph::new(&a).expect("graph within default limits");
    assert_eq!(g.neighbours[3], vec![(1, Truth::True)]);
}

#[test]
fn skipped_expansions_are_unknown_instead_of_empty() {
    let a = analyze(
        r#"
resource "test_node" "n" { count = 3 }
resource "test_link" "l" {
  size = length(test_node.n)
  present = can(test_node.n[0].value)
}
"#,
        &[],
        AnalyzeOptions {
            max_instances: 2,
            ..AnalyzeOptions::default()
        },
    );
    let r = a.modules[0].resources.last().unwrap();
    assert!(r.value("size").unwrap().as_number().is_none());
    assert!(r.value("present").unwrap().as_bool().is_none());
}

#[test]
fn bare_splats_and_conditional_objects_keep_direct_resource_identity() {
    let a = analyze(
        r#"
variable "pick" {}
resource "test_node" "a" { value = {item = 1} }
resource "test_node" "b" { value = {item = 2} }
resource "test_node" "n" {
  count = 2
  value = count.index
  choice = var.pick ? test_node.a.value : test_node.b.value
}
locals { all = test_node.n[*] }
resource "test_link" "l" {
  value = local.all[1].value
  choice = local.all[1].choice.item
}
"#,
        &[],
        AnalyzeOptions::default(),
    );
    assert_eq!(
        a.modules[0].resources[4]
            .value("value")
            .unwrap()
            .as_number(),
        Some(1.0)
    );
    let g = ResourceGraph::new(&a).expect("graph within default limits");
    assert_eq!(g.neighbours[4].len(), 1, "{:?}", g.neighbours[4]);
    assert_eq!(g.neighbours[4][0].0, 3);
}

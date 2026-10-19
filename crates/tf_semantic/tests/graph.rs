use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tf_eval::Truth;
use tf_semantic::{AnalyzeOptions, FileTable, analyze_module, graph::ResourceGraph};

fn edges(files: &[(&str, &str)]) -> Vec<(String, String, Truth)> {
    let files = FileTable::with_overlay(
        files
            .iter()
            .map(|(p, s)| (PathBuf::from(format!("graph-test/{p}")), Arc::from(*s))),
    );
    let analysis = analyze_module(Path::new("graph-test"), &AnalyzeOptions::default(), &files);
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    let graph = ResourceGraph::new(&analysis);
    let mut edges = Vec::new();
    for (i, neighbours) in graph.neighbours.iter().enumerate() {
        for &(j, certainty) in neighbours {
            if i < j {
                edges.push((
                    graph.resources[i].address.to_string(),
                    graph.resources[j].address.to_string(),
                    certainty,
                ));
            }
        }
    }
    edges
}

#[test]
fn dependencies_are_not_literal_equality_or_transitive_resource_identity() {
    let result = edges(&[(
        "main.tf",
        r#"
resource "test_node" "a" { name = "same" }
resource "test_node" "literal" { name = "same" }
resource "test_node" "b" { name = upper(test_node.a.name) }
resource "test_node" "c" { name = test_node.b.name }
resource "test_node" "d" { depends_on = [test_node.c] }
"#,
    )]);
    assert_eq!(
        result,
        vec![
            ("test_node.a".into(), "test_node.b".into(), Truth::True),
            ("test_node.b".into(), "test_node.c".into(), Truth::True),
            ("test_node.c".into(), "test_node.d".into(), Truth::True),
        ]
    );
}

#[test]
fn instance_keys_locals_and_module_outputs_keep_edges() {
    let result = edges(&[
        (
            "main.tf",
            r#"
module "child" { source = "./child" }
locals { selected = module.child.id }
resource "test_link" "selected" { id = local.selected }
"#,
        ),
        (
            "child/main.tf",
            r#"
resource "test_node" "n" { for_each = toset(["a", "b"]) }
output "id" { value = test_node.n["b"].id }
"#,
        ),
    ]);
    assert_eq!(
        result,
        vec![(
            "test_link.selected".into(),
            "module.child.test_node.n[\"b\"]".into(),
            Truth::True
        )]
    );
}

#[test]
fn unknown_indices_and_optional_targets_do_not_prove_connections() {
    let result = edges(&[(
        "main.tf",
        r#"
variable "key" { type = string }
resource "test_node" "n" { for_each = toset(["a", "b"]) }
resource "test_link" "unknown" { id = test_node.n[var.key].id }
"#,
    )]);
    assert_eq!(result.len(), 2);
    assert!(result.iter().all(|(_, _, t)| *t == Truth::Tainted));
}

#[test]
fn dependencies_survive_the_explanation_limit() {
    let mut text = "resource \"test_node\" \"n\" {}\nlocals {\nx0 = test_node.n.id\n".to_string();
    for i in 1..90 {
        text.push_str(&format!("x{i} = local.x{}\n", i - 1));
    }
    text.push_str("}\nresource \"test_link\" \"l\" { id = local.x89 }");
    assert_eq!(edges(&[("main.tf", &text)]).len(), 1);
}

#[test]
fn conditional_reference_targets_remain_possible_even_for_equal_values() {
    let result = edges(&[(
        "main.tf",
        r#"
variable "pick" { type = bool }
resource "test_node" "a" { name = "same" }
resource "test_node" "b" { name = "same" }
resource "test_link" "l" { target = var.pick ? test_node.a.name : test_node.b.name }
"#,
    )]);
    assert_eq!(result.len(), 2);
    assert!(result.iter().all(|(_, _, truth)| *truth == Truth::Tainted));
}

#[test]
fn whole_collection_and_transformed_containers_keep_dependencies() {
    let result = edges(&[(
        "main.tf",
        r#"
resource "test_node" "n" { for_each = toset(["a", "b"]) }
resource "test_link" "whole" { depends_on = [test_node.n] }
resource "test_link" "length" { size = length([test_node.n["a"].id]) }
"#,
    )]);
    assert_eq!(result.len(), 3, "{result:?}");
    assert!(result.iter().all(|(_, _, truth)| *truth == Truth::True));
}

#[test]
fn a_field_taken_from_a_local_object_does_not_carry_sibling_dependencies() {
    let result = edges(&[(
        "main.tf",
        r#"
resource "test_node" "a" {}
resource "test_node" "b" {}
locals { cfg = { a = test_node.a.id, b = test_node.b.id, lit = "x" } }
resource "test_link" "a" { id = local.cfg.a }
resource "test_link" "lit" { id = local.cfg.lit }
resource "test_link" "all" { ids = values(local.cfg) }
"#,
    )]);
    assert_eq!(
        result,
        vec![
            ("test_node.a".into(), "test_link.a".into(), Truth::True),
            ("test_node.a".into(), "test_link.lit".into(), Truth::True),
            ("test_node.a".into(), "test_link.all".into(), Truth::True),
            ("test_node.b".into(), "test_link.lit".into(), Truth::True),
            ("test_node.b".into(), "test_link.all".into(), Truth::True),
        ]
    );
}

#[test]
fn indexed_reference_to_unexpanded_count_is_uncertain_not_absent() {
    let result = edges(&[(
        "main.tf",
        r#"
resource "test_node" "n" { count = 2 }
resource "test_link" "l" { target = test_node.n[0].id }
"#,
    )]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].2, Truth::Unknown);
}

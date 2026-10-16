use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tf_eval::Truth;
use tf_semantic::{FileTable, graph::ResourceGraph};

#[test]
fn plan_configuration_recovers_known_value_edges_through_outputs_and_inputs() {
    let resource = |address: &str, module: &str, ty: &str, name: &str, after| {
        json!({
            "address":address,"module_address":module,"mode":"managed","type":ty,"name":name,
            "change":{"actions":["create"],"after":after,"after_unknown":{}}
        })
    };
    let plan = json!({"format_version":"1.2", "resource_changes":[
        resource("test_node.root","","test_node","root",json!({"id":"known-root"})),
        resource("module.child.test_link.in","module.child","test_link","in",json!({"target":"known-root"})),
        resource("module.child.test_node.out","module.child","test_node","out",json!({"id":"known-child"})),
        resource("test_link.out","","test_link","out",json!({"target":"known-child"}))
    ],"configuration":{"root_module":{
        "resources":[{"address":"test_node.root"},{"address":"test_link.out","expressions":{"target":{"references":["module.child.id","module.child"]}}}],
        "module_calls":{"child":{"expressions":{"target":{"references":["test_node.root.id","test_node.root"]}},"module":{
            "resources":[{"address":"test_node.out"},{"address":"test_link.in","expressions":{"target":{"references":["var.target"]}}}],
            "outputs":{"id":{"expression":{"references":["test_node.out.id","test_node.out"]}}}
        }}
    }}}});
    let files = FileTable::with_overlay([(
        PathBuf::from("graph-plan/plan.json"),
        Arc::from(plan.to_string()),
    )]);
    let analysis = tf_plan::load_plan(
        Path::new("graph-plan/plan.json"),
        &tf_plan::PlanOptions::default(),
        &files,
    )
    .unwrap();
    let graph = ResourceGraph::new(&analysis);
    assert!(graph.resources.iter().all(|r| r.dependencies_complete));
    let mut edges: Vec<_> = graph
        .neighbours
        .iter()
        .enumerate()
        .flat_map(|(i, n)| {
            n.iter()
                .filter(move |(j, _)| i < *j)
                .map(move |(j, t)| (i, *j, *t))
        })
        .collect();
    edges.sort_by_key(|&(i, j, _)| (i, j));
    let names: Vec<_> = edges
        .iter()
        .map(|&(i, j, t)| {
            (
                graph.resources[i].address.as_ref(),
                graph.resources[j].address.as_ref(),
                t,
            )
        })
        .collect();
    assert_eq!(
        names,
        vec![
            ("test_node.root", "module.child.test_link.in", Truth::True),
            ("test_link.out", "module.child.test_node.out", Truth::True)
        ]
    );
}

#[test]
fn missing_plan_configuration_is_explicitly_incomplete() {
    let plan = json!({"format_version":"1.2","resource_changes":[{"address":"test_node.n","mode":"managed","type":"test_node","name":"n","change":{"actions":["create"],"after":{}}}]});
    let files = FileTable::with_overlay([(
        PathBuf::from("graph-incomplete/plan.json"),
        Arc::from(plan.to_string()),
    )]);
    let analysis = tf_plan::load_plan(
        Path::new("graph-incomplete/plan.json"),
        &tf_plan::PlanOptions::default(),
        &files,
    )
    .unwrap();
    assert!(!analysis.modules[0].resources[0].dependencies_complete);
}

#[test]
fn source_defaults_differing_from_plan_inputs_cannot_prove_local_edges() {
    let plan = json!({"format_version":"1.2","variables":{"pick":{"value":"b"}},"resource_changes":[
        {"address":"test_link.l","mode":"managed","type":"test_link","name":"l","change":{"actions":["create"],"after":{"target":"planned-b"}}}
    ],"configuration":{"root_module":{"resources":[{"address":"test_link.l","expressions":{"target":{"references":["local.target"]}}}]}}});
    let files = FileTable::with_overlay([
        (
            PathBuf::from("graph-inputs/plan.json"),
            Arc::from(plan.to_string()),
        ),
        (
            PathBuf::from("graph-inputs/main.tf"),
            Arc::from(
                r#"
variable "pick" { default = "a" }
resource "test_node" "n" { for_each = toset(["a", "b"]) }
locals { target = test_node.n[var.pick].id }
resource "test_link" "l" { target = local.target }
"#,
            ),
        ),
    ]);
    let analysis = tf_plan::load_plan(
        Path::new("graph-inputs/plan.json"),
        &tf_plan::PlanOptions::default(),
        &files,
    )
    .unwrap();
    let link = &analysis.modules[0].resources[0];
    assert!(!link.dependencies_complete);
    assert!(link.dependencies.is_empty());
}

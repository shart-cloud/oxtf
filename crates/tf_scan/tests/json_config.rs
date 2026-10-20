use std::{path::PathBuf, sync::Arc};

use tf_linter::ScanStatus;
use tf_scan::{ScanOutput, ScanRequest, scan};

fn run(files: &[(&str, &str)]) -> ScanOutput {
    let root = PathBuf::from("/nonexistent/oxtf-json-config");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog.bundled = false;
    req.overlay = files
        .iter()
        .map(|(p, s)| (root.join(p), Arc::from(*s)))
        .collect();
    scan(req).unwrap()
}

#[test]
fn json_resource_expression_matches_hcl_and_points_to_original_source() {
    let json = r#"{
  "variable": {"encrypted": {"default": false}},
  "resource": {"aws_db_instance": {"db": {
    "storage_encrypted": "${var.encrypted}"
  }}}
}"#;
    let hcl = r#"
variable "encrypted" { default = false }
resource "aws_db_instance" "db" { storage_encrypted = var.encrypted }
"#;
    let a = run(&[("main.tf.json", json)]);
    let b = run(&[("main.tf", hcl)]);
    assert_eq!(
        a.result.status(),
        ScanStatus::Complete,
        "{:?}",
        a.result.diagnostics
    );
    let ra = a.record();
    let rb = b.record();
    assert_eq!(ra.findings.len(), 1);
    assert_eq!(ra.findings[0].rule, rb.findings[0].rule);
    let resource = &a.analyses[0].modules[0].resources[0];
    assert_eq!(
        resource.value("storage_encrypted").unwrap().as_bool(),
        Some(false)
    );
    let at = resource.attr("storage_encrypted").unwrap().span;
    assert_eq!(
        at.span.source_text(json),
        r#""storage_encrypted": "${var.encrypted}""#
    );
    assert!(ra.findings[0].fix_hint.is_none());
}

#[test]
fn literal_fields_types_and_reference_fields_use_their_configuration_context() {
    let out = run(&[
        (
            "main.tf.json",
            r#"{
          "variable": {
            "flag": {"type": "bool", "default": "false", "description": "${literal"},
            "text": {"default": {"${key}": "${literal"}}
          },
          "module": {"child": {"source": "./child", "flag": "${var.flag}",
            "providers": {"aws": "aws.west"}}},
          "resource": {"test": {
            "upstream": {"value": "${var.text}", "provider": "aws.west"},
            "downstream": {"flag": "${module.child.flag}", "depends_on": ["test.upstream"]}
          }},
          "output": {"flag": {"value": "${var.flag}", "description": "${literal"}}
        }"#,
        ),
        (
            "child/main.tf.json",
            r#"{
          "variable": {"flag": {"type": "bool"}},
          "output": {"flag": {"value": "${var.flag}"}}
        }"#,
        ),
    ]);
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    let resources = &out.analyses[0].modules[0].resources;
    assert_eq!(
        resources[0]
            .value("value")
            .unwrap()
            .get_attr("${key}")
            .as_str(),
        Some("${literal")
    );
    assert_eq!(resources[1].value("flag").unwrap().as_bool(), Some(false));
    assert_eq!(resources[1].dependencies.len(), 1);
}

#[test]
fn schema_blocks_repeat_in_source_order_and_dynamic_content_is_evaluated() {
    let out = run(&[(
        "main.tf.json",
        r#"{
      "resource": {"aws_s3_bucket": {"b": {
        "lifecycle_rule": {"id": "first", "enabled": true},
        "lifecycle_rule": [{"id": "second", "enabled": false}],
        "dynamic": {"lifecycle_rule": {
          "for_each": ["third"], "iterator": "item",
          "content": {"id": "${item.value}", "enabled": true}
        }},
        "lifecycle": {"prevent_destroy": true}
      }}}
    }"#,
    )]);
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    let r = &out.analyses[0].modules[0].resources[0];
    let ids: Vec<_> = r
        .body
        .blocks_of("lifecycle_rule")
        .map(|b| b.body.attr("id").unwrap().value.as_str().unwrap())
        .collect();
    assert_eq!(ids, ["first", "second", "third"]);
    assert!(r.attr("lifecycle").is_none());
}

#[test]
fn escaped_templates_and_diagnostics_map_back_to_json_bytes() {
    let source = r#"{
      "variable": {"flag": {"default": false}},
      "resource": {"test": {"r": {
        "flag": "\u0024{\u0076ar.flag}",
        "literal": "a\n\"b\"\\c \ud83d\ude80 $${keep}",
        "object": "${jsondecode(\"{\\\"ok\\\": false}\")}",
        "text": "hello %{ if true }yes%{ endif }"
      }}}
    }"#;
    let out = run(&[("main.tf.json", source)]);
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    let r = &out.analyses[0].modules[0].resources[0];
    assert_eq!(r.value("flag").unwrap().as_bool(), Some(false));
    assert_eq!(
        r.value("literal").unwrap().as_str(),
        Some("a\n\"b\"\\c 🚀 ${keep}")
    );
    assert_eq!(
        r.value("object").unwrap().get_attr("ok").as_bool(),
        Some(false)
    );
    assert_eq!(r.value("text").unwrap().as_str(), Some("hello yes"));
    let reference = out.analyses[0].modules[0]
        .references
        .iter()
        .find(|r| matches!(r.to, tf_semantic::SymbolRef::Variable(_)))
        .unwrap();
    assert_eq!(reference.at.span.source_text(source), r#"\u0076ar.flag"#);
    let bad = r#"{"resource":{"test":{"r":{"value":"🚀\n${\u0076ar.flag + }"}}}}"#;
    let out = run(&[("main.tf.json", bad)]);
    assert_eq!(out.result.status(), ScanStatus::Failed);
    let diagnostic = out
        .result
        .diagnostics
        .iter()
        .find(|d| d.code == "parse-error")
        .unwrap();
    let at = diagnostic.at.unwrap();
    assert_eq!(at.span.source_text(bad), "}");
}

#[test]
fn malformed_json_and_duplicate_attributes_fail_with_original_locations() {
    for source in [
        r#"{"resource":{"test":{"r":{"value":1,"value":2}}}}"#,
        r#"{"locals":{"x":{"a":1,"a":2}}}"#,
        r#"{"variable":{"x":{"default":{"a":1,"a":2}}}}"#,
        r#"{"resource":{"test":{"r":false}}}"#,
        r#"{"resource":{"test":{"r":{"value":"${1 + }"}}}}"#,
        r#"{"resource":"invalid"}"#,
        r#"{"locals":{"x":1,}}"#,
    ] {
        let out = run(&[("main.tf.json", source)]);
        assert_eq!(out.result.status(), ScanStatus::Failed, "{source}");
        assert!(
            out.result
                .diagnostics
                .iter()
                .any(|d| d.code == "parse-error" && d.at.is_some())
        );
    }
}

#[test]
fn plan_mapping_discovers_json_only_sources_and_suppresses_json_fixes() {
    let root = PathBuf::from("/nonexistent/oxtf-json-plan");
    let plan = serde_json::json!({
        "format_version":"1.2",
        "resource_changes":[{"address":"aws_db_instance.db","mode":"managed",
          "type":"aws_db_instance","name":"db",
          "change":{"actions":["create"],"after":{"storage_encrypted":false},
            "after_unknown":{},"after_sensitive":{}}}]
    })
    .to_string();
    let source = r#"{"resource":{"aws_db_instance":{"db":{"storage_encrypted":false}}}}"#;
    let mut req = ScanRequest::plan(root.join("plan.json"), None);
    req.catalog.bundled = false;
    req.overlay = vec![
        (root.join("plan.json"), Arc::from(plan)),
        (root.join("main.tf.json"), Arc::from(source)),
    ];
    let out = scan(req).unwrap();
    let record = out.record();
    assert_eq!(record.findings.len(), 1);
    assert!(record.findings[0].location.file.ends_with("main.tf.json"));
    assert!(record.findings[0].fix_hint.is_none());
}

#[test]
fn installed_json_only_module_and_mixed_source_keep_graph_and_sensitivity() {
    let out = run(&[
        (
            "main.tf",
            r#"
module "db" { source = "acme/db/aws" }
resource "test" "consumer" { value = module.db.value }
"#,
        ),
        (
            ".terraform/modules/modules.json",
            r#"{"Modules":[
          {"Key":"db","Source":"acme/db/aws","Version":"1.0.0","Dir":".terraform/modules/db"}
        ]}"#,
        ),
        (
            ".terraform/modules/db/main.tf.json",
            r#"{
          "variable":{"secret":{"default":"json-private-secret","sensitive":true}},
          "resource":{"aws_db_instance":{"db":{"storage_encrypted":false,"password":"${var.secret}"}}},
          "output":{"value":{"value":"${aws_db_instance.db.id}"}}
        }"#,
        ),
    ]);
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    let record = out.record();
    assert!(record.findings[0].package.is_some());
    assert!(record.findings[0].fix_hint.is_none());
    assert!(
        !serde_json::to_string(&record)
            .unwrap()
            .contains("json-private-secret")
    );
    let graph = tf_semantic::graph::ResourceGraph::new(&out.analyses[0]);
    assert_eq!(graph.resources.len(), 2);
    assert_eq!(graph.neighbours[0].len(), 1);
}

#[test]
fn body_arrays_comments_and_attribute_objects_keep_their_distinct_meanings() {
    let source = r#"[
      {"//":"first","locals":[{"x":"value"},{"y":"${local.x}"}]},
      {"resource":{"aws_security_group":{"sg":{
        "//":{"ignored":"${bad"},
        "ingress":[{"from_port":80,"to_port":80,"protocol":"tcp","cidr_blocks":["0.0.0.0/0"]}],
        "tags":{"${local.y}":"${local.x}","//":"kept"}
      }}}}
    ]"#;
    let out = run(&[("main.tf.json", source)]);
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    let r = &out.analyses[0].modules[0].resources[0];
    assert!(r.attr("ingress").is_some());
    assert_eq!(
        r.value("tags").unwrap().get_attr("value").as_str(),
        Some("value")
    );
    assert_eq!(
        r.value("tags").unwrap().get_attr("//").as_str(),
        Some("kept")
    );
}

#[test]
fn provider_metadata_keeps_its_provider_label() {
    let out = run(&[(
        "main.tf.json",
        r#"{
      "terraform":{"provider_meta":{"test":{"module_name":"fixture"}}}
    }"#,
    )]);
    assert_eq!(out.result.status(), ScanStatus::Complete);
    let store = tf_semantic::ModuleStore::new();
    let def = store.module(&out.result.files, &out.analyses[0].root_dir);
    let meta = def.files[0]
        .1
        .body
        .find_block("terraform")
        .unwrap()
        .body
        .find_block("provider_meta")
        .unwrap();
    assert_eq!(meta.label(0), Some("test"));
    assert!(meta.body.find_attribute("module_name").is_some());
}

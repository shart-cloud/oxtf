use std::{path::PathBuf, sync::Arc};

use tf_linter::ScanStatus;
use tf_scan::{ScanRequest, scan};

fn request(files: &[(&str, &str)]) -> ScanRequest {
    let root = PathBuf::from("/nonexistent/oxtf-overrides");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog.bundled = false;
    req.overlay = files
        .iter()
        .map(|(p, s)| (root.join(p), Arc::from(*s)))
        .collect();
    req
}

#[test]
fn type_overrides_preserve_nulls_in_previously_converted_defaults() {
    let out = scan(request(&[
        (
            "main.tf",
            r#"
variable "config" {
  type = object({ encrypted = optional(bool) })
  default = {}
}
resource "aws_db_instance" "db" {
  storage_encrypted = coalesce(var.config.encrypted, false)
}
"#,
        ),
        (
            "override.tf",
            r#"
variable "config" { type = object({ encrypted = optional(bool, true) }) }
"#,
        ),
    ]))
    .unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    assert_eq!(
        out.analyses[0].modules[0].resources[0]
            .value("storage_encrypted")
            .unwrap()
            .as_bool(),
        Some(false)
    );
    assert_eq!(out.record().findings.len(), 1);
}

#[test]
fn replacement_defaults_use_original_optional_defaults_after_type_overrides() {
    for default in ["{}", "{a=null}"] {
        let overriding = format!("variable \"x\" {{ default = {default} }}\n");
        let out = scan(request(&[
            (
                "main.tf",
                r#"
variable "x" {
  type = object({a=optional(string, "original")})
  default = {}
}
resource "test" "r" { value = var.x.a }
"#,
            ),
            (
                "a_override.tf",
                r#"variable "x" { type = object({a=optional(string, "overridden")}) }"#,
            ),
            ("z_override.tf", &overriding),
        ]))
        .unwrap();
        assert_eq!(out.result.status(), ScanStatus::Complete);
        assert_eq!(
            out.analyses[0].modules[0].resources[0]
                .value("value")
                .unwrap()
                .as_str(),
            Some("original")
        );
    }
}

#[test]
fn override_conversion_checks_types_of_nulls_and_empty_collections() {
    for (base_type, default, final_type, valid) in [
        ("string", "null", "list(string)", false),
        ("bool", "null", "number", false),
        ("object({a=string})", "null", "string", false),
        ("list(bool)", "[]", "list(number)", false),
        ("map(bool)", "{}", "map(number)", false),
        ("set(bool)", "[]", "set(number)", false),
        ("list(object({a=string}))", "[]", "list(number)", false),
        ("string", "null", "bool", true),
        ("any", "null", "list(string)", true),
        ("list(bool)", "[]", "list(string)", true),
    ] {
        let base = format!("variable \"x\" {{\ntype={base_type}\ndefault={default}\n}}\n");
        let overriding = format!("variable \"x\" {{ type={final_type} }}\n");
        let out = scan(request(&[("main.tf", &base), ("override.tf", &overriding)])).unwrap();
        assert_eq!(
            out.result.status(),
            if valid {
                ScanStatus::Complete
            } else {
                ScanStatus::Failed
            },
            "{base_type} {default} -> {final_type}"
        );
    }
}

#[test]
fn dynamic_override_constraints_preserve_empty_collection_element_types() {
    for (base_type, default, middle_type, final_type) in [
        ("list(bool)", "[]", "list(any)", "list(number)"),
        ("list(bool)", "null", "list(any)", "list(number)"),
        ("map(bool)", "{}", "map(any)", "map(number)"),
        ("set(bool)", "[]", "set(any)", "set(number)"),
    ] {
        let base = format!("variable \"x\" {{\ntype={base_type}\ndefault={default}\n}}\n");
        let middle = format!("variable \"x\" {{ type={middle_type} }}\n");
        let last = format!("variable \"x\" {{ type={final_type} }}\n");
        let out = scan(request(&[
            ("main.tf", &base),
            ("a_override.tf", &middle),
            ("z_override.tf", &last),
        ]))
        .unwrap();
        assert_eq!(
            out.result.status(),
            ScanStatus::Failed,
            "{base_type} {default}"
        );
    }
}

#[test]
fn override_conversion_preserves_collection_types_through_any_and_nested_values() {
    for (base_type, default, final_type) in [
        ("list(string)", r#"["a", "b"]"#, "tuple([string, string])"),
        ("set(string)", r#"["a", "b"]"#, "tuple([string, string])"),
        (
            "object({xs=list(string)})",
            r#"{xs=["a", "b"]}"#,
            "object({xs=tuple([string, string])})",
        ),
        (
            "list(list(string))",
            r#"[["a", "b"]]"#,
            "list(tuple([string, string]))",
        ),
    ] {
        let base = format!("variable \"v\" {{\n type = {base_type}\n default = {default}\n}}\n");
        let last = format!("variable \"v\" {{ type = {final_type} }}\n");
        let out = scan(request(&[
            ("main.tf", &base),
            ("a_override.tf", "variable \"v\" { type = any }\n"),
            ("z_override.tf", &last),
        ]))
        .unwrap();
        assert_eq!(
            out.result.status(),
            ScanStatus::Failed,
            "{base_type} -> {final_type}"
        );
    }
    let out = scan(request(&[
        (
            "main.tf",
            "variable \"v\" {\n type = list(string)\n default = [\"a\", \"b\"]\n}\n",
        ),
        (
            "override.tf",
            "variable \"v\" {\n type = tuple([string, string])\n default = [\"c\", \"d\"]\n}\n",
        ),
    ]))
    .unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
}

#[test]
fn effective_attributes_keep_their_files_and_fix_the_winning_assignment() {
    let req = request(&[
        (
            "main.tf",
            r#"resource "aws_db_instance" "db" {
  storage_encrypted = true
  identifier = "kept"
}"#,
        ),
        (
            "a_override.tf.json",
            r#"{"resource":{"aws_db_instance":{"db":{"storage_encrypted":true}}}}"#,
        ),
        (
            "z_override.tf",
            r#"resource "aws_db_instance" "db" { storage_encrypted = false }"#,
        ),
    ]);
    let out = scan(req.try_clone().unwrap()).unwrap();
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    assert_eq!(out.result.stats.resources, 1);
    let r = &out.analyses[0].modules[0].resources[0];
    assert_eq!(r.value("identifier").unwrap().as_str(), Some("kept"));
    for (name, expected) in [
        ("storage_encrypted", "z_override.tf"),
        ("identifier", "main.tf"),
    ] {
        let at = r.attr(name).unwrap().span;
        assert!(out.result.files.get(at.file).path.ends_with(expected));
        assert!(
            at.span
                .source_text(&out.result.files.get(at.file).text)
                .starts_with(name)
        );
    }
    let record = out.record();
    assert_eq!(record.findings.len(), 1);
    assert!(record.findings[0].location.file.ends_with("z_override.tf"));
    let fixed = tf_scan::fix(req, &record.findings[0].fingerprint, None).unwrap();
    assert!(fixed.verified, "{:?}", fixed.verification_errors);
    assert!(fixed.edit.file.ends_with("z_override.tf"));
    assert!(fixed.edit.text.contains("storage_encrypted = true"));
}

#[test]
fn overridden_variable_defaults_preserve_provenance_and_choose_a_writable_fix() {
    for (name, source, expected_fix) in [
        (
            "override.tf",
            r#"variable "encrypted" { default = false }"#,
            "override.tf",
        ),
        (
            "override.tf.json",
            r#"{"variable":{"encrypted":{"default":false}}}"#,
            "main.tf",
        ),
    ] {
        let req = request(&[
            (
                "main.tf",
                r#"variable "encrypted" { default = true }
resource "aws_db_instance" "db" { storage_encrypted = var.encrypted }
"#,
            ),
            (name, source),
        ]);
        let out = scan(req.try_clone().unwrap()).unwrap();
        assert_eq!(out.result.status(), ScanStatus::Complete);
        let record = out.record();
        let f = &record.findings[0];
        let default = f
            .provenance
            .iter()
            .find(|s| s.kind == "variable_default")
            .unwrap();
        assert!(default.location.file.ends_with(name));
        let fixed = tf_scan::fix(req, &f.fingerprint, None).unwrap();
        assert!(fixed.verified, "{:?}", fixed.verification_errors);
        assert!(
            fixed.edit.file.ends_with(expected_fix),
            "{:?}",
            fixed.edit.file
        );
    }
}

#[test]
fn locals_merge_by_name_and_module_values_keep_each_origin() {
    let req = request(&[
        (
            "main.tf",
            r#"locals { first = true }
module "child" {
  source = "./child"
  encrypted = true
}

resource "aws_db_instance" "db" { storage_encrypted = module.child.encrypted }
"#,
        ),
        ("other.tf", r#"locals { second = true }"#),
        (
            "override.tf.json",
            r#"{
          "locals":{"first":false,"second":"${local.first}"},
          "module":{"child":{"encrypted":"${local.second}"}}
        }"#,
        ),
        (
            "child/main.tf",
            r#"variable "encrypted" {}
output "encrypted" { value = true }
"#,
        ),
        (
            "child/override.tf",
            r#"output "encrypted" { value = var.encrypted }"#,
        ),
    ]);
    let out = scan(req).unwrap();
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    let f = &out.record().findings[0];
    for (kind, file) in [
        ("local", "override.tf.json"),
        ("module_argument", "override.tf.json"),
        ("output", "child/override.tf"),
    ] {
        let steps: Vec<_> = f.provenance.iter().filter(|s| s.kind == kind).collect();
        assert!(!steps.is_empty(), "{kind}");
        assert!(
            steps.iter().all(|s| s.location.file.ends_with(file)),
            "{steps:?}"
        );
    }
    for module in &out.analyses[0].modules {
        for reference in module.references.iter() {
            let sf = out.result.files.get(reference.at.file);
            let text = reference.at.span.source_text(&sf.text);
            assert!(
                text.starts_with("local.")
                    || text.starts_with("var.")
                    || text.starts_with("module."),
                "{text:?}"
            );
        }
    }
}

#[test]
fn nested_blocks_replace_by_type_but_lifecycle_attributes_merge() {
    let req = request(&[
        (
            "main.tf.json",
            r#"{"resource":{"aws_s3_bucket":{"b":{
          "lifecycle_rule":[{"id":"old-1","enabled":true},{"id":"old-2","enabled":true}],
          "logging":{"target_bucket":"kept"},
          "lifecycle":{"prevent_destroy":true,"ignore_changes":["tags"]},
          "connection":{"type":"ssh","user":"base"}
        }}}}"#,
        ),
        (
            "override.tf",
            r#"resource "aws_s3_bucket" "b" {
  lifecycle_rule {
    id = "new"
    enabled = true
    expiration { days = 2 }
  }
  lifecycle { create_before_destroy = true }
  connection { type = "winrm" }
}"#,
        ),
    ]);
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    let r = &out.analyses[0].modules[0].resources[0];
    let blocks: Vec<_> = r.body.blocks_of("lifecycle_rule").collect();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].body.value("id").unwrap().as_str(), Some("new"));
    assert_eq!(
        r.body
            .blocks_of("logging")
            .next()
            .unwrap()
            .body
            .value("target_bucket")
            .unwrap()
            .as_str(),
        Some("kept")
    );
    assert!(
        out.result
            .files
            .get(blocks[0].body.span.file)
            .path
            .ends_with("override.tf")
    );
    let store = tf_semantic::ModuleStore::new();
    let def = store.module(&out.result.files, &out.analyses[0].root_dir);
    let body = &def.resources[0].block.body;
    let lifecycle = &body.find_block("lifecycle").unwrap().body;
    assert!(lifecycle.find_attribute("prevent_destroy").is_some());
    assert!(lifecycle.find_attribute("ignore_changes").is_some());
    assert!(lifecycle.find_attribute("create_before_destroy").is_some());
    let connection = &body.find_block("connection").unwrap().body;
    assert!(connection.find_attribute("user").is_none());
}

#[test]
fn terraform_settings_merge_per_component_and_providers_match_aliases() {
    let req = request(&[
        (
            "main.tf",
            r#"terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
    google = { source = "hashicorp/google" }
  }
  backend "s3" { bucket = "old" }
}
provider "aws" {
  alias = "west"
  region = "us-west-1"
}
provider "aws" {
  alias = "east"
  region = "us-east-1"
}
"#,
        ),
        ("settings.tf", r#"terraform { required_version = "< 2.0" }"#),
        (
            "a_override.tf.json",
            r#"{
          "terraform":{
            "required_version":">= 1.5",
            "required_providers":{"aws":{"source":"hashicorp/aws","version":"~> 6.0"}},
            "cloud":{"organization":"example"}
          },
          "provider":{"aws":[{"alias":"east","region":"us-east-2"},{"region":"us-west-2"}]}
        }"#,
        ),
        (
            "z_override.tf",
            r#"provider "aws" { region = "eu-west-1" }"#,
        ),
    ]);
    let out = scan(req).unwrap();
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    let store = tf_semantic::ModuleStore::new();
    let def = store.module(&out.result.files, &out.analyses[0].root_dir);
    let settings: Vec<_> = def
        .files
        .iter()
        .flat_map(|(_, f)| f.body.blocks())
        .filter(|b| b.block_type() == "terraform")
        .collect();
    let versions: Vec<_> = settings
        .iter()
        .flat_map(|b| b.body.attributes())
        .filter(|a| a.key.name == "required_version")
        .collect();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].value.as_string_literal(), Some(">= 1.5"));
    assert!(
        !settings
            .iter()
            .any(|b| b.body.find_block("backend").is_some())
    );
    let settings = settings
        .iter()
        .find(|b| b.body.find_block("cloud").is_some())
        .unwrap();
    let providers = &settings.body.find_block("required_providers").unwrap().body;
    assert!(providers.find_attribute("google").is_some());
    assert!(providers.find_attribute("aws").is_some());
    let mut regions = std::collections::BTreeMap::new();
    for b in def
        .files
        .iter()
        .flat_map(|(_, f)| f.body.blocks())
        .filter(|b| b.block_type() == "provider")
    {
        let alias = b
            .body
            .find_attribute("alias")
            .and_then(|a| a.value.as_string_literal())
            .unwrap_or("");
        regions.insert(
            alias,
            b.body
                .find_attribute("region")
                .unwrap()
                .value
                .as_string_literal()
                .unwrap(),
        );
    }
    assert_eq!(
        regions,
        [
            ("", "eu-west-1"),
            ("east", "us-east-2"),
            ("west", "us-west-1")
        ]
        .into()
    );
}

#[test]
fn invalid_overrides_and_ordinary_duplicates_are_errors() {
    for (base, filename, other) in [
        (
            r#"resource "test" "r" {}"#,
            "extra.tf",
            r#"resource "test" "r" {}"#,
        ),
        (
            r#"resource "test" "r" {}"#,
            "override.tf",
            r#"resource "test" "missing" {}"#,
        ),
        (
            r#"locals { x = 1 }"#,
            "override.tf",
            r#"locals { missing = 2 }"#,
        ),
        (
            r#"resource "test" "r" {}"#,
            "override.tf",
            r#"resource "test" "r" { depends_on = [test.r] }"#,
        ),
        (
            r#"resource "test" "r" { count = 1 }"#,
            "override.tf",
            r#"resource "test" "r" { for_each = {} }"#,
        ),
        (
            r#"output "x" { value = true }"#,
            "override.tf",
            r#"output "x" { depends_on = [test.r] }"#,
        ),
        (
            r#"variable "x" {}"#,
            "override.tf",
            "variable \"x\" {\nvalidation {\ncondition = true\nerror_message = \"No\"\n}\n}",
        ),
        (
            r#"resource "test" "r" {}"#,
            "override.tf",
            "resource \"test\" \"r\" {\nvalue = 1\nvalue = 2\n}",
        ),
        (
            "",
            "override.tf",
            r#"moved { from = test.old
to = test.new }"#,
        ),
        (
            r#"provider "aws" {}"#,
            "override.tf",
            r#"provider "aws" { alias = "missing" }"#,
        ),
    ] {
        let out = scan(request(&[("main.tf", base), (filename, other)])).unwrap();
        assert_eq!(
            out.result.status(),
            ScanStatus::Failed,
            "{base}\n{filename}\n{other}"
        );
        assert!(out.result.diagnostics.iter().any(|d| d.at.is_some()));
    }
}

#[test]
fn variable_type_changes_convert_the_previous_default_and_reject_incompatible_values() {
    let out = scan(request(&[
        ("main.tf", "variable \"x\" {\ntype = number\ndefault = \"01\"\n}\nresource \"test\" \"r\" { value = var.x }"),
        ("override.tf.json", r#"{"variable":{"x":{"type":"string"}}}"#),
    ])).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    assert_eq!(
        out.analyses[0].modules[0].resources[0]
            .value("value")
            .unwrap()
            .as_str(),
        Some("1")
    );
    for (base_type, base_default, overriding) in [
        ("string", "\"invalid\"", r#"{"type":"bool"}"#),
        ("number", "1", r#"{"default":"invalid"}"#),
        ("string", "\"ok\"", r#"{"default":null,"nullable":false}"#),
        ("list(number)", "[1]", r#"{"default":["bad"]}"#),
        ("object({a=number})", "{a=1}", r#"{"default":{}}"#),
    ] {
        let base = format!("variable \"x\" {{\ntype = {base_type}\ndefault = {base_default}\n}}\n");
        let override_json = format!("{{\"variable\":{{\"x\":{overriding}}}}}");
        let out = scan(request(&[
            ("main.tf", &base),
            ("override.tf.json", &override_json),
        ]))
        .unwrap();
        assert_eq!(
            out.result.status(),
            ScanStatus::Failed,
            "{base}\n{override_json}"
        );
        assert!(
            out.result
                .diagnostics
                .iter()
                .any(|d| d.message.contains("default") && d.at.is_some())
        );
    }
}

#[test]
fn lifecycle_empty_ignore_list_and_all_follow_the_pinned_loader() {
    for (base_ignore, overriding_ignore, expected) in
        [("[input]", "[]", "input"), ("all", r#"["input"]"#, "all")]
    {
        let base = format!(
            "resource \"test\" \"r\" {{\nlifecycle {{ ignore_changes = {base_ignore} }}\n}}\n"
        );
        let overriding = format!(
            r#"{{"resource":{{"test":{{"r":{{"lifecycle":{{"ignore_changes":{overriding_ignore}}}}}}}}}}}"#
        );
        let out = scan(request(&[
            ("main.tf", &base),
            ("override.tf.json", &overriding),
        ]))
        .unwrap();
        assert_eq!(out.result.status(), ScanStatus::Complete);
        let store = tf_semantic::ModuleStore::new();
        let def = store.module(&out.result.files, &out.analyses[0].root_dir);
        let attribute = def.resources[0]
            .block
            .body
            .find_block("lifecycle")
            .unwrap()
            .body
            .find_attribute("ignore_changes")
            .unwrap();
        let file = def.origins.file(attribute, def.resources[0].file);
        assert!(out.result.files.get(file).path.ends_with("main.tf"));
        assert!(
            attribute
                .span
                .source_text(&out.result.files.get(file).text)
                .contains(expected)
        );
    }
}

#[test]
fn ignored_override_meta_arguments_preserve_the_base_configuration() {
    let out = scan(request(&[
        (
            "main.tf",
            r#"
module "child" {
  source = "./child"
  providers = { test = test.base }
}
resource "test" "r" {
  lifecycle { replace_triggered_by = [test.base] }
}
"#,
        ),
        ("child/main.tf", ""),
        (
            "override.tf.json",
            r#"{
          "module":{"child":{"providers":{}}},
          "resource":{"test":{"r":{"lifecycle":{"replace_triggered_by":["test.other"]}}}}
        }"#,
        ),
    ]))
    .unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    let store = tf_semantic::ModuleStore::new();
    let def = store.module(&out.result.files, &out.analyses[0].root_dir);
    for a in [
        def.module_calls[0]
            .block
            .body
            .find_attribute("providers")
            .unwrap(),
        def.resources[0]
            .block
            .body
            .find_block("lifecycle")
            .unwrap()
            .body
            .find_attribute("replace_triggered_by")
            .unwrap(),
    ] {
        let file = def.origins.file(a, def.resources[0].file);
        let sf = out.result.files.get(file);
        assert!(sf.path.ends_with("main.tf"));
        assert!(a.span.source_text(&sf.text).contains("test.base"));
    }
}

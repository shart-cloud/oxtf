use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value as J, json};
use tf_linter::ScanStatus;
use tf_scan::{ScanRequest, scan};

const ROOT: &str = "/nonexistent/oxtf-installed";
const CHILD: &str = r#"
variable "encrypted" { default = false }
resource "aws_db_instance" "this" { storage_encrypted = var.encrypted }
output "encrypted" { value = var.encrypted }
"#;
const MAIN: &str = r#"
module "db" {
  source = "acme/db/aws"
  version = "~> 1.2"
}
resource "aws_db_instance" "consumer" { storage_encrypted = module.db.encrypted }
"#;

fn request(main: &str, dir: &str, source: &str, version: Option<&str>) -> ScanRequest {
    let root = PathBuf::from(ROOT);
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = tf_scan::Catalog::seed();
    let manifest = json!({"Modules":[
        {"Key":"","Source":"","Dir":"."},
        {"Key":"db","Source":source,"Version":version,"Dir":dir}
    ]});
    req.overlay = vec![
        (root.join("main.tf"), Arc::from(main)),
        (
            root.join(".terraform/modules/modules.json"),
            Arc::from(manifest.to_string()),
        ),
        (root.join(dir).join("main.tf"), Arc::from(CHILD)),
    ];
    req
}

fn manifest(req: &mut ScanRequest, records: J) {
    let sf = req
        .overlay
        .iter_mut()
        .find(|(p, _)| p.ends_with("modules.json"))
        .unwrap();
    sf.1 = Arc::from(json!({"Modules":records}).to_string());
}

#[test]
fn manifest_and_definition_refusal_report_storage_without_stale_installation_warnings() {
    let req = request(MAIN, ".terraform/modules/db", "acme/db/aws", Some("1.2.3"));
    let full = scan(req.try_clone().unwrap()).unwrap();
    assert_eq!(full.result.status(), ScanStatus::Complete);
    let cost = full.result.files.input_budget().stats().collection_bytes;
    for keep_models in [false, true] {
        for allowance in (1..cost).step_by(64).chain([cost - 1, cost, cost + 1]) {
            let mut req = req.try_clone().unwrap();
            req.keep_models = keep_models;
            req.limits = tf_limits::Limits::default()
                .with_collection_bytes(allowance)
                .unwrap();
            let out = scan(req).unwrap();
            let limited = allowance < cost;
            assert_eq!(
                out.result.status(),
                if limited {
                    ScanStatus::Incomplete
                } else {
                    ScanStatus::Complete
                }
            );
            let diagnostics = &out.result.diagnostics;
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|d| d.code == "coverage-storage")
                    .count(),
                usize::from(limited)
            );
            assert!(
                !diagnostics
                    .iter()
                    .any(|d| matches!(d.code, "parse-error" | "coverage-remote-module"))
            );
            assert!(out.result.files.input_budget().stats().collection_bytes <= allowance);
        }
    }
}

fn finding_id(req: ScanRequest) -> String {
    let out = scan(req).unwrap();
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    out.record()
        .findings
        .iter()
        .find(|f| f.package.is_some())
        .unwrap()
        .fingerprint
        .clone()
}

#[test]
fn installed_registry_modules_evaluate_inputs_outputs_and_report_origin() {
    let req = request(
        MAIN,
        ".terraform/modules/db",
        "registry.terraform.io/acme/db/aws",
        Some("1.2.3"),
    );
    let out = scan(req.try_clone().unwrap()).unwrap();
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    assert_eq!(out.result.stats.resources, 2);
    let record = out.record();
    assert_eq!(record.findings.len(), 2);
    let remote = record
        .findings
        .iter()
        .find(|f| f.package.is_some())
        .unwrap();
    let package = remote.package.as_ref().unwrap();
    assert_eq!(package.source, "registry.terraform.io/acme/db/aws");
    assert_eq!(package.version.as_deref(), Some("1.2.3"));
    assert_eq!(package.file, "main.tf");
    assert_eq!(package.calls[0].file, format!("{ROOT}/main.tf"));
    assert!(remote.fix_hint.is_none());
    assert!(tf_scan::fix(req, &remote.fingerprint, None).is_err());
    let child = &out.analyses[0].modules[1];
    let hint = tf_linter::FixHint::set(&child.resources[0], "storage_encrypted", json!(true));
    assert!(
        tf_scan::apply_fix_at(
            &out,
            &PathBuf::from(ROOT),
            &hint,
            tf_scan::FixSite::Attribute
        )
        .unwrap_err()
        .contains("installed module")
    );
}

#[test]
fn cache_location_does_not_change_fingerprints() {
    let first = finding_id(request(
        MAIN,
        ".terraform/modules/db",
        "acme/db/aws",
        Some("1.2.3"),
    ));
    let second = finding_id(request(
        MAIN,
        "/different/cache/package",
        "acme/db/aws",
        Some("1.2.3"),
    ));
    assert_eq!(first, second);
    assert_ne!(
        first,
        finding_id(request(
            MAIN,
            ".terraform/modules/db",
            "acme/db/aws",
            Some("1.3.0")
        ))
    );
}

#[test]
fn git_sources_and_subdirectories_use_installed_files() {
    for (declared, recorded) in [
        (
            "git::https://example.com/db.git//modules/db?ref=v1",
            "git::https://example.com/db.git//modules/db?ref=v1",
        ),
        (
            "github.com/acme/db//modules/db?ref=v1",
            "git::https://github.com/acme/db.git//modules/db?ref=v1",
        ),
    ] {
        let main = format!("module \"db\" {{ source = \"{declared}\" }}");
        let out = scan(request(
            &main,
            ".terraform/modules/db/modules/db",
            recorded,
            None,
        ))
        .unwrap();
        assert_eq!(
            out.result.status(),
            ScanStatus::Complete,
            "{:?}",
            out.result.diagnostics
        );
        assert_eq!(out.result.stats.resources, 1);
    }
}

#[test]
fn stale_or_missing_installations_remain_incomplete() {
    for constraint in ["", ">= nope", "^1.2"] {
        let out = scan(request(
            &MAIN.replace("~> 1.2", constraint),
            ".terraform/modules/db",
            "acme/db/aws",
            Some("1.2.3"),
        ))
        .unwrap();
        assert_eq!(out.result.status(), ScanStatus::Incomplete, "{constraint}");
    }
    for (source, version) in [
        ("acme/other/aws", Some("1.2.3")),
        ("acme/db/aws", Some("2.0.0")),
        ("acme/db/aws", None),
        ("acme/db/aws", Some("invalid")),
    ] {
        let out = scan(request(MAIN, ".terraform/modules/db", source, version)).unwrap();
        assert_eq!(out.result.status(), ScanStatus::Incomplete);
        assert_eq!(out.result.stats.resources, 1);
        assert!(
            out.result
                .diagnostics
                .iter()
                .any(|d| d.code == "coverage-remote-module" && d.at.is_some())
        );
    }
    for kind in [
        "missing_manifest",
        "missing_dir",
        "missing_entry",
        "duplicate",
        "invalid",
    ] {
        let mut req = request(MAIN, ".terraform/modules/db", "acme/db/aws", Some("1.2.3"));
        match kind {
            "missing_manifest" => req.overlay.retain(|(p, _)| !p.ends_with("modules.json")),
            "missing_dir" => req.overlay.retain(|(p, _)| !p.ends_with("db/main.tf")),
            "missing_entry" => manifest(&mut req, json!([])),
            "duplicate" => manifest(
                &mut req,
                json!([
                    {"Key":"db","Source":"acme/db/aws","Dir":"x"},
                    {"Key":"db","Source":"acme/db/aws","Dir":"y"}
                ]),
            ),
            _ => req.overlay[1].1 = Arc::from("{invalid"),
        }
        let out = scan(req).unwrap();
        assert_eq!(out.result.status(), ScanStatus::Incomplete, "{kind}");
    }
}

#[test]
fn repeated_calls_have_distinct_inputs_and_group_installed_findings() {
    let main = r#"
module "db" {
  source = "acme/db/aws"
  for_each = { open = false, closed = true }
  encrypted = each.value
}
module "other" { source = "acme/db/aws" }
"#;
    let mut req = request(main, ".terraform/modules/db", "acme/db/aws", Some("1.2.3"));
    req.overlay.push((
        PathBuf::from(ROOT).join(".terraform/modules/other/main.tf"),
        Arc::from(CHILD),
    ));
    manifest(
        &mut req,
        json!([
            {"Key":"db","Source":"acme/db/aws","Version":"1.2.3","Dir":".terraform/modules/db"},
            {"Key":"other","Source":"acme/db/aws","Version":"1.2.3","Dir":".terraform/modules/other"}
        ]),
    );
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    assert_eq!(out.result.stats.resources, 3);
    let record = out.record();
    assert_eq!(record.findings.len(), 1);
    assert_eq!(record.findings[0].occurrences.len(), 2);
    assert!(
        record.findings[0]
            .occurrences
            .iter()
            .all(|o| o.package.is_some())
    );
    assert!(
        record.findings[0]
            .occurrences
            .iter()
            .all(|o| !o.address.contains("closed"))
    );
}

#[test]
fn nested_local_and_remote_modules_resolve_by_static_call_path() {
    let mut req = request(
        "module \"db\" { source = \"acme/db/aws\" }",
        ".terraform/modules/db/modules/db",
        "acme/db/aws",
        Some("1.2.3"),
    );
    req.overlay[2].1 = Arc::from(
        "module \"local\" { source = \"../shared\" }\noutput \"encrypted\" { value = module.local.encrypted }",
    );
    let root = PathBuf::from(ROOT);
    req.overlay.push((root.join(".terraform/modules/db/modules/shared/main.tf"),
        Arc::from("module \"remote\" { source = \"git::https://example.com/leaf.git?ref=v1\" }\noutput \"encrypted\" { value = module.remote.encrypted }")));
    req.overlay.push((
        root.join(".terraform/modules/leaf/main.tf"),
        Arc::from(CHILD),
    ));
    manifest(
        &mut req,
        json!([
            {"Key":"db","Source":"acme/db/aws","Version":"1.2.3","Dir":".terraform/modules/db/modules/db"},
            {"Key":"db.local","Source":"../shared","Dir":".terraform/modules/db/modules/shared"},
            {"Key":"db.local.remote","Source":"git::https://example.com/leaf.git?ref=v1","Dir":".terraform/modules/leaf"}
        ]),
    );
    let out = scan(req.try_clone().unwrap()).unwrap();
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    assert_eq!(out.analyses[0].modules[0].outputs.len(), 0);
    assert_eq!(
        out.analyses[0].modules[1].outputs[0].value.as_bool(),
        Some(false)
    );
    assert_eq!(
        out.record().findings[0]
            .package
            .as_ref()
            .unwrap()
            .calls
            .len(),
        3
    );
    let mut records: J = serde_json::from_str(&req.overlay[1].1).unwrap();
    records["Modules"][1]["Source"] = json!("../old");
    req.overlay[1].1 = Arc::from(records.to_string());
    assert_eq!(scan(req).unwrap().result.status(), ScanStatus::Incomplete);
}

#[test]
fn custom_data_directory_and_recursive_overlays_do_not_add_cache_roots() {
    let mut req = request(MAIN, "cache/modules/db", "acme/db/aws", Some("1.2.3"));
    req.data_dir = Some("cache".into());
    req.overlay[1].0 = PathBuf::from(ROOT).join("cache/modules/modules.json");
    req.input = tf_scan::ScanInput::Dirs {
        paths: vec![ROOT.into()],
        recursive: true,
    };
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    assert_eq!(out.result.stats.roots, 1);
    assert_eq!(out.result.stats.resources, 2);
}

#[test]
fn disabled_remote_call_does_not_read_a_bad_manifest() {
    let mut req = request(
        "module \"db\" {\nsource = \"acme/db/aws\"\ncount = 0\n}",
        ".terraform/modules/db",
        "acme/db/aws",
        None,
    );
    req.overlay[1].1 = Arc::from("invalid");
    assert_eq!(scan(req).unwrap().result.status(), ScanStatus::Complete);
}

#[test]
fn installed_sensitive_outputs_are_masked() {
    let main = r#"module "db" { source = "acme/db/aws" }
resource "aws_db_instance" "consumer" {
  password = module.db.secret
  storage_encrypted = false
}"#;
    let mut req = request(main, ".terraform/modules/db", "acme/db/aws", Some("1.2.3"));
    req.overlay[2].1 =
        Arc::from("output \"secret\" {\nvalue = \"private-secret\"\nsensitive = true\n}");
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    let password = out.analyses[0].modules[0].resources[0]
        .value("password")
        .unwrap();
    assert_eq!(password.as_str(), Some("private-secret"));
    assert!(password.is_sensitive());
    assert!(
        !serde_json::to_string(&out.record())
            .unwrap()
            .contains("private-secret")
    );
}

#[test]
fn installed_outputs_preserve_resource_dependency_edges() {
    let main = "module \"db\" { source = \"acme/db/aws\" }\nresource \"test\" \"consumer\" { target = module.db.id }";
    let mut req = request(main, ".terraform/modules/db", "acme/db/aws", Some("1.2.3"));
    req.overlay[2].1 = Arc::from(
        "resource \"aws_s3_bucket\" \"b\" {}\noutput \"id\" { value = aws_s3_bucket.b.id }",
    );
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    let graph = tf_semantic::graph::ResourceGraph::new(&out.analyses[0]);
    let consumer = graph
        .resources
        .iter()
        .position(|r| r.address.as_ref() == "test.consumer")
        .unwrap();
    assert!(graph.neighbours[consumer].iter().any(|(i, certainty)| {
        graph.resources[*i].address.as_ref() == "module.db.aws_s3_bucket.b"
            && *certainty == tf_eval::Truth::True
    }));
}

#[test]
fn multiple_roots_resolve_the_same_call_name_independently() {
    let first = request(MAIN, ".terraform/modules/db", "acme/db/aws", Some("1.2.3"));
    let mut second = request(
        &MAIN.replace("acme/db/aws", "acme/other/aws"),
        ".terraform/modules/db",
        "acme/other/aws",
        Some("1.2.3"),
    );
    second.overlay[2].1 = Arc::from(CHILD.replace("default = false", "default = true"));
    let roots = [
        PathBuf::from("/nonexistent/first-root"),
        PathBuf::from("/nonexistent/second-root"),
    ];
    let mut req = ScanRequest::dirs(roots.to_vec(), false);
    req.catalog = tf_scan::Catalog::seed();
    for (request, root) in [first, second].into_iter().zip(&roots) {
        req.overlay.extend(
            request
                .overlay
                .into_iter()
                .map(|(p, text)| (root.join(p.strip_prefix(ROOT).unwrap()), text)),
        );
    }
    let out = scan(req).unwrap();
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    assert_eq!(out.result.stats.roots, 2);
    assert_eq!(out.result.stats.resources, 4);
    assert_eq!(out.record().findings.len(), 2);
    assert!(
        out.record()
            .findings
            .iter()
            .all(|f| f.root == roots[0].to_string_lossy())
    );
}

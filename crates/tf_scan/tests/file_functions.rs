use std::{path::PathBuf, sync::Arc};

use tf_eval::Value;
use tf_linter::ScanStatus;
use tf_scan::{Catalog, ScanRequest, scan};

fn evaluate(files: &[(&str, &str)]) -> (tf_scan::ScanOutput, Value) {
    let root = PathBuf::from("/nonexistent/oxtf-file-functions");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = Catalog::default();
    req.keep_models = true;
    req.overlay = files
        .iter()
        .map(|(p, s)| (root.join(p), Arc::from(*s)))
        .collect();
    let out = scan(req).unwrap();
    let v = out.analyses[0].modules[0].resources[0]
        .value("input")
        .unwrap();
    (out, v)
}

#[test]
fn file_and_template_functions_use_overlays_and_the_scanned_root() {
    let (out, v) = evaluate(&[
        (
            "main.tf",
            r#"resource "terraform_data" "r" {
  input = {
    text = file("${path.module}/text.txt")
    hash = filesha256("text.txt")
    encoded = filebase64("text.txt")
    template = templatefile("data.tftpl", { ports = [80, 443], name = "web" })
  }
}"#,
        ),
        ("text.txt", "abc"),
        (
            "data.tftpl",
            "%{ for port in ports }${name}:${port};%{ endfor }",
        ),
    ]);
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    assert_eq!(v.get_attr("text").to_str().as_deref(), Some("abc"));
    assert_eq!(
        v.get_attr("hash").to_str().as_deref(),
        Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(v.get_attr("encoded").to_str().as_deref(), Some("YWJj"));
    assert_eq!(
        v.get_attr("template").to_str().as_deref(),
        Some("web:80;web:443;")
    );
}

#[test]
fn templates_preserve_types_uncertainty_and_sensitivity() {
    let (out, v) = evaluate(&[
        (
            "main.tf",
            r#"variable "unknown" {}
resource "terraform_data" "r" {
  input = {
    typed = templatefile("value.tftpl", { value = [true, 2] })
    unknown = templatefile("value.tftpl", { value = var.unknown })
    secret = templatefile("value.tftpl", { value = sensitive("secret") })
    choice = file(var.unknown ? "one.txt" : "two.txt")
  }
}"#,
        ),
        ("value.tftpl", "${value}"),
        ("one.txt", "one"),
        ("two.txt", "two"),
    ]);
    assert_eq!(out.result.status(), ScanStatus::Complete);
    assert_eq!(v.get_attr("typed").as_list().unwrap().len(), 2);
    assert!(v.get_attr("unknown").is_tainted());
    assert!(v.get_attr("secret").is_sensitive());
    assert!(matches!(v.get_attr("choice").kind, tf_eval::Kind::OneOf(_)));
}

#[test]
fn file_errors_are_catchable_but_unhandled_errors_fail_analysis() {
    for expression in [
        r#"file("missing.txt")"#,
        r#"templatefile("bad.tftpl", {})"#,
        r#"templatefile("recursive.tftpl", {})"#,
        r#"templatefile("external.tftpl", {})"#,
        r#"templatefile("unused.tftpl", {})"#,
    ] {
        let src = format!("resource \"terraform_data\" \"r\" {{ input = {expression} }}");
        let files = [
            ("main.tf", src.as_str()),
            ("bad.tftpl", "${missing}"),
            ("recursive.tftpl", "${templatefile(\"value.tftpl\", {})}"),
            ("external.tftpl", "${path.module}"),
            ("value.tftpl", "value"),
            ("unused.tftpl", "${true ? \"ok\" : missing}"),
        ];
        let (out, v) = evaluate(&files);
        assert!(v.is_error(), "{expression}: {v}");
        assert_eq!(out.result.status(), ScanStatus::Failed, "{expression}");
        let caught = format!(
            "resource \"terraform_data\" \"r\" {{ input = try({expression}, \"fallback\") }}"
        );
        let mut files = files;
        files[0].1 = &caught;
        let (out, v) = evaluate(&files);
        assert_eq!(out.result.status(), ScanStatus::Complete, "{expression}");
        assert_eq!(v.to_str().as_deref(), Some("fallback"));
    }
}

#[test]
fn child_module_file_paths_are_relative_to_the_scanned_root() {
    let root = PathBuf::from("oxtf-file-child/example");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = Catalog::default();
    req.keep_models = true;
    req.overlay = vec![
        (
            root.join("main.tf"),
            Arc::from("module \"child\" { source = \"../shared\" }\n"),
        ),
        (
            root.join("../shared/main.tf"),
            Arc::from(
                "resource \"terraform_data\" \"r\" { input = file(\"${path.module}/payload.txt\") }",
            ),
        ),
        (root.join("../shared/payload.txt"), Arc::from("child")),
    ];
    let out = scan(req).unwrap();
    assert_eq!(
        out.result.status(),
        ScanStatus::Complete,
        "{:?}",
        out.result.diagnostics
    );
    assert_eq!(
        out.analyses[0].modules[1].resources[0]
            .value("input")
            .unwrap()
            .to_str()
            .as_deref(),
        Some("child")
    );
}

#[test]
fn binary_hashes_do_not_use_lossy_text_decoding() {
    let root = std::env::temp_dir().join(format!("oxtf-binary-functions-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("binary.bin"), [0xff, 0x00, 0x80]).unwrap();
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = Catalog::default();
    req.keep_models = true;
    req.overlay = vec![(
        root.join("main.tf"),
        Arc::from(
            r#"resource "terraform_data" "r" {
 input = { binary = filebase64("binary.bin"), hash = filemd5("binary.bin"), text = can(file("binary.bin")) }
}"#,
        ),
    )];
    let out = scan(req).unwrap();
    let value = out.analyses[0].modules[0].resources[0]
        .value("input")
        .unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    assert_eq!(value.get_attr("binary").to_str().as_deref(), Some("/wCA"));
    assert_eq!(value.get_attr("text").as_bool(), Some(false));
    assert_eq!(
        value.get_attr("hash").to_str().as_deref(),
        Some("60cdccd4000580a3c394b8ad6ea9b899")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn fetched_package_file_reads_preserve_the_package_boundary() {
    let root = PathBuf::from("/nonexistent/oxtf-file-package");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = Catalog::default();
    req.keep_models = true;
    let manifest = serde_json::json!({"Modules": [{
        "Key": "pkg", "Source": "example/pkg/aws", "Version": "1.0.0",
        "Dir": ".terraform/modules/pkg/sub", "OxtfPackageRoot": ".terraform/modules/pkg"
    }]})
    .to_string();
    req.overlay = [
        ("main.tf", "module \"pkg\" { source = \"example/pkg/aws\" }"),
        (".terraform/modules/modules.json", &manifest),
        (
            ".terraform/modules/pkg/sub/main.tf",
            r#"resource "terraform_data" "r" {
 input = { allowed = file("${path.module}/../payload.txt"), blocked = file("outside.txt") }
}"#,
        ),
        (".terraform/modules/pkg/payload.txt", "package content"),
        ("outside.txt", "private caller content"),
    ]
    .into_iter()
    .map(|(path, text)| (root.join(path), Arc::from(text)))
    .collect();
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Incomplete);
    let value = out.analyses[0].modules[1].resources[0]
        .value("input")
        .unwrap();
    assert_eq!(
        value.get_attr("allowed").to_str().as_deref(),
        Some("package content")
    );
    assert!(matches!(
        value.get_attr("blocked").origin(),
        Some(tf_eval::Origin::Limit(_))
    ));
}

#[test]
fn sensitive_file_contents_are_redacted_from_finding_evidence() {
    let root = PathBuf::from("/nonexistent/oxtf-sensitive-file");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = Catalog::seed();
    req.overlay = vec![
        (
            root.join("main.tf"),
            Arc::from(
                r#"resource "aws_iam_policy" "r" { policy = sensitive(file("policy.json")) }"#,
            ),
        ),
        (
            root.join("policy.json"),
            Arc::from(
                r#"{"Statement":[{"Sid":"private-file-secret","Effect":"Allow","Action":"*","Resource":"*"}]}"#,
            ),
        ),
    ];
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    let record = out.record();
    assert_eq!(record.findings.len(), 1);
    assert!(
        !serde_json::to_string(&record)
            .unwrap()
            .contains("private-file-secret")
    );
    assert!(!tf_linter::formats::ndjson(&record).contains("private-file-secret"));
    for finding in &out.result.findings {
        assert!(
            !tf_linter::render::render_finding(&out.result.files, finding, false)
                .contains("private-file-secret")
        );
    }
}

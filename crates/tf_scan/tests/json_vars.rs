use std::path::PathBuf;
use std::sync::Arc;

use tf_linter::ScanStatus;
use tf_scan::{ScanRequest, scan};

fn request(config: &str, inputs: &[(&str, &str)]) -> ScanRequest {
    let root = PathBuf::from("/nonexistent/oxtf-json-vars");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = tf_scan::Catalog::seed();
    req.overlay.push((root.join("main.tf"), Arc::from(config)));
    req.overlay
        .extend(inputs.iter().map(|(p, s)| (root.join(p), Arc::from(*s))));
    req
}

#[test]
fn json_values_are_literal_and_match_hcl_values_with_original_spans() {
    let config = "variable \"settings\" {}\nresource \"test\" \"r\" { value = var.settings }\n";
    let json = r#"{
  "settings": {"${key}": ["${var.name}", "%{ if true }", "a\n\u263a", null, true, -1.25e2]}
}"#;
    let hcl = "settings = { \"$${key}\" = [\"$${var.name}\", \"%%{ if true }\", \"a\\n☺\", null, true, -125] }";
    let a = scan(request(config, &[("terraform.tfvars.json", json)])).unwrap();
    let b = scan(request(config, &[("terraform.tfvars", hcl)])).unwrap();
    assert_eq!(a.result.status(), ScanStatus::Complete);
    let value = a.analyses[0].modules[0].resources[0]
        .value("value")
        .unwrap();
    assert_eq!(
        value.to_str(),
        b.analyses[0].modules[0].resources[0]
            .value("value")
            .unwrap()
            .to_str()
    );
    let step = value
        .prov
        .steps()
        .into_iter()
        .find(|s| s.kind == tf_eval::StepKind::Tfvars)
        .unwrap();
    let file = a.result.files.get(step.at.file);
    assert_eq!(file.line_col(step.at.span.start), (2, 3));
    assert!(
        step.at
            .span
            .source_text(&file.text)
            .starts_with("\"settings\":")
    );
}

#[test]
fn mixed_variable_files_follow_terraform_precedence() {
    let config = "variable \"x\" { default = 0 }\nresource \"test\" \"r\" { value = var.x }";
    let inputs = [
        ("terraform.tfvars", "x = 1"),
        ("terraform.tfvars.json", r#"{"x":2}"#),
        ("a.auto.tfvars.json", r#"{"x":3}"#),
        ("b.auto.tfvars", "x = 4"),
        ("c.auto.tfvars.json", r#"{"x":5}"#),
        ("first.json", r#"{"x":6}"#),
        ("second.tfvars", "x = 7"),
    ];
    for end in 1..=5 {
        let out = scan(request(config, &inputs[..end])).unwrap();
        assert_eq!(out.result.status(), ScanStatus::Complete);
        assert_eq!(
            out.analyses[0].modules[0].resources[0]
                .value("value")
                .unwrap()
                .as_number(),
            Some(end as f64)
        );
    }
    for names in [
        ["first.json", "second.tfvars"],
        ["second.tfvars", "first.json"],
    ] {
        let mut req = request(config, &inputs);
        req.var_files = names
            .iter()
            .map(|n| PathBuf::from("/nonexistent/oxtf-json-vars").join(n))
            .collect();
        let out = scan(req).unwrap();
        let expected = if names[1] == "first.json" { 6.0 } else { 7.0 };
        assert_eq!(
            out.analyses[0].modules[0].resources[0]
                .value("value")
                .unwrap()
                .as_number(),
            Some(expected)
        );
    }
}

#[test]
fn invalid_json_is_failed_with_a_location() {
    for input in [
        "[]",
        "{\"x\":",
        r#"{"x":1,"x":2}"#,
        r#"{"x":{"a":1,"a":2}}"#,
        r#"{"x":1e400}"#,
    ] {
        let out = scan(request(
            "variable \"x\" {}\n",
            &[("terraform.tfvars.json", input)],
        ))
        .unwrap();
        assert_eq!(out.result.status(), ScanStatus::Failed, "{input}");
        assert!(
            out.result
                .diagnostics
                .iter()
                .any(|d| d.code == "parse-error" && d.at.is_some())
        );
    }
}

#[test]
fn excessive_json_depth_is_incomplete_with_a_location() {
    let deep = format!("{{\"x\":{}0{}}}", "[".repeat(200), "]".repeat(200));
    let out = scan(request(
        "variable \"x\" {}\n",
        &[("terraform.tfvars.json", &deep)],
    ))
    .unwrap();
    assert_eq!(out.result.status(), ScanStatus::Incomplete);
    assert!(
        out.result
            .diagnostics
            .iter()
            .any(|d| { d.code == "coverage-parse-limit" && d.at.is_some() })
    );
    assert!(
        !out.result
            .diagnostics
            .iter()
            .any(|d| d.code == "parse-error")
    );
}

#[test]
fn root_comments_are_ignored_and_nested_comment_keys_are_values() {
    let out = scan(request(
        "variable \"settings\" {}\nresource \"test\" \"r\" { value = var.settings }",
        &[(
            "terraform.tfvars.json",
            r#"{"//":"first","//":"second","settings":{"//":"kept"}}"#,
        )],
    ))
    .unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    let value = out.analyses[0].modules[0].resources[0]
        .value("value")
        .unwrap();
    assert_eq!(value.get_attr("//").as_str(), Some("kept"));
}

#[test]
fn json_sensitive_values_reach_rules_but_not_reports() {
    let config =
        "variable \"secret\" { sensitive = true }\nresource \"test\" \"r\" { value = var.secret }";
    let mut req = request(
        config,
        &[("terraform.tfvars.json", r#"{"secret":"private-value"}"#)],
    );
    req.catalog.rule_json.push(
        serde_json::json!({
            "name":"json-secret", "description":"Secret test", "message":"found {witness}",
            "clauses":[{"resource_types":["test"],"condition":{"op":"cmp","cmp":"eq",
                "left":{"op":"col","path":["value"]},"right":{"op":"lit","value":"private-value"}}}]
        })
        .to_string(),
    );
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Complete);
    assert_eq!(out.record().findings.len(), 1);
    assert!(
        !serde_json::to_string(&out.record())
            .unwrap()
            .contains("private-value")
    );
    let binding = out
        .result
        .files
        .load(&PathBuf::from(
            "/nonexistent/oxtf-json-vars/terraform.tfvars.json",
        ))
        .unwrap();
    assert!(
        !out.result
            .files
            .display_text(binding.id)
            .contains("private-value")
    );
}

//! Real values reach rules; sensitive evidence never reaches reports.
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value as J, json};
use tf_scan::{ScanRequest, scan};

const SECRET: &str = "DO-NOT-PRINT-SECRET";

fn rule() -> String {
    json!({
        "name": "secret-evidence", "description": "Check the configured value",
        "message": "bad value {witness}",
        "clauses": [{
            "resource_types": ["test_resource"],
            "condition": {"op": "cmp", "cmp": "eq",
                "left": {"op": "col", "path": ["value"]},
                "right": {"op": "lit", "value": SECRET}}
        }]
    })
    .to_string()
}

fn assert_redacted(out: &tf_scan::ScanOutput) {
    let record = out.record();
    assert_eq!(
        record.findings.len(),
        1,
        "rules must still see the real value"
    );
    let json = serde_json::to_string(&record).unwrap();
    assert!(!json.contains(SECRET), "{json}");
    let value = record.findings[0].configured.as_ref().unwrap();
    assert!(value.sensitive);
    assert_eq!(value.value, None);
    assert_eq!(value.display, "(sensitive)");
    let text = tf_linter::render::render_finding(&out.result.files, &out.result.findings[0], false);
    assert!(!text.contains(SECRET), "{text}");
    assert!(!tf_linter::formats::ndjson(&record).contains(SECRET));
    assert!(
        !tf_linter::formats::sarif(&record)
            .to_string()
            .contains(SECRET)
    );
}

#[test]
fn source_variables_tfvars_transformations_and_messages_are_redacted() {
    let root = PathBuf::from("/nonexistent/oxtf-sensitive");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog.rule_json.push(rule());
    req.overlay = vec![
        (
            root.join("main.tf"),
            Arc::from(
                "variable \"password\" {\n  type = string\n  sensitive = true\n}\nlocals { secret = upper(var.password) }\nresource \"test_resource\" \"r\" { value = local.secret }\n",
            ),
        ),
        (
            root.join("terraform.tfvars"),
            Arc::from(format!("password = \"{SECRET}\"\n")),
        ),
    ];
    let out = scan(req).unwrap();
    assert_eq!(
        out.analyses[0].modules[0].resources[0]
            .value("value")
            .unwrap()
            .as_str(),
        Some(SECRET)
    );
    assert_redacted(&out);
}

#[test]
fn plans_preserve_sensitive_values_for_rules_and_mask_source_context() {
    let plan = PathBuf::from("/nonexistent/oxtf-sensitive-plan/plan.json");
    let mut req = ScanRequest::plan(plan.clone(), None);
    req.catalog.rule_json.push(rule());
    req.overlay = vec![(plan, Arc::from(json!({
        "format_version": "1.2",
        "resource_changes": [{
            "address": "test_resource.r", "mode": "managed", "type": "test_resource", "name": "r",
            "change": {"actions": ["create"], "after": {"value": SECRET},
                "after_unknown": {}, "after_sensitive": {"value": true}}
        }]
    }).to_string()))];
    assert_redacted(&scan(req).unwrap());
}

#[test]
fn sensitive_provider_attributes_are_masked_even_beside_unrelated_findings() {
    let root = PathBuf::from("/nonexistent/oxtf-sensitive-schema");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = tf_scan::Catalog::seed();
    req.overlay = vec![(
        root.join("main.tf"),
        Arc::from(format!(
            "resource \"aws_db_instance\" \"db\" {{\n  password = \"{SECRET}\"\n  storage_encrypted = false\n}}\n"
        )),
    )];
    let out = scan(req).unwrap();
    assert!(
        out.analyses[0].modules[0].resources[0]
            .value("password")
            .unwrap()
            .is_sensitive()
    );
    let text = tf_linter::render::render_finding(&out.result.files, &out.result.findings[0], false);
    assert!(!text.contains(SECRET), "{text}");
    let fp = &out.record().findings[0].fingerprint;
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = tf_scan::Catalog::seed();
    req.overlay = vec![(
        root.join("main.tf"),
        Arc::from(format!(
            "resource \"aws_db_instance\" \"db\" {{\n  password = \"{SECRET}\"\n  storage_encrypted = false\n}}\n"
        )),
    )];
    let fix = tf_scan::fix(req, fp, None).unwrap();
    assert!(fix.verified);
    assert!(!fix.diff.contains(SECRET));
    assert!(
        fix.edit.text.contains(SECRET),
        "applying an edit must retain the password"
    );
}

#[test]
fn sensitive_default_crosses_module_output_and_json_boundaries() {
    let root = PathBuf::from("/nonexistent/oxtf-sensitive-module");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog.rule_json.push(rule());
    req.overlay = vec![
        (
            root.join("main.tf"),
            Arc::from(
                "module \"child\" { source = \"./child\" }\nresource \"test_resource\" \"r\" { value = jsondecode(module.child.secret).value }\n",
            ),
        ),
        (
            root.join("child/main.tf"),
            Arc::from(format!(
                "variable \"password\" {{\n default = \"{SECRET}\"\n sensitive = true\n}}\noutput \"secret\" {{ value = jsonencode({{ value = var.password }}) }}\n"
            )),
        ),
    ];
    let out = scan(req).unwrap();
    assert_redacted(&out);
    let record: J = serde_json::to_value(out.record()).unwrap();
    assert_eq!(record["findings"][0]["configured"]["sensitive"], true);
}

#[test]
fn native_messages_mask_sensitive_witnesses() {
    let root = PathBuf::from("/nonexistent/oxtf-sensitive-native");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = tf_scan::Catalog::seed();
    req.overlay = vec![(
        root.join("main.tf"),
        Arc::from(
            "resource \"aws_security_group\" \"sg\" {\ningress {\nfrom_port = 22\nto_port = 22\nprotocol = \"tcp\"\ncidr_blocks = sensitive([\"0.0.0.0/0\"])\n}\n}\n",
        ),
    )];
    let out = scan(req).unwrap();
    assert_eq!(out.result.findings.len(), 1);
    // The static description lists public CIDRs; witness-derived wording
    // and evidence must not disclose which sensitive value was inspected.
    let record = out.record();
    let finding = &record.findings[0];
    assert!(
        finding
            .message
            .ends_with("(policy message redacted: sensitive input)")
    );
    assert!(finding.configured.as_ref().unwrap().sensitive);
    assert_eq!(finding.configured.as_ref().unwrap().value, None);
    assert!(
        !serde_json::to_string(&finding.provenance)
            .unwrap()
            .contains("0.0.0.0/0")
    );
}

#[test]
fn sensitive_instance_keys_are_rejected_without_exposure() {
    let root = PathBuf::from("/nonexistent/oxtf-sensitive-keys");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.overlay = vec![(
        root.join("main.tf"),
        Arc::from(format!(
            "resource \"aws_db_instance\" \"db\" {{\nfor_each = sensitive({{ \"{SECRET}\" = true }})\nstorage_encrypted = false\n}}\n"
        )),
    )];
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), tf_linter::ScanStatus::Failed);
    assert!(
        !serde_json::to_string(&out.record())
            .unwrap()
            .contains(SECRET)
    );
    for f in &out.result.findings {
        assert!(!tf_linter::render::render_finding(&out.result.files, f, false).contains(SECRET));
    }
}

use std::path::PathBuf;
use tf_linter::{ScanStatus, record::ScanRecord};
use tf_scan::{Catalog, ScanComparison, ScanRequest, scan};

const ROOT: &str = "/nonexistent/oxtf-agent-contract";
fn request(source: &str) -> ScanRequest {
    let mut req = ScanRequest::dirs(vec![ROOT.into()], false);
    req.catalog = Catalog::seed();
    req.selection = Some(vec!["aws-rds-unencrypted".into()]);
    req.overlay = vec![(PathBuf::from(ROOT).join("main.tf"), source.into())];
    req
}
fn record(source: &str) -> ScanRecord {
    scan(request(source)).unwrap().record()
}
const BAD: &str = "resource \"aws_db_instance\" \"db\" { storage_encrypted = false }";
const GOOD: &str = "resource \"aws_db_instance\" \"db\" { storage_encrypted = true }";

#[test]
fn clean_and_empty_scans_expose_executed_versus_inapplicable_rules() {
    let clean = record(GOOD);
    let c = &clean.coverage.as_ref().unwrap().rules["aws-rds-unencrypted"];
    assert_eq!(
        (c.planned, c.executed, c.completed, c.failed, c.skipped),
        (1, 1, 1, 0, 0)
    );
    assert!(clean.findings.is_empty());
    let empty = record("locals { a = 1 }");
    let c = empty.coverage.as_ref().unwrap();
    assert_eq!(c.selected_rules, 1);
    assert_eq!(c.rules["aws-rds-unencrypted"].planned, 0);
    assert_eq!(c.totals().completed, 0);
}

#[test]
fn stopped_checks_are_accounted_without_calling_them_passes() {
    let source = (0..3)
        .map(|i| {
            format!("resource \"aws_db_instance\" \"db{i}\" {{ storage_encrypted = false }}\n")
        })
        .collect::<String>();
    let mut req = request(&source);
    req.limits = req.limits.with_rule_steps(1).unwrap();
    let rec = scan(req).unwrap().record();
    let c = rec.coverage.as_ref().unwrap().totals();
    assert_eq!(c.planned, 3);
    assert!(c.skipped > 0);
    assert_eq!(c.executed, c.completed + c.failed);
    assert_eq!(c.planned, c.executed + c.skipped);
    assert_ne!(rec.status, ScanStatus::Complete);
}

#[test]
fn unresolved_inputs_keep_names_and_locations_without_values() {
    let rec = record(
        r#"
variable "encrypted" { type = bool }
variable "secret" { default = "PRIVATE_MARKER"
sensitive = true }
resource "aws_db_instance" "db" { storage_encrypted = var.encrypted }
"#,
    );
    assert_eq!(rec.status, ScanStatus::Complete);
    let inputs = &rec.roots[0].unresolved_inputs;
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].variable, "encrypted");
    assert!(inputs[0].location.line > 0);
    assert!(
        !serde_json::to_string(inputs)
            .unwrap()
            .contains("PRIVATE_MARKER")
    );
}

#[test]
fn dependency_recovery_is_machine_readable_in_all_formats() {
    let rec = record("module \"db\" { source = \"acme/db/aws\" }");
    let d = rec
        .diagnostics
        .iter()
        .find(|d| d.code == "coverage-module-not-installed")
        .unwrap();
    let action = serde_json::to_value(d.action.as_ref().unwrap()).unwrap();
    assert_eq!(action["kind"], "install_modules");
    assert_eq!(action["retryable"], false);
    let lines: Vec<serde_json::Value> = tf_linter::formats::ndjson(&rec)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(lines.iter().any(|v| v["action"] == action));
    assert_eq!(
        lines.last().unwrap()["coverage"],
        serde_json::to_value(&rec.coverage).unwrap()
    );
    let sarif = tf_linter::formats::sarif(&rec);
    assert!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["properties"]["action"] == action)
    );
}

#[test]
fn comparison_separates_fixes_regressions_and_changes_in_certainty() {
    let bad = record(BAD);
    let good = record(GOOD);
    let fixed = ScanComparison::between(&bad, &good).unwrap();
    assert!(fixed.comparable && !fixed.has_regressions());
    assert_eq!(fixed.resolved, vec![bad.findings[0].fingerprint.clone()]);
    let regression = ScanComparison::between(&good, &bad).unwrap();
    assert!(regression.has_regressions());
    let conditional = record(
        "variable \"e\" { type = bool }\nresource \"aws_db_instance\" \"db\" { storage_encrypted = var.e }",
    );
    let changed = ScanComparison::between(&conditional, &bad).unwrap();
    assert_eq!(changed.certainty_changes.len(), 1);
    assert_eq!(changed.delta.changed.len(), 1);
    assert_eq!(changed.delta.unchanged, 0);
    assert!(changed.has_regressions());
}

#[test]
fn lost_coverage_and_changed_scopes_cannot_verify_a_resolution() {
    let before = record(BAD);
    let mut cases = Vec::new();
    cases.push(record("broken = )"));
    let mut rules = request(GOOD);
    rules.selection = Some(vec![]);
    cases.push(scan(rules).unwrap().record());
    let mut legacy = record(GOOD);
    legacy.coverage = None;
    cases.push(legacy);
    let mut kind = record(GOOD);
    kind.input_kind = Some(tf_linter::record::InputKind::Plan);
    cases.push(kind);
    let mut roots = request(GOOD);
    roots.input = tf_scan::ScanInput::Dirs {
        paths: vec!["/nonexistent/other".into()],
        recursive: false,
    };
    roots.overlay = vec![(PathBuf::from("/nonexistent/other/main.tf"), GOOD.into())];
    cases.push(scan(roots).unwrap().record());
    cases.push(record(
        "variable \"new_input\" { type = bool }\nlocals { x = 1 }",
    ));
    for after in cases {
        let diff = ScanComparison::between(&before, &after).unwrap();
        assert!(!diff.comparable, "{diff:?}");
        assert!(diff.resolved.is_empty());
        assert_eq!(diff.unverified_removed.len(), 1);
        assert!(!diff.issues.is_empty());
    }
}

#[test]
fn suppressed_findings_are_not_resolutions_and_shifted_lines_are_unchanged() {
    let before = record(BAD);
    let shifted = record(&format!("\n\n{BAD}"));
    let diff = ScanComparison::between(&before, &shifted).unwrap();
    assert_eq!(diff.delta.unchanged, 1);
    let mut after = record(GOOD);
    after.suppressed.push(tf_linter::record::SuppressedRecord {
        rule: before.findings[0].rule.clone(),
        resource: "aws_db_instance.db".into(),
        comment: "suppressed".into(),
        location: before.findings[0].location.clone(),
    });
    let diff = ScanComparison::between(&before, &after).unwrap();
    assert!(!diff.comparable);
    assert_eq!(diff.unverified_removed.len(), 1);
}

struct Hooks;
impl tf_linter::rule::DynRule for Hooks {
    fn info(&self) -> tf_linter::rule::RuleInfo {
        let mut info = tf_linter::Linter::with_seed_rules().rules()[0].clone();
        info.name = "hook-test".into();
        info.resource_types = vec!["*".into()];
        info.runs_on_module = true;
        info
    }
    fn judge_module<'m>(
        &self,
        _: &'m tf_semantic::Module,
    ) -> Result<Vec<(&'m tf_semantic::Resource, tf_linter::rule::Judgement)>, String> {
        Ok(Vec::new())
    }
    fn needs_graph(&self) -> bool {
        true
    }
    fn needs_files(&self) -> bool {
        true
    }
    fn judge_resource(
        &self,
        _: &tf_semantic::Resource,
    ) -> Result<Vec<tf_linter::rule::Judgement>, String> {
        Err("test rule failure".into())
    }
}

#[test]
fn all_hook_kinds_and_rule_failures_contribute_to_accounting() {
    let mut req = request("resource \"test_node\" \"n\" { value = 1 }");
    req.catalog = Catalog::default();
    req.catalog.runtime.push(Box::new(Hooks));
    req.selection = None;
    let rec = scan(req).unwrap().record();
    let c = rec.coverage.unwrap().totals();
    assert_eq!(
        (c.planned, c.executed, c.completed, c.failed, c.skipped),
        (4, 4, 3, 1, 0)
    );
    assert_eq!(rec.rule_errors.len(), 1);
    let error = serde_json::to_value(&rec.rule_errors[0]).unwrap();
    assert_eq!(error["code"], "rule-execution-failed");
    assert_eq!(error["action"]["kind"], "inspect_rule_execution");
    let roundtrip: tf_linter::record::RuleError = serde_json::from_value(error).unwrap();
    assert_eq!(roundtrip, rec.rule_errors[0]);
}

#[test]
fn a_more_certain_occurrence_is_a_regression_even_when_group_certainty_is_unchanged() {
    let mut before = record(BAD);
    let mut occurrence = before.findings[0].occurrences[0].clone();
    occurrence.address = "aws_db_instance.db[1]".into();
    occurrence.certainty = tf_linter::Certainty::Conditional;
    before.findings[0].occurrences.push(occurrence);
    let mut after = before.clone();
    after.findings[0].occurrences[1].certainty = tf_linter::Certainty::Definite;
    let diff = ScanComparison::between(&before, &after).unwrap();
    assert!(diff.has_regressions());
    assert_eq!(diff.delta.changed.len(), 1);
    assert_eq!(diff.certainty_changes[0].occurrences.len(), 1);
}

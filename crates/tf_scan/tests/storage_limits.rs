use std::path::PathBuf;
use tf_linter::ScanStatus;
use tf_scan::{Catalog, Limits, ScanInput, ScanRequest, scan};

const SOURCE: &str = "resource \"aws_db_instance\" \"db\" { storage_encrypted = false }";

fn request() -> ScanRequest {
    let root = PathBuf::from("/nonexistent/oxtf-storage-scan");
    let mut req = ScanRequest::dirs(vec![root.clone()], false);
    req.catalog = Catalog::seed();
    req.overlay.push((root.join("main.tf"), SOURCE.into()));
    req
}

fn assert_limit(req: ScanRequest, resource: &str) {
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Incomplete);
    let diagnostics: Vec<_> = out
        .result
        .diagnostics
        .iter()
        .filter(|d| d.code == "coverage-storage")
        .collect();
    assert_eq!(diagnostics.len(), 1, "{:?}", out.result.diagnostics);
    assert!(diagnostics[0].message.starts_with(resource));
}

#[test]
fn input_and_aggregate_boundaries_preserve_completion() {
    let n = SOURCE.len() as u64;
    for offset in [-1i64, 0, 1] {
        for per_input in [true, false] {
            let allowance = ((if per_input { n } else { 2 * n }) as i64 + offset) as u64;
            let mut req = request();
            req.limits = if per_input {
                Limits::default().with_input_bytes(allowance).unwrap()
            } else {
                Limits::default().with_source_bytes(allowance).unwrap()
            };
            if offset < 0 {
                assert_limit(
                    req,
                    if per_input {
                        "input_bytes"
                    } else {
                        "source_bytes"
                    },
                );
            } else {
                let out = scan(req).unwrap();
                assert_eq!(out.result.status(), ScanStatus::Complete);
                assert_eq!(out.result.findings.len(), 1);
            }
        }
    }
}

#[test]
fn directories_roots_and_empty_files_have_finite_admission() {
    let mut req = request();
    req.limits = Limits::default().with_directory_entries(1).unwrap();
    assert_limit(req, "directory_entries");
    let mut req = request();
    req.overlay.push((
        PathBuf::from("/nonexistent/oxtf-storage-scan/empty.tf"),
        "".into(),
    ));
    req.limits = Limits::default().with_file_entries(1).unwrap();
    assert_limit(req, "file_entries");
    let mut req = request();
    let ScanInput::Dirs { paths, .. } = &mut req.input else {
        unreachable!()
    };
    paths.push(PathBuf::from("/nonexistent/oxtf-storage-scan/second"));
    req.overlay.push((paths[1].join("main.tf"), "".into()));
    req.limits = Limits::default().with_roots(1).unwrap();
    assert_limit(req, "roots");
}

#[test]
fn raw_file_reads_cannot_be_hidden_by_try_or_verify_a_fix() {
    let mut req = request();
    let path = req.overlay[0].0.clone();
    req.overlay[0].1 = format!("{SOURCE}\nlocals {{ v = try(file(\"payload\"), \"\") }}").into();
    req.overlay
        .push((path.with_file_name("payload"), "1234".into()));
    let complete = scan(req.try_clone().unwrap()).unwrap();
    let fingerprint = complete.record().findings[0].fingerprint.clone();
    let bytes = req.overlay.iter().map(|(_, s)| s.len() as u64).sum::<u64>()
        + req.overlay[0].1.len() as u64;
    req.limits = Limits::default().with_source_bytes(bytes).unwrap();
    assert_limit(req.try_clone().unwrap(), "source_bytes");
    let fix = tf_scan::fix(req, &fingerprint, None).unwrap();
    assert!(!fix.verified);
    assert!(
        fix.verification_errors
            .iter()
            .any(|e| e.contains("coverage-storage"))
    );
}

#[test]
fn rule_documents_share_scan_input_admission() {
    let mut req = request();
    req.catalog.rule_json.push(" ".repeat(SOURCE.len() + 1));
    req.limits = Limits::default()
        .with_input_bytes(SOURCE.len() as u64)
        .unwrap();
    assert_limit(req, "input_bytes");
}

#[test]
fn storage_wire_configuration_is_strict() {
    for field in [
        "input_bytes",
        "source_bytes",
        "file_entries",
        "directory_entries",
        "roots",
        "rego_time_ms",
        "arena_bytes",
        "ast_nodes",
        "text_bytes",
        "collection_bytes",
    ] {
        assert!(tf_scan::limits::from_json(&format!("{{\"{field}\":1}}")).is_ok());
        for value in ["0", "-1", "null", "true", "1.0", "18446744073709551616"] {
            assert!(tf_scan::limits::from_json(&format!("{{\"{field}\":{value}}}")).is_err());
        }
    }
}

#[test]
fn source_rule_policy_and_plan_files_use_the_same_admission_path() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    for input in ["source", "rule", "rego", "plan"] {
        let mut req = request();
        req.overlay.clear();
        req.limits = Limits::default().with_input_bytes(1).unwrap();
        req.input = ScanInput::Dirs {
            paths: vec![dir.join("rules/aws-rds-unencrypted/fail_explicit_false")],
            recursive: false,
        };
        match input {
            "rule" => req.catalog.rule_files.push(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../tfscan_py/rules/sg_open_ssh.json"),
            ),
            "rego" => req
                .catalog
                .policies
                .foreign
                .push(dir.join("rego/foreign/conftest_hcl2_deny.rego")),
            "plan" => {
                let plan = dir.join("rules/aws-rds-unencrypted/fail_explicit_false/main.tf");
                // Admission happens before JSON parsing, regardless of the filename.
                req.input = ScanInput::Plan { plan, source: None };
            }
            _ => {}
        }
        assert_limit(req, "input_bytes");
    }
}

#[test]
fn aggregate_exhaustion_is_never_complete_with_one_or_many_workers() {
    for workers in [1, 4] {
        let mut req = request();
        let roots: Vec<_> = (0..4)
            .map(|i| PathBuf::from(format!("/nonexistent/oxtf-storage-root-{i}")))
            .collect();
        req.overlay = roots
            .iter()
            .map(|root| (root.join("main.tf"), SOURCE.into()))
            .collect();
        req.input = ScanInput::Dirs {
            paths: roots,
            recursive: false,
        };
        req.threads = Some(workers);
        req.limits = Limits::default()
            .with_source_bytes(5 * SOURCE.len() as u64)
            .unwrap();
        let out = scan(req).unwrap();
        assert_eq!(out.result.status(), ScanStatus::Incomplete);
        assert_eq!(
            out.result
                .diagnostics
                .iter()
                .filter(|d| d.code == "coverage-storage")
                .count(),
            1
        );
        assert!(out.result.files.input_budget().stats().source_bytes <= 5 * SOURCE.len() as u64);
    }
}

#[test]
fn standalone_rule_documents_reject_before_deserializing() {
    let limits = Limits::default().with_input_bytes(1).unwrap();
    assert!(
        tf_rule_ir::parse_rules_with_limits("[]", limits)
            .unwrap_err()
            .contains("input_bytes")
    );
    assert!(
        tf_rule_ir::parse_rules_with_limits("[]", limits.with_input_bytes(2).unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn plan_requests_release_the_model_when_retention_is_disabled() {
    let mut req = request();
    req.overlay.clear();
    req.input = ScanInput::Plan {
        plan: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/plans/aws-rds-unencrypted/fail_explicit_false.json"),
        source: None,
    };
    req.keep_models = false;
    let out = scan(req).unwrap();
    assert!(out.analyses.is_empty());
    assert_eq!(out.result.findings.len(), 1);
    assert!(out.result.stats.resources > 0);
}

#[test]
fn arena_refusal_is_shared_across_roots_and_never_complete() {
    for workers in [1, 4] {
        for bytes in [true, false] {
            let mut req = request();
            req.threads = Some(workers);
            let roots: Vec<_> = (0..4)
                .map(|i| PathBuf::from(format!("/nonexistent/oxtf-arena-root-{i}")))
                .collect();
            req.overlay = roots
                .iter()
                .map(|root| (root.join("main.tf"), SOURCE.into()))
                .collect();
            req.input = ScanInput::Dirs {
                paths: roots,
                recursive: false,
            };
            req.limits = if bytes {
                Limits::default().with_arena_bytes(1).unwrap()
            } else {
                Limits::default().with_ast_nodes(1).unwrap()
            };
            assert_limit(req, if bytes { "arena_bytes" } else { "ast_nodes" });
        }
    }
}

#[test]
fn template_arena_refusal_survives_try_and_prevents_fix_verification() {
    let mut req = request();
    let path = req.overlay[0].0.clone();
    req.overlay[0].1 =
        format!("{SOURCE}\nlocals {{ v = try(templatefile(\"template\", {{}}), \"\") }}").into();
    req.overlay
        .push((path.with_file_name("template"), "hello ${1 + 2}".into()));
    let baseline = scan(req.try_clone().unwrap()).unwrap();
    assert_eq!(baseline.result.status(), ScanStatus::Complete);
    let fingerprint = baseline.record().findings[0].fingerprint.clone();
    let nodes = baseline.result.files.input_budget().stats().ast_nodes;
    req.limits = Limits::default().with_ast_nodes(nodes - 1).unwrap();
    assert_limit(req.try_clone().unwrap(), "ast_nodes");
    let fixed = tf_scan::fix(req, &fingerprint, None).unwrap();
    assert!(!fixed.verified);
    assert!(
        fixed
            .verification_errors
            .iter()
            .any(|e| e.contains("coverage-storage"))
    );
}

#[test]
fn syntax_failure_retains_precedence_over_arena_exhaustion() {
    let mut req = request();
    req.overlay[0].1 = format!("@\n{SOURCE}").into();
    req.limits = Limits::default().with_ast_nodes(1).unwrap();
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Failed);
    assert!(
        out.result
            .diagnostics
            .iter()
            .any(|d| d.code == "parse-error")
    );
    assert!(
        out.result
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-storage")
    );
}

#[test]
fn rego_parse_config_uses_the_scan_arena_allowance() {
    let mut req = request();
    let path = std::env::temp_dir().join(format!("oxtf-arena-policy-{}.rego", std::process::id()));
    let module_cost = scan(req.try_clone().unwrap())
        .unwrap()
        .result
        .files
        .input_budget()
        .stats()
        .ast_nodes;
    req.catalog.policies.foreign.push(path.clone());
    req.catalog.policies.all_namespaces = true;
    std::fs::write(
        &path,
        r#"package main
import rego.v1
deny contains "parsed" if {
    input.resource
    config := parse_config("hcl2", sprintf("locals { x = [%d, 2, 3] }", [count(input.resource)]))
    config.locals.x[0] == 1
}
"#,
    )
    .unwrap();
    let baseline = scan(req.try_clone().unwrap()).unwrap();
    assert_eq!(
        baseline.result.status(),
        ScanStatus::Complete,
        "{:?}",
        baseline.result.rule_errors
    );
    assert!(baseline.result.files.input_budget().stats().ast_nodes > module_cost);
    req.limits = Limits::default().with_ast_nodes(module_cost + 1).unwrap();
    let out = scan(req).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_ne!(out.result.status(), ScanStatus::Complete);
    assert_eq!(
        out.result
            .files
            .input_budget()
            .exhaustion()
            .unwrap()
            .resource,
        tf_limits::Resource::AstNodes
    );
    assert_eq!(
        out.result
            .diagnostics
            .iter()
            .filter(|d| d.code == "coverage-storage")
            .count(),
        1
    );
}

#[test]
fn text_amplification_is_incomplete_and_cannot_verify_fixes() {
    for expression in [
        r#"try(replace("aaaaaaaa", "a", "large text"), "fallback")"#,
        r#""${jsonencode(["a", "b", "c", "d"])}""#,
        r#"templatefile("payload", {v = "abcdefghijk"})"#,
        r#"filebase64("payload")"#,
        r#"file("payload")"#,
    ] {
        let mut req = request();
        req.overlay[0].1 = format!("{SOURCE}\nlocals {{ v = {expression} }}").into();
        req.overlay.push((
            req.overlay[0].0.with_file_name("payload"),
            "${v}${v}${v}${v}${v}${v}${v}${v}".into(),
        ));
        let complete = scan(req.try_clone().unwrap()).unwrap();
        assert_eq!(
            complete.result.status(),
            ScanStatus::Complete,
            "{expression}"
        );
        let cost = complete.result.files.input_budget().stats().text_bytes;
        let fingerprint = complete.record().findings[0].fingerprint.clone();
        for allowance in [cost - 1, cost, cost + 1] {
            req.limits = Limits::default().with_text_bytes(allowance).unwrap();
            if allowance < cost {
                assert_limit(req.try_clone().unwrap(), "text_bytes");
            } else {
                assert_eq!(
                    scan(req.try_clone().unwrap()).unwrap().result.status(),
                    ScanStatus::Complete
                );
            }
        }
        req.limits = Limits::default().with_text_bytes(cost - 1).unwrap();
        let fixed = tf_scan::fix(req, &fingerprint, None).unwrap();
        assert!(!fixed.verified);
    }
}

#[test]
fn text_storage_is_shared_across_workers_and_preserves_prior_failure() {
    for workers in [1, 4] {
        let mut req = request();
        let roots: Vec<_> = (0..4)
            .map(|i| PathBuf::from(format!("/nonexistent/oxtf-text-root-{i}")))
            .collect();
        req.overlay = roots
            .iter()
            .map(|p| {
                (
                    p.join("main.tf"),
                    format!("{SOURCE}\nlocals {{ x = \"1234\" }}").into(),
                )
            })
            .collect();
        req.input = ScanInput::Dirs {
            paths: roots,
            recursive: false,
        };
        req.threads = Some(workers);
        req.limits = Limits::default().with_text_bytes(15).unwrap();
        assert_limit(req, "text_bytes");
    }
    let mut req = request();
    req.overlay[0].1 = format!("{SOURCE}\nlocals {{ a = @\nz = \"long text\" }}").into();
    req.limits = Limits::default().with_text_bytes(1).unwrap();
    let result = scan(req).unwrap();
    assert_eq!(result.result.status(), ScanStatus::Failed);
    assert!(
        result
            .result
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-storage")
    );
}

#[test]
fn collection_refusal_survives_catches_and_prevents_fix_verification() {
    for expression in [
        "[1, 2, 3]",
        "{a = [1, 2], b = 3}",
        "[for x in [1, 2, 3] : [x, x]]",
        "{for x in [1, 2, 1] : x => x...}",
        "[{a = 1}, {a = 2}][*].a",
        "max([1, 2, 3]...)",
        "try([1, 2, 3], [])",
        "can([1, 2, 3])",
        "try(reverse([1, 2, 3]), [])",
        "can(reverse([1, 2, 3]))",
        "length([reverse([1, 2, 3])])",
        "templatefile(\"payload\", {})",
    ] {
        let mut req = request();
        req.overlay[0].1 = format!("{SOURCE}\nlocals {{ v = {expression} }}").into();
        req.overlay.push((
            req.overlay[0].0.with_file_name("payload"),
            "${length(reverse([1, 2, 3]))}".into(),
        ));
        let complete = scan(req.try_clone().unwrap()).unwrap();
        assert_eq!(complete.result.status(), ScanStatus::Complete);
        let cost = complete
            .result
            .files
            .input_budget()
            .stats()
            .collection_bytes;
        let fingerprint = complete.record().findings[0].fingerprint.clone();
        for allowance in [cost - 1, cost, cost + 1] {
            req.limits = Limits::default().with_collection_bytes(allowance).unwrap();
            if allowance < cost {
                assert_limit(req.try_clone().unwrap(), "collection_bytes");
            } else {
                assert_eq!(
                    scan(req.try_clone().unwrap()).unwrap().result.status(),
                    ScanStatus::Complete
                );
            }
        }
        req.limits = Limits::default().with_collection_bytes(cost - 1).unwrap();
        assert!(!tf_scan::fix(req, &fingerprint, None).unwrap().verified);
    }
}

#[test]
fn collection_admission_is_shared_across_workers_and_preserves_failure() {
    for workers in [1, 4] {
        let mut req = request();
        let roots: Vec<_> = (0..4)
            .map(|i| PathBuf::from(format!("/nonexistent/oxtf-collections-{i}")))
            .collect();
        req.overlay = roots
            .iter()
            .map(|root| {
                (
                    root.join("main.tf"),
                    format!("{SOURCE}\nlocals {{ v = reverse([1, 2, 3]) }}").into(),
                )
            })
            .collect();
        req.input = ScanInput::Dirs {
            paths: roots,
            recursive: false,
        };
        req.threads = Some(workers);
        req.limits = Limits::default().with_collection_bytes(3 * 3 * 32).unwrap();
        assert_limit(req, "collection_bytes");
    }
    let mut req = request();
    req.overlay[0].1 = format!("{SOURCE}\nlocals {{ a = @\nz = reverse([1, 2]) }}").into();
    let full = scan(req.try_clone().unwrap()).unwrap();
    let cost = full.result.files.input_budget().stats().collection_bytes;
    // Allow parsing to observe the syntax error before later collection refusal.
    req.limits = Limits::default().with_collection_bytes(cost - 1).unwrap();
    let out = scan(req).unwrap();
    assert_eq!(out.result.status(), ScanStatus::Failed);
    assert!(
        out.result
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-storage")
    );
}

#[test]
fn semantic_conversion_refusal_stays_incomplete_and_prevents_fix_verification() {
    for cached in [false, true] {
        let mut req = request();
        req.overlay[0].1 = format!(
            r#"{SOURCE}
            variable "v" {{
                type = object({{x=optional(list(number), [1,2]), y=optional(number, 7)}})
                default = {{}}
            }}
            locals {{ used = try(var.v, {{}}) }}"#
        )
        .into();
        if cached {
            req.overlay
                .push((req.overlay[0].0.with_file_name("override.tf"), "".into()));
        }
        let complete = scan(req.try_clone().unwrap()).unwrap();
        assert_eq!(complete.result.status(), ScanStatus::Complete);
        let cost = complete
            .result
            .files
            .input_budget()
            .stats()
            .collection_bytes;
        let fingerprint = complete.record().findings[0].fingerprint.clone();
        for allowance in [cost - 1, cost, cost + 1] {
            req.limits = Limits::default().with_collection_bytes(allowance).unwrap();
            if allowance < cost {
                assert_limit(req.try_clone().unwrap(), "collection_bytes");
            } else {
                assert_eq!(
                    scan(req.try_clone().unwrap()).unwrap().result.status(),
                    ScanStatus::Complete
                );
            }
        }
        req.limits = Limits::default().with_collection_bytes(cost - 1).unwrap();
        assert!(!tf_scan::fix(req, &fingerprint, None).unwrap().verified);
    }
}

#[test]
fn model_payload_refusal_retains_completed_findings_and_blocks_fix_verification() {
    let mut req = request();
    let complete = scan(req.try_clone().unwrap()).unwrap();
    let cost = complete
        .result
        .files
        .input_budget()
        .stats()
        .collection_bytes;
    let fingerprint = complete.record().findings[0].fingerprint.clone();
    // The source has scalar attributes: this boundary is model payload, not a
    // literal or builtin collection. The completed resource remains reviewable.
    req.limits = Limits::default().with_collection_bytes(cost - 1).unwrap();
    let limited = scan(req.try_clone().unwrap()).unwrap();
    assert_eq!(limited.result.status(), ScanStatus::Incomplete);
    assert_eq!(limited.result.findings.len(), 1);
    assert!(!tf_scan::fix(req, &fingerprint, None).unwrap().verified);
}

#[test]
fn model_payload_is_shared_by_workers_with_or_without_retained_models() {
    let single = scan(request()).unwrap();
    let cost = single.result.files.input_budget().stats().collection_bytes;
    for workers in [1, 4] {
        for keep_models in [false, true] {
            let mut req = request();
            let roots: Vec<_> = (0..4)
                .map(|i| PathBuf::from(format!("/nonexistent/oxtf-model-worker-{i}")))
                .collect();
            req.overlay = roots
                .iter()
                .map(|root| (root.join("main.tf"), SOURCE.into()))
                .collect();
            req.input = ScanInput::Dirs {
                paths: roots,
                recursive: false,
            };
            req.keep_models = keep_models;
            req.threads = Some(workers);
            req.limits = Limits::default().with_collection_bytes(2 * cost).unwrap();
            assert_limit(req, "collection_bytes");
        }
    }
}

#[test]
fn discarded_model_body_retains_an_earlier_evaluation_error() {
    let mut req = request();
    req.overlay[0].1 = "resource \"test_node\" \"r\" { x = var.missing\n y = [1, 2] }".into();
    let full = scan(req.try_clone().unwrap()).unwrap();
    assert_eq!(full.result.status(), ScanStatus::Failed);
    let cost = full.result.files.input_budget().stats().collection_bytes;
    let mut discarded_with_error = false;
    for allowance in (1..cost).step_by(16) {
        req.limits = Limits::default().with_collection_bytes(allowance).unwrap();
        let limited = scan(req.try_clone().unwrap()).unwrap();
        if limited.result.status() == ScanStatus::Failed && limited.result.stats.resources == 0 {
            discarded_with_error = true;
            assert!(
                limited
                    .result
                    .diagnostics
                    .iter()
                    .any(|d| d.code == "evaluation-error")
            );
            assert!(
                limited
                    .result
                    .diagnostics
                    .iter()
                    .any(|d| d.code == "coverage-storage")
            );
        }
    }
    assert!(discarded_with_error);
}

#[test]
fn partial_parsed_references_never_publish_a_model_or_hide_a_composition_error() {
    for invalid in [false, true] {
        let mut req = request();
        req.overlay[0].1 = "variable \"v\" { default=false }\n\
            resource \"aws_db_instance\" \"db\" { storage_encrypted=var.v }"
            .into();
        if invalid {
            req.overlay[0].1 = format!("{}\nlocals {{ a=1\n a=2 }}", req.overlay[0].1).into();
        }
        req.overlay
            .push((req.overlay[0].0.with_file_name("override.tf"), "".into()));
        let files = tf_semantic::FileTable::with_overlay(req.overlay.clone());
        let store = tf_semantic::ModuleStore::new();
        let def = store
            .module(&files, req.overlay[0].0.parent().unwrap())
            .unwrap();
        assert!(!def.references.is_empty());
        let cost = files.input_budget().stats().collection_bytes;
        for keep_models in [false, true] {
            let mut limited = req.try_clone().unwrap();
            limited.keep_models = keep_models;
            limited.limits = Limits::default().with_collection_bytes(cost - 1).unwrap();
            let out = scan(limited).unwrap();
            assert_eq!(
                out.result.status(),
                if invalid {
                    ScanStatus::Failed
                } else {
                    ScanStatus::Incomplete
                }
            );
            assert_eq!(out.result.stats.resources, 0);
            assert!(out.analyses.iter().all(|a| a.modules.is_empty()));
            assert_eq!(
                out.result
                    .diagnostics
                    .iter()
                    .filter(|d| d.code == "coverage-storage")
                    .count(),
                1
            );
            assert_eq!(
                out.result
                    .diagnostics
                    .iter()
                    .any(|d| d.code == "parse-error"),
                invalid
            );
        }
    }
}

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tf_limits::Limits;
use tf_semantic::{Analysis, AnalyzeOptions, FileTable, ModuleStore, analyze_module_shared};

const ROOT: &str = "/nonexistent/oxtf-loader";
const SOURCE: &str = "variable \"value\" {\n type = list(number)\n default = [1, 2, 3]\n}\n\
    resource \"aws_db_instance\" \"db\" { allocated_storage = length(var.value) }\n";

fn files(source: &str) -> FileTable {
    FileTable::with_overlay([
        (PathBuf::from(ROOT).join("main.tf"), Arc::from(source)),
        (PathBuf::from(ROOT).join("override.tf"), Arc::from("")),
    ])
}

fn analyze(files: &FileTable, store: &ModuleStore, allowance: u64) -> Analysis {
    analyze_module_shared(
        Path::new(ROOT),
        &AnalyzeOptions {
            limits: Limits::default().with_loader_steps(allowance).unwrap(),
            ..AnalyzeOptions::default()
        },
        files,
        store,
    )
}

fn diagnostics(analysis: &Analysis) -> Vec<(&str, &str, Option<tf_span::FileSpan>)> {
    analysis
        .diagnostics
        .iter()
        .map(|d| (d.code, d.message.as_str(), d.at))
        .collect()
}

#[test]
fn cold_and_warm_cache_have_identical_costs_and_boundary_outcomes() {
    let files = files(SOURCE);
    let measured = analyze(&files, &ModuleStore::new(), 1000);
    assert!(
        measured.diagnostics.is_empty(),
        "{:?}",
        measured.diagnostics
    );
    let cost = measured.stats.loader_steps;
    assert!(cost > 3);
    for allowance in [cost - 1, cost, cost + 1] {
        let store = ModuleStore::new();
        let cold = analyze(&files, &store, allowance);
        let warm = analyze(&files, &store, allowance);
        assert_eq!(cold.stats.loader_steps, warm.stats.loader_steps);
        assert_eq!(cold.stats.evaluation_steps, warm.stats.evaluation_steps);
        assert_eq!(diagnostics(&cold), diagnostics(&warm));
        assert_eq!(cold.stats.resources, warm.stats.resources);
        assert_eq!(store.len(), 1);
        if allowance < cost {
            assert_eq!(cold.stats.resources, 0);
            assert!(cold.diagnostics.iter().any(|d| d.code == "coverage-budget"));
            assert!(!cold.diagnostics.iter().any(|d| d.code == "parse-error"));
        } else {
            assert_eq!(cold.stats.loader_steps, cost);
            assert_eq!(cold.stats.resources, 1);
            assert!(cold.diagnostics.is_empty());
        }
    }
}

#[test]
fn exhausted_entries_do_not_poison_other_allowances() {
    let files = files(SOURCE);
    let store = ModuleStore::new();
    for allowance in [1, 1000, 1, 1000] {
        let analysis = analyze(&files, &store, allowance);
        assert_eq!(analysis.stats.resources, usize::from(allowance == 1000));
        assert_eq!(analysis.diagnostics.is_empty(), allowance == 1000);
    }
    assert_eq!(store.len(), 2);
}

#[test]
fn fixed_limits_in_discarded_default_values_are_coverage_not_syntax_errors() {
    let files = files("variable \"value\" { default = length([indent(1e100, \"a\\nb\")]) }");
    let store = ModuleStore::new();
    for _ in 0..2 {
        let analysis = analyze(&files, &store, 1000);
        assert!(
            analysis
                .diagnostics
                .iter()
                .any(|d| d.code == "coverage-loader")
        );
        assert!(!analysis.diagnostics.iter().any(|d| d.code == "parse-error"));
        assert!(analysis.modules[0].variables.is_empty());
    }
}

#[test]
fn declarations_optional_defaults_and_conversion_share_the_allowance() {
    let source = (0..8).map(|i| format!(
        "variable \"v{i}\" {{\n type = object({{ x = optional(number, 1) }})\n default = {{}}\n}}\n"
    )).collect::<String>();
    let files = files(&source);
    let complete = analyze(&files, &ModuleStore::new(), 10_000);
    assert!(
        complete.diagnostics.is_empty(),
        "{:?}",
        complete.diagnostics
    );
    let limited = analyze(&files, &ModuleStore::new(), complete.stats.loader_steps / 2);
    assert!(
        limited
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-budget")
    );
    assert!(limited.modules[0].variables.is_empty());
}

#[test]
fn set_comparisons_are_charged_before_deduplication() {
    let source = format!(
        "variable \"value\" {{\n type = set(number)\n default = [{}]\n}}",
        (0..64).map(|i| i.to_string()).collect::<Vec<_>>().join(",")
    );
    let files = files(&source);
    let limited = analyze(&files, &ModuleStore::new(), 1000);
    assert!(
        limited
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-budget")
    );
    assert!(limited.stats.loader_steps <= 1000);
    let complete = analyze(&files, &ModuleStore::new(), 100_000);
    assert!(
        complete.diagnostics.is_empty(),
        "{:?}",
        complete.diagnostics
    );
    assert_eq!(
        complete.modules[0].variables[0]
            .value
            .as_list()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn loader_exhaustion_retains_already_observed_errors() {
    let files = files(
        "variable \"invalid\" { type = invalid }\n\
        variable \"value\" { default = [1, 2, 3, 4] }",
    );
    let result = analyze(&files, &ModuleStore::new(), 2);
    assert!(result.diagnostics.iter().any(|d| d.code == "parse-error"));
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-budget")
    );
}

#[test]
fn module_definitions_are_charged_once_and_further_loads_stop_after_exhaustion() {
    let child_files = files(SOURCE);
    let cost = analyze(&child_files, &ModuleStore::new(), 1000)
        .stats
        .loader_steps;
    for (calls, expected_cost, expected_entries) in [
        (vec!["child", "child"], cost, 2),
        (vec!["child", "other", "never"], cost, 3),
    ] {
        let mut overlay = vec![(
            PathBuf::from(ROOT).join("main.tf"),
            Arc::from(
                calls
                    .iter()
                    .enumerate()
                    .map(|(i, dir)| format!("module \"m{i}\" {{ source = \"./{dir}\" }}\n"))
                    .collect::<String>(),
            ),
        )];
        for dir in ["child", "other", "never"] {
            overlay.push((
                PathBuf::from(ROOT).join(dir).join("main.tf"),
                Arc::from(SOURCE),
            ));
            overlay.push((
                PathBuf::from(ROOT).join(dir).join("override.tf"),
                Arc::from(""),
            ));
        }
        let files = FileTable::with_overlay(overlay);
        let store = ModuleStore::new();
        let cold = analyze(&files, &store, cost);
        let warm = analyze(&files, &store, cost);
        assert_eq!(cold.stats.loader_steps, expected_cost);
        assert_eq!(diagnostics(&cold), diagnostics(&warm));
        assert_eq!(store.len(), expected_entries);
        assert_eq!(cold.diagnostics.is_empty(), calls[0] == calls[1]);
    }
}

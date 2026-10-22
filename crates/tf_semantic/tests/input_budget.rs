use std::path::Path;
use std::sync::Arc;

use serde_json::json;
use tf_eval::Origin;
use tf_limits::Limits;
use tf_semantic::{Analysis, AnalyzeOptions, FileTable, ModuleStore, analyze_module_shared};

const ROOT: &str = "/nonexistent/oxtf-input-budget";

fn analyze(files: &FileTable, store: &ModuleStore, allowance: u64) -> Analysis {
    analyze_module_shared(
        Path::new(ROOT),
        &AnalyzeOptions {
            limits: Limits::new(allowance).unwrap(),
            ..AnalyzeOptions::default()
        },
        files,
        store,
    )
}

fn files(entries: &[(&str, &str)]) -> FileTable {
    FileTable::with_overlay(
        entries
            .iter()
            .map(|(p, s)| (Path::new(ROOT).join(p), Arc::from(*s))),
    )
}

#[test]
fn runtime_conversion_boundaries_preserve_values_with_cold_and_warm_caches() {
    let cases = [
        ("list(number)", r#"["1", "2"]"#, json!([1, 2])),
        ("set(string)", "[1, 2]", json!(["1", "2"])),
        (
            "map(bool)",
            r#"{x="true",y="false"}"#,
            json!({"x":true,"y":false}),
        ),
        (
            "tuple([number, bool, string])",
            r#"["1", "false", 2]"#,
            json!([1, false, "2"]),
        ),
        (
            "object({x=optional(number,7), nested=optional(list(number),[1,2])})",
            "{}",
            json!({"x":7,"nested":[1,2]}),
        ),
    ];
    for (ty, value, expected) in cases {
        let source = format!("variable \"value\" {{\n type = {ty}\n default = {value}\n}}");
        for cached in [false, true] {
            let mut entries = vec![("main.tf", source.as_str())];
            if cached {
                entries.push(("override.tf", ""));
            }
            let files = files(&entries);
            let store = ModuleStore::new();
            let complete = analyze(&files, &store, 10_000);
            assert!(
                complete.diagnostics.is_empty(),
                "{ty}: {:?}",
                complete.diagnostics
            );
            let cost = complete.stats.evaluation_steps;
            assert!(cost > 1);
            for allowance in [cost - 1, cost, cost + 1] {
                let cold = analyze(&files, &ModuleStore::new(), allowance);
                let warm = analyze(&files, &store, allowance);
                assert_eq!(cold.stats.evaluation_steps, warm.stats.evaluation_steps);
                assert_eq!(cold.stats.loader_steps, warm.stats.loader_steps);
                for result in [cold, warm] {
                    let value = &result.modules[0].variables[0].value;
                    assert!(result.stats.evaluation_steps <= allowance);
                    if allowance < cost {
                        assert!(
                            matches!(value.origin(), Some(Origin::Limit(_))),
                            "{ty}: {value:?}"
                        );
                        assert_eq!(
                            result
                                .diagnostics
                                .iter()
                                .filter(|d| d.code == "coverage-budget")
                                .count(),
                            1
                        );
                    } else {
                        assert!(result.diagnostics.is_empty());
                        assert_eq!(tf_eval::value::to_json(value), Some(expected.clone()));
                    }
                }
            }
        }
    }
}

#[test]
fn cached_collection_copies_are_refused_before_element_conversion() {
    let source = format!(
        "variable \"value\" {{\n type = list(number)\n default = [{}]\n sensitive = true\n}}",
        vec!["1"; 1024].join(",")
    );
    let files = files(&[("main.tf", &source), ("override.tf", "")]);
    let limited = analyze(&files, &ModuleStore::new(), 2);
    let value = &limited.modules[0].variables[0].value;
    assert!(matches!(value.origin(), Some(Origin::Limit(_))));
    assert!(value.is_sensitive());
    assert_eq!(limited.stats.evaluation_steps, 1);
    let diagnostic = limited
        .diagnostics
        .iter()
        .find(|d| d.code == "coverage-budget")
        .unwrap();
    assert!(diagnostic.message.contains("evaluation_steps"));
    let at = diagnostic.at.unwrap();
    assert_eq!(files.get(at.file).path, Path::new(ROOT).join("main.tf"));
}

#[test]
fn retained_optional_defaults_charge_each_runtime_input_and_child_instance() {
    let child = "variable \"value\" {\n type = list(object({x=optional(number,7)}))\n}";
    let override_type = "variable \"value\" { type = list(object({x=optional(string)})) }";
    let root = "module \"child\" {\n count = 3\n source = \"./child\"\n value = [{},{}]\n}";
    let files = files(&[
        ("main.tf", root),
        ("child/main.tf", child),
        ("child/override.tf", override_type),
    ]);
    let store = ModuleStore::new();
    let complete = analyze(&files, &store, 10_000);
    assert!(
        complete.diagnostics.is_empty(),
        "{:?}",
        complete.diagnostics
    );
    assert_eq!(complete.modules.len(), 4);
    for module in &complete.modules[1..] {
        assert_eq!(
            tf_eval::value::to_json(&module.variables[0].value),
            Some(json!([{"x":"7"},{"x":"7"}]))
        );
    }
    let limited = analyze(&files, &store, complete.stats.evaluation_steps - 1);
    assert_eq!(limited.stats.loader_steps, complete.stats.loader_steps);
    assert!(
        limited
            .diagnostics
            .iter()
            .any(|d| d.code == "coverage-budget")
    );
    assert!(matches!(
        limited.modules[3].variables[0].value.origin(),
        Some(Origin::Limit(_))
    ));
}

#[test]
fn tfvars_optional_defaults_share_the_runtime_allowance_in_both_formats() {
    let source = "variable \"value\" {\n type = list(object({x=optional(number,7)}))\n}";
    for input in [
        ("terraform.tfvars", "value = [{}, {}]"),
        ("terraform.tfvars.json", r#"{"value":[{},{}]}"#),
    ] {
        let files = files(&[("main.tf", source), ("override.tf", ""), input]);
        let store = ModuleStore::new();
        let complete = analyze(&files, &store, 10_000);
        assert!(complete.diagnostics.is_empty());
        assert_eq!(
            tf_eval::value::to_json(&complete.modules[0].variables[0].value),
            Some(json!([{"x":7},{"x":7}]))
        );
        let limited = analyze(&files, &store, complete.stats.evaluation_steps - 1);
        assert!(matches!(
            limited.modules[0].variables[0].value.origin(),
            Some(Origin::Limit(_))
        ));
        assert_eq!(limited.stats.loader_steps, complete.stats.loader_steps);
    }
}

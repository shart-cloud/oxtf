//! Turns `data/checkov/rules.json` into a static table, so a scan reads
//! no JSON for the bundled catalog until a rule is first used.
//!
//! Each entry holds what the linter needs before judging (the rule's
//! metadata, resource types and whether it needs the graph) and the
//! rule's own JSON, which `bundled::LazyRule` compiles on first use.
//! `tests/bundled.rs` checks every entry against the compiled rule.

use std::fmt::Write as _;

use serde_json::Value;

fn main() {
    let path = "data/checkov/rules.json";
    println!("cargo:rerun-if-changed={path}");
    let text = std::fs::read_to_string(path).expect("read the bundled catalog");
    let bundle: Value = serde_json::from_str(&text).expect("parse the bundled catalog");
    let rules = bundle["rules"].as_array().expect("bundled catalog rules");

    let mut out = String::from("&[\n");
    for entry in rules {
        let rule = &entry["rule"];
        let str_of = |v: &Value, what: &str| -> String {
            v.as_str()
                .unwrap_or_else(|| panic!("bundled rule {}: {what} is not a string", rule["name"]))
                .to_string()
        };
        let clauses = rule["clauses"].as_array().expect("clauses");
        // In clause order, without repeats, as `compile` lists them.
        let mut types: Vec<&str> = Vec::new();
        for c in clauses {
            for t in c["resource_types"].as_array().expect("resource_types") {
                let t = t.as_str().expect("resource type");
                if !types.contains(&t) {
                    types.push(t);
                }
            }
        }
        let needs_graph = clauses
            .iter()
            .any(|c| c["condition"]["op"] == "checkov_graph");
        // The serde defaults of `RuleSpec`.
        let or = |v: &Value, default: &str| v.as_str().unwrap_or(default).to_string();
        writeln!(
            out,
            "Header {{ name: {:?}, description: {:?}, level: {:?}, category: {:?}, \
             guideline: {:?}, file: {:?}, line: {:?}, types: &{:?}, needs_graph: {}, json: {:?} }},",
            str_of(&rule["name"], "name"),
            or(&rule["description"], ""),
            or(&rule["level"], "medium"),
            or(&rule["category"], "network"),
            rule["guideline"].as_str(),
            str_of(&entry["file"], "file"),
            entry["line"].as_u64().map(|l| l as u32),
            types,
            needs_graph,
            serde_json::to_string(rule).unwrap(),
        )
        .unwrap();
    }
    out.push(']');
    let dest = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("bundled_checkov.rs");
    std::fs::write(dest, out).expect("write the bundled catalog table");
}

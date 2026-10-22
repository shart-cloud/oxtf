//! Turns `data/checkov/rules.json` into a static table, so a scan reads
//! no JSON for the bundled catalog until a rule is first used.
//!
//! Each entry holds what the linter needs before judging (the rule's
//! metadata, resource types and whether it needs the graph) and the
//! rule's own JSON, which `bundled::LazyRule` compiles on first use.
//! `tests/bundled.rs` checks every entry against the compiled rule.
//!
//! `data/checkov/curation.toml` (hand-maintained) overrides a rule's level
//! and category and supplies rationale, optional remediation and a profile;
//! a rule it does not list is
//! `unreviewed`. A rule without a guideline gets its Checkov source at the
//! pinned version.

use std::fmt::Write as _;

use serde_json::Value;

const LEVELS: &[&str] = &["low", "medium", "high", "critical"];
const CATEGORIES: &[&str] = &["network", "storage", "iam", "encryption", "other"];
const PROFILES: &[&str] = &["security", "audit", "hygiene"];

struct Curated {
    level: String,
    category: Option<String>,
    profile: String,
    rationale: String,
    remediation: Option<String>,
    guideline: Option<String>,
    description: Option<String>,
}

fn curation(path: &str) -> std::collections::HashMap<String, Curated> {
    let text = std::fs::read_to_string(path).expect("read the curation");
    let table: toml::Table = text.parse().unwrap_or_else(|e| panic!("{path}: {e}"));
    table
        .into_iter()
        .map(|(id, entry)| {
            let entry = entry
                .as_table()
                .unwrap_or_else(|| panic!("{path}: [{id}] is not a table"));
            let field = |name: &str, allowed: &[&str], required: bool| -> Option<String> {
                let v = entry.get(name).map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| panic!("{path}: [{id}] {name} is not a string"))
                        .to_string()
                });
                match &v {
                    Some(v) if !allowed.contains(&v.as_str()) => {
                        panic!("{path}: [{id}] {name} = {v:?}: expected one of {allowed:?}")
                    }
                    None if required => panic!("{path}: [{id}] needs {name}"),
                    _ => v,
                }
            };
            for key in entry.keys() {
                if ![
                    "level",
                    "category",
                    "profile",
                    "why",
                    "remediation",
                    "guideline",
                    "description",
                ]
                .contains(&key.as_str())
                {
                    panic!("{path}: [{id}] has unknown field {key}");
                }
            }
            let text = |name: &str| {
                entry.get(name).map(|v| {
                    v.as_str()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| panic!("{path}: [{id}] {name} needs nonempty text"))
                        .to_string()
                })
            };
            let guideline = text("guideline");
            let remediation = text("remediation");
            if guideline.is_some() != remediation.is_some() {
                panic!("{path}: [{id}] remediation and guideline must be supplied together");
            }
            if guideline
                .as_ref()
                .is_some_and(|g| !g.starts_with("https://"))
            {
                panic!("{path}: [{id}] guideline must be an HTTPS documentation URL");
            }
            let curated = Curated {
                level: field("level", LEVELS, true).expect("required"),
                category: field("category", CATEGORIES, false),
                profile: field("profile", PROFILES, true).expect("required"),
                rationale: text("why").unwrap_or_else(|| panic!("{path}: [{id}] needs a why")),
                remediation,
                guideline,
                description: text("description"),
            };
            (id, curated)
        })
        .collect()
}

fn main() {
    let path = "data/checkov/rules.json";
    let curation_path = "data/checkov/curation.toml";
    println!("cargo:rerun-if-changed={path}");
    println!("cargo:rerun-if-changed={curation_path}");
    let text = std::fs::read_to_string(path).expect("read the bundled catalog");
    let bundle: Value = serde_json::from_str(&text).expect("parse the bundled catalog");
    let rules = bundle["rules"].as_array().expect("bundled catalog rules");
    let version = bundle["source_version"].as_str().expect("source_version");
    let mut curation = curation(curation_path);

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
        let name = str_of(&rule["name"], "name");
        let file = str_of(&entry["file"], "file");
        let curated = curation.remove(&name);
        let level = curated
            .as_ref()
            .map(|c| c.level.clone())
            .unwrap_or_else(|| or(&rule["level"], "medium"));
        let category = curated
            .as_ref()
            .and_then(|c| c.category.clone())
            .unwrap_or_else(|| or(&rule["category"], "network"));
        let profile = curated
            .as_ref()
            .map(|c| c.profile.as_str())
            .unwrap_or("unreviewed");
        let rationale = curated.as_ref().map(|c| c.rationale.as_str());
        let remediation = curated.as_ref().and_then(|c| c.remediation.as_deref());
        let description = curated
            .as_ref()
            .and_then(|c| c.description.as_deref())
            .unwrap_or_else(|| rule["description"].as_str().unwrap_or(""));
        let guideline = curated
            .as_ref()
            .and_then(|c| c.guideline.clone())
            .or_else(|| rule["guideline"].as_str().map(str::to_string))
            .unwrap_or_else(|| {
                format!("https://github.com/bridgecrewio/checkov/blob/{version}/{file}")
            });
        // Keep lazy metadata, compiled metadata, and finding wording in sync.
        // The generated catalog on disk and its predicates remain unchanged.
        let mut compiled_rule = rule.clone();
        compiled_rule["level"] = Value::from(level.clone());
        compiled_rule["category"] = Value::from(category.clone());
        compiled_rule["guideline"] = Value::from(guideline.clone());
        compiled_rule["rationale"] = rationale.into();
        compiled_rule["remediation"] = remediation.into();
        compiled_rule["description"] = Value::from(description);
        if curated.as_ref().is_some_and(|c| c.description.is_some()) {
            compiled_rule["message"] = Value::from(description);
        }
        writeln!(
            out,
            "Header {{ name: {:?}, description: {:?}, level: {:?}, category: {:?}, profile: {:?}, \
             guideline: Some({:?}), rationale: {:?}, remediation: {:?}, file: {:?}, line: {:?}, types: &{:?}, needs_graph: {}, json: {:?} }},",
            name,
            description,
            level,
            category,
            profile,
            guideline,
            rationale,
            remediation,
            file,
            entry["line"].as_u64().map(|l| l as u32),
            types,
            needs_graph,
            serde_json::to_string(&compiled_rule).unwrap(),
        )
        .unwrap();
    }
    out.push(']');
    if let Some(id) = curation.keys().next() {
        panic!("{curation_path}: [{id}] is not a bundled rule");
    }
    let dest = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("bundled_checkov.rs");
    std::fs::write(dest, out).expect("write the bundled catalog table");
}

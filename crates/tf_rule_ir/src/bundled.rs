//! The bundled Checkov catalog: Checkov's Terraform resource value checks
//! and graph policies, translated to rule IR at a pinned version and
//! compiled into the binary, so a scan runs them with no Checkov, Python
//! or policy checkout.
//!
//! `data/checkov/` holds the generated `rules.json`, the `manifest.json`
//! inventory (every upstream check, translated or not, with its reason)
//! and Checkov's license. `examples/bundle_checkov.rs` regenerates it from
//! a value pack exported by `scripts/import_checkov.py` and the graph
//! policies of the same Checkov install; `tests/bundled.rs` checks it
//! against both when they are available.

use serde::{Deserialize, Serialize};

use crate::{Origin, RuleSpec};

/// The Checkov release the bundled catalog was generated from.
pub const CHECKOV_VERSION: &str = "3.2.328";

/// The generated document, as embedded.
pub const CHECKOV_RULES_JSON: &str = include_str!("../data/checkov/rules.json");

/// The inventory of every upstream check.
pub const CHECKOV_MANIFEST_JSON: &str = include_str!("../data/checkov/manifest.json");

/// The bundled catalog's file format.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema: u32,
    pub source: String,
    pub source_version: String,
    pub rules: Vec<BundledRule>,
}

/// One rule and the upstream file it was translated from.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundledRule {
    /// The upstream file, e.g.
    /// `checkov/terraform/checks/resource/aws/S3Encryption.py`.
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub rule: RuleSpec,
}

/// The bundled Checkov rules, with their upstream files as origins.
pub fn checkov() -> Result<Vec<RuleSpec>, String> {
    let bundle: Bundle = serde_json::from_str(CHECKOV_RULES_JSON)
        .map_err(|e| format!("bundled Checkov catalog: {e}"))?;
    Ok(bundle
        .rules
        .into_iter()
        .map(|b| RuleSpec {
            origin: Origin(tf_linter::RuleSource {
                engine: tf_linter::Engine::Checkov,
                file: Some(b.file.into()),
                line: b.line,
            }),
            ..b.rule
        })
        .collect())
}

/// The generated catalog: `rules.json` and `manifest.json` text.
pub struct Generated {
    pub rules_json: String,
    pub manifest_json: String,
}

/// Build the bundled catalog from a value pack exported by
/// `scripts/import_checkov.py` (`rules.json`, `manifest.json`) and the
/// `checkov/terraform/checks/graph_checks` directory of the same install.
///
/// Value rules keep the upstream file of their check, graph rules their
/// policy file and line. An ID that is both a value check and a graph
/// policy (Checkov runs both) becomes one rule with both sets of clauses.
/// Every graph policy that does not translate is inventoried with its
/// reason, as the value pack inventories its checks.
pub fn generate(
    pack: &std::path::Path,
    graph_checks: &std::path::Path,
) -> Result<Generated, String> {
    use serde_json::{Value as Json, json};

    let read = |p: std::path::PathBuf| {
        std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))
    };
    let manifest: Json = serde_json::from_str(&read(pack.join("manifest.json"))?)
        .map_err(|e| format!("value pack manifest: {e}"))?;
    if manifest["source_version"] != CHECKOV_VERSION {
        return Err(format!(
            "value pack is Checkov {}, the bundle pins {CHECKOV_VERSION}",
            manifest["source_version"]
        ));
    }
    let mut checks: Vec<Json> = manifest["checks"]
        .as_array()
        .ok_or("value pack manifest has no checks")?
        .clone();
    let source_of = |id: &str| {
        checks
            .iter()
            .find(|c| c["id"] == id && c["status"] == "translated")
            .and_then(|c| c["source"].as_str())
            .map(|s| format!("checkov/{s}"))
    };

    let mut rules: Vec<BundledRule> = Vec::new();
    for rule in crate::parse_rules(&read(pack.join("rules.json"))?)? {
        let file = source_of(&rule.name)
            .ok_or_else(|| format!("{}: not translated in the manifest", rule.name))?;
        rules.push(BundledRule {
            file,
            line: None,
            rule,
        });
    }

    let upstream = |path: &std::path::Path| -> Result<String, String> {
        let rel = path
            .strip_prefix(graph_checks)
            .map_err(|_| format!("{} is outside the graph checks", path.display()))?;
        Ok(format!(
            "checkov/terraform/checks/graph_checks/{}",
            rel.to_string_lossy().replace('\\', "/")
        ))
    };
    let loaded = crate::load_rules_file(graph_checks)?;
    if !loaded.rego.is_empty() {
        return Err("graph checks hold Rego files".into());
    }
    for skipped in &loaded.skipped {
        checks.push(json!({
            "id": null, "kind": "graph", "source": upstream(&skipped.path)?,
            "status": "unsupported", "reason": skipped.reason,
        }));
    }
    for mut rule in loaded.rules {
        let source = rule
            .origin
            .0
            .file
            .take()
            .ok_or("graph rule without a file")?;
        let file = upstream(&source)?;
        checks.push(json!({
            "id": rule.name, "kind": "graph", "name": rule.description,
            "source": file, "status": "translated",
        }));
        match rules.iter_mut().find(|r| r.rule.name == rule.name) {
            Some(existing) => {
                existing.rule.version = existing.rule.version.max(rule.version);
                existing.rule.clauses.extend(rule.clauses);
            }
            None => rules.push(BundledRule {
                file,
                line: rule.origin.0.line,
                rule,
            }),
        }
    }
    rules.sort_by(|a, b| a.rule.name.cmp(&b.rule.name));

    let count = |kind: &str, status: &str| {
        checks
            .iter()
            .filter(|c| c["kind"] == kind && c["status"] == status)
            .count()
    };
    let manifest = json!({
        "schema": 1,
        "source": "checkov",
        "source_version": CHECKOV_VERSION,
        "ir_version": crate::IR_VERSION,
        "rules": rules.len(),
        "translated": {"resource": count("resource", "translated"), "graph": count("graph", "translated")},
        "unsupported": {"resource": count("resource", "unsupported"), "graph": count("graph", "unsupported")},
        "semantics": manifest["semantics"],
        "checks": checks,
    });
    let bundle = Bundle {
        schema: 1,
        source: "checkov".into(),
        source_version: CHECKOV_VERSION.into(),
        rules,
    };
    Ok(Generated {
        rules_json: pretty(&bundle)?,
        manifest_json: pretty(&manifest)?,
    })
}

fn pretty<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map(|s| s + "\n")
        .map_err(|e| e.to_string())
}

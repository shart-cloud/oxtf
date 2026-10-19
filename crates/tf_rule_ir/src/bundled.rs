//! The bundled Checkov catalog: Checkov's Terraform resource value checks
//! and graph policies, translated to rule IR at a pinned version and
//! compiled into the binary, so a scan runs them with no Checkov, Python
//! or policy checkout.
//!
//! `data/checkov/` holds the generated `rules.json`, the `manifest.json`
//! inventory (every upstream check, translated or not, with its reason)
//! and Checkov's license. `build.rs` tabulates `rules.json` so a scan
//! compiles only the rules it uses ([`rules`]).
//! `examples/bundle_checkov.rs` regenerates the data from
//! a value pack exported by `scripts/import_checkov.py` and the graph
//! policies of the same Checkov install; `tests/bundled.rs` checks it
//! against both when they are available.

use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use tf_linter::{DynRule, Judgement, RuleFailure, RuleInfo};
use tf_semantic::{Module, Resource};

use crate::{CompiledRule, Origin, RuleSpec};

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

/// One bundled rule as `build.rs` tabulates it: what the linter reads
/// before judging, and the rule's JSON.
struct Header {
    name: &'static str,
    description: &'static str,
    level: &'static str,
    category: &'static str,
    guideline: Option<&'static str>,
    file: &'static str,
    line: Option<u32>,
    types: &'static [&'static str],
    needs_graph: bool,
    json: &'static str,
}

static TABLE: &[Header] = include!(concat!(env!("OUT_DIR"), "/bundled_checkov.rs"));

/// The bundled Checkov rules, each compiled the first time it judges.
///
/// A scan judges only the rules of the resource types it meets, so it
/// pays for those and not for the whole catalog. Listing rules compiles
/// none.
pub fn rules() -> Result<Vec<Box<dyn DynRule>>, String> {
    TABLE
        .iter()
        .map(|h| {
            let ctx = |e: String| format!("bundled rule {:?}: {e}", h.name);
            Ok(Box::new(LazyRule {
                header: h,
                info: RuleInfo {
                    name: Arc::from(h.name),
                    category: crate::parse_category(h.category).map_err(ctx)?,
                    level: crate::parse_level(h.level).map_err(ctx)?,
                    description: Arc::from(h.description),
                    resource_types: h.types.iter().map(|t| Arc::from(*t)).collect(),
                    runs_on_module: false,
                    guideline: h.guideline.map(Arc::from),
                    source: tf_linter::RuleSource {
                        engine: tf_linter::Engine::Checkov,
                        file: Some(h.file.into()),
                        line: h.line,
                    },
                },
                compiled: OnceLock::new(),
            }) as Box<dyn DynRule>)
        })
        .collect()
}

struct LazyRule {
    header: &'static Header,
    info: RuleInfo,
    compiled: OnceLock<Result<CompiledRule, String>>,
}

impl LazyRule {
    fn compiled(&self) -> Result<&CompiledRule, RuleFailure> {
        self.compiled
            .get_or_init(|| {
                COMPILES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let spec: RuleSpec = serde_json::from_str(self.header.json)
                    .map_err(|e| format!("bundled rule {:?}: {e}", self.header.name))?;
                crate::compile(RuleSpec {
                    origin: Origin(self.info.source.clone()),
                    ..spec
                })
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

static COMPILES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many bundled rules this process has compiled, for tests.
#[doc(hidden)]
pub fn compiled_count() -> usize {
    COMPILES.load(std::sync::atomic::Ordering::Relaxed)
}

impl DynRule for LazyRule {
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn needs_graph(&self) -> bool {
        self.header.needs_graph
    }
    fn judge_graph<'a>(
        &self,
        graph: &tf_semantic::graph::ResourceGraph<'a>,
    ) -> Result<Vec<(&'a Resource, Judgement)>, RuleFailure> {
        self.compiled()?.judge_graph(graph)
    }
    fn judge_resource(&self, r: &Resource) -> Result<Vec<Judgement>, RuleFailure> {
        // A graph rule judges in `judge_graph` only (see `CompiledRule`).
        if self.header.needs_graph {
            return Ok(Vec::new());
        }
        self.compiled()?.judge_resource(r)
    }
    fn judge_module<'m>(
        &self,
        m: &'m Module,
    ) -> Result<Vec<(&'m Resource, Judgement)>, RuleFailure> {
        self.compiled()?.judge_module(m)
    }
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

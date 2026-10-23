//! Foreign Rego policies: Conftest policy directories and OPA bundles
//! people already have, run unchanged.
//!
//! Two modes, chosen by whether entry rules are named:
//!
//! - **Conftest** (no `entries`): as `conftest test`, policy paths load
//!   `.rego` files only, data comes from `data` paths, and every rule named
//!   `deny`, `violation` or `warn` (alone or with a `_suffix`) in the
//!   selected namespaces (`main` by default) is one oxtf rule. A rule's
//!   results on an input are suppressed when the namespace's `exception`
//!   set names it.
//! - **OPA** (`entries` given): as `opa eval -d a -d b`, `.json`/`.yaml`
//!   files next to the policies are data too, and each entry rule is one
//!   oxtf rule.
//!
//! In both, packages merge across files, data documents sit at their
//! directory's path below the root they were found under, and identity,
//! level and description come from the policy's own metadata ([`Meta`]).
//!
//! Rego never sees an abstract value: each evaluation's input is the
//! Known-only [`projection`](crate::projection), and certainty is decided
//! from what the projection had to leave out.

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use regorus::unstable::{Expr, Module, Rule, RuleHead};
use serde_json::{Map as JsonMap, Value as Json, json};
use tf_eval::{Kind, Known, Truth, Value};
use tf_linter::rule::{ConfigFile, DynRule, Hidden, Judgement, RuleFailure, RuleInfo, Subject};
use tf_linter::{ANY_TYPE, Category, Certainty, Level};
use tf_semantic::{Body, Resource};

use crate::projection::{self, Abstraction, Projection, Shape};

mod annotations;
mod bundle;
mod documents;
mod evaluation;
mod policy;
#[cfg(test)]
mod tests;
mod verify;
use annotations::*;
use bundle::*;
use documents::*;
use evaluation::*;
use policy::*;
pub use verify::*;

/// How foreign policies are loaded.
#[derive(Clone, Debug)]
pub struct Options<'a> {
    pub paths: &'a [PathBuf],
    /// Data documents (`.json`/`.yaml`/`.yml`), as Conftest's `--data`.
    pub data: &'a [PathBuf],
    /// Entry rules, `data.<package>.<rule>`; each becomes one oxtf rule.
    /// Naming any selects OPA mode.
    pub entries: &'a [String],
    /// Conftest namespaces to run (`main` when empty).
    pub namespaces: &'a [String],
    /// Run every namespace (`conftest --all-namespaces`).
    pub all_namespaces: bool,
    /// Files below `paths` to leave out (rule files of other formats).
    pub exclude: &'a [PathBuf],
    /// The input shape for policies that do not declare
    /// `custom.oxtf.shape`.
    pub shape: Shape,
    /// Parse as `opa eval --v0-compatible` does (a file that imports
    /// `rego.v1` is still v1).
    pub rego_v0: bool,
}

/// The default entry rule, Conftest's.
pub const DEFAULT_ENTRY: &str = "data.main.deny";

/// Conftest's rule-name conventions (`policy/engine.go`).
fn conftest_kind(name: &str) -> Option<RuleKind> {
    let suffix_ok = |rest: &str| {
        rest.is_empty()
            || rest.strip_prefix('_').is_some_and(|r| {
                r.split('_')
                    .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_alphanumeric()))
            })
    };
    if let Some(rest) = name.strip_prefix("warn") {
        return suffix_ok(rest).then_some(RuleKind::Warning);
    }
    for prefix in ["deny", "violation"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return suffix_ok(rest).then_some(RuleKind::Failure);
        }
    }
    None
}

/// The name an `exception` entry uses for a rule: without its
/// `deny_`/`violation_`/`warn_` prefix, `""` for a bare `deny`.
fn exception_name(rule: &str) -> &str {
    if matches!(rule, "deny" | "violation" | "warn") {
        return "";
    }
    ["violation_", "deny_", "warn_"]
        .iter()
        .find_map(|p| rule.strip_prefix(p))
        .unwrap_or(rule)
}

/// A Conftest rule's class: failures (`deny`, `violation`) or warnings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RuleKind {
    Failure,
    Warning,
}

/// Load the bundle and build one rule per entry. Every load-time problem
/// (unreadable file, compile error, missing entry, bad metadata, merge
/// conflict) is an `Err` naming the file.
pub fn rules(opts: &Options) -> Result<Vec<Box<dyn DynRule>>, String> {
    rules_with_sources(opts, Arc::new(tf_semantic::FileTable::new()))
}

#[expect(clippy::too_many_lines)]
pub fn rules_with_sources(
    opts: &Options,
    sources: Arc<tf_semantic::FileTable>,
) -> Result<Vec<Box<dyn DynRule>>, String> {
    let bundle = Bundle::load_with_sources(opts, sources)?;
    let mut units = Vec::new();
    if opts.entries.is_empty() {
        for (path, kind) in bundle.conftest_rules(opts)? {
            units.push(bundle.unit(path, Some(kind))?);
        }
    } else {
        for entry in opts.entries {
            units.push(bundle.unit(parse_entry(entry)?, None)?);
        }
    }
    // Fallback IDs from file stems must be unique; ambiguous ones use the
    // rule path instead.
    let mut stems: HashMap<String, usize> = HashMap::new();
    for u in &units {
        if let Fallback::Stem(s) = &u.fallback {
            *stems.entry(s.clone()).or_default() += 1;
        }
    }
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let trace = Trace::from_env()?;
    let bundle = Arc::new(bundle);
    let mut rules: Vec<Box<dyn DynRule>> = Vec::new();
    for u in units {
        let id = match (&u.meta.id, &u.fallback) {
            (Some(id), _) => id.clone(),
            (None, Fallback::Stem(s)) if stems[s] == 1 => format!("rego:{s}"),
            (None, _) => format!("rego:{}", u.path.join(".")),
        };
        let entry = format!("data.{}", u.path.join("."));
        if let Some(other) = seen.insert(id.clone(), entry.clone()) {
            return Err(format!(
                "rule ID {id} is declared by both {other} and {entry}"
            ));
        }
        let shape = u.meta.shape.unwrap_or(opts.shape);
        // Conftest evaluates whole documents unless the policy says otherwise.
        let input = match (u.kind, u.meta.input_set) {
            (Some(_), false) => Input::Document,
            _ => u.meta.input,
        };
        if input == Input::Module && shape != Shape::Plan {
            return Err(format!(
                "{entry}: custom.oxtf.input `module` needs the plan input shape"
            ));
        }
        // Only a package that defines `exception` can suppress (Conftest's
        // query is simply undefined otherwise).
        let exception = u.kind.and_then(|_| {
            let (rule, package) = u.path.split_last().expect("a rule path");
            let mut defined = package.to_vec();
            defined.push("exception".into());
            bundle
                .rules
                .iter()
                .any(|r| r.path == defined)
                .then(|| Exception {
                    rule: format!("data.{}", defined.join(".")),
                    name: exception_name(rule).to_string(),
                })
        });
        let default_level = match u.kind {
            Some(RuleKind::Warning) => Level::Low,
            _ => Level::Medium,
        };
        rules.push(Box::new(ForeignPolicy {
            info: RuleInfo {
                name: id.as_str().into(),
                category: u.meta.category.unwrap_or(Category::Other),
                level: u.meta.level.unwrap_or(default_level),
                description: u
                    .meta
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Rego policy {entry}"))
                    .into(),
                resource_types: match &u.meta.resource_types {
                    Some(types) => types.iter().map(|t| t.as_str().into()).collect(),
                    None => vec![ANY_TYPE.into()],
                },
                runs_on_module: false,
                guideline: u.meta.guideline.as_deref().map(Into::into),
                rationale: None,
                remediation: None,
                source: tf_linter::RuleSource {
                    engine: if u.kind.is_some() {
                        tf_linter::Engine::Conftest
                    } else {
                        tf_linter::Engine::Rego
                    },
                    file: Some(u.file.clone()),
                    line: Some(u.line),
                },
                aliases: Vec::new(),
                profile: tf_linter::Profile::Security,
            },
            types: u.meta.resource_types.clone(),
            input,
            bundle: bundle.clone(),
            entry,
            shape,
            exception,
            trace: trace.clone(),
        }));
    }
    Ok(rules)
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// A regorus engine configured as `opa eval` behaves: OPA has no line,
/// file-size or line-count limits, so regorus's defaults (1024 columns,
/// 1 MiB, 20 000 lines) are raised far beyond any real policy.
pub fn new_engine(rego_v0: bool) -> regorus::Engine {
    use std::num::{NonZeroU32, NonZeroUsize};
    let mut engine = regorus::Engine::new();
    engine.set_rego_v0(rego_v0);
    engine.set_execution_timer_config(timer_config(std::time::Duration::from_millis(
        tf_limits::REGO_TIME_MS_DEFAULT,
    )));
    engine.set_policy_length_config(regorus::PolicyLengthConfig {
        max_col: NonZeroU32::new(1 << 24).expect("nonzero"),
        max_file_bytes: NonZeroUsize::new(1 << 30).expect("nonzero"),
        max_lines: NonZeroUsize::new(1 << 24).expect("nonzero"),
    });
    engine
}

fn timer_config(limit: std::time::Duration) -> regorus::utils::limits::ExecutionTimerConfig {
    regorus::utils::limits::ExecutionTimerConfig {
        limit,
        check_interval: std::num::NonZeroU32::new(128).expect("positive check interval"),
    }
}

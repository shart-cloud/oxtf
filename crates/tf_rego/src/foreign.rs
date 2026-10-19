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
use tf_linter::{ANY_TYPE, Category, Level, Severity};
use tf_semantic::{Body, Resource};

use crate::projection::{self, Abstraction, Projection, Shape};

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
    let bundle = Bundle::load(opts)?;
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
    engine.set_policy_length_config(regorus::PolicyLengthConfig {
        max_col: NonZeroU32::new(1 << 24).expect("nonzero"),
        max_file_bytes: NonZeroUsize::new(1 << 30).expect("nonzero"),
        max_lines: NonZeroUsize::new(1 << 24).expect("nonzero"),
    });
    engine
}

struct PackageDef {
    path: Vec<String>,
    file: PathBuf,
    line: u32,
}

struct RuleDef {
    /// Package path followed by the head's path, without `data`.
    path: Vec<String>,
    file: PathBuf,
    /// First and last line of the whole rule.
    lines: (u32, u32),
}

struct Bundle {
    /// Unique per bundle (keys the per-thread working engines).
    id: u64,
    engine: regorus::Engine,
    /// Rules whose evaluation may read `data.conftest` (see
    /// [`conftest_readers`]): only these see `data.conftest.file`, set per
    /// file with Rego's `with`. Others run on the reused engine.
    file_info: std::collections::HashSet<Vec<String>>,
    packages: Vec<PackageDef>,
    rules: Vec<RuleDef>,
    annotations: Vec<Annotation>,
    shape: Shape,
}

/// The `exception` set that can suppress a Conftest rule, and the name it
/// must contain.
#[derive(Clone, Debug)]
struct Exception {
    rule: String,
    name: String,
}

enum Fallback {
    Stem(String),
    Path,
}

struct Unit {
    path: Vec<String>,
    kind: Option<RuleKind>,
    meta: Meta,
    fallback: Fallback,
    /// Where the rule is first defined.
    file: PathBuf,
    line: u32,
}

impl Bundle {
    fn load(opts: &Options) -> Result<Bundle, String> {
        let mut modules = Vec::new();
        let mut data = Json::Object(JsonMap::new());
        // Conftest loads only `.rego` from policy paths; `opa eval -d`
        // loads data next to the policies too.
        let only = if opts.entries.is_empty() {
            Some(Load::Rego)
        } else {
            None
        };
        for root in opts.paths {
            collect(root, root, only, opts.exclude, &mut modules, &mut data)?;
        }
        for root in opts.data {
            collect(root, root, Some(Load::Data), &[], &mut modules, &mut data)?;
        }
        if modules.is_empty() {
            return Err("no .rego files in the policy paths".into());
        }
        let mut engine = new_engine(opts.rego_v0);
        // As `opa eval --strict-builtin-errors`: a builtin error fails the
        // evaluation (a rule error) rather than making the expression
        // undefined. Without it, a builtin regorus gets wrong would be a
        // silent pass.
        engine.set_strict_builtin_errors(true);
        if opts.entries.is_empty() {
            conftest_builtins(&mut engine, &modules)?;
        }
        for (path, source) in &modules {
            engine
                .add_policy(path.display().to_string(), source.clone())
                .map_err(|e| e.to_string())?;
        }
        let (packages, rules) = index(engine.get_modules())?;
        for r in &rules {
            if let Some(v) = lookup(&data, &r.path)
                && !v.is_object()
            {
                return Err(format!(
                    "{}: rule data.{} conflicts with a data document",
                    r.file.display(),
                    r.path.join(".")
                ));
            }
        }
        engine
            .add_data(regorus::Value::from(data))
            .map_err(|e| format!("policy data: {e}"))?;
        // Prepare (schedule, hoist, gather rules) once: a clone of a
        // prepared engine stays prepared, so per-evaluation clones only pay
        // for the evaluation.
        engine
            .eval_query("true".to_string(), false)
            .map_err(|e| e.to_string())?;
        let mut annotations = Vec::new();
        for (path, source) in &modules {
            annotations.extend(parse_annotations(path, source, &packages, &rules)?);
        }
        let file_info = conftest_readers(&modules, &rules);
        static IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Ok(Bundle {
            id: IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            engine,
            file_info,
            packages,
            rules,
            annotations,
            shape: opts.shape,
        })
    }

    /// The Conftest rules in the selected namespaces, in name order.
    fn conftest_rules(&self, opts: &Options) -> Result<Vec<(Vec<String>, RuleKind)>, String> {
        let mut namespaces: Vec<Vec<String>> = if opts.all_namespaces {
            self.packages.iter().map(|p| p.path.clone()).collect()
        } else if opts.namespaces.is_empty() {
            vec![vec!["main".to_string()]]
        } else {
            opts.namespaces
                .iter()
                .map(|n| n.split('.').map(str::to_string).collect())
                .collect()
        };
        namespaces.sort();
        namespaces.dedup();
        let mut out = Vec::new();
        for ns in &namespaces {
            if !self.packages.iter().any(|p| &p.path == ns) {
                return Err(format!(
                    "no policy declares package {} (select namespaces with --namespace or --all-namespaces)",
                    ns.join(".")
                ));
            }
            let mut names: Vec<(&str, RuleKind)> = self
                .rules
                .iter()
                .filter(|r| r.path.len() == ns.len() + 1 && r.path.starts_with(ns))
                .filter_map(|r| {
                    let name = r.path.last().expect("nonempty").as_str();
                    conftest_kind(name).map(|k| (name, k))
                })
                .collect();
            names.sort();
            names.dedup();
            for (name, kind) in names {
                let mut path = ns.clone();
                path.push(name.to_string());
                out.push((path, kind));
            }
        }
        Ok(out)
    }

    fn unit(&self, path: Vec<String>, kind: Option<RuleKind>) -> Result<Unit, String> {
        let entry = &format!("data.{}", path.join("."));
        let defs: Vec<&RuleDef> = self.rules.iter().filter(|r| r.path == path).collect();
        let Some(first) = defs.first() else {
            return Err(format!("entry rule {entry} is not defined by any policy"));
        };
        let package = self
            .packages
            .iter()
            .map(|p| &p.path)
            .filter(|p| path.starts_with(p) && p.len() < path.len())
            .max_by_key(|p| p.len())
            .expect("a rule belongs to a package")
            .clone();
        let meta = self.meta(&path, &package)?;
        // The entry must produce violations (or nothing) on an empty document.
        let empty = match meta.shape.unwrap_or(self.shape) {
            Shape::Hcl => json!({"resource": {}}),
            Shape::Plan => {
                json!({"format_version": "1.2", "resource_changes": [], "planned_values": {"root_module": {"resources": []}}})
            }
        };
        let result = eval(&self.engine, empty, entry).map_err(|e| format!("{entry}: {e}"))?;
        violations(&result).map_err(|e| format!("{entry}: {e}"))?;
        let fallback = if defs.iter().all(|d| d.file == first.file) {
            Fallback::Stem(
                first
                    .file
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("policy")
                    .to_string(),
            )
        } else {
            Fallback::Path
        };
        Ok(Unit {
            file: first.file.clone(),
            line: first.lines.0,
            path,
            kind,
            meta,
            fallback,
        })
    }

    /// Metadata for the rule at `path`: each field from the nearest
    /// annotation that sets it (rule, document, package, then enclosing
    /// `subpackages` scopes), then `__rego_metadata__`.
    fn meta(&self, path: &[String], package: &[String]) -> Result<Meta, String> {
        let mut chain: Vec<&Annotation> = Vec::new();
        let mut rule_scoped: Vec<&Annotation> = self
            .annotations
            .iter()
            .filter(|a| a.scope == Scope::Rule && a.target == path)
            .collect();
        rule_scoped.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
        chain.extend(rule_scoped);
        chain.extend(
            self.annotations
                .iter()
                .filter(|a| a.scope == Scope::Document && a.target == path),
        );
        chain.extend(
            self.annotations
                .iter()
                .filter(|a| a.scope == Scope::Package && a.target == package),
        );
        for len in (0..=package.len()).rev() {
            chain.extend(
                self.annotations
                    .iter()
                    .filter(|a| a.scope == Scope::Subpackages && a.target == package[..len]),
            );
        }
        let mut meta = Meta::default();
        for a in &chain {
            meta.fill(&a.fields, &format!("{}:{}:1", a.file.display(), a.line))?;
        }
        let mut legacy = package.to_vec();
        legacy.push("__rego_metadata__".into());
        if self.rules.iter().any(|r| r.path == legacy) {
            let rule = format!("data.{}", legacy.join("."));
            let v = eval(&self.engine, json!({}), &rule).map_err(|e| format!("{rule}: {e}"))?;
            if !matches!(v, regorus::Value::Undefined) {
                let v = to_serde(&v)?;
                if !v.is_object() {
                    return Err(format!("{rule} must be an object"));
                }
                meta.fill_legacy(&v, &rule)?;
            }
        }
        Ok(meta)
    }
}

/// A configuration in one of the formats `parse_config` reproduces.
fn parse_with(parser: &str, text: &str) -> anyhow::Result<Json> {
    Ok(match parser {
        "hcl2" => {
            let alloc = tf_allocator::Allocator::new();
            let parsed = tf_parser::parse(&alloc, text);
            if !parsed.errors.is_empty() {
                anyhow::bail!("parse_config: hcl2: the configuration does not parse");
            }
            let file = alloc.alloc(parsed.file);
            crate::hcl2json::raw(file, text).map_err(|e| anyhow::anyhow!("parse_config: {e}"))?
        }
        "json" => {
            serde_json::from_str(text).map_err(|e| anyhow::anyhow!("parse_config: json: {e}"))?
        }
        other => anyhow::bail!("parse_config: parser {other:?} is not supported (hcl2, json)"),
    })
}

/// Conftest's own builtins, as far as they can be reproduced exactly:
///
/// - `parse_config` for the `hcl2` parser (hcl2json,
///   [`crate::hcl2json::raw`]) and `json`;
/// - `parse_config_file`, which resolves its path against the directory of
///   the calling policy file. An extension does not see its caller, so each
///   string literal passed to it in the bundle is mapped to the directories
///   of the files that pass it; a path with exactly one such directory
///   resolves, any other is an error;
/// - `parse_combined_config_files` fails: Conftest's combined document is
///   not reproduced.
fn conftest_builtins(
    engine: &mut regorus::Engine,
    modules: &[(PathBuf, String)],
) -> Result<(), String> {
    let parse_config = |args: Vec<regorus::Value>| -> anyhow::Result<regorus::Value> {
        let (Ok(parser), Ok(text)) = (args[0].as_string(), args[1].as_string()) else {
            anyhow::bail!("parse_config: expected (parser, configuration) strings");
        };
        Ok(regorus::Value::from(parse_with(parser, text)?))
    };
    let mut callers: HashMap<String, std::collections::BTreeSet<PathBuf>> = HashMap::new();
    for (path, source) in modules {
        let mut rest = source.as_str();
        while let Some(i) = rest.find("parse_config_file(") {
            rest = &rest[i + "parse_config_file(".len()..];
            let arg = rest.trim_start();
            if let Some(lit) = arg
                .strip_prefix('"')
                .and_then(|a| a.split_once('"'))
                .map(|(l, _)| l)
            {
                callers
                    .entry(lit.to_string())
                    .or_default()
                    .insert(path.parent().unwrap_or(Path::new(".")).to_path_buf());
            }
        }
    }
    let parse_config_file = move |args: Vec<regorus::Value>| -> anyhow::Result<regorus::Value> {
        let Ok(arg) = args[0].as_string() else {
            anyhow::bail!("parse_config_file: expected a path string");
        };
        let dirs = callers
            .get(&**arg)
            .map(|d| d.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let [dir] = dirs.as_slice() else {
            anyhow::bail!(
                "parse_config_file({arg:?}): the calling policy file cannot be determined (pass a string literal from one directory)"
            );
        };
        let path = dir.join(&**arg);
        let parser = match path.extension().and_then(|e| e.to_str()) {
            Some("tf" | "hcl") => "hcl2",
            Some("json") => "json",
            _ => anyhow::bail!(
                "parse_config_file: {}: unsupported file type",
                path.display()
            ),
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("read config file {}: {e}", path.display()))?;
        Ok(regorus::Value::from(parse_with(parser, &text)?))
    };
    let unsupported = |name: &'static str| {
        move |_: Vec<regorus::Value>| -> anyhow::Result<regorus::Value> {
            anyhow::bail!("{name} is not supported: Conftest's combined document is not reproduced")
        }
    };
    engine
        .add_extension("parse_config".into(), 2, Box::new(parse_config))
        .and_then(|_| {
            engine.add_extension("parse_config_file".into(), 1, Box::new(parse_config_file))
        })
        .and_then(|_| {
            engine.add_extension(
                "parse_combined_config_files".into(),
                1,
                Box::new(unsupported("parse_combined_config_files")),
            )
        })
        .map_err(|e| e.to_string())
}

/// One `test_*` rule's outcome (`oxtf rules test`, Conftest's `verify`).
#[derive(Clone, Debug, PartialEq)]
pub struct TestOutcome {
    /// `data.<package>.<rule>`.
    pub rule: String,
    pub file: PathBuf,
    pub result: TestResult,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TestResult {
    Pass,
    Fail,
    /// `todo_test_*`.
    Skip,
    Error(String),
}

/// Run the bundle's tests as `conftest verify` does (OPA's tester): every
/// rule named `test_*` passes when it evaluates to `true`; `todo_test_*`
/// is skipped. `namespaces` narrows the packages reported.
pub fn verify(opts: &Options) -> Result<Vec<TestOutcome>, String> {
    let bundle = Bundle::load(opts)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for r in &bundle.rules {
        let (name, package) = r.path.split_last().expect("a rule path");
        let skip = name.starts_with("todo_test_");
        if !(name.starts_with("test_") || skip) || !seen.insert(r.path.clone()) {
            continue;
        }
        let ns = package.join(".");
        if !opts.namespaces.is_empty() && !opts.namespaces.iter().any(|n| glob(n, &ns)) {
            continue;
        }
        let rule = format!("data.{}", r.path.join("."));
        let result = if skip {
            TestResult::Skip
        } else {
            match eval(&bundle.engine, json!({}), &rule) {
                Ok(v) if v == regorus::Value::from(true) => TestResult::Pass,
                Ok(_) => TestResult::Fail,
                Err(e) => TestResult::Error(e),
            }
        };
        out.push(TestOutcome {
            rule,
            file: r.file.clone(),
            result,
        });
    }
    Ok(out)
}

/// Conftest's namespace patterns: literal, or with `*` wildcards.
fn glob(pattern: &str, s: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == s,
        Some((head, tail)) => {
            s.starts_with(head)
                && (0..=s.len() - head.len())
                    .any(|i| s.is_char_boundary(head.len() + i) && glob(tail, &s[head.len() + i..]))
        }
    }
}

/// The rules whose evaluation may read `data.conftest`, conservatively:
/// every rule of a module that imports `data.conftest` (or all of `data`),
/// every rule whose text reads `data.conftest` or reads `data` dynamically,
/// and every rule whose text names one of those (by its last path
/// segment), to a fixed point. A false positive only costs time.
fn conftest_readers(
    modules: &[(PathBuf, String)],
    rules: &[RuleDef],
) -> std::collections::HashSet<Vec<String>> {
    let text = |r: &RuleDef| -> &str {
        let Some((_, src)) = modules.iter().find(|(p, _)| *p == r.file) else {
            return "";
        };
        let lines: Vec<&str> = src.lines().collect();
        let (a, b) = (
            r.lines.0 as usize - 1,
            (r.lines.1 as usize).min(lines.len()),
        );
        let start: usize = lines[..a].iter().map(|l| l.len() + 1).sum();
        let end: usize = lines[..b].iter().map(|l| l.len() + 1).sum();
        &src[start.min(src.len())..end.min(src.len())]
    };
    let mut out = std::collections::HashSet::new();
    for (path, src) in modules {
        // `import data.conftest...`, or `import data` (which makes all of
        // `data` reachable through an alias).
        let imports = src.lines().map(str::trim).any(|l| {
            l.strip_prefix("import").is_some_and(|rest| {
                let target = rest.split_whitespace().next().unwrap_or("");
                target == "data" || target.starts_with("data.conftest")
            })
        });
        for r in rules.iter().filter(|r| r.file == *path) {
            if imports || reads_conftest(text(r)) {
                out.insert(r.path.clone());
            }
        }
    }
    loop {
        let names: std::collections::HashSet<&str> = out
            .iter()
            .filter_map(|p| p.last().map(String::as_str))
            .collect();
        let more: Vec<Vec<String>> = rules
            .iter()
            .filter(|r| !out.contains(&r.path))
            .filter(|r| names.iter().any(|n| mentions(text(r), n)))
            .map(|r| r.path.clone())
            .collect();
        if more.is_empty() {
            return out;
        }
        out.extend(more);
    }
}

/// Whether `text` contains `name` as a whole identifier.
fn mentions(text: &str, name: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(name).any(|(i, _)| {
        !text[..i].chars().next_back().is_some_and(ident)
            && !text[i + name.len()..].chars().next().is_some_and(ident)
    })
}

/// Whether text can read `data.conftest`: it names it, or reads `data`
/// other than through a static `data.<name>` path (`data[x]`, `walk(data)`).
fn reads_conftest(src: &str) -> bool {
    let b = src.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while let Some(off) = src[i..].find("data") {
        let at = i + off;
        i = at + 4;
        if at > 0 && ident(b[at - 1]) || b.get(at + 4).is_some_and(|&c| ident(c)) {
            continue;
        }
        if b.get(at + 4) != Some(&b'.') {
            return true;
        }
        let rest = &src[at + 5..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name == "conftest" {
            return true;
        }
    }
    false
}

/// Per-root work shared by every rule of a bundle: each file's rendered
/// document and exception results. Rules run one
/// after another per root on one thread, so the cache lives in a
/// thread-local keyed by (bundle, analysis) and is replaced per root.
#[derive(Default)]
struct RootCache {
    /// The bundle and [`ConfigFile::run`] the entries belong to.
    key: (usize, u64),
    documents: HashMap<(usize, tf_span::FileId), Arc<CachedDocument>>,
    /// The `exception` set's value, by (exception rule, file).
    exceptions: HashMap<(String, PathBuf), regorus::Value>,
}

/// A rendered file document without borrows: instances by index into the
/// module's resources.
struct CachedDocument {
    doc: regorus::Value,
    abstractions: Vec<Abstraction>,
    instances: Vec<(usize, regorus::Value)>,
}

thread_local! {
    static ROOT_CACHE: std::cell::RefCell<RootCache> = std::cell::RefCell::new(RootCache::default());
    /// Working copies of bundle engines, by bundle id. regorus engines are
    /// reusable: `set_input` replaces the input and `eval_rule` clears the
    /// previous evaluation's state.
    static WORK: std::cell::RefCell<HashMap<u64, regorus::Engine>> = std::cell::RefCell::new(HashMap::new());
}

/// What a path may contribute; `None` in [`collect`] is both.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Load {
    Rego,
    Data,
}

/// Collect modules and data below `root` (a file or directory), in name
/// order, as OPA's loader does: hidden files included, other extensions
/// ignored.
fn collect(
    root: &Path,
    path: &Path,
    only: Option<Load>,
    exclude: &[PathBuf],
    modules: &mut Vec<(PathBuf, String)>,
    data: &mut Json,
) -> Result<(), String> {
    if exclude.iter().any(|e| e == path) {
        return Ok(());
    }
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.is_dir() {
        let mut children: Vec<PathBuf> = std::fs::read_dir(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .map(|e| e.map(|e| e.path()))
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        children.sort();
        for child in children {
            collect(root, &child, only, exclude, modules, data)?;
        }
        return Ok(());
    }
    let read = || std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()));
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let wanted = match ext {
        "rego" => Load::Rego,
        "json" | "yaml" | "yml" => Load::Data,
        _ => Load::Rego,
    };
    if only.is_some_and(|o| o != wanted) && ["rego", "json", "yaml", "yml"].contains(&ext) {
        if path == root {
            return Err(format!(
                "{}: expected {}",
                path.display(),
                if wanted == Load::Rego {
                    "data (.json, .yaml)"
                } else {
                    "a .rego file"
                }
            ));
        }
        return Ok(());
    }
    let doc = match ext {
        "rego" => {
            modules.push((path.to_path_buf(), read()?));
            return Ok(());
        }
        "json" => serde_json::from_str::<Json>(&read()?)
            .map_err(|e| format!("{}: {e}", path.display()))?,
        "yaml" | "yml" => tf_yaml::goyaml::load(&read()?)
            .map_err(|e| format!("{}:{e}", path.display()))?
            .unwrap_or(Json::Null),
        _ if path == root => {
            return Err(format!(
                "{}: not a .rego, .json or .yaml file",
                path.display()
            ));
        }
        _ => return Ok(()),
    };
    if !doc.is_object() {
        return Err(format!(
            "{}: document must be of type object",
            path.display()
        ));
    }
    let at: Vec<String> = path
        .parent()
        .and_then(|p| p.strip_prefix(root).ok())
        .map(|rel| {
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut slot = &mut *data;
    for key in &at {
        let obj = slot.as_object_mut().ok_or_else(|| merge_error(path))?;
        slot = obj.entry(key.clone()).or_insert_with(|| json!({}));
    }
    if !merge(slot, doc) {
        return Err(merge_error(path));
    }
    Ok(())
}

fn merge_error(path: &Path) -> String {
    format!("{}: merge error", path.display())
}

/// Deep-merge objects; any other overlap is a conflict.
fn merge(dst: &mut Json, src: Json) -> bool {
    match (dst, src) {
        (Json::Object(d), Json::Object(s)) => {
            for (k, v) in s {
                match d.get_mut(&k) {
                    Some(existing) => {
                        if !merge(existing, v) {
                            return false;
                        }
                    }
                    None => {
                        d.insert(k, v);
                    }
                }
            }
            true
        }
        _ => false,
    }
}

fn lookup<'a>(data: &'a Json, path: &[String]) -> Option<&'a Json> {
    path.iter().try_fold(data, |v, k| v.get(k))
}

fn parse_entry(entry: &str) -> Result<Vec<String>, String> {
    let rest = entry
        .strip_prefix("data.")
        .ok_or_else(|| format!("entry rule {entry:?} must start with `data.`"))?;
    let path: Vec<String> = rest.split('.').map(str::to_string).collect();
    let ident = |s: &str| {
        s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if path.len() < 2 || !path.iter().all(|s| ident(s)) {
        return Err(format!(
            "entry rule {entry:?} must be `data.<package>.<rule>` with dotted identifiers"
        ));
    }
    Ok(path)
}

/// Package and rule definitions, from the parsed modules.
fn index(
    modules: &[regorus::unstable::Ref<Module>],
) -> Result<(Vec<PackageDef>, Vec<RuleDef>), String> {
    let mut packages = Vec::new();
    let mut rules = Vec::new();
    for m in modules {
        let file = PathBuf::from(m.package.span.source.get_path());
        let package = ref_path(&m.package.refr)
            .ok_or_else(|| format!("{}: unsupported package path", file.display()))?;
        // `package data.x` and `package x` name the same package.
        let package: Vec<String> = match package.split_first() {
            Some((d, rest)) if d == "data" => rest.to_vec(),
            _ => package,
        };
        packages.push(PackageDef {
            path: package.clone(),
            file: file.clone(),
            line: m.package.span.line,
        });
        for rule in &m.policy {
            let head = match rule.as_ref() {
                Rule::Spec { head, .. } => match head {
                    RuleHead::Compr { refr, .. }
                    | RuleHead::Set { refr, .. }
                    | RuleHead::Func { refr, .. } => refr,
                },
                Rule::Default { refr, .. } => refr,
            };
            let Some(head) = ref_path(head) else {
                continue;
            };
            let span = rule.span();
            let end = span.line + span.text().matches('\n').count() as u32;
            let mut path = package.clone();
            path.extend(head);
            rules.push(RuleDef {
                path,
                file: file.clone(),
                lines: (span.line, end),
            });
        }
    }
    Ok((packages, rules))
}

/// The static path of a reference: `a.b["c"]` is `[a, b, c]`; a variable
/// index ends the path at its container (`deny[msg]` is `deny`).
fn ref_path(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::Var { span, .. } => Some(vec![span.text().to_string()]),
        Expr::RefDot { refr, field, .. } => {
            let mut p = ref_path(refr)?;
            p.push(field.0.text().to_string());
            Some(p)
        }
        Expr::RefBrack { refr, index, .. } => {
            let mut p = ref_path(refr)?;
            match index.as_ref() {
                Expr::String { value, .. } | Expr::RawString { value, .. } => {
                    p.push(value.as_string().ok()?.to_string());
                    Some(p)
                }
                _ => Some(p),
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Annotations
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    Package,
    Subpackages,
    Rule,
    Document,
}

struct Annotation {
    scope: Scope,
    /// The package path (package scopes) or rule path (rule scopes).
    target: Vec<String>,
    fields: JsonMap<String, Json>,
    file: PathBuf,
    /// Line of the `# METADATA` comment.
    line: u32,
}

/// `# METADATA` blocks in one module, attached as OPA attaches them: to
/// the next package or rule statement, across blank lines.
fn comment(l: &str) -> Option<&str> {
    l.trim_start().strip_prefix('#')
}

fn parse_annotations(
    file: &Path,
    source: &str,
    packages: &[PackageDef],
    rules: &[RuleDef],
) -> Result<Vec<Annotation>, String> {
    let package = packages
        .iter()
        .find(|p| p.file == file)
        .expect("each module has a package");
    let file_rules: Vec<&RuleDef> = rules.iter().filter(|r| r.file == file).collect();
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let header = comment(lines[i]).is_some_and(|c| c.trim() == "METADATA");
        if !header {
            i += 1;
            continue;
        }
        let start = i + 1; // 1-based line of the header
        let mut yaml = String::new();
        i += 1;
        while i < lines.len() {
            match comment(lines[i]) {
                Some(c) if c.trim() != "METADATA" => {
                    yaml.push_str(c);
                    yaml.push('\n');
                    i += 1;
                }
                _ => break,
            }
        }
        let start = start as u32;
        let at = format!("{}:{start}:1", file.display());
        // A block inside a rule body is an ordinary comment.
        if file_rules
            .iter()
            .any(|r| r.lines.0 < start && start <= r.lines.1)
        {
            continue;
        }
        let fields =
            match tf_yaml::goyaml::load(&yaml).map_err(|e| format!("{at}: METADATA: {e}"))? {
                Some(Json::Object(m)) => m,
                None => JsonMap::new(),
                Some(_) => return Err(format!("{at}: METADATA must be a mapping")),
            };
        let end = start + yaml.lines().count() as u32;
        let next_rule = file_rules
            .iter()
            .filter(|r| r.lines.0 > end)
            .min_by_key(|r| r.lines.0);
        let (default, target, line) =
            if package.line > end && next_rule.is_none_or(|r| package.line < r.lines.0) {
                (Scope::Package, package.path.clone(), package.line)
            } else if let Some(r) = next_rule {
                (Scope::Rule, r.path.clone(), r.lines.0)
            } else {
                return Err(format!(
                    "{at}: METADATA is not followed by a package or rule"
                ));
            };
        let scope = match fields.get("scope") {
            None => default,
            Some(Json::String(s)) => match (s.as_str(), default) {
                ("package", Scope::Package) => Scope::Package,
                ("subpackages", Scope::Package) => Scope::Subpackages,
                ("rule", Scope::Rule) => Scope::Rule,
                ("document", Scope::Rule) => Scope::Document,
                _ => {
                    return Err(format!(
                        "{at}: METADATA scope `{s}` cannot annotate the statement on line {line}"
                    ));
                }
            },
            Some(other) => {
                return Err(format!(
                    "{at}: METADATA scope must be a string, got {other}"
                ));
            }
        };
        out.push(Annotation {
            scope,
            target,
            fields,
            file: file.to_path_buf(),
            line: start,
        });
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Input {
    #[default]
    Resource,
    Module,
    /// Conftest's unit: a whole document (a `.tf` file in the HCL shape,
    /// the root's plan in the plan shape), with results attributed by
    /// ablation.
    Document,
}

/// The metadata oxtf reads; `None` until some annotation sets it.
#[derive(Debug, Default)]
struct Meta {
    id: Option<String>,
    level: Option<Level>,
    description: Option<String>,
    category: Option<Category>,
    guideline: Option<String>,
    resource_types: Option<Vec<String>>,
    input: Input,
    input_set: bool,
    shape: Option<Shape>,
}

fn level(s: &str, at: &str) -> Result<Level, String> {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Ok(Level::Critical),
        "high" => Ok(Level::High),
        "medium" => Ok(Level::Medium),
        "low" | "info" => Ok(Level::Low),
        _ => Err(format!(
            "{at}: unknown severity {s:?} (critical, high, medium, low, info)"
        )),
    }
}

impl Meta {
    fn fill(&mut self, fields: &JsonMap<String, Json>, at: &str) -> Result<(), String> {
        let string = |v: &Json, name: &str| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{at}: METADATA {name} must be a string"))
        };
        if self.description.is_none()
            && let Some(v) = fields.get("title").or_else(|| fields.get("description"))
        {
            self.description = Some(string(v, "title")?);
        }
        if self.guideline.is_none()
            && let Some(related) = fields.get("related_resources")
        {
            // `[{"ref": url, "description": ...}]` or `[url]` (OPA allows both).
            let first = related.as_array().and_then(|a| a.first());
            self.guideline = first
                .and_then(|r| r.get("ref").or(Some(r)))
                .and_then(Json::as_str)
                .map(str::to_string);
        }
        let Some(custom) = fields.get("custom") else {
            return Ok(());
        };
        if self.category.is_none()
            && let Some(v) = custom.get("category")
        {
            self.category = Some(Category::from_foreign(&string(v, "custom.category")?));
        }
        let custom = custom
            .as_object()
            .ok_or_else(|| format!("{at}: METADATA custom must be a mapping"))?;
        if self.id.is_none()
            && let Some(v) = custom.get("id")
        {
            self.id = Some(string(v, "custom.id")?);
        }
        if self.level.is_none()
            && let Some(v) = custom.get("severity")
        {
            self.level = Some(level(&string(v, "custom.severity")?, at)?);
        }
        let Some(oxtf) = custom.get("oxtf") else {
            return Ok(());
        };
        let oxtf = oxtf
            .as_object()
            .ok_or_else(|| format!("{at}: METADATA custom.oxtf must be a mapping"))?;
        for key in oxtf.keys() {
            if !matches!(key.as_str(), "resource_types" | "input" | "shape") {
                return Err(format!("{at}: unknown METADATA field custom.oxtf.{key}"));
            }
        }
        if self.resource_types.is_none()
            && let Some(v) = oxtf.get("resource_types")
        {
            let types = v
                .as_array()
                .and_then(|a| a.iter().map(|t| t.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
                .filter(|t| !t.is_empty())
                .ok_or_else(|| {
                    format!("{at}: METADATA custom.oxtf.resource_types must be a nonempty list of strings")
                })?;
            self.resource_types = Some(types);
        }
        if self.shape.is_none()
            && let Some(v) = oxtf.get("shape")
        {
            self.shape = Some(v.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                format!("{at}: METADATA custom.oxtf.shape must be `plan` or `hcl`")
            })?);
        }
        if !self.input_set
            && let Some(v) = oxtf.get("input")
        {
            self.input = match v.as_str() {
                Some("resource") => Input::Resource,
                Some("module") => Input::Module,
                Some("document") => Input::Document,
                _ => {
                    return Err(format!(
                        "{at}: METADATA custom.oxtf.input must be `resource`, `module` or `document`"
                    ));
                }
            };
            self.input_set = true;
        }
        Ok(())
    }

    /// `__rego_metadata__` (Trivy/tfsec style): `id`, `title`,
    /// `description`, `severity`.
    fn fill_legacy(&mut self, v: &Json, at: &str) -> Result<(), String> {
        let get = |k: &str| -> Result<Option<String>, String> {
            match v.get(k) {
                None | Some(Json::Null) => Ok(None),
                Some(Json::String(s)) => Ok(Some(s.clone())),
                Some(other) => Err(format!("{at}: {k} must be a string, got {other}")),
            }
        };
        if self.id.is_none() {
            self.id = get("id")?;
        }
        if self.description.is_none() {
            self.description = get("title")?.or(get("description")?);
        }
        if self.level.is_none()
            && let Some(s) = get("severity")?
        {
            self.level = Some(level(&s, at)?);
        }
        if self.guideline.is_none() {
            self.guideline = get("url")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

pub(crate) fn eval(
    engine: &regorus::Engine,
    input: Json,
    rule: &str,
) -> Result<regorus::Value, String> {
    eval_value(engine, regorus::Value::from(input), rule)
}

fn eval_value(
    engine: &regorus::Engine,
    input: regorus::Value,
    rule: &str,
) -> Result<regorus::Value, String> {
    let mut engine = engine.clone();
    engine.set_input(input);
    engine
        .eval_rule(rule.to_string())
        .map_err(|e| e.to_string())
}

fn to_serde(v: &regorus::Value) -> Result<Json, String> {
    serde_json::from_str(&v.to_json_str().map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// Whether an `exception` set's value names the rule.
fn exception_names(v: &regorus::Value, e: &Exception) -> Result<bool, String> {
    if matches!(v, regorus::Value::Undefined) {
        return Ok(false);
    }
    Ok(match to_serde(v)? {
        Json::Array(items) => items.iter().any(|inner| match inner {
            Json::Array(names) => names.iter().any(|n| n.as_str() == Some(&e.name)),
            Json::Object(m) => m.values().any(|n| n.as_str() == Some(&e.name)),
            _ => false,
        }),
        Json::Object(m) => m.values().any(|inner| match inner {
            Json::Array(names) => names.iter().any(|n| n.as_str() == Some(&e.name)),
            Json::Object(m) => m.values().any(|n| n.as_str() == Some(&e.name)),
            _ => false,
        }),
        _ => false,
    })
}

/// One violation an entry rule produced.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Violation {
    pub msg: String,
    /// The resource the violation is about (`address`).
    pub address: Option<String>,
    /// The attribute it is about (`path`): `a.b[0].c` or `["a", "b", 0, "c"]`.
    pub path: Option<Vec<Segment>>,
    /// A mechanical fix (`fix`): set top-level `attribute` to `value`.
    pub fix: Option<(String, Json)>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Segment {
    Key(String),
    Index(usize),
}

/// The violations an entry rule produced, read as Conftest reads them: a
/// set or array whose strings are messages and whose objects need a `msg`
/// string (optional `address`, `path`, `fix`; other keys are metadata).
/// An empty message is a pass and other values are ignored, as in
/// Conftest.
pub(crate) fn violations(result: &regorus::Value) -> Result<Vec<Violation>, String> {
    if matches!(result, regorus::Value::Undefined) {
        return Ok(Vec::new());
    }
    let items = match to_serde(result)? {
        Json::Array(items) => items,
        Json::Bool(false) | Json::Null => Vec::new(),
        other => {
            return Err(format!(
                "entry rule must produce a set of violations, got {other}"
            ));
        }
    };
    let mut out = Vec::new();
    for item in items {
        if let Some(v) = violation(item)?
            && !v.msg.is_empty()
        {
            out.push(v);
        }
    }
    Ok(out)
}

fn violation(item: Json) -> Result<Option<Violation>, String> {
    let o = match item {
        Json::String(msg) => {
            return Ok(Some(Violation {
                msg,
                address: None,
                path: None,
                fix: None,
            }));
        }
        Json::Object(o) => o,
        _ => return Ok(None),
    };
    let msg = match o.get("msg") {
        Some(Json::String(s)) => s.clone(),
        _ => {
            return Err(format!(
                "\"msg\" field must be present and a string in {}",
                Json::Object(o)
            ));
        }
    };
    let address = match o.get("address") {
        None | Some(Json::Null) => None,
        Some(Json::String(s)) => Some(s.clone()),
        Some(other) => return Err(format!("violation address must be a string, got {other}")),
    };
    let path = match o.get("path") {
        None | Some(Json::Null) => None,
        Some(Json::String(s)) => {
            Some(parse_path(s).ok_or_else(|| format!("invalid violation path {s:?}"))?)
        }
        Some(Json::Array(items)) => Some(
            items
                .iter()
                .map(|s| match s {
                    Json::String(k) => Some(Segment::Key(k.clone())),
                    Json::Number(n) => n.as_u64().map(|i| Segment::Index(i as usize)),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| format!("invalid violation path {}", Json::Array(items.clone())))?,
        ),
        Some(other) => {
            return Err(format!(
                "violation path must be a string or list, got {other}"
            ));
        }
    };
    let fix = match o.get("fix") {
        None | Some(Json::Null) => None,
        Some(Json::Object(f)) => match (f.get("attribute"), f.get("value")) {
            (Some(Json::String(a)), Some(v)) if !a.is_empty() && !a.contains(['.', '[']) => {
                Some((a.clone(), v.clone()))
            }
            _ => {
                return Err(format!(
                    "violation fix must be {{\"attribute\": <top-level name>, \"value\": <literal>}}, got {}",
                    Json::Object(f.clone())
                ));
            }
        },
        Some(other) => return Err(format!("violation fix must be an object, got {other}")),
    };
    Ok(Some(Violation {
        msg,
        address,
        path,
        fix,
    }))
}

/// `a.b[0].c`
fn parse_path(s: &str) -> Option<Vec<Segment>> {
    let mut out = Vec::new();
    for part in s.split('.') {
        let (name, mut rest) = part.split_once('[').map_or((part, ""), |(n, r)| (n, r));
        if name.is_empty() {
            return None;
        }
        out.push(Segment::Key(name.to_string()));
        while !rest.is_empty() {
            let (index, tail) = rest.split_once(']')?;
            out.push(Segment::Index(index.parse().ok()?));
            rest = tail.strip_prefix('[').unwrap_or(tail);
            if !tail.is_empty() && !tail.starts_with('[') {
                return None;
            }
        }
    }
    Some(out)
}

/// The configured value at `path` in a resource body, with provenance.
fn locate(body: &Body, path: &[Segment]) -> Option<Value> {
    let (Segment::Key(first), rest) = path.split_first()? else {
        return None;
    };
    if let Some(v) = body.value(first) {
        return descend(v, rest);
    }
    let blocks: Vec<&Body> = body
        .blocks
        .iter()
        .filter(|b| *b.ty == **first && b.existence == Truth::True)
        .map(|b| &b.body)
        .collect();
    match rest.split_first() {
        Some((Segment::Index(i), rest)) => locate(blocks.get(*i)?, rest),
        _ => None,
    }
}

fn descend(v: &Value, path: &[Segment]) -> Option<Value> {
    let Some((seg, rest)) = path.split_first() else {
        return Some(v.clone());
    };
    match (&v.kind, seg) {
        (Kind::Known(Known::Object(m)), Segment::Key(k)) => {
            descend(&m.get(k.as_str())?.child_of(v), rest)
        }
        (Kind::Known(Known::List(l)), Segment::Index(i)) => descend(&l.get(*i)?.child_of(v), rest),
        _ => None,
    }
}

/// `OXTF_POLICY_TRACE=FILE` appends one JSON line per evaluation (entry,
/// input, raw result) for the `opa eval` conformance harness.
#[derive(Clone)]
struct Trace(Arc<Mutex<std::fs::File>>);

impl Trace {
    fn from_env() -> Result<Option<Trace>, String> {
        let Some(path) = std::env::var_os("OXTF_POLICY_TRACE") else {
            return Ok(None);
        };
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("OXTF_POLICY_TRACE {}: {e}", Path::new(&path).display()))?;
        Ok(Some(Trace(Arc::new(Mutex::new(file)))))
    }

    fn record(
        &self,
        entry: &str,
        input: &Json,
        file: Option<(&Path, bool)>,
        result: &Result<regorus::Value, String>,
    ) {
        let mut line = match result {
            Ok(v) => json!({"entry": entry, "input": input, "result": to_serde(v).ok()}),
            Err(e) => json!({"entry": entry, "input": input, "error": e}),
        };
        if let Some((f, whole)) = file {
            line["file"] = json!(f.display().to_string());
            line["whole_file"] = json!(whole);
        }
        let mut f = self.0.lock().expect("trace lock");
        let _ = writeln!(f, "{line}");
    }
}

struct ForeignPolicy {
    info: RuleInfo,
    types: Option<Vec<String>>,
    input: Input,
    bundle: Arc<Bundle>,
    entry: String,
    shape: Shape,
    exception: Option<Exception>,
    trace: Option<Trace>,
}

impl ForeignPolicy {
    fn run(&self, input: Json) -> Result<Vec<Violation>, String> {
        self.run_on(regorus::Value::from(input), None, true)
    }

    /// [`ForeignPolicy::run`] with Conftest's `data.conftest.file` set to
    /// the file under evaluation.
    /// A file document (`whole`) or one instance alone (ablation, which
    /// asks only whether the instance produces the violation: exceptions
    /// were already decided on the whole file).
    fn run_file(
        &self,
        input: regorus::Value,
        file: &Path,
        whole: bool,
    ) -> Result<Vec<Violation>, String> {
        self.run_on(input, Some((file, whole)), whole)
    }

    /// Evaluate `rule` on a reused working copy of the bundle's engine. For
    /// a file and a rule that may read it, `data.conftest.file` is set with
    /// Rego's `with`, which needs no re-prepared engine.
    fn evaluate(
        &self,
        file: Option<&Path>,
        input: regorus::Value,
        rule: &str,
    ) -> Result<regorus::Value, String> {
        let reads = rule
            .strip_prefix("data.")
            .map(|r| r.split('.').map(str::to_string).collect::<Vec<_>>())
            .is_some_and(|p| self.bundle.file_info.contains(&p));
        let with = match file {
            Some(f) if reads => {
                let abs = std::path::absolute(f).unwrap_or_else(|_| f.to_path_buf());
                Some(json!({
                    "name": abs.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                    "dir": abs.parent().map(|d| d.display().to_string()).unwrap_or_default(),
                }))
            }
            _ => None,
        };
        WORK.with(|w| {
            // Taken out while evaluating: an extension may evaluate too.
            let mut engine = w
                .borrow_mut()
                .remove(&self.bundle.id)
                .unwrap_or_else(|| self.bundle.engine.clone());
            engine.set_input(input);
            let result = match &with {
                None => engine
                    .eval_rule(rule.to_string())
                    .map_err(|e| e.to_string()),
                Some(info) => engine
                    .eval_query(
                        format!("__oxtf_result := {rule} with data.conftest.file as {info}"),
                        false,
                    )
                    .map_err(|e| e.to_string())
                    .map(|r| {
                        r.result
                            .first()
                            .and_then(|r| {
                                r.bindings.as_object().ok().and_then(|b| {
                                    b.get(&regorus::Value::from("__oxtf_result")).cloned()
                                })
                            })
                            .unwrap_or(regorus::Value::Undefined)
                    }),
            };
            w.borrow_mut().insert(self.bundle.id, engine);
            result
        })
    }

    /// Start (or keep) the per-root cache for `run`.
    fn enter_root(&self, run: u64) {
        let key = (Arc::as_ptr(&self.bundle) as usize, run);
        ROOT_CACHE.with(|c| {
            let mut c = c.borrow_mut();
            if c.key != key {
                *c = RootCache {
                    key,
                    ..RootCache::default()
                };
            }
        });
    }

    /// The file's rendered document, shared by the bundle's rules for this
    /// root.
    fn document(&self, cf: &ConfigFile<'_>) -> Result<Arc<CachedDocument>, String> {
        let key = (std::ptr::from_ref(cf.module) as usize, cf.source.id);
        if let Some(d) = ROOT_CACHE.with(|c| c.borrow().documents.get(&key).cloned()) {
            return Ok(d);
        }
        let fd = crate::hcl2json::evaluated(cf)?;
        let instances = fd
            .instances
            .into_iter()
            .map(|i| {
                let index = cf
                    .module
                    .resources
                    .iter()
                    .position(|r| std::ptr::eq(r, i.resource))
                    .expect("an instance of this module");
                (index, regorus::Value::from(i.doc))
            })
            .collect();
        let d = Arc::new(CachedDocument {
            doc: regorus::Value::from(fd.doc),
            abstractions: fd.abstractions,
            instances,
        });
        ROOT_CACHE.with(|c| c.borrow_mut().documents.insert(key, d.clone()));
        Ok(d)
    }

    /// `file`: the document's file, and whether this is the whole file (not
    /// one instance alone, for ablation); for the trace only.
    fn run_on(
        &self,
        input: regorus::Value,
        file: Option<(&Path, bool)>,
        exceptions: bool,
    ) -> Result<Vec<Violation>, String> {
        let path = file.map(|(f, _)| f);
        if exceptions
            && let Some(e) = &self.exception
            && self.is_excepted(&input, path, e)?
        {
            return Ok(Vec::new());
        }
        let result = self.evaluate(path, input.clone(), &self.entry);
        if let Some(t) = &self.trace {
            t.record(
                &self.entry,
                &to_serde(&input).unwrap_or(Json::Null),
                file,
                &result,
            );
        }
        violations(&result?)
    }

    /// The exception check, with the set's value cached per (exception
    /// rule, file) for a root.
    fn is_excepted(
        &self,
        input: &regorus::Value,
        file: Option<&Path>,
        e: &Exception,
    ) -> Result<bool, String> {
        let Some(file) = file else {
            return exception_names(&self.evaluate(None, input.clone(), &e.rule)?, e);
        };
        // The set depends on the file, not on the rule asking: evaluate it
        // once per file and test each rule's name against it.
        let key = (e.rule.clone(), file.to_path_buf());
        let cached = ROOT_CACHE.with(|c| c.borrow().exceptions.get(&key).cloned());
        let value = match cached {
            Some(v) => v,
            None => {
                let v = self.evaluate(Some(file), input.clone(), &e.rule)?;
                ROOT_CACHE.with(|c| c.borrow_mut().exceptions.insert(key, v.clone()));
                v
            }
        };
        exception_names(&value, e)
    }

    fn judgement(&self, r: &Resource, v: &Violation, abstractions: &[Abstraction]) -> Judgement {
        let mut j = self.judgement_on(Some(r), v, abstractions);
        if j.witness.is_none() && j.severity == Severity::Definite {
            j.witness = v.path.as_deref().and_then(|path| locate(&r.body, path));
        }
        j
    }

    fn judgement_on(
        &self,
        r: Option<&Resource>,
        v: &Violation,
        abstractions: &[Abstraction],
    ) -> Judgement {
        let p = Projection {
            attributes: JsonMap::new(),
            abstractions: abstractions.to_vec(),
        };
        let severity = p.certainty();
        let witness = match (severity, p.deciding()) {
            (Severity::Definite, _) | (_, None) => {
                r.and_then(|r| v.path.as_deref().and_then(|path| locate(&r.body, path)))
            }
            (_, Some(a)) => Some(a.value.clone()),
        };
        let suffix = match severity {
            Severity::Indeterminate => {
                let paths: Vec<_> = abstractions.iter().map(|a| a.path.as_str()).collect();
                format!(
                    " (cannot be confirmed: {} computed at apply time)",
                    paths.join(", ")
                )
            }
            _ => String::new(),
        };
        Judgement {
            severity,
            witness,
            message: format!("{}{suffix}", v.msg),
            hidden: abstractions
                .iter()
                .map(|a| Hidden {
                    path: a.path.clone(),
                    truth: a.truth,
                })
                .collect(),
            fix_hint: r.zip(v.fix.as_ref()).map(|(r, (attribute, value))| {
                tf_linter::FixHint::set(r, attribute, value.clone())
            }),
        }
    }

    fn judge(&self, r: &Resource) -> Result<Vec<Judgement>, String> {
        let projection = projection::project(r);
        let input = projection::input(r, &projection, self.shape);
        let found = self.run(input)?;
        found
            .iter()
            .map(|v| match &v.address {
                Some(a) if **a != *r.address => Err(format!(
                    "violation names {a}, but the input held only {}",
                    r.address
                )),
                _ => Ok(self.judgement(r, v, &projection.abstractions)),
            })
            .collect()
    }

    /// Every managed instance of the root (of the declared types) in one
    /// plan document, and each instance alone.
    fn plan_document<'a>(&self, resources: &[&'a Resource]) -> PlanDocument<'a> {
        let selected = resources
            .iter()
            .copied()
            .filter(|r| r.mode == tf_semantic::Mode::Managed && r.existence != Truth::False)
            .filter(|r| {
                self.types
                    .as_ref()
                    .is_none_or(|t| t.iter().any(|t| *t == *r.ty))
            });
        let mut changes = Vec::new();
        let mut planned = Vec::new();
        let mut abstractions = Vec::new();
        let mut instances = Vec::new();
        for r in selected {
            let p = projection::project(r);
            let doc = projection::input(r, &p, Shape::Plan);
            changes.extend(
                doc["resource_changes"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            );
            planned.extend(
                doc["planned_values"]["root_module"]["resources"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            );
            abstractions.extend(p.abstractions.into_iter().map(|mut a| {
                a.path = format!("{}.{}", r.address, a.path);
                a
            }));
            if r.existence != Truth::True {
                abstractions.push(Abstraction {
                    path: r.address.to_string(),
                    truth: if r.existence == Truth::Tainted {
                        Truth::Tainted
                    } else {
                        Truth::Unknown
                    },
                    value: Value::other("resource existence"),
                });
            }
            instances.push((r, doc));
        }
        PlanDocument {
            doc: json!({
                "format_version": "1.2",
                "resource_changes": changes,
                "planned_values": {"root_module": {"resources": planned}},
            }),
            abstractions,
            instances,
        }
    }

    /// Module input: results attributed by `address`.
    fn judge_root<'a>(
        &self,
        resources: &[&'a Resource],
    ) -> Result<Vec<(&'a Resource, Judgement)>, String> {
        let pd = self.plan_document(resources);
        let found = self.run(pd.doc)?;
        found
            .iter()
            .map(|v| {
                let a = v.address.as_deref().ok_or_else(|| {
                    format!("module-input violation without an address: {}", v.msg)
                })?;
                let r = pd
                    .instances
                    .iter()
                    .find(|(r, _)| *r.address == *a)
                    .map(|(r, _)| *r)
                    .ok_or_else(|| format!("violation names {a}, which is not in the input"))?;
                Ok((r, self.judgement(r, v, &pd.abstractions)))
            })
            .collect()
    }

    /// Ablation: the owners of each violation of a whole document are the
    /// instances that reproduce it alone (the one its `address` names, when
    /// it names one).
    fn attribute<'a, D: Clone>(
        &self,
        found: Vec<Violation>,
        instances: &[(&'a Resource, D)],
        run: impl Fn(D) -> Result<Vec<Violation>, String>,
    ) -> Result<Vec<(Violation, Vec<&'a Resource>)>, String> {
        if found.is_empty() {
            return Ok(Vec::new());
        }
        // The ablation runs are only needed for violations that name no
        // instance.
        let mut alone: Vec<Vec<String>> = Vec::new();
        if found.iter().any(|v| v.address.is_none()) {
            for (_, doc) in instances {
                alone.push(run(doc.clone())?.into_iter().map(|v| v.msg).collect());
            }
        }
        found
            .into_iter()
            .map(|v| {
                let owners: Vec<&'a Resource> = match &v.address {
                    Some(a) => vec![
                        instances
                            .iter()
                            .find(|(r, _)| *r.address == **a)
                            .map(|(r, _)| *r)
                            .ok_or_else(|| {
                                format!("violation names {a}, which is not in the input")
                            })?,
                    ],
                    None => instances
                        .iter()
                        .zip(&alone)
                        .filter(|(_, msgs)| msgs.contains(&v.msg))
                        .map(|((r, _), _)| *r)
                        .collect(),
                };
                Ok((v, owners))
            })
            .collect()
    }

    /// Document input: per file (HCL shape) or per root (plan shape).
    fn judge_documents<'a>(
        &self,
        analysis: &'a tf_semantic::Analysis,
        files: &[ConfigFile<'a>],
    ) -> Result<Vec<(Subject<'a>, Judgement)>, String> {
        let mut out = Vec::new();
        match self.shape {
            Shape::Hcl => {
                if files.is_empty() && analysis.modules.iter().any(|m| !m.resources.is_empty()) {
                    return Err(
                        "the HCL input shape needs source files; scan a plan with the plan shape"
                            .into(),
                    );
                }
                if let Some(first) = files.first() {
                    self.enter_root(first.run);
                }
                for cf in files {
                    let path = &cf.source.path;
                    let at = |e: String| format!("{}: {e}", path.display());
                    let fd = self.document(cf).map_err(at)?;
                    let found = self.run_file(fd.doc.clone(), path, true).map_err(at)?;
                    let instances: Vec<(&'a Resource, regorus::Value)> = fd
                        .instances
                        .iter()
                        .map(|(i, doc)| (&cf.module.resources[*i], doc.clone()))
                        .collect();
                    for (v, owners) in self
                        .attribute(found, &instances, |d| self.run_file(d, path, false))
                        .map_err(at)?
                    {
                        if owners.is_empty() {
                            out.push((
                                Subject::File {
                                    module: cf.module,
                                    file: cf.source.id,
                                },
                                self.judgement_on(None, &v, &fd.abstractions),
                            ));
                        }
                        for r in owners {
                            out.push((
                                Subject::Resource(r),
                                self.judgement(r, &v, &fd.abstractions),
                            ));
                        }
                    }
                }
            }
            Shape::Plan => {
                let resources: Vec<&'a Resource> =
                    analysis.modules.iter().flat_map(|m| &m.resources).collect();
                let pd = self.plan_document(&resources);
                let found = self.run(pd.doc)?;
                let mut lost = Vec::new();
                for (v, owners) in self.attribute(found, &pd.instances, |d| self.run(d))? {
                    if owners.is_empty() {
                        lost.push(v.msg.clone());
                    }
                    for r in owners {
                        out.push((
                            Subject::Resource(r),
                            self.judgement(r, &v, &pd.abstractions),
                        ));
                    }
                }
                if !lost.is_empty() {
                    return Err(format!(
                        "no single resource reproduces these plan violations (a plan has no file to report them on): {}",
                        lost.join("; ")
                    ));
                }
            }
        }
        Ok(out)
    }
}

struct PlanDocument<'a> {
    doc: Json,
    abstractions: Vec<Abstraction>,
    instances: Vec<(&'a Resource, Json)>,
}

impl DynRule for ForeignPolicy {
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn needs_graph(&self) -> bool {
        self.input == Input::Module
    }
    fn needs_files(&self) -> bool {
        self.input == Input::Document
    }
    fn judge_files<'a>(
        &self,
        analysis: &'a tf_semantic::Analysis,
        files: &[ConfigFile<'a>],
    ) -> Result<Vec<(Subject<'a>, Judgement)>, RuleFailure> {
        self.judge_documents(analysis, files)
    }
    fn judge_graph<'a>(
        &self,
        graph: &tf_semantic::graph::ResourceGraph<'a>,
    ) -> Result<Vec<(&'a Resource, Judgement)>, RuleFailure> {
        self.judge_root(&graph.resources)
    }
    fn judge_resource(&self, r: &Resource) -> Result<Vec<Judgement>, RuleFailure> {
        if self.input != Input::Resource {
            return Ok(Vec::new());
        }
        self.judge(r)
    }
    fn judge_module<'m>(
        &self,
        _m: &'m tf_semantic::Module,
    ) -> Result<Vec<(&'m Resource, Judgement)>, RuleFailure> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(files: &[(&str, &str)]) -> tempdir::Dir {
        tempdir::Dir::new(files)
    }

    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(pub PathBuf);

        impl Dir {
            pub fn new(files: &[(&str, &str)]) -> Dir {
                use std::sync::atomic::{AtomicUsize, Ordering};
                static N: AtomicUsize = AtomicUsize::new(0);
                let root = std::env::temp_dir().join(format!(
                    "tf_rego_foreign_{}_{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                let _ = std::fs::remove_dir_all(&root);
                for (name, text) in files {
                    let path = root.join(name);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(path, text).unwrap();
                }
                Dir(root)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn load(d: &tempdir::Dir, entries: &[&str]) -> Result<Vec<RuleInfo>, String> {
        let paths = [d.path().to_path_buf()];
        let entries: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
        rules(&Options {
            paths: &paths,
            data: &[],
            namespaces: &[],
            all_namespaces: false,
            exclude: &[],
            entries: &entries,
            shape: Shape::Plan,
            rego_v0: false,
        })
        .map(|rs| rs.iter().map(|r| r.info()).collect())
    }

    #[test]
    fn packages_merge_across_files_and_data_is_placed_by_directory() {
        let d = dir(&[
            (
                "a.rego",
                "package main\nimport rego.v1\ndeny contains data.lib.cfg.msg if true\n",
            ),
            (
                "b.rego",
                "package main\nimport rego.v1\ndeny contains \"b\" if true\n",
            ),
            ("lib/cfg.json", "{\"cfg\": {\"msg\": \"from data\"}}"),
        ]);
        let infos = load(&d, &[]).unwrap();
        assert_eq!(infos.len(), 1);
        // Defined in two files: the fallback ID is the rule path.
        assert_eq!(&*infos[0].name, "rego:main.deny");
        let paths = [d.path().to_path_buf()];
        // OPA mode (an entry is named): data next to the policies loads, as
        // with `opa eval -d`.
        let opa = Bundle::load(&Options {
            paths: &paths,
            data: &[],
            namespaces: &[],
            all_namespaces: false,
            exclude: &[],
            entries: &[DEFAULT_ENTRY.into()],
            shape: Shape::Plan,
            rego_v0: false,
        })
        .unwrap();
        let msgs = |bundle: &Bundle| {
            let v = violations(&eval(&bundle.engine, json!({}), DEFAULT_ENTRY).unwrap()).unwrap();
            let mut msgs: Vec<_> = v.into_iter().map(|v| v.msg).collect();
            msgs.sort();
            msgs
        };
        assert_eq!(msgs(&opa), ["b", "from data"]);
        // Conftest mode: policy paths load `.rego` only; data comes from
        // `data` paths.
        let conftest = |data: &[PathBuf]| {
            Bundle::load(&Options {
                paths: &paths,
                data,
                namespaces: &[],
                all_namespaces: false,
                exclude: &[],
                entries: &[],
                shape: Shape::Plan,
                rego_v0: false,
            })
            .unwrap()
        };
        assert_eq!(msgs(&conftest(&[])), ["b"]);
        // Data sits at its directory's path below the data root, so the
        // root is the parent of `lib`; `.rego` files there are not data.
        assert_eq!(
            msgs(&conftest(&[d.path().to_path_buf()])),
            ["b", "from data"]
        );
    }

    #[test]
    fn conftest_rules_namespaces_and_exceptions() {
        let d = dir(&[
            (
                "main.rego",
                "package main\nimport rego.v1\ndeny contains \"d\" if true\nviolation_tags contains {\"msg\": \"v\"} if true\nwarn_old contains \"w\" if true\ndenyx contains \"not a rule\" if true\ndeny_ contains \"not a rule\" if true\nexception contains [\"old\"] if input.skip_old\n",
            ),
            (
                "other.rego",
                "package other.ns\nimport rego.v1\ndeny_x contains \"o\" if true\n",
            ),
        ]);
        let paths = [d.path().to_path_buf()];
        let load = |namespaces: &[String], all: bool| {
            rules(&Options {
                paths: &paths,
                data: &[],
                namespaces,
                all_namespaces: all,
                exclude: &[],
                entries: &[],
                shape: Shape::Plan,
                rego_v0: false,
            })
        };
        let names = |rs: Vec<Box<dyn DynRule>>| -> Vec<(String, Level)> {
            rs.iter()
                .map(|r| (r.info().name.to_string(), r.info().level))
                .collect()
        };
        assert_eq!(
            names(load(&[], false).unwrap()),
            [
                ("rego:main.deny".to_string(), Level::Medium),
                ("rego:main.violation_tags".to_string(), Level::Medium),
                ("rego:main.warn_old".to_string(), Level::Low),
            ]
        );
        assert_eq!(
            names(load(&["other.ns".into()], false).unwrap()),
            [("rego:other".to_string(), Level::Medium)]
        );
        assert_eq!(names(load(&[], true).unwrap()).len(), 4);
        assert!(
            load(&["nope".into()], false)
                .err()
                .unwrap()
                .contains("package nope")
        );
        assert_eq!(conftest_kind("deny_a_B1"), Some(RuleKind::Failure));
        assert_eq!(conftest_kind("deny__a"), None);
        assert_eq!(conftest_kind("warning"), None);
        assert_eq!(exception_name("violation_tags"), "tags");
        assert_eq!(exception_name("deny"), "");
        // The exception set suppresses `warn_old` on inputs that ask for it.
        let bundle = Bundle::load(&Options {
            paths: &paths,
            data: &[],
            namespaces: &[],
            all_namespaces: false,
            exclude: &[],
            entries: &[],
            shape: Shape::Plan,
            rego_v0: false,
        })
        .unwrap();
        let e = Exception {
            rule: "data.main.exception".into(),
            name: "old".into(),
        };
        let v = |j: Json| regorus::Value::from(j);
        let excepted = |input: Json| {
            exception_names(&eval_value(&bundle.engine, v(input), &e.rule).unwrap(), &e).unwrap()
        };
        assert!(excepted(json!({"skip_old": true})));
        assert!(!excepted(json!({})));
    }

    #[test]
    fn load_errors_are_loud() {
        let missing = dir(&[(
            "a.rego",
            "package other\nimport rego.v1\ndeny contains 1 if true\n",
        )]);
        assert!(
            load(&missing, &[])
                .unwrap_err()
                .contains("no policy declares package main")
        );
        assert!(
            load(&missing, &[DEFAULT_ENTRY])
                .unwrap_err()
                .contains("not defined")
        );
        let conflict = dir(&[
            (
                "a.rego",
                "package main\nimport rego.v1\ndeny contains 1 if true\n",
            ),
            ("x.json", "{\"k\": 1}"),
            ("y.json", "{\"k\": 2}"),
        ]);
        assert!(
            load(&conflict, &[DEFAULT_ENTRY])
                .unwrap_err()
                .contains("merge error")
        );
        assert!(
            load(&conflict, &[]).is_ok(),
            "Conftest mode ignores data next to policies"
        );
        let v0 = dir(&[("a.rego", "package main\ndeny[msg] { msg := \"x\" }\n")]);
        assert!(load(&v0, &[]).is_err(), "v0 syntax is an error in v1 mode");
        let paths = [v0.path().to_path_buf()];
        assert!(
            rules(&Options {
                paths: &paths,
                data: &[],
                namespaces: &[],
                all_namespaces: false,
                exclude: &[],
                entries: &[],
                shape: Shape::Plan,
                rego_v0: true
            })
            .is_ok()
        );
        let bad_severity = dir(&[(
            "a.rego",
            "# METADATA\n# custom:\n#   severity: urgent\npackage main\nimport rego.v1\ndeny contains 1 if true\n",
        )]);
        assert!(load(&bad_severity, &[]).unwrap_err().contains("a.rego:1"));
        let dup = dir(&[
            (
                "a.rego",
                "# METADATA\n# custom:\n#   id: X\npackage a\nimport rego.v1\ndeny contains 1 if true\n",
            ),
            (
                "b.rego",
                "# METADATA\n# custom:\n#   id: X\npackage b\nimport rego.v1\ndeny contains 1 if true\n",
            ),
        ]);
        assert!(
            load(&dup, &["data.a.deny", "data.b.deny"])
                .unwrap_err()
                .contains("rule ID X")
        );
    }

    #[test]
    fn metadata_comes_from_the_nearest_annotation() {
        let d = dir(&[
            (
                "s3.rego",
                "# METADATA\n# title: Package title\n# custom:\n#   id: PKG-1\n#   severity: low\n#   oxtf:\n#     resource_types: [aws_s3_bucket]\npackage demo.s3\n\nimport rego.v1\n\n# METADATA\n# title: Rule title\n# custom:\n#  id: RULE-1\n\ndeny contains \"x\" if {\n  # METADATA\n  # title: not an annotation\n  true\n}\n\nwarn contains \"w\" if true\n",
            ),
            (
                "legacy.rego",
                "package legacy\nimport rego.v1\n__rego_metadata__ := {\"id\": \"AVD-1\", \"title\": \"Legacy\", \"severity\": \"CRITICAL\"}\ndeny contains 1 if false\n",
            ),
        ]);
        let infos = load(
            &d,
            &["data.demo.s3.deny", "data.demo.s3.warn", "data.legacy.deny"],
        )
        .unwrap();
        let summary: Vec<_> = infos
            .iter()
            .map(|i| {
                (
                    i.name.to_string(),
                    i.level,
                    i.description.to_string(),
                    i.resource_types.clone(),
                )
            })
            .collect();
        let s3 = vec![Arc::<str>::from("aws_s3_bucket")];
        assert_eq!(
            summary,
            vec![
                ("RULE-1".into(), Level::Low, "Rule title".into(), s3.clone()),
                ("PKG-1".into(), Level::Low, "Package title".into(), s3),
                (
                    "AVD-1".into(),
                    Level::Critical,
                    "Legacy".into(),
                    vec![Arc::<str>::from(ANY_TYPE)]
                ),
            ]
        );
    }

    #[test]
    fn structured_violations() {
        let v = regorus::Value::from_json_str(
            r#"["a", {"msg": "b", "x": 1}, 3, "", {"msg": "c", "address": "aws_s3_bucket.b", "path": "versioning[0].enabled", "fix": {"attribute": "acl", "value": "private"}}, {"msg": "d", "path": ["tags", "env"]}]"#,
        )
        .unwrap();
        // As Conftest reads results: non-string, non-object values and empty
        // messages are not violations.
        let got = violations(&v).unwrap();
        let msgs: Vec<_> = got.iter().map(|v| v.msg.as_str()).collect();
        assert_eq!(msgs, ["a", "b", "c", "d"]);
        let got = &got[1..];
        assert_eq!(got[1].fix, Some(("acl".into(), json!("private"))));
        assert_eq!(got[1].address.as_deref(), Some("aws_s3_bucket.b"));
        assert_eq!(
            got[1].path,
            Some(vec![
                Segment::Key("versioning".into()),
                Segment::Index(0),
                Segment::Key("enabled".into())
            ])
        );
        assert_eq!(
            got[2].path,
            Some(vec![
                Segment::Key("tags".into()),
                Segment::Key("env".into())
            ])
        );
        assert!(violations(&regorus::Value::Undefined).unwrap().is_empty());
        assert!(violations(&regorus::Value::from_json_str("\"x\"").unwrap()).is_err());
        for bad in [
            r#"[{"msg": "x", "address": 1}]"#,
            r#"[{"message": "no msg"}]"#,
            r#"[{"msg": "x", "fix": {"attribute": "a.b", "value": 1}}]"#,
        ] {
            assert!(
                violations(&regorus::Value::from_json_str(bad).unwrap()).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            parse_path("a[0][1].b"),
            Some(vec![
                Segment::Key("a".into()),
                Segment::Index(0),
                Segment::Index(1),
                Segment::Key("b".into())
            ])
        );
        assert_eq!(parse_path("a..b"), None);
        assert_eq!(parse_path("a[x]"), None);
    }

    /// Evaluates one policy file with `data.main.deny` as the entry.
    fn eval_one(src: &str, input: Json, rego_v0: bool) -> Result<Vec<String>, String> {
        let d = dir(&[("p.rego", src)]);
        let paths = [d.path().to_path_buf()];
        let bundle = Bundle::load(&Options {
            paths: &paths,
            data: &[],
            namespaces: &[],
            all_namespaces: false,
            exclude: &[],
            entries: &[],
            shape: Shape::Plan,
            rego_v0,
        })?;
        let mut msgs: Vec<String> = violations(&eval(&bundle.engine, input, DEFAULT_ENTRY)?)?
            .into_iter()
            .map(|v| v.msg)
            .collect();
        msgs.sort();
        Ok(msgs)
    }

    /// regorus 0.12.0 differed from OPA 1.17.0 on these (loudly). The
    /// regorus fork (FIRST_CLASS_RULES_PLAN.md, F3) fixes them; each
    /// expected value is OPA's answer.
    #[test]
    fn former_regorus_divergences_match_opa() {
        // `some x in null` is undefined, not an error.
        let got = eval_one(
            "package main\nimport rego.v1\ndeny contains x if { some x in input.xs }\n",
            json!({"xs": null}),
            false,
        );
        assert_eq!(got, Ok(vec![]));
        // `%q` of a string is Go-quoted.
        let got = eval_one(
            "package main\nimport rego.v1\ndeny contains sprintf(\"%q\", [input.x]) if true\n",
            json!({"x": "a\"b"}),
            false,
        );
        assert_eq!(got, Ok(vec![r#""a\"b""#.to_string()]));
        // An import after rules applies to the whole module.
        let got = eval_one(
            "package main\nimport rego.v1\ndeny contains l.v if true\nimport input as l\n",
            json!({"v": "late"}),
            false,
        );
        assert_eq!(got, Ok(vec!["late".to_string()]));
        // A comprehension variable may be named like its function.
        let got = eval_one(
            "package main\nimport rego.v1\nf(xs) := [f | some f in xs]\ndeny contains \"hit\" if f([1]) == [1]\n",
            json!({}),
            false,
        );
        assert_eq!(got, Ok(vec!["hit".to_string()]));
        // A v0 rule with several bodies is several rules with one head.
        let got = eval_one(
            "package main\ndeny[x] { x := \"a\" } { x := \"b\" }\n",
            json!({}),
            true,
        );
        assert_eq!(got, Ok(vec!["a".to_string(), "b".to_string()]));
    }

    /// The fork still differs from OPA here, loudly: OPA formats `%q` of
    /// any value, regorus only strings. When an upgrade fixes it, this
    /// fails and the plan's gap list needs updating.
    #[test]
    fn known_regorus_divergences_fail_loudly() {
        let err = eval_one(
            "package main\nimport rego.v1\ndeny contains sprintf(\"%q\", [input.x]) if true\n",
            json!({"x": 1}),
            false,
        )
        .unwrap_err();
        assert!(err.contains("format verb q"), "{err}");
    }
}

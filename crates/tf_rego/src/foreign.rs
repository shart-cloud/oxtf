//! Foreign Rego policies: OPA bundles people already have, run unchanged.
//!
//! Every `--policy` path loads into one engine, as `opa eval -d a -d b`
//! loads its paths: `.rego` files are modules (packages merge across
//! files) and `.json`/`.yaml`/`.yml` files are data documents placed at
//! their directory's path below the root they were found under. Each entry
//! rule (`data.main.deny` by default) is one oxtf rule, with its identity,
//! level and description from the policy's own metadata ([`Meta`]).
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
use tf_linter::rule::{DynRule, Hidden, Judgement, RuleFailure, RuleInfo};
use tf_linter::{ANY_TYPE, Category, Level, Severity};
use tf_semantic::{Body, Resource};

use crate::projection::{self, Abstraction, Projection, Shape};

/// How foreign policies are loaded.
#[derive(Clone, Debug)]
pub struct Options<'a> {
    pub paths: &'a [PathBuf],
    /// Entry rules, `data.<package>.<rule>`; each becomes one oxtf rule.
    pub entries: &'a [String],
    pub shape: Shape,
    /// Parse as `opa eval --v0-compatible` does (a file that imports
    /// `rego.v1` is still v1).
    pub rego_v0: bool,
}

/// The default entry rule, Conftest's.
pub const DEFAULT_ENTRY: &str = "data.main.deny";

/// Load the bundle and build one rule per entry. Every load-time problem
/// (unreadable file, compile error, missing entry, bad metadata, merge
/// conflict) is an `Err` naming the file.
pub fn rules(opts: &Options) -> Result<Vec<Box<dyn DynRule>>, String> {
    let bundle = Bundle::load(opts)?;
    let defaults = [DEFAULT_ENTRY.to_string()];
    let entries = if opts.entries.is_empty() {
        &defaults[..]
    } else {
        opts.entries
    };
    let mut units = Vec::new();
    for entry in entries {
        units.push(bundle.unit(entry)?);
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
        if u.meta.input == Input::Module && opts.shape != Shape::Plan {
            return Err(format!(
                "{entry}: custom.oxtf.input `module` needs the plan input shape"
            ));
        }
        rules.push(Box::new(ForeignPolicy {
            info: RuleInfo {
                name: id.as_str().into(),
                category: Category::Other,
                level: u.meta.level.unwrap_or(Level::Medium),
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
            },
            types: u.meta.resource_types.clone(),
            input: u.meta.input,
            bundle: bundle.clone(),
            entry,
            shape: opts.shape,
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
    engine: regorus::Engine,
    packages: Vec<PackageDef>,
    rules: Vec<RuleDef>,
    annotations: Vec<Annotation>,
    shape: Shape,
}

enum Fallback {
    Stem(String),
    Path,
}

struct Unit {
    path: Vec<String>,
    meta: Meta,
    fallback: Fallback,
}

impl Bundle {
    fn load(opts: &Options) -> Result<Bundle, String> {
        let mut modules = Vec::new();
        let mut data = Json::Object(JsonMap::new());
        for root in opts.paths {
            collect(root, root, &mut modules, &mut data)?;
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
        // Prepare once (see `engine_with`): per-evaluation clones then only
        // pay for the evaluation.
        engine
            .eval_query("true".to_string(), false)
            .map_err(|e| e.to_string())?;
        let mut annotations = Vec::new();
        for (path, source) in &modules {
            annotations.extend(parse_annotations(path, source, &packages, &rules)?);
        }
        Ok(Bundle {
            engine,
            packages,
            rules,
            annotations,
            shape: opts.shape,
        })
    }

    fn unit(&self, entry: &str) -> Result<Unit, String> {
        let path = parse_entry(entry)?;
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
        // The entry must produce violations (or nothing) on an empty document.
        let empty = match self.shape {
            Shape::Hcl => json!({"resource": {}}),
            Shape::Plan => {
                json!({"format_version": "1.2", "resource_changes": [], "planned_values": {"root_module": {"resources": []}}})
            }
        };
        let result = eval(&self.engine, empty, entry).map_err(|e| format!("{entry}: {e}"))?;
        violations(&result).map_err(|e| format!("{entry}: {e}"))?;
        let meta = self.meta(&path, &package)?;
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
            path,
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
            meta.fill(&a.fields, &format!("{}:{}", a.file.display(), a.line))?;
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

/// Collect modules and data below `root` (a file or directory), in name
/// order, as OPA's loader does: hidden files included, other extensions
/// ignored.
fn collect(
    root: &Path,
    path: &Path,
    modules: &mut Vec<(PathBuf, String)>,
    data: &mut Json,
) -> Result<(), String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.is_dir() {
        let mut children: Vec<PathBuf> = std::fs::read_dir(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .map(|e| e.map(|e| e.path()))
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        children.sort();
        for child in children {
            collect(root, &child, modules, data)?;
        }
        return Ok(());
    }
    let read = || std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()));
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let doc = match ext {
        "rego" => {
            modules.push((path.to_path_buf(), read()?));
            return Ok(());
        }
        "json" => serde_json::from_str::<Json>(&read()?)
            .map_err(|e| format!("{}: {e}", path.display()))?,
        "yaml" | "yml" => tf_rule_ir::goyaml::load(&read()?)
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
        let at = format!("{}:{start}", file.display());
        // A block inside a rule body is an ordinary comment.
        if file_rules
            .iter()
            .any(|r| r.lines.0 < start && start <= r.lines.1)
        {
            continue;
        }
        let fields =
            match tf_rule_ir::goyaml::load(&yaml).map_err(|e| format!("{at}: METADATA: {e}"))? {
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
}

/// The metadata oxtf reads; `None` until some annotation sets it.
#[derive(Debug, Default)]
struct Meta {
    id: Option<String>,
    level: Option<Level>,
    description: Option<String>,
    resource_types: Option<Vec<String>>,
    input: Input,
    input_set: bool,
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
        let Some(custom) = fields.get("custom") else {
            return Ok(());
        };
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
            if !matches!(key.as_str(), "resource_types" | "input") {
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
        if !self.input_set
            && let Some(v) = oxtf.get("input")
        {
            self.input = match v.as_str() {
                Some("resource") => Input::Resource,
                Some("module") => Input::Module,
                _ => {
                    return Err(format!(
                        "{at}: METADATA custom.oxtf.input must be `resource` or `module`"
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
    let mut engine = engine.clone();
    engine.set_input(regorus::Value::from(input));
    engine
        .eval_rule(rule.to_string())
        .map_err(|e| e.to_string())
}

fn to_serde(v: &regorus::Value) -> Result<Json, String> {
    serde_json::from_str(&v.to_json_str().map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// One violation an entry rule produced.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Violation {
    pub msg: String,
    /// The resource the violation is about (`address`).
    pub address: Option<String>,
    /// The attribute it is about (`path`): `a.b[0].c` or `["a", "b", 0, "c"]`.
    pub path: Option<Vec<Segment>>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Segment {
    Key(String),
    Index(usize),
}

/// The violations an entry rule produced: a set or array of strings, or of
/// objects with a `msg` string and optional `address` and `path`.
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
    items.into_iter().map(violation).collect()
}

fn violation(item: Json) -> Result<Violation, String> {
    let Json::Object(o) = &item else {
        let msg = match item {
            Json::String(s) => s,
            other => other.to_string(),
        };
        return Ok(Violation {
            msg,
            address: None,
            path: None,
        });
    };
    let msg = match o.get("msg") {
        Some(Json::String(s)) => s.clone(),
        _ => item.to_string(),
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
    Ok(Violation { msg, address, path })
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

    fn record(&self, entry: &str, input: &Json, result: &Result<regorus::Value, String>) {
        let line = match result {
            Ok(v) => json!({"entry": entry, "input": input, "result": to_serde(v).ok()}),
            Err(e) => json!({"entry": entry, "input": input, "error": e}),
        };
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
    trace: Option<Trace>,
}

impl ForeignPolicy {
    fn run(&self, input: Json) -> Result<Vec<Violation>, String> {
        let result = eval(&self.bundle.engine, input.clone(), &self.entry);
        if let Some(t) = &self.trace {
            t.record(&self.entry, &input, &result);
        }
        violations(&result?)
    }

    fn judgement(&self, r: &Resource, v: &Violation, abstractions: &[Abstraction]) -> Judgement {
        let p = Projection {
            attributes: JsonMap::new(),
            abstractions: abstractions.to_vec(),
        };
        let severity = p.certainty();
        let witness = match (severity, p.deciding()) {
            (Severity::Definite, _) | (_, None) => {
                v.path.as_deref().and_then(|path| locate(&r.body, path))
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
            fix_hint: None,
        }
    }

    fn judge(&self, r: &Resource) -> Result<Vec<Judgement>, String> {
        let projection = projection::project(r, self.shape);
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

    /// Module input: every managed instance of the root in one plan
    /// document, results attributed by `address`.
    fn judge_root<'a>(
        &self,
        resources: &[&'a Resource],
    ) -> Result<Vec<(&'a Resource, Judgement)>, String> {
        let selected: Vec<&'a Resource> = resources
            .iter()
            .copied()
            .filter(|r| r.mode == tf_semantic::Mode::Managed)
            .filter(|r| {
                self.types
                    .as_ref()
                    .is_none_or(|t| t.iter().any(|t| *t == *r.ty))
            })
            .collect();
        let mut changes = Vec::new();
        let mut planned = Vec::new();
        let mut abstractions = Vec::new();
        let mut by_address: HashMap<&str, &'a Resource> = HashMap::new();
        for r in &selected {
            let p = projection::project(r, Shape::Plan);
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
            by_address.insert(&r.address, r);
        }
        let input = json!({
            "format_version": "1.2",
            "resource_changes": changes,
            "planned_values": {"root_module": {"resources": planned}},
        });
        let found = self.run(input)?;
        found
            .iter()
            .map(|v| {
                let a = v.address.as_deref().ok_or_else(|| {
                    format!("module-input violation without an address: {}", v.msg)
                })?;
                let r = by_address
                    .get(a)
                    .ok_or_else(|| format!("violation names {a}, which is not in the input"))?;
                Ok((*r, self.judgement(r, v, &abstractions)))
            })
            .collect()
    }
}

impl DynRule for ForeignPolicy {
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn needs_graph(&self) -> bool {
        self.input == Input::Module
    }
    fn judge_graph<'a>(
        &self,
        graph: &tf_semantic::graph::ResourceGraph<'a>,
    ) -> Result<Vec<(&'a Resource, Judgement)>, RuleFailure> {
        self.judge_root(&graph.resources)
    }
    fn judge_resource(&self, r: &Resource) -> Result<Vec<Judgement>, RuleFailure> {
        if self.input == Input::Module {
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
        let bundle = Bundle::load(&Options {
            paths: &paths,
            entries: &[],
            shape: Shape::Plan,
            rego_v0: false,
        })
        .unwrap();
        let v = violations(&eval(&bundle.engine, json!({}), "data.main.deny").unwrap()).unwrap();
        let mut msgs: Vec<_> = v.into_iter().map(|v| v.msg).collect();
        msgs.sort();
        assert_eq!(msgs, ["b", "from data"]);
    }

    #[test]
    fn load_errors_are_loud() {
        let missing = dir(&[(
            "a.rego",
            "package other\nimport rego.v1\ndeny contains 1 if true\n",
        )]);
        assert!(load(&missing, &[]).unwrap_err().contains("not defined"));
        let conflict = dir(&[
            (
                "a.rego",
                "package main\nimport rego.v1\ndeny contains 1 if true\n",
            ),
            ("x.json", "{\"k\": 1}"),
            ("y.json", "{\"k\": 2}"),
        ]);
        assert!(load(&conflict, &[]).unwrap_err().contains("merge error"));
        let v0 = dir(&[("a.rego", "package main\ndeny[msg] { msg := \"x\" }\n")]);
        assert!(load(&v0, &[]).is_err(), "v0 syntax is an error in v1 mode");
        let paths = [v0.path().to_path_buf()];
        assert!(
            rules(&Options {
                paths: &paths,
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
            r#"["a", {"msg": "b", "x": 1}, 3, {"msg": "c", "address": "aws_s3_bucket.b", "path": "versioning[0].enabled"}, {"msg": "d", "path": ["tags", "env"]}]"#,
        )
        .unwrap();
        let got = violations(&v).unwrap();
        assert_eq!(got[0].msg, "a");
        assert_eq!(got[1].msg, "b");
        assert_eq!(got[2].msg, "3");
        assert_eq!(got[3].address.as_deref(), Some("aws_s3_bucket.b"));
        assert_eq!(
            got[3].path,
            Some(vec![
                Segment::Key("versioning".into()),
                Segment::Index(0),
                Segment::Key("enabled".into())
            ])
        );
        assert_eq!(
            got[4].path,
            Some(vec![
                Segment::Key("tags".into()),
                Segment::Key("env".into())
            ])
        );
        assert!(violations(&regorus::Value::Undefined).unwrap().is_empty());
        assert!(violations(&regorus::Value::from_json_str("\"x\"").unwrap()).is_err());
        assert!(
            violations(&regorus::Value::from_json_str(r#"[{"msg": "x", "address": 1}]"#).unwrap())
                .is_err()
        );
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

    /// regorus 0.12.0 differs from OPA 1.17.0 on these, always loudly: a
    /// load error or a rule error, never a different answer. Each is
    /// listed in FIRST_CLASS_RULES_PLAN.md (F3); when a regorus upgrade
    /// fixes one, its assertion here fails and the list needs updating.
    #[test]
    fn known_regorus_divergences_fail_loudly() {
        let eval_one = |src: &str, input: Json| -> Result<Vec<Violation>, String> {
            let d = dir(&[("p.rego", src)]);
            let paths = [d.path().to_path_buf()];
            let bundle = Bundle::load(&Options {
                paths: &paths,
                entries: &[],
                shape: Shape::Plan,
                rego_v0: false,
            })?;
            violations(&eval(&bundle.engine, input, DEFAULT_ENTRY)?)
        };
        // OPA: `some x in null` is undefined.
        let err = eval_one(
            "package main\nimport rego.v1\ndeny contains x if { some x in input.xs }\n",
            json!({"xs": null}),
        )
        .unwrap_err();
        assert!(err.contains("expects array/set/object"), "{err}");
        // OPA formats `%q` of any value (fixed for strings in regorus 0.13.0).
        let err = eval_one(
            "package main\nimport rego.v1\ndeny contains sprintf(\"%q\", [input.x]) if true\n",
            json!({"x": "s"}),
        )
        .unwrap_err();
        assert!(err.contains("%q"), "{err}");
        // OPA accepts an import after rules.
        let err = eval_one(
            "package main\nimport rego.v1\ndeny contains 1 if false\nimport data.lib\n",
            json!({}),
        )
        .unwrap_err();
        assert!(err.contains("import"), "{err}");
        // OPA accepts a comprehension variable named like the function.
        let err = eval_one(
            "package main\nimport rego.v1\nf(xs) := [f | some f in xs]\ndeny contains 1 if f([1])\n",
            json!({}),
        )
        .unwrap_err();
        assert!(err.contains("before definition"), "{err}");
        // OPA v0 accepts a rule with several bodies.
        let d = dir(&[("p.rego", "package main\ndeny[x] { x := 1 } { x := 2 }\n")]);
        let paths = [d.path().to_path_buf()];
        let err = Bundle::load(&Options {
            paths: &paths,
            entries: &[],
            shape: Shape::Plan,
            rego_v0: true,
        })
        .err()
        .unwrap();
        assert!(err.contains("else cannot be used"), "{err}");
    }
}

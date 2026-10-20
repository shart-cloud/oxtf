//! A serializable rule IR (JSON) and its compiler to a [`tf_linter::DynRule`].
//!
//! The Python expression API (`tfscan.rule(...)`, `tfscan.col(...)`) builds
//! this IR; the Python extension and the `oxtf` CLI (`--rule-file`) both
//! compile it with [`compile`] and run it through the same engine as the
//! built-in rules, on rayon workers, with no Python runtime involved.
//!
//! ```json
//! {
//!   "version": 1,
//!   "name": "py-sg-open-ssh",
//!   "level": "high",
//!   "category": "network",
//!   "message": "ingress allows SSH (port 22) from {witness|the internet}",
//!   "clauses": [{
//!     "resource_types": ["aws_security_group"],
//!     "for_each": {"op": "col", "path": ["ingress"]},
//!     "condition": {"op": "and", "args": [
//!       {"op": "list_contains", "list": {"op": "col", "path": ["cidr_blocks"]}, "value": "0.0.0.0/0"},
//!       {"op": "cmp", "cmp": "le", "left": {"op": "col", "path": ["from_port"]}, "right": {"op": "lit", "value": 22}}
//!     ]}
//!   }]
//! }
//! ```
//!
//! # Semantics
//!
//! Expressions are evaluated over the owned, evaluated model
//! (`tf_semantic::Resource`, `tf_eval::Value`) with the four-valued truth of
//! `tf_eval::truth`, exactly like the hand-written rules:
//!
//! - a predicate over a `Known` value is `True` / `False`; over a `Tainted`
//!   value it is `Tainted` (→ *conditional* finding); over an `Unknown`
//!   value it is `Unknown` (→ no finding); `OneOf` values are lifted
//!   (`truth::map` / `truth::test` / `truth::exists`);
//! - `and` / `or` are `Verdict::and` / `Verdict::or` folded left (min / max
//!   over `False < Unknown < Tainted < True`, keeping the deciding witness);
//! - the reported finding's provenance is the witness value's chain.
//!
//! A rule has one or more *clauses*. Each clause applies to some resource
//! types; with `for_each`, the condition is evaluated per element of a list
//! attribute (`exists`), so `col(...)` then reads fields of the element. The
//! verdicts of the clauses that apply to a resource are or-ed.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tf_eval::truth::{self, Truth};
use tf_eval::{Kind, Known, Prov, Value, Verdict};
use tf_linter::{Category, DynRule, Judgement, Level, RuleFailure, RuleInfo};
use tf_semantic::{Module, Resource};

pub mod bundled;
pub mod checkov;
pub mod checkov_policy;
pub mod checkov_python;
pub mod graph;
pub mod jsonpath;
pub mod py;
pub mod pyliteral;
pub mod pyre;

/// The IR version this build writes. A document's `version` says which
/// build wrote it; every build reads every version up to its own, and
/// reads each operator the same way whatever the version says. (Versions
/// 2, 3 and 4 added the Checkov value, graph and Python operators.)
pub const IR_VERSION: u32 = 4;

fn ir_version() -> u32 {
    IR_VERSION
}
fn default_level() -> String {
    "medium".into()
}
fn default_category() -> String {
    "network".into()
}

/// One rule.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    #[serde(default = "ir_version")]
    pub version: u32,
    /// Rule id (`py-sg-open-ssh`).
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// `low` | `medium` | `high` | `critical`.
    #[serde(default = "default_level")]
    pub level: String,
    /// `network` | `storage` | `iam` | `encryption`.
    #[serde(default = "default_category")]
    pub category: String,
    /// Message template. Placeholders: `{address}`, `{type}`, `{name}`,
    /// `{rule}`, `{witness}` (the deciding value as a string),
    /// `{witness|fallback}`; `{{` / `}}` escape braces.
    pub message: String,
    pub clauses: Vec<Clause>,
    /// A page explaining the rule and its fix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guideline: Option<String>,
    /// Where the rule was loaded from: set by the loader, not part of the
    /// IR, and ignored by equality.
    #[serde(skip)]
    pub origin: Origin,
}

/// The front-end and file a [`RuleSpec`] came from.
#[derive(Clone, Debug, Default)]
pub struct Origin(pub tf_linter::RuleSource);

impl PartialEq for Origin {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Clause {
    pub resource_types: Vec<String>,
    /// A list-valued expression evaluated on the resource; `condition` is
    /// then evaluated per element ("some element satisfies").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_each: Option<Expr>,
    pub condition: Expr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// An expression. Value expressions (`col`, `element`, `lit`) used where a
/// predicate is expected mean "is `true`".
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expr {
    /// Complete graph policy, evaluated once per root. Pass results are negated.
    CheckovGraph {
        definition: graph::GraphExpr,
    },
    /// Attribute predicate from a Checkov graph policy (true means pass).
    CheckovAttribute {
        #[serde(flatten)]
        check: checkov::AttributeCheck,
    },
    /// A Checkov check's own Python (`scan_resource_conf`), interpreted
    /// natively over the Checkov-shaped configuration.
    CheckovPython {
        program: Box<checkov_python::Program>,
    },
    /// Checkov's declarative value-check semantics, over configured values.
    /// Imported checks carry their own missing-value policy; provider defaults
    /// must not silently change the upstream rule.
    CheckovValue {
        #[serde(flatten)]
        check: checkov::ValueCheck,
    },
    /// Attribute access. At resource scope the first segment is a top-level
    /// attribute (absent → `null`, or the defaults-overlay value when
    /// `default` is set); further segments (and every segment at element
    /// scope) are object fields (missing → `null`) or list indices.
    Col {
        path: Vec<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        default: bool,
    },
    /// The current element (inside `list_any` / `list_all` / `for_each`).
    Element,
    Lit {
        value: serde_json::Value,
    },
    /// Comparison with Terraform's conversions: numbers compare numerically
    /// (strings are parsed), bools as bools, strings by their string form
    /// (whitespace-trimmed); ordering is numeric only.
    Cmp {
        cmp: CmpOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// The value equals one of `values` (as in `cmp eq`).
    IsIn {
        expr: Box<Expr>,
        values: Vec<serde_json::Value>,
    },
    /// Some element of the list equals `value`.
    ListContains {
        list: Box<Expr>,
        value: serde_json::Value,
    },
    /// Some element satisfies `pred` (evaluated with the element as scope).
    ListAny {
        list: Box<Expr>,
        pred: Box<Expr>,
    },
    /// Every element satisfies `pred` (`not any(not pred)`; true when empty).
    ListAll {
        list: Box<Expr>,
        pred: Box<Expr>,
    },
    And {
        args: Vec<Expr>,
    },
    Or {
        args: Vec<Expr>,
    },
    Not {
        arg: Box<Expr>,
    },
    /// The value is `null` (lifted: Tainted → Tainted, Unknown → Unknown).
    IsNull {
        expr: Box<Expr>,
    },
    /// The value is wholly known (no Unknown / Tainted / OneOf inside).
    /// Two-valued: never Unknown or Tainted itself.
    IsKnown {
        expr: Box<Expr>,
    },
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(untagged)]
enum RulesFile {
    List(Vec<RuleSpec>),
    Wrapped { rules: Vec<RuleSpec> },
    One(Box<RuleSpec>),
}

/// Parse a rules document: a rule object, a list of rules, or
/// `{"rules": [...]}`.
pub fn parse_rules(json: &str) -> Result<Vec<RuleSpec>, String> {
    // Parse strictly first so that the error message of a single rule is
    // useful (untagged enums only say "did not match any variant").
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let one =
        |v: serde_json::Value| serde_json::from_value::<RuleSpec>(v).map_err(|e| e.to_string());
    match v {
        serde_json::Value::Array(a) => a.into_iter().map(one).collect(),
        serde_json::Value::Object(ref o) if o.contains_key("rules") && !o.contains_key("name") => {
            match serde_json::from_value::<RulesFile>(v).map_err(|e| e.to_string())? {
                RulesFile::Wrapped { rules } | RulesFile::List(rules) => Ok(rules),
                RulesFile::One(r) => Ok(vec![*r]),
            }
        }
        other => Ok(vec![one(other)?]),
    }
}

/// Rules loaded from a `--rule-file` path, and the files of a directory
/// that were skipped.
#[derive(Debug, Default)]
pub struct LoadedRules {
    pub rules: Vec<RuleSpec>,
    pub skipped: Vec<SkippedFile>,
    /// `.rego` files, for the Rego bundle (`tf_rego`).
    pub rego: Vec<std::path::PathBuf>,
    /// JSON/YAML files read as rules (loaded or skipped): not data for a
    /// Rego bundle loaded from the same directory.
    pub claimed: Vec<std::path::PathBuf>,
}

/// A file in a rule directory that did not load: unparsable, an unsupported
/// policy, or a rule name already defined by an earlier file.
#[derive(Debug, PartialEq)]
pub struct SkippedFile {
    pub path: std::path::PathBuf,
    /// One line per problem, each starting with the file (and position).
    pub reason: String,
}

/// Read and parse a rules file or directory, detecting each file's format.
///
/// A file is rule IR JSON, a Checkov policy (`.yaml`/`.yml` always, `.json`
/// when it has Checkov's `metadata` and `definition`), or a Rego module
/// (`.rego`, returned in [`LoadedRules::rego`] for `tf_rego`). A named file
/// that does not load is an error.
///
/// A directory is walked recursively in name order, as Checkov walks a
/// policy directory, and each file is read by its own format. A rule file
/// that does not load is skipped and reported in [`LoadedRules::skipped`],
/// never dropped silently. When two files define the same rule name, the
/// first wins (as in Checkov) and the later file is skipped. In a directory
/// that holds Rego, a JSON/YAML file that is neither a Checkov policy nor
/// rule IR is a data document or test mock (Conftest ignores it unless it
/// is named with `--data`), not a broken rule.
pub fn load_rules_file(path: &std::path::Path) -> Result<LoadedRules, String> {
    if !path.is_dir() {
        if path.extension().is_some_and(|e| e == "rego") {
            return Ok(LoadedRules {
                rego: vec![path.to_path_buf()],
                ..LoadedRules::default()
            });
        }
        return load_one(path).map(|rules| LoadedRules {
            rules,
            claimed: vec![path.to_path_buf()],
            ..LoadedRules::default()
        });
    }
    let mut files = Vec::new();
    let mut rego = Vec::new();
    collect_rule_files(path, &mut files, &mut rego)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = LoadedRules {
        rego,
        ..LoadedRules::default()
    };
    let mut seen: std::collections::HashMap<String, std::path::PathBuf> = Default::default();
    for file in files {
        if !out.rego.is_empty() && !is_rule_document(&file) {
            continue;
        }
        out.claimed.push(file.clone());
        let specs = match load_one(&file) {
            Ok(specs) => specs,
            Err(reason) => {
                out.skipped.push(SkippedFile { path: file, reason });
                continue;
            }
        };
        let duplicates: Vec<String> = specs
            .iter()
            .filter_map(|spec| {
                seen.get(&spec.name).map(|first| {
                    format!(
                        "{}: rule {} is already defined in {}",
                        file.display(),
                        spec.name,
                        first.display()
                    )
                })
            })
            .collect();
        if !duplicates.is_empty() {
            out.skipped.push(SkippedFile {
                path: file,
                reason: duplicates.join("\n"),
            });
            continue;
        }
        for spec in specs {
            seen.insert(spec.name.clone(), file.clone());
            out.rules.push(spec);
        }
    }
    Ok(out)
}

fn collect_rule_files(
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
    rego: &mut Vec<std::path::PathBuf>,
) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_rule_files(&path, out, rego)?;
        } else {
            match path.extension().and_then(|e| e.to_str()) {
                Some("json" | "yaml" | "yml") => out.push(path),
                Some("rego") => rego.push(path),
                _ => {}
            }
        }
    }
    Ok(())
}

/// A rule IR error as `file:line:col: message`, with the position serde
/// reports when the document is read with the shape it has.
fn ir_error(path: &std::path::Path, text: &str, message: String) -> String {
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct Wrapped {
        rules: Vec<RuleSpec>,
    }
    let positioned = match serde_json::from_str::<serde_json::Value>(text) {
        Err(e) => Some(e),
        Ok(serde_json::Value::Array(_)) => serde_json::from_str::<Vec<RuleSpec>>(text).err(),
        Ok(v) if v.get("rules").is_some() && v.get("name").is_none() => {
            serde_json::from_str::<Wrapped>(text).err()
        }
        Ok(_) => serde_json::from_str::<RuleSpec>(text).err(),
    };
    match positioned {
        Some(e) if e.line() > 0 => {
            let msg = e.to_string();
            let msg = msg
                .rsplit_once(" at line ")
                .map_or(msg.as_str(), |(m, _)| m)
                .to_string();
            format!(
                "{}:{}:{}: {msg}",
                path.display(),
                e.line(),
                e.column().max(1)
            )
        }
        _ => format!("{}: {message}", path.display()),
    }
}

/// Whether a JSON/YAML file is meant as a rule: a Checkov policy, or rule
/// IR (a rule with `clauses`, a list of them, or `{"rules": [...]}`). An
/// unparsable file counts as one when it is `.json` with a `clauses` key in
/// its text, so a broken rule is reported rather than ignored.
fn is_rule_document(path: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return true;
    };
    let value = match path.extension().and_then(|e| e.to_str()) {
        Some("yaml" | "yml") => tf_yaml::pyyaml::load(&text).ok().map(|d| d.value),
        _ => serde_json::from_str::<serde_json::Value>(&text).ok(),
    };
    let rule = |v: &serde_json::Value| v.get("clauses").is_some();
    match value {
        Some(v) => {
            checkov_policy::is_policy(&v)
                || rule(&v)
                || v.as_array()
                    .is_some_and(|a| !a.is_empty() && a.iter().all(rule))
                || v.get("rules")
                    .and_then(|r| r.as_array())
                    .is_some_and(|a| a.iter().all(rule))
        }
        None => text.contains("\"clauses\""),
    }
}

fn load_one(path: &std::path::Path) -> Result<Vec<RuleSpec>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let source = match path.extension().and_then(|e| e.to_str()) {
        Some("yaml" | "yml") => checkov_policy::PolicySource::parse(path, &text),
        _ => match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) if checkov_policy::is_policy(&v) => {
                Ok(checkov_policy::PolicySource::from_json(v, &text))
            }
            _ => {
                let mut specs = parse_rules(&text).map_err(|e| ir_error(path, &text, e))?;
                for spec in &mut specs {
                    spec.origin = Origin(tf_linter::RuleSource {
                        engine: tf_linter::Engine::Ir,
                        file: Some(path.to_path_buf()),
                        line: None,
                    });
                }
                return Ok(specs);
            }
        },
    };
    let source = source.map_err(|e| format!("{}: {e}", path.display()))?;
    checkov_policy::translate_source(path, &source).map(|r| vec![r])
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

/// Internal, pre-converted expression tree (literals as `Value`s).
#[derive(Debug)]
enum Node {
    CheckovGraph(graph::GraphExpr),
    CheckovAttribute(checkov::AttributeCheck),
    CheckovValue(checkov::ValueCheck),
    CheckovPython(checkov_python::Check),
    Col { path: Vec<Seg>, default: bool },
    Element,
    Lit(Value),
    Cmp(CmpOp, Box<Node>, Box<Node>, bool),
    IsIn(Box<Node>, Vec<Value>),
    ListContains(Box<Node>, Value),
    ListAny(Box<Node>, Box<Node>),
    ListAll(Box<Node>, Box<Node>),
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    IsNull(Box<Node>),
    IsKnown(Box<Node>),
}

#[derive(Debug)]
struct Seg {
    name: Arc<str>,
    index: Option<usize>,
}

#[derive(Debug)]
struct CClause {
    for_each: Option<Node>,
    condition: Node,
}

#[derive(Debug)]
enum Piece {
    Text(String),
    Address,
    Type,
    Name,
    Rule,
    Witness(Option<String>),
}

/// A rule compiled from a [`RuleSpec`]; implements [`DynRule`].
#[derive(Debug)]
pub struct CompiledRule {
    spec: RuleSpec,
    info: RuleInfo,
    clauses: Vec<CClause>,
    by_type: HashMap<String, Vec<usize>>,
    message: Vec<Piece>,
    /// Per resource type, the fix the predicate implies, when it is
    /// unambiguous: an attribute path and the literal to write.
    fix: HashMap<String, (Vec<String>, serde_json::Value)>,
}

impl CompiledRule {
    pub fn spec(&self) -> &RuleSpec {
        &self.spec
    }
}

fn parse_level(s: &str) -> Result<Level, String> {
    Ok(match s {
        "low" => Level::Low,
        "medium" => Level::Medium,
        "high" => Level::High,
        "critical" => Level::Critical,
        _ => return Err(format!("unknown level {s:?} (low|medium|high|critical)")),
    })
}

fn parse_category(s: &str) -> Result<Category, String> {
    Ok(match s {
        "network" => Category::Network,
        "storage" => Category::Storage,
        "iam" => Category::Iam,
        "encryption" => Category::Encryption,
        "other" => Category::Other,
        _ => {
            return Err(format!(
                "unknown category {s:?} (network|storage|iam|encryption)"
            ));
        }
    })
}

fn lit(v: &serde_json::Value) -> Result<Value, String> {
    match v {
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => Err(format!(
            "literal must be a scalar (null, bool, number, string), got {v}"
        )),
        _ => Ok(tf_eval::value::from_json(v, &Prov::EMPTY)),
    }
}

fn compile_expr(e: &Expr) -> Result<Node, String> {
    let b = |e: &Expr| compile_expr(e).map(Box::new);
    Ok(match e {
        Expr::CheckovGraph { .. } => {
            return Err("checkov_graph must be the complete clause condition".into());
        }
        Expr::CheckovAttribute { check } => {
            check.validate()?;
            Node::CheckovAttribute(check.clone())
        }
        Expr::CheckovValue { check } => {
            check.validate()?;
            Node::CheckovValue(check.clone())
        }
        Expr::CheckovPython { program } => {
            program.validate()?;
            Node::CheckovPython(checkov_python::Check::new((**program).clone()))
        }
        Expr::Col { path, default } => {
            if path.is_empty() {
                return Err("col: empty path".into());
            }
            Node::Col {
                path: path
                    .iter()
                    .map(|s| Seg {
                        name: Arc::from(s.as_str()),
                        index: s.parse().ok(),
                    })
                    .collect(),
                default: *default,
            }
        }
        Expr::Element => Node::Element,
        Expr::Lit { value } => Node::Lit(lit(value)?),
        Expr::Cmp { cmp, left, right } => {
            // The witness is the non-literal side (the attribute value, with
            // its provenance), as in the hand-written rules.
            let witness_left =
                !matches!(**left, Expr::Lit { .. }) || matches!(**right, Expr::Lit { .. });
            Node::Cmp(*cmp, b(left)?, b(right)?, witness_left)
        }
        Expr::IsIn { expr, values } => {
            Node::IsIn(b(expr)?, values.iter().map(lit).collect::<Result<_, _>>()?)
        }
        Expr::ListContains { list, value } => Node::ListContains(b(list)?, lit(value)?),
        Expr::ListAny { list, pred } => Node::ListAny(b(list)?, b(pred)?),
        Expr::ListAll { list, pred } => Node::ListAll(b(list)?, b(pred)?),
        Expr::And { args } | Expr::Or { args } => {
            if args.is_empty() {
                return Err("and/or: no arguments".into());
            }
            let args = args.iter().map(compile_expr).collect::<Result<_, _>>()?;
            if matches!(e, Expr::And { .. }) {
                Node::And(args)
            } else {
                Node::Or(args)
            }
        }
        Expr::Not { arg } => Node::Not(b(arg)?),
        Expr::IsNull { expr } => Node::IsNull(b(expr)?),
        Expr::IsKnown { expr } => Node::IsKnown(b(expr)?),
    })
}

fn compile_message(m: &str) -> Result<Vec<Piece>, String> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut it = m.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '{' if it.peek() == Some(&'{') => {
                it.next();
                text.push('{');
            }
            '}' if it.peek() == Some(&'}') => {
                it.next();
                text.push('}');
            }
            '{' => {
                let mut name = String::new();
                loop {
                    match it.next() {
                        Some('}') => break,
                        Some(c) => name.push(c),
                        None => return Err(format!("message: unclosed '{{' in {m:?}")),
                    }
                }
                if !text.is_empty() {
                    out.push(Piece::Text(std::mem::take(&mut text)));
                }
                let (key, fallback) = match name.split_once('|') {
                    Some((k, f)) => (k.trim(), Some(f.to_string())),
                    None => (name.trim(), None),
                };
                out.push(match key {
                    "address" => Piece::Address,
                    "type" => Piece::Type,
                    "name" => Piece::Name,
                    "rule" => Piece::Rule,
                    "witness" => Piece::Witness(fallback),
                    other => return Err(format!("message: unknown placeholder {{{other}}}")),
                });
            }
            '}' => return Err(format!("message: unmatched '}}' in {m:?}")),
            c => text.push(c),
        }
    }
    if !text.is_empty() {
        out.push(Piece::Text(text));
    }
    Ok(out)
}

/// Validate and compile a rule.
pub fn compile(spec: RuleSpec) -> Result<CompiledRule, String> {
    let ctx = |e: String| format!("rule {:?}: {e}", spec.name);
    if !(1..=IR_VERSION).contains(&spec.version) {
        return Err(ctx(format!(
            "unsupported IR version {} (this build reads {IR_VERSION})",
            spec.version
        )));
    }
    if spec.name.trim().is_empty() {
        return Err("rule with empty name".into());
    }
    if spec.clauses.is_empty() {
        return Err(ctx("no clauses".into()));
    }
    let level = parse_level(&spec.level).map_err(ctx)?;
    let category = parse_category(&spec.category).map_err(ctx)?;
    let message = compile_message(&spec.message).map_err(ctx)?;
    let mut clauses = Vec::new();
    let mut by_type: HashMap<String, Vec<usize>> = HashMap::new();
    let mut types: Vec<Arc<str>> = Vec::new();
    for (i, c) in spec.clauses.iter().enumerate() {
        if c.resource_types.is_empty() {
            return Err(ctx(format!("clause {i}: no resource_types")));
        }
        for t in &c.resource_types {
            by_type.entry(t.clone()).or_default().push(i);
            if !types.iter().any(|x| **x == **t) {
                types.push(Arc::from(t.as_str()));
            }
        }
        clauses.push(CClause {
            for_each: c
                .for_each
                .as_ref()
                .map(compile_expr)
                .transpose()
                .map_err(|e| ctx(format!("clause {i}: for_each: {e}")))?,
            condition: if let Expr::CheckovGraph { definition } = &c.condition {
                if c.for_each.is_some() {
                    return Err(ctx("checkov_graph takes no for_each".into()));
                }
                definition.validate().map_err(ctx)?;
                if definition.is_filter() {
                    return Err(ctx("graph filters require a predicate".into()));
                }
                Node::CheckovGraph(definition.clone())
            } else {
                compile_expr(&c.condition)
                    .map_err(|e| ctx(format!("clause {i}: condition: {e}")))?
            },
        });
    }
    let info = RuleInfo {
        name: Arc::from(spec.name.as_str()),
        category,
        level,
        description: Arc::from(spec.description.as_str()),
        resource_types: types,
        runs_on_module: false,
        guideline: spec.guideline.as_deref().map(Arc::from),
        source: spec.origin.0.clone(),
        aliases: Vec::new(),
        profile: tf_linter::Profile::Security,
    };
    let fix = derive_fix(&spec);
    Ok(CompiledRule {
        spec,
        info,
        clauses,
        by_type,
        message,
        fix,
    })
}

/// The mechanical fix a Checkov policy's predicate implies, per resource
/// type. A clause implies one when its definition holds exactly one
/// fixable leaf (beside filters) and the leaf names the value to write:
/// `equals` a literal, `is_true`, `is_false`, or `within` a single literal.
/// A Checkov value check implies one when it expects a single literal
/// ([`checkov::ValueCheck::fix`]). Paths may be nested; whether the edit
/// is valid for a resource is decided when the hint is built
/// ([`tf_linter::FixHint::set_path`]). A type whose clauses imply
/// different fixes gets none. `exists` and other operators do not say what
/// to write, so they derive none.
fn derive_fix(spec: &RuleSpec) -> HashMap<String, (Vec<String>, serde_json::Value)> {
    use checkov::AttributeOp::*;
    fn leaves<'g>(e: &'g graph::GraphExpr, out: &mut Vec<&'g graph::GraphExpr>) -> bool {
        match e {
            graph::GraphExpr::And { args } => args.iter().all(|a| leaves(a, out)),
            graph::GraphExpr::Filter { .. } | graph::GraphExpr::AttributeFilter { .. } => true,
            graph::GraphExpr::Attribute { .. } => {
                out.push(e);
                true
            }
            _ => false,
        }
    }
    fn literal(v: &serde_json::Value) -> bool {
        !v.is_array() && !v.is_object() && !v.is_null()
    }
    type Fix = (Vec<String>, serde_json::Value);
    // The fix, and the types the leaf is about (a graph clause may also
    // name types it only filters or connects).
    fn clause_fix(c: &Clause) -> Option<(Option<&[String]>, Fix)> {
        let definition = match &c.condition {
            Expr::CheckovGraph { definition } => definition,
            Expr::CheckovValue { check } if c.for_each.is_none() => {
                return check.fix().map(|f| (None, f));
            }
            _ => return None,
        };
        let mut found = Vec::new();
        if !leaves(definition, &mut found) {
            return None;
        }
        let [
            graph::GraphExpr::Attribute {
                check,
                resource_types,
            },
        ] = found.as_slice()
        else {
            return None;
        };
        if check.attribute.is_empty() || check.attribute.contains(['*', '[']) {
            return None;
        }
        let value = match (check.operator, &check.value) {
            (Equals, v) if literal(v) => v.clone(),
            (IsTrue, _) => serde_json::Value::Bool(true),
            (IsFalse, _) => serde_json::Value::Bool(false),
            (Within, serde_json::Value::Array(a)) if a.len() == 1 && literal(&a[0]) => a[0].clone(),
            _ => return None,
        };
        let path = check.attribute.split('.').map(str::to_string).collect();
        Some((Some(resource_types.as_slice()), (path, value)))
    }
    let mut by_type: HashMap<String, Option<Fix>> = HashMap::new();
    for c in &spec.clauses {
        let (about, fix) = match clause_fix(c) {
            Some((about, fix)) => (about, Some(fix)),
            None => (None, None),
        };
        for ty in &c.resource_types {
            let fix = fix
                .clone()
                .filter(|_| about.is_none_or(|a| a.is_empty() || a.contains(ty)));
            by_type
                .entry(ty.clone())
                .and_modify(|f| {
                    if *f != fix {
                        *f = None;
                    }
                })
                .or_insert(fix);
        }
    }
    by_type
        .into_iter()
        .filter_map(|(ty, f)| Some((ty, f?)))
        .collect()
}

/// Parse and compile every rule of a rules document.
pub fn compile_json(json: &str) -> Result<Vec<CompiledRule>, String> {
    parse_rules(json)?.into_iter().map(compile).collect()
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Scope<'s> {
    Resource(&'s Resource),
    Value(&'s Value),
}

fn step(v: &Value, s: &Seg) -> Value {
    if let (Some(i), Kind::Known(Known::List(_))) = (s.index, &v.kind) {
        return v.index(&Value::number(i as f64));
    }
    v.field_or_null(&s.name)
}

/// Loose equality of two Known values, with Terraform conversions.
fn eq(a: &Value, b: &Value) -> bool {
    use Known as K;
    let (Some(x), Some(y)) = (a.as_known(), b.as_known()) else {
        return false;
    };
    match (x, y) {
        (K::Null, K::Null) => true,
        (K::Null, _) | (_, K::Null) => false,
        (K::Number(_), _) | (_, K::Number(_)) => match (a.as_number(), b.as_number()) {
            (Some(p), Some(q)) => p == q,
            _ => false,
        },
        (K::Bool(_), _) | (_, K::Bool(_)) => match (a.as_bool(), b.as_bool()) {
            (Some(p), Some(q)) => p == q,
            _ => false,
        },
        (K::String(_) | K::Json(_), _) | (_, K::String(_) | K::Json(_)) => {
            match (a.to_str(), b.to_str()) {
                (Some(p), Some(q)) => p.trim() == q.trim(),
                _ => false,
            }
        }
        _ => a.known_eq(b) == Some(true),
    }
}

fn cmp(op: CmpOp, a: &Value, b: &Value) -> bool {
    match op {
        CmpOp::Eq => eq(a, b),
        CmpOp::Ne => !eq(a, b),
        _ => match (a.as_number(), b.as_number()) {
            (Some(p), Some(q)) => match op {
                CmpOp::Lt => p < q,
                CmpOp::Le => p <= q,
                CmpOp::Gt => p > q,
                CmpOp::Ge => p >= q,
                _ => unreachable!(),
            },
            _ => false,
        },
    }
}

fn eval_value(n: &Node, s: Scope<'_>) -> Value {
    match n {
        Node::Col { path, default } => {
            let (mut v, rest) = match s {
                Scope::Resource(r) => {
                    let first = &path[0].name;
                    let v = if *default {
                        r.value_or_default(first)
                    } else {
                        r.value(first)
                    };
                    (v.unwrap_or_else(Value::null), &path[1..])
                }
                Scope::Value(v) => (v.clone(), &path[..]),
            };
            for seg in rest {
                v = step(&v, seg);
            }
            v
        }
        Node::Element => match s {
            Scope::Value(v) => v.clone(),
            Scope::Resource(_) => Value::null(),
        },
        Node::Lit(v) => v.clone(),
        pred => {
            let v = eval_pred(pred, s);
            match v.truth {
                Truth::True => Value::bool(true),
                Truth::False => Value::bool(false),
                Truth::Tainted => v.witness.unwrap_or_else(|| Value::tainted("(expression)")),
                Truth::Unknown => v.witness.unwrap_or_else(|| Value::other("(expression)")),
            }
        }
    }
}

fn is_true(v: &Value) -> Verdict {
    truth::test(v, &|x| x.as_bool() == Some(true))
}

fn eval_pred(n: &Node, s: Scope<'_>) -> Verdict {
    match n {
        Node::CheckovGraph(_) => Verdict::new(Truth::Unknown, None),
        Node::CheckovAttribute(check) => match s {
            Scope::Resource(r) => check.evaluate(r),
            Scope::Value(_) => Verdict::new(Truth::Unknown, None),
        },
        Node::CheckovValue(check) => match s {
            Scope::Resource(r) => check.evaluate(r),
            Scope::Value(_) => Verdict::new(Truth::Unknown, None),
        },
        Node::CheckovPython(check) => match s {
            Scope::Resource(r) => check.evaluate(r),
            Scope::Value(_) => Verdict::new(Truth::Unknown, None),
        },
        Node::Col { .. } | Node::Element | Node::Lit(_) => is_true(&eval_value(n, s)),
        Node::Cmp(op, l, r, witness_left) => {
            let (lv, rv) = (eval_value(l, s), eval_value(r, s));
            truth::map(&lv, &|a| {
                truth::map(&rv, &|b| {
                    Verdict::new(
                        Truth::from_bool(cmp(*op, a, b)),
                        Some(if *witness_left { a.clone() } else { b.clone() }),
                    )
                })
            })
        }
        Node::IsIn(e, vals) => {
            let v = eval_value(e, s);
            truth::test(&v, &|x| vals.iter().any(|l| eq(x, l)))
        }
        Node::ListContains(l, val) => {
            let list = eval_value(l, s);
            truth::exists(&list, &|e| truth::test(e, &|x| eq(x, val)))
        }
        Node::ListAny(l, p) => {
            let list = eval_value(l, s);
            truth::exists(&list, &|e| eval_pred(p, Scope::Value(e)))
        }
        Node::ListAll(l, p) => {
            let list = eval_value(l, s);
            truth::forall(&list, &|e| eval_pred(p, Scope::Value(e)))
        }
        Node::And(args) => {
            let mut acc = eval_pred(&args[0], s);
            for a in &args[1..] {
                if acc.truth == Truth::False {
                    break;
                }
                acc = acc.and(eval_pred(a, s));
            }
            acc
        }
        Node::Or(args) => {
            let mut acc = eval_pred(&args[0], s);
            for a in &args[1..] {
                if acc.truth == Truth::True {
                    break;
                }
                acc = acc.or(eval_pred(a, s));
            }
            acc
        }
        Node::Not(a) => eval_pred(a, s).negate(),
        Node::IsNull(e) => truth::test(&eval_value(e, s), &|x| x.is_null()),
        Node::IsKnown(e) => {
            let v = eval_value(e, s);
            Verdict::new(Truth::from_bool(v.is_wholly_known()), Some(v))
        }
    }
}

impl CompiledRule {
    /// The verdict of this rule for one resource (`None` when no clause
    /// applies to its type).
    pub fn verdict(&self, r: &Resource) -> Option<Verdict> {
        let typed = self.by_type.get(&*r.ty);
        let wildcard = self.by_type.get("*");
        if typed.is_none() && wildcard.is_none() {
            return None;
        }
        let idx = typed
            .into_iter()
            .flatten()
            .chain(wildcard.into_iter().flatten());
        let mut acc = Verdict::FALSE;
        for &i in idx {
            let c = &self.clauses[i];
            if matches!(c.condition, Node::CheckovGraph(_)) {
                continue;
            }
            let v = match &c.for_each {
                Some(fe) => {
                    let list = eval_value(fe, Scope::Resource(r));
                    truth::exists(&list, &|e| {
                        truth::map(e, &|e| eval_pred(&c.condition, Scope::Value(e)))
                    })
                }
                None => eval_pred(&c.condition, Scope::Resource(r)),
            };
            acc = acc.or(v);
            if acc.truth == Truth::True {
                break;
            }
        }
        Some(acc)
    }

    fn with_fix(&self, r: &Resource, j: Judgement) -> Judgement {
        let hint = self.fix.get(&*r.ty).and_then(|(path, value)| {
            let path: Vec<&str> = path.iter().map(String::as_str).collect();
            tf_linter::FixHint::set_path(r, &path, value.clone())
        });
        Judgement {
            fix_hint: hint.or(j.fix_hint),
            ..j
        }
    }

    fn render(&self, r: &Resource, w: Option<&Value>) -> String {
        let mut s = String::new();
        for p in &self.message {
            match p {
                Piece::Text(t) => s.push_str(t),
                Piece::Address => s.push_str(&r.address),
                Piece::Type => s.push_str(&r.ty),
                Piece::Name => s.push_str(&r.name),
                Piece::Rule => s.push_str(&self.spec.name),
                Piece::Witness(fallback) => match (w.and_then(|v| v.to_str()), fallback) {
                    (Some(x), _) => s.push_str(&x),
                    (None, Some(f)) => s.push_str(f),
                    (None, None) => match w {
                        Some(v) => s.push_str(&v.to_string()),
                        None => s.push('?'),
                    },
                },
            }
        }
        s
    }
}

impl DynRule for CompiledRule {
    fn needs_graph(&self) -> bool {
        self.clauses
            .iter()
            .any(|c| matches!(c.condition, Node::CheckovGraph(_)))
    }
    fn judge_graph<'a>(
        &self,
        graph: &tf_semantic::graph::ResourceGraph<'a>,
    ) -> Result<Vec<(&'a Resource, Judgement)>, RuleFailure> {
        if let Some(r) = graph.resources.iter().find(|r| !r.dependencies_complete && self.clauses.iter().any(|c| matches!(&c.condition, Node::CheckovGraph(e) if e.connection_tree() && e.targets(r)))) {
            return Err(format!("graph dependencies unavailable for {}; include Terraform source or a plan with complete configuration references", r.address));
        }

        let mut verdicts: Vec<_> = graph
            .resources
            .iter()
            .map(|r| {
                if r.mode == tf_semantic::Mode::Managed {
                    self.verdict(r).unwrap_or(Verdict::FALSE)
                } else {
                    Verdict::FALSE
                }
            })
            .collect();
        for (clause, spec) in self.clauses.iter().zip(&self.spec.clauses) {
            if let Node::CheckovGraph(expr) = &clause.condition {
                for (i, result) in expr.evaluate(graph).into_iter().enumerate() {
                    let r = graph.resources[i];
                    if !graph::matches(&spec.resource_types, r) {
                        continue;
                    }
                    if let Some(pass) = result {
                        verdicts[i] = verdicts[i].clone().or(pass.negate());
                    }
                }
            }
        }
        Ok(graph
            .resources
            .iter()
            .zip(verdicts)
            .filter_map(|(&r, v)| {
                Judgement::from_verdict(v, |v| self.render(r, v.witness.as_ref()))
                    .map(|j| (r, self.with_fix(r, j)))
            })
            .collect())
    }
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn judge_resource(&self, r: &Resource) -> Result<Vec<Judgement>, RuleFailure> {
        // Mixed packs can merge resource and graph clauses under the same ID.
        // Their verdicts are combined once by judge_graph, avoiding duplicates.
        if self.needs_graph() {
            return Ok(Vec::new());
        }
        Ok(self
            .verdict(r)
            .and_then(|v| Judgement::from_verdict(v, |v| self.render(r, v.witness.as_ref())))
            .map(|j| self.with_fix(r, j))
            .into_iter()
            .collect())
    }
    fn judge_module<'m>(
        &self,
        _m: &'m Module,
    ) -> Result<Vec<(&'m Resource, Judgement)>, RuleFailure> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_templates() {
        assert!(compile_message("a {witness|x} {{b}}").is_ok());
        assert!(compile_message("{nope}").is_err());
        assert!(compile_message("{witness").is_err());
    }

    #[test]
    fn parse_forms() {
        let one = r#"{"name":"r","message":"m","clauses":[{"resource_types":["t"],"condition":{"op":"lit","value":true}}]}"#;
        assert_eq!(parse_rules(one).unwrap().len(), 1);
        assert_eq!(parse_rules(&format!("[{one},{one}]")).unwrap().len(), 2);
        assert_eq!(
            parse_rules(&format!(r#"{{"rules":[{one}]}}"#))
                .unwrap()
                .len(),
            1
        );
        let bad = r#"{"name":"r","message":"m","clauses":[{"resource_types":["t"],"condition":{"op":"nope"}}]}"#;
        assert!(parse_rules(bad).is_err());
        let bad_level = one.replace(r#""message""#, r#""level":"severe","message""#);
        assert!(compile_json(&bad_level).is_err());
    }

    #[test]
    fn lattice() {
        let n = Node::Cmp(
            CmpOp::Le,
            Box::new(Node::Element),
            Box::new(Node::Lit(Value::number(22.0))),
            true,
        );
        let t = |v: Value| eval_pred(&n, Scope::Value(&v)).truth;
        assert_eq!(t(Value::number(0.0)), Truth::True);
        assert_eq!(t(Value::string("0")), Truth::True);
        assert_eq!(t(Value::number(80.0)), Truth::False);
        assert_eq!(t(Value::tainted("x")), Truth::Tainted);
        assert_eq!(t(Value::other("y")), Truth::Unknown);
        let c = Node::ListContains(Box::new(Node::Element), Value::string("0.0.0.0/0"));
        let l = Value::list(vec![Value::string("10.0.0.0/8"), Value::tainted("v")]);
        assert_eq!(eval_pred(&c, Scope::Value(&l)).truth, Truth::Tainted);
        let all = Node::ListAll(
            Box::new(Node::Element),
            Box::new(Node::Cmp(
                CmpOp::Ne,
                Box::new(Node::Element),
                Box::new(Node::Lit(Value::string("0.0.0.0/0"))),
                true,
            )),
        );
        assert_eq!(
            eval_pred(&all, Scope::Value(&Value::list(vec![]))).truth,
            Truth::True
        );
        assert_eq!(eval_pred(&all, Scope::Value(&l)).truth, Truth::Tainted);
    }
}

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
use tf_linter::{Category, DynRule, Judgement, Level, RuleInfo};
use tf_semantic::{Module, Resource};

/// Current IR version. Readers reject other versions.
pub const IR_VERSION: u32 = 1;

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

/// Read and parse a rules file.
pub fn load_rules_file(path: &std::path::Path) -> Result<Vec<RuleSpec>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_rules(&text).map_err(|e| format!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

/// Internal, pre-converted expression tree (literals as `Value`s).
#[derive(Debug)]
enum Node {
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
    if spec.version != IR_VERSION {
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
            condition: compile_expr(&c.condition)
                .map_err(|e| ctx(format!("clause {i}: condition: {e}")))?,
        });
    }
    let info = RuleInfo {
        name: Arc::from(spec.name.as_str()),
        category,
        level,
        description: Arc::from(spec.description.as_str()),
        resource_types: types,
        runs_on_module: false,
    };
    Ok(CompiledRule {
        spec,
        info,
        clauses,
        by_type,
        message,
    })
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

/// Field `name` of an object value; a missing field of a Known object is
/// null (attributes not written in a block are unset). Lifts over `OneOf`.
/// Same semantics as the seed rules' helper.
pub fn field(obj: &Value, name: &str) -> Value {
    match &obj.kind {
        Kind::Known(Known::Object(m)) => match m.get(name) {
            Some(v) => v.child_of(obj),
            None => Value::null(),
        },
        Kind::Known(Known::Null) => Value::null(),
        Kind::OneOf(o) => Value::one_of(
            o.alternatives
                .iter()
                .map(|a| field(&a.child_of(obj), name))
                .collect(),
            o.tainted,
        ),
        _ => obj.get_attr(name),
    }
}

fn step(v: &Value, s: &Seg) -> Value {
    if let (Some(i), Kind::Known(Known::List(_))) = (s.index, &v.kind) {
        return v.index(&Value::number(i as f64));
    }
    field(v, &s.name)
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
            let v = truth::exists(&list, &|e| negate(eval_pred(p, Scope::Value(e))));
            negate(v)
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
        Node::Not(a) => negate(eval_pred(a, s)),
        Node::IsNull(e) => truth::test(&eval_value(e, s), &|x| x.is_null()),
        Node::IsKnown(e) => {
            let v = eval_value(e, s);
            Verdict::new(Truth::from_bool(v.is_wholly_known()), Some(v))
        }
    }
}

fn negate(v: Verdict) -> Verdict {
    Verdict::new(v.truth.negate(), v.witness)
}

impl CompiledRule {
    /// The verdict of this rule for one resource (`None` when no clause
    /// applies to its type).
    pub fn verdict(&self, r: &Resource) -> Option<Verdict> {
        let idx = self.by_type.get(&*r.ty)?;
        let mut acc = Verdict::FALSE;
        for &i in idx {
            let c = &self.clauses[i];
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
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn judge_resource(&self, r: &Resource) -> Vec<Judgement> {
        self.verdict(r)
            .map(|verdict| {
                let message = if verdict.holds() {
                    self.render(r, verdict.witness.as_ref())
                } else {
                    String::new()
                };
                Judgement { verdict, message }
            })
            .into_iter()
            .collect()
    }
    fn judge_module<'m>(&self, _m: &'m Module) -> Vec<(&'m Resource, Judgement)> {
        Vec::new()
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

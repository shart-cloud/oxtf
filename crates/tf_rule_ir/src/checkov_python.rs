//! Checkov resource checks written in Python, run natively.
//!
//! The importer (`tfscan/checkov_python.py`) serializes a check's
//! `scan_resource_conf` (with the methods and helper functions it calls,
//! and every constant it reads) as a restricted-Python AST. This module
//! interprets that AST over the Checkov-shaped configuration of a resource
//! ([`crate::checkov::configuration`]), with Python's semantics for the
//! subset: truthiness, `==` / `in` / ordering across types, indexing and
//! slicing, `dict` / `list` / `str` / `set` methods, the built-ins and
//! Checkov helpers the checks use, `re`, `try` / `except`, and in-place
//! mutation of the check's own copy of the configuration.
//!
//! Abstract values stay abstract until the program inspects them:
//!
//! - an `Unknown` or `Tainted` leaf that decides a branch, a comparison or
//!   an operation stops the run with that truth (no finding, or a
//!   conditional one), witnessed by the leaf;
//! - a `OneOf` is resolved by running the program once per alternative
//!   (forking at the first inspection) and joining the results as
//!   [`truth::combine_one_of`] does.
//!
//! `FAILED` is a finding; `PASSED` and `UNKNOWN` are not. A Python
//! exception that escapes the check, an operation outside the subset or an
//! exhausted step budget is `Unknown`: Checkov reports no result for a
//! check that raises. A finding is located by the check's
//! `evaluated_keys` (the paths Checkov reports), else the resource.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tf_eval::truth::{self, Truth};
use tf_eval::{Kind, Known, Value, Verdict};
use tf_semantic::Resource;

use crate::{py, pyre};

/// The program format this build reads (`version` in the program).
pub const PROGRAM_VERSION: u32 = 1;

/// Statements executed per resource before giving up (`Unknown`).
const STEP_BUDGET: u32 = 200_000;
/// Runs per resource when forking over `OneOf` alternatives.
const RUN_BUDGET: usize = 64;

// -- the serialized program ---------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub version: u32,
    /// The key of `scan_resource_conf` in `functions`.
    pub entry: String,
    pub functions: BTreeMap<String, Function>,
    /// The check instance's attributes (constants, and per-run state such
    /// as `evaluated_keys`).
    #[serde(rename = "self")]
    pub self_attrs: BTreeMap<String, Json>,
    /// The key of the check's `get_evaluated_keys`, when it defines one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_keys: Option<String>,
    /// For a check calling `super().scan_resource_conf` (Checkov's generic
    /// value check): its parameters per resource type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_check: Option<BTreeMap<String, crate::checkov::ValueCheck>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    pub params: Vec<String>,
    pub defaults: Vec<Option<Expr>>,
    pub body: Vec<Stmt>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "s", rename_all = "snake_case", deny_unknown_fields)]
pub enum Stmt {
    Expr {
        value: Expr,
    },
    Return {
        value: Option<Expr>,
    },
    If {
        test: Expr,
        body: Vec<Stmt>,
        orelse: Vec<Stmt>,
    },
    For {
        target: Target,
        iter: Expr,
        body: Vec<Stmt>,
        orelse: Vec<Stmt>,
    },
    Assign {
        targets: Vec<Target>,
        value: Expr,
    },
    Aug {
        target: Target,
        op: BinOp,
        value: Expr,
    },
    Pass,
    Break,
    Continue,
    Try {
        body: Vec<Stmt>,
        handlers: Vec<Handler>,
        orelse: Vec<Stmt>,
        #[serde(rename = "finally")]
        finalbody: Vec<Stmt>,
    },
    Raise {
        #[serde(rename = "type")]
        ty: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handler {
    /// Exception class names; `None` is a bare `except:`.
    pub types: Option<Vec<String>>,
    pub name: Option<String>,
    pub body: Vec<Stmt>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Name {
        id: String,
    },
    Tuple {
        elts: Vec<Target>,
    },
    Sub {
        value: Expr,
        index: Expr,
    },
    #[serde(rename = "self")]
    SelfAttr {
        attr: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Floordiv,
    Mod,
    Pow,
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
    In,
    NotIn,
    Is,
    IsNot,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generator {
    pub target: Target,
    pub iter: Expr,
    pub ifs: Vec<Expr>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Func {
    Builtin { builtin: String },
    Func { func: String },
    Local { local: String },
    Method { method: String, obj: Box<Expr> },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "e", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expr {
    Const {
        v: Json,
    },
    Name {
        id: String,
    },
    #[serde(rename = "self")]
    SelfAttr {
        attr: String,
    },
    Call {
        func: Func,
        args: Vec<Expr>,
        kwargs: Vec<(String, Expr)>,
    },
    Sub {
        value: Box<Expr>,
        index: Box<Expr>,
    },
    Slice {
        value: Box<Expr>,
        lower: Option<Box<Expr>>,
        upper: Option<Box<Expr>>,
        step: Option<Box<Expr>>,
    },
    Cmp {
        left: Box<Expr>,
        ops: Vec<CmpOp>,
        comparators: Vec<Expr>,
    },
    And {
        values: Vec<Expr>,
    },
    Or {
        values: Vec<Expr>,
    },
    Not {
        operand: Box<Expr>,
    },
    Neg {
        operand: Box<Expr>,
    },
    Pos {
        operand: Box<Expr>,
    },
    Bin {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Ifexp {
        test: Box<Expr>,
        body: Box<Expr>,
        orelse: Box<Expr>,
    },
    List {
        elts: Vec<Expr>,
    },
    Tuple {
        elts: Vec<Expr>,
    },
    Set {
        elts: Vec<Expr>,
    },
    Dict {
        keys: Vec<Expr>,
        values: Vec<Expr>,
    },
    Listcomp {
        elt: Box<Expr>,
        generators: Vec<Generator>,
    },
    Genexp {
        elt: Box<Expr>,
        generators: Vec<Generator>,
    },
    Setcomp {
        elt: Box<Expr>,
        generators: Vec<Generator>,
    },
    Dictcomp {
        key: Box<Expr>,
        value: Box<Expr>,
        generators: Vec<Generator>,
    },
    Lambda {
        params: Vec<String>,
        body: Box<Expr>,
    },
    Fstr {
        parts: Vec<Expr>,
    },
    /// An exception class used as a value (only to raise it).
    Exception {
        #[serde(rename = "type")]
        ty: String,
    },
}

impl Program {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != PROGRAM_VERSION {
            return Err(format!(
                "checkov_python: program version {} (this build reads {PROGRAM_VERSION})",
                self.version
            ));
        }
        if !self.functions.contains_key(&self.entry) {
            return Err(format!(
                "checkov_python: no entry function {:?}",
                self.entry
            ));
        }
        if let Some(k) = &self.evaluated_keys
            && !self.functions.contains_key(k)
        {
            return Err(format!("checkov_python: no function {k:?}"));
        }
        let mut missing = Vec::new();
        for f in self.functions.values() {
            calls(&f.body, &mut |name| {
                if !self.functions.contains_key(name) {
                    missing.push(name.to_string());
                }
            });
        }
        if let Some(name) = missing.first() {
            return Err(format!(
                "checkov_python: call to undefined function {name:?}"
            ));
        }
        // Constants must decode.
        for v in self.self_attrs.values() {
            Py::from_const(v)?;
        }
        for check in self.value_check.iter().flat_map(BTreeMap::values) {
            check.validate()?;
        }
        Ok(())
    }
}

/// Every program function `stmts` call or reference (`{"func": key}`,
/// a `{"funcref": key}` constant).
fn calls(stmts: &[Stmt], f: &mut dyn FnMut(&str)) {
    fn target(t: &Target, f: &mut dyn FnMut(&str)) {
        match t {
            Target::Tuple { elts } => elts.iter().for_each(|t| target(t, f)),
            Target::Sub { value, index } => {
                expr(value, f);
                expr(index, f);
            }
            Target::Name { .. } | Target::SelfAttr { .. } => {}
        }
    }
    fn exprs(es: &[Expr], f: &mut dyn FnMut(&str)) {
        es.iter().for_each(|e| expr(e, f));
    }
    fn generators(gs: &[Generator], f: &mut dyn FnMut(&str)) {
        for g in gs {
            target(&g.target, f);
            expr(&g.iter, f);
            exprs(&g.ifs, f);
        }
    }
    fn expr(e: &Expr, f: &mut dyn FnMut(&str)) {
        match e {
            Expr::Const { v } => {
                if let Some(Json::String(key)) = v.get("funcref") {
                    f(key);
                }
            }
            Expr::Call { func, args, kwargs } => {
                match func {
                    Func::Func { func } => f(func),
                    Func::Method { obj, .. } => expr(obj, f),
                    Func::Builtin { .. } | Func::Local { .. } => {}
                }
                exprs(args, f);
                kwargs.iter().for_each(|(_, e)| expr(e, f));
            }
            Expr::Sub { value, index } => {
                expr(value, f);
                expr(index, f);
            }
            Expr::Slice {
                value,
                lower,
                upper,
                step,
            } => {
                expr(value, f);
                for b in [lower, upper, step].into_iter().flatten() {
                    expr(b, f);
                }
            }
            Expr::Cmp {
                left, comparators, ..
            } => {
                expr(left, f);
                exprs(comparators, f);
            }
            Expr::And { values } | Expr::Or { values } => exprs(values, f),
            Expr::Not { operand } | Expr::Neg { operand } | Expr::Pos { operand } => {
                expr(operand, f)
            }
            Expr::Bin { left, right, .. } => {
                expr(left, f);
                expr(right, f);
            }
            Expr::Ifexp { test, body, orelse } => {
                expr(test, f);
                expr(body, f);
                expr(orelse, f);
            }
            Expr::List { elts } | Expr::Tuple { elts } | Expr::Set { elts } => exprs(elts, f),
            Expr::Dict { keys, values } => {
                exprs(keys, f);
                exprs(values, f);
            }
            Expr::Listcomp { elt, generators: g }
            | Expr::Genexp { elt, generators: g }
            | Expr::Setcomp { elt, generators: g } => {
                expr(elt, f);
                generators(g, f);
            }
            Expr::Dictcomp {
                key,
                value,
                generators: g,
            } => {
                expr(key, f);
                expr(value, f);
                generators(g, f);
            }
            Expr::Lambda { body, .. } => expr(body, f),
            Expr::Fstr { parts } => exprs(parts, f),
            Expr::Name { .. } | Expr::SelfAttr { .. } | Expr::Exception { .. } => {}
        }
    }
    for s in stmts {
        match s {
            Stmt::Expr { value } => expr(value, f),
            Stmt::Return { value } => {
                if let Some(v) = value {
                    expr(v, f);
                }
            }
            Stmt::If { test, body, orelse } => {
                expr(test, f);
                calls(body, f);
                calls(orelse, f);
            }
            Stmt::For {
                target: t,
                iter,
                body,
                orelse,
            } => {
                target(t, f);
                expr(iter, f);
                calls(body, f);
                calls(orelse, f);
            }
            Stmt::Assign { targets, value } => {
                targets.iter().for_each(|t| target(t, f));
                expr(value, f);
            }
            Stmt::Aug {
                target: t, value, ..
            } => {
                target(t, f);
                expr(value, f);
            }
            Stmt::Try {
                body,
                handlers,
                orelse,
                finalbody,
            } => {
                calls(body, f);
                for h in handlers {
                    calls(&h.body, f);
                }
                calls(orelse, f);
                calls(finalbody, f);
            }
            Stmt::Pass | Stmt::Break | Stmt::Continue | Stmt::Raise { .. } => {}
        }
    }
}

// -- runtime values -------------------------------------------------------

type List = Rc<RefCell<Vec<Py>>>;

#[derive(Clone)]
enum Py {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    List(List),
    Tuple(Rc<Vec<Py>>),
    Set(List),
    Dict(Rc<RefCell<Vec<(Py, Py)>>>),
    Range(i64, i64, i64),
    /// A `CheckResult` member.
    Result(Rc<str>),
    /// A type object (`isinstance`'s second argument).
    Type(Rc<str>),
    Pattern(Rc<str>),
    Match(Rc<Vec<Option<Rc<str>>>>),
    Lambda(Rc<(Vec<String>, Expr)>),
    /// A program function used as a value (`map(self.f, xs)`).
    FuncRef(Rc<str>),
    /// A built-in used as a value (`map(str, xs)`, `key=len`).
    Builtin(Rc<str>),
    Exception(Rc<str>),
    /// An abstract configured value (Unknown / Tainted).
    Abstract(Rc<Value>, bool),
    /// A `OneOf`, by id, with its alternatives.
    OneOf(usize, Rc<Vec<Py>>),
}

impl Py {
    fn str(s: &str) -> Py {
        Py::Str(Rc::from(s))
    }
    fn list(v: Vec<Py>) -> Py {
        Py::List(Rc::new(RefCell::new(v)))
    }
    fn tuple(v: Vec<Py>) -> Py {
        Py::Tuple(Rc::new(v))
    }

    /// A program constant (`checkov_python.py` tagged form).
    fn from_const(v: &Json) -> Result<Py, String> {
        Ok(match v {
            Json::Null => Py::None,
            Json::Bool(b) => Py::Bool(*b),
            Json::Number(n) => match n.as_i64() {
                Some(i) if !n.is_f64() => Py::Int(i),
                _ => Py::Float(n.as_f64().ok_or("number out of range")?),
            },
            Json::String(s) => Py::str(s),
            Json::Object(m) if m.len() == 1 => {
                let (tag, inner) = m.iter().next().expect("one entry");
                let items = |inner: &Json| -> Result<Vec<Py>, String> {
                    inner
                        .as_array()
                        .ok_or("tagged container is not an array")?
                        .iter()
                        .map(Py::from_const)
                        .collect()
                };
                match tag.as_str() {
                    "list" => Py::list(items(inner)?),
                    "tuple" => Py::tuple(items(inner)?),
                    "set" => Py::Set(Rc::new(RefCell::new(items(inner)?))),
                    "dict" => {
                        let mut out = Vec::new();
                        for pair in inner.as_array().ok_or("dict is not an array")? {
                            let [k, v] = pair.as_array().map(Vec::as_slice).unwrap_or(&[]) else {
                                return Err("dict entry is not a pair".into());
                            };
                            out.push((Py::from_const(k)?, Py::from_const(v)?));
                        }
                        Py::Dict(Rc::new(RefCell::new(out)))
                    }
                    "result" => Py::Result(Rc::from(inner.as_str().ok_or("result")?)),
                    // A plain enum member, equal only to itself: kept as a
                    // result-like constant under its qualified name.
                    "enum" => Py::Result(Rc::from(inner.as_str().ok_or("enum")?)),
                    "funcref" => Py::FuncRef(Rc::from(inner.as_str().ok_or("funcref")?)),
                    "builtin" => Py::Builtin(Rc::from(inner.as_str().ok_or("builtin")?)),
                    "type" => Py::Type(Rc::from(inner.as_str().ok_or("type")?)),
                    "pattern" => {
                        let p = inner.as_str().ok_or("pattern")?;
                        pyre::translate(p)?;
                        Py::Pattern(Rc::from(p))
                    }
                    "range" => {
                        let r: Vec<i64> = inner
                            .as_array()
                            .ok_or("range")?
                            .iter()
                            .map(|x| x.as_i64().ok_or("range bound"))
                            .collect::<Result<_, _>>()?;
                        let [a, b, s] = r[..] else {
                            return Err("range".into());
                        };
                        Py::Range(a, b, s)
                    }
                    other => return Err(format!("unknown constant tag {other:?}")),
                }
            }
            other => return Err(format!("untagged constant {other}")),
        })
    }

    fn type_name(&self) -> &'static str {
        match self {
            Py::None => "NoneType",
            Py::Bool(_) => "bool",
            Py::Int(_) => "int",
            Py::Float(_) => "float",
            Py::Str(_) => "str",
            Py::List(_) => "list",
            Py::Tuple(_) => "tuple",
            Py::Set(_) => "set",
            Py::Dict(_) => "dict",
            Py::Range(..) => "range",
            Py::Result(_) => "CheckResult",
            Py::Type(_) => "type",
            Py::Pattern(_) => "Pattern",
            Py::Match(_) => "Match",
            Py::Lambda(_) | Py::FuncRef(_) => "function",
            Py::Builtin(_) => "builtin_function_or_method",
            Py::Exception(_) => "type",
            Py::Abstract(..) | Py::OneOf(..) => "abstract",
        }
    }
}

// -- control flow ---------------------------------------------------------

enum Flow {
    Return(Py),
    Break,
    Continue,
    /// A Python exception, by class name.
    Exc(Rc<str>),
    /// An abstract value decided the run.
    Abstract(Rc<Value>, bool),
    /// A `OneOf` (by id, with its number of alternatives) must be resolved.
    Fork(usize, usize),
    /// Outside the interpreted subset, or the step budget ran out.
    Unsupported(String),
}

type R<T> = Result<T, Flow>;

fn exc<T>(name: &str) -> R<T> {
    Err(Flow::Exc(Rc::from(name)))
}

fn unsupported<T>(what: impl Into<String>) -> R<T> {
    Err(Flow::Unsupported(what.into()))
}

/// Whether an exception of class `raised` is caught by `handler`.
fn catches(handler: &str, raised: &str) -> bool {
    let parents: &[&str] = match raised {
        "KeyError" | "IndexError" => &["LookupError"],
        "JSONDecodeError" => &["ValueError"],
        "ZeroDivisionError" => &["ArithmeticError"],
        _ => &[],
    };
    handler == raised || handler == "Exception" || parents.contains(&handler)
}

// -- the interpreter -------------------------------------------------------

struct Interp<'p> {
    program: &'p Program,
    resource: &'p Resource,
    self_attrs: HashMap<String, Py>,
    /// The alternative chosen for each `OneOf` resolved so far.
    choices: HashMap<usize, usize>,
    steps: u32,
}

type Env = HashMap<String, Py>;

impl<'p> Interp<'p> {
    fn step(&mut self) -> R<()> {
        self.steps += 1;
        if self.steps > STEP_BUDGET {
            return unsupported("step budget exhausted");
        }
        Ok(())
    }

    /// `v` with abstractions resolved, or the flow they demand.
    fn concrete(&self, v: &Py) -> R<Py> {
        match v {
            Py::Abstract(w, tainted) => Err(Flow::Abstract(w.clone(), *tainted)),
            Py::OneOf(id, alts) => match self.choices.get(id) {
                Some(&i) => self.concrete(&alts[i]),
                None => Err(Flow::Fork(*id, alts.len())),
            },
            other => Ok(other.clone()),
        }
    }

    fn truthy(&self, v: &Py) -> R<bool> {
        Ok(match self.concrete(v)? {
            Py::None => false,
            Py::Bool(b) => b,
            Py::Int(i) => i != 0,
            Py::Float(f) => f != 0.0,
            Py::Str(s) => !s.is_empty(),
            Py::List(l) | Py::Set(l) => !l.borrow().is_empty(),
            Py::Tuple(t) => !t.is_empty(),
            Py::Dict(d) => !d.borrow().is_empty(),
            Py::Range(a, b, s) => range_len(a, b, s) > 0,
            _ => true,
        })
    }

    fn eq(&self, a: &Py, b: &Py) -> R<bool> {
        let (a, b) = (self.concrete(a)?, self.concrete(b)?);
        Ok(match (&a, &b) {
            (Py::None, Py::None) => true,
            (Py::Str(x), Py::Str(y)) => x == y,
            (Py::Result(x), Py::Result(y)) | (Py::Type(x), Py::Type(y)) => x == y,
            (Py::List(x), Py::List(y)) => {
                if Rc::ptr_eq(x, y) {
                    return Ok(true);
                }
                let (x, y) = (x.borrow().clone(), y.borrow().clone());
                self.seq_eq(&x, &y)?
            }
            (Py::Tuple(x), Py::Tuple(y)) => self.seq_eq(x, y)?,
            (Py::Set(x), Py::Set(y)) => {
                let (x, y) = (x.borrow().clone(), y.borrow().clone());
                x.len() == y.len() && self.all_in(&x, &y)?
            }
            (Py::Dict(x), Py::Dict(y)) => {
                let (x, y) = (x.borrow().clone(), y.borrow().clone());
                if x.len() != y.len() {
                    return Ok(false);
                }
                for (k, v) in &x {
                    match self.dict_get(&y, k)? {
                        Some(w) if self.eq(v, &w)? => {}
                        _ => return Ok(false),
                    }
                }
                true
            }
            (Py::Range(a1, b1, s1), Py::Range(a2, b2, s2)) => (a1, b1, s1) == (a2, b2, s2),
            _ => match (number(&a), number(&b)) {
                (Some(x), Some(y)) => x == y,
                _ => false,
            },
        })
    }

    fn seq_eq(&self, x: &[Py], y: &[Py]) -> R<bool> {
        if x.len() != y.len() {
            return Ok(false);
        }
        for (a, b) in x.iter().zip(y) {
            if !self.eq(a, b)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn all_in(&self, x: &[Py], y: &[Py]) -> R<bool> {
        for a in x {
            if !self.contains_seq(y, a)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `needle in items`: true as soon as a concrete element equals it;
    /// an abstract element only matters when nothing concrete matched.
    fn contains_seq(&self, items: &[Py], needle: &Py) -> R<bool> {
        let mut pending = None;
        for item in items {
            match self.eq(item, needle) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(f @ (Flow::Abstract(..) | Flow::Fork(..))) => {
                    pending.get_or_insert(f);
                }
                Err(f) => return Err(f),
            }
        }
        match pending {
            Some(f) => Err(f),
            None => Ok(false),
        }
    }

    fn dict_get(&self, items: &[(Py, Py)], key: &Py) -> R<Option<Py>> {
        let key = self.concrete(key)?;
        for (k, v) in items {
            if self.eq(k, &key)? {
                return Ok(Some(v.clone()));
            }
        }
        Ok(None)
    }

    fn contains(&self, container: &Py, needle: &Py) -> R<bool> {
        match self.concrete(container)? {
            Py::Str(s) => match self.concrete(needle)? {
                Py::Str(n) => Ok(s.contains(&*n)),
                _ => exc("TypeError"),
            },
            Py::List(l) | Py::Set(l) => {
                let items = l.borrow().clone();
                self.contains_seq(&items, needle)
            }
            Py::Tuple(t) => self.contains_seq(&t, needle),
            Py::Dict(d) => {
                let keys: Vec<Py> = d.borrow().iter().map(|(k, _)| k.clone()).collect();
                self.contains_seq(&keys, needle)
            }
            Py::Range(a, b, s) => match self.concrete(needle)? {
                Py::Int(i) => Ok(range_items(a, b, s).contains(&i)),
                _ => Ok(false),
            },
            _ => exc("TypeError"),
        }
    }

    fn order(&self, a: &Py, b: &Py) -> R<std::cmp::Ordering> {
        let (a, b) = (self.concrete(a)?, self.concrete(b)?);
        if let (Some(x), Some(y)) = (number(&a), number(&b)) {
            return x.partial_cmp(&y).map_or_else(|| exc("ValueError"), Ok);
        }
        match (&a, &b) {
            (Py::Str(x), Py::Str(y)) => Ok(x.cmp(y)),
            (Py::List(x), Py::List(y)) => {
                let (x, y) = (x.borrow().clone(), y.borrow().clone());
                self.seq_order(&x, &y)
            }
            (Py::Tuple(x), Py::Tuple(y)) => self.seq_order(x, y),
            _ => exc("TypeError"),
        }
    }

    fn seq_order(&self, x: &[Py], y: &[Py]) -> R<std::cmp::Ordering> {
        for (a, b) in x.iter().zip(y) {
            if !self.eq(a, b)? {
                return self.order(a, b);
            }
        }
        Ok(x.len().cmp(&y.len()))
    }

    fn compare(&self, op: CmpOp, a: &Py, b: &Py) -> R<bool> {
        use std::cmp::Ordering::*;
        Ok(match op {
            CmpOp::Eq => self.eq(a, b)?,
            CmpOp::Ne => !self.eq(a, b)?,
            CmpOp::Lt => self.order(a, b)? == Less,
            CmpOp::Le => self.order(a, b)? != Greater,
            CmpOp::Gt => self.order(a, b)? == Greater,
            CmpOp::Ge => self.order(a, b)? != Less,
            CmpOp::In => self.contains(b, a)?,
            CmpOp::NotIn => !self.contains(b, a)?,
            CmpOp::Is => self.is(a, b)?,
            CmpOp::IsNot => !self.is(a, b)?,
        })
    }

    fn is(&self, a: &Py, b: &Py) -> R<bool> {
        let (a, b) = (self.concrete(a)?, self.concrete(b)?);
        Ok(match (&a, &b) {
            (Py::None, Py::None) => true,
            (Py::Bool(x), Py::Bool(y)) => x == y,
            (Py::Result(x), Py::Result(y)) | (Py::Type(x), Py::Type(y)) => x == y,
            (Py::List(x), Py::List(y)) | (Py::Set(x), Py::Set(y)) => Rc::ptr_eq(x, y),
            (Py::Dict(x), Py::Dict(y)) => Rc::ptr_eq(x, y),
            (Py::Tuple(x), Py::Tuple(y)) => Rc::ptr_eq(x, y),
            // Small ints and strings are interned by CPython; the checks
            // only compare with None, True and False.
            (Py::Int(x), Py::Int(y)) => x == y && (-5..=256).contains(x),
            _ => false,
        })
    }

    // -- statements ------------------------------------------------------

    fn block(&mut self, stmts: &[Stmt], env: &mut Env) -> R<()> {
        for s in stmts {
            self.stmt(s, env)?;
        }
        Ok(())
    }

    fn stmt(&mut self, s: &Stmt, env: &mut Env) -> R<()> {
        self.step()?;
        match s {
            Stmt::Expr { value } => {
                self.expr(value, env)?;
            }
            Stmt::Return { value } => {
                let v = match value {
                    Some(e) => self.expr(e, env)?,
                    None => Py::None,
                };
                return Err(Flow::Return(v));
            }
            Stmt::If { test, body, orelse } => {
                let t = self.expr(test, env)?;
                if self.truthy(&t)? {
                    self.block(body, env)?;
                } else {
                    self.block(orelse, env)?;
                }
            }
            Stmt::For {
                target,
                iter,
                body,
                orelse,
            } => {
                let it = self.expr(iter, env)?;
                let items = self.iterate(&it)?;
                let mut broke = false;
                for item in items {
                    self.assign(target, item, env)?;
                    match self.block(body, env) {
                        Ok(()) | Err(Flow::Continue) => {}
                        Err(Flow::Break) => {
                            broke = true;
                            break;
                        }
                        Err(f) => return Err(f),
                    }
                }
                if !broke {
                    self.block(orelse, env)?;
                }
            }
            Stmt::Assign { targets, value } => {
                let v = self.expr(value, env)?;
                for t in targets {
                    self.assign(t, v.clone(), env)?;
                }
            }
            Stmt::Aug { target, op, value } => {
                let current = match target {
                    Target::Name { id } => self.lookup(id, env)?,
                    Target::SelfAttr { attr } => self.self_attr(attr)?,
                    Target::Sub { value, index } => {
                        let (c, i) = (self.expr(value, env)?, self.expr(index, env)?);
                        self.subscript(&c, &i)?
                    }
                    Target::Tuple { .. } => return unsupported("augmented tuple assignment"),
                };
                let rhs = self.expr(value, env)?;
                let v = self.binop(*op, &current, &rhs, true)?;
                self.assign(target, v, env)?;
            }
            Stmt::Pass => {}
            Stmt::Break => return Err(Flow::Break),
            Stmt::Continue => return Err(Flow::Continue),
            Stmt::Try {
                body,
                handlers,
                orelse,
                finalbody,
            } => {
                let outcome = match self.block(body, env) {
                    Ok(()) => self.block(orelse, env),
                    Err(Flow::Exc(raised)) => {
                        let handler = handlers.iter().find(|h| {
                            h.types
                                .as_ref()
                                .is_none_or(|ts| ts.iter().any(|t| catches(t, &raised)))
                        });
                        match handler {
                            Some(h) => {
                                if let Some(n) = &h.name {
                                    env.insert(n.clone(), Py::Exception(raised.clone()));
                                }
                                self.block(&h.body, env)
                            }
                            None => Err(Flow::Exc(raised)),
                        }
                    }
                    Err(f) => Err(f),
                };
                // `finally` runs on every exit; its own exit wins.
                if !finalbody.is_empty() {
                    match outcome {
                        Err(f @ (Flow::Abstract(..) | Flow::Fork(..) | Flow::Unsupported(_))) => {
                            return Err(f);
                        }
                        other => {
                            self.block(finalbody, env)?;
                            return other;
                        }
                    }
                }
                return outcome;
            }
            Stmt::Raise { ty } => {
                return Err(Flow::Exc(Rc::from(ty.as_deref().unwrap_or("Exception"))));
            }
        }
        Ok(())
    }

    fn assign(&mut self, t: &Target, v: Py, env: &mut Env) -> R<()> {
        match t {
            Target::Name { id } => {
                env.insert(id.clone(), v);
            }
            Target::SelfAttr { attr } => {
                self.self_attrs.insert(attr.clone(), v);
            }
            Target::Tuple { elts } => {
                let items = self.iterate(&v)?;
                if items.len() != elts.len() {
                    return exc("ValueError");
                }
                for (t, item) in elts.iter().zip(items) {
                    self.assign(t, item, env)?;
                }
            }
            Target::Sub { value, index } => {
                let container = self.expr(value, env)?;
                let index = self.expr(index, env)?;
                match self.concrete(&container)? {
                    Py::List(l) => {
                        let i = self.index_of(&index, l.borrow().len())?;
                        l.borrow_mut()[i] = v;
                    }
                    Py::Dict(d) => {
                        let key = self.concrete(&index)?;
                        let pos = {
                            let items = d.borrow();
                            let mut found = None;
                            for (i, (k, _)) in items.iter().enumerate() {
                                if self.eq(k, &key)? {
                                    found = Some(i);
                                    break;
                                }
                            }
                            found
                        };
                        match pos {
                            Some(i) => d.borrow_mut()[i].1 = v,
                            None => d.borrow_mut().push((key, v)),
                        }
                    }
                    _ => return exc("TypeError"),
                }
            }
        }
        Ok(())
    }

    fn lookup(&self, id: &str, env: &Env) -> R<Py> {
        match env.get(id) {
            Some(v) => Ok(v.clone()),
            None => exc("NameError"),
        }
    }

    fn self_attr(&self, attr: &str) -> R<Py> {
        match self.self_attrs.get(attr) {
            Some(v) => Ok(v.clone()),
            None => exc("AttributeError"),
        }
    }

    /// The elements `for x in v` visits.
    fn iterate(&self, v: &Py) -> R<Vec<Py>> {
        Ok(match self.concrete(v)? {
            Py::List(l) | Py::Set(l) => l.borrow().clone(),
            Py::Tuple(t) => t.to_vec(),
            Py::Dict(d) => d.borrow().iter().map(|(k, _)| k.clone()).collect(),
            Py::Str(s) => s
                .chars()
                .map(|c| Py::str(c.encode_utf8(&mut [0; 4])))
                .collect(),
            Py::Range(a, b, s) => range_items(a, b, s).into_iter().map(Py::Int).collect(),
            _ => return exc("TypeError"),
        })
    }

    fn index_of(&self, index: &Py, len: usize) -> R<usize> {
        let i = match self.concrete(index)? {
            Py::Int(i) => i,
            Py::Bool(b) => b as i64,
            _ => return exc("TypeError"),
        };
        let i = if i < 0 { i + len as i64 } else { i };
        if i < 0 || i >= len as i64 {
            return exc("IndexError");
        }
        Ok(i as usize)
    }

    fn subscript(&self, container: &Py, index: &Py) -> R<Py> {
        match self.concrete(container)? {
            Py::List(l) => {
                let items = l.borrow();
                let i = self.index_of(index, items.len())?;
                Ok(items[i].clone())
            }
            Py::Tuple(t) => {
                let i = self.index_of(index, t.len())?;
                Ok(t[i].clone())
            }
            Py::Str(s) => {
                let chars: Vec<char> = s.chars().collect();
                let i = self.index_of(index, chars.len())?;
                Ok(Py::str(chars[i].encode_utf8(&mut [0; 4])))
            }
            Py::Dict(d) => {
                let items = d.borrow().clone();
                match self.dict_get(&items, index)? {
                    Some(v) => Ok(v),
                    None => exc("KeyError"),
                }
            }
            Py::Match(groups) => {
                let i = self.index_of(index, groups.len())?;
                Ok(groups[i].as_deref().map_or(Py::None, Py::str))
            }
            _ => exc("TypeError"),
        }
    }

    // -- expressions -----------------------------------------------------

    fn expr(&mut self, e: &Expr, env: &mut Env) -> R<Py> {
        self.step()?;
        Ok(match e {
            Expr::Const { v } => Py::from_const(v).map_err(Flow::Unsupported)?,
            Expr::Name { id } => self.lookup(id, env)?,
            Expr::SelfAttr { attr } => self.self_attr(attr)?,
            Expr::Call { func, args, kwargs } => self.call(func, args, kwargs, env)?,
            Expr::Sub { value, index } => {
                let (c, i) = (self.expr(value, env)?, self.expr(index, env)?);
                self.subscript(&c, &i)?
            }
            Expr::Slice {
                value,
                lower,
                upper,
                step,
            } => {
                let c = self.expr(value, env)?;
                let mut bound = |b: &Option<Box<Expr>>, this: &mut Self| -> R<Option<i64>> {
                    match b {
                        None => Ok(None),
                        Some(e) => match this.expr(e, env)? {
                            Py::None => Ok(None),
                            Py::Int(i) => Ok(Some(i)),
                            Py::Bool(b) => Ok(Some(b as i64)),
                            _ => exc("TypeError"),
                        },
                    }
                };
                let (lo, hi, st) = (bound(lower, self)?, bound(upper, self)?, bound(step, self)?);
                self.slice(&c, lo, hi, st)?
            }
            Expr::Cmp {
                left,
                ops,
                comparators,
            } => {
                let mut a = self.expr(left, env)?;
                for (op, c) in ops.iter().zip(comparators) {
                    let b = self.expr(c, env)?;
                    if !self.compare(*op, &a, &b)? {
                        return Ok(Py::Bool(false));
                    }
                    a = b;
                }
                Py::Bool(true)
            }
            Expr::And { values } => {
                let mut last = Py::Bool(true);
                for v in values {
                    last = self.expr(v, env)?;
                    if !self.truthy(&last)? {
                        return Ok(last);
                    }
                }
                last
            }
            Expr::Or { values } => {
                let mut last = Py::Bool(false);
                for v in values {
                    last = self.expr(v, env)?;
                    if self.truthy(&last)? {
                        return Ok(last);
                    }
                }
                last
            }
            Expr::Not { operand } => {
                let v = self.expr(operand, env)?;
                Py::Bool(!self.truthy(&v)?)
            }
            Expr::Neg { operand } | Expr::Pos { operand } => {
                let v = self.expr(operand, env)?;
                let neg = matches!(e, Expr::Neg { .. });
                match self.concrete(&v)? {
                    Py::Int(i) => Py::Int(if neg {
                        i.checked_neg().ok_or_else(overflow)?
                    } else {
                        i
                    }),
                    Py::Bool(b) => Py::Int(if neg { -(b as i64) } else { b as i64 }),
                    Py::Float(f) => Py::Float(if neg { -f } else { f }),
                    _ => return exc("TypeError"),
                }
            }
            Expr::Bin { op, left, right } => {
                let (a, b) = (self.expr(left, env)?, self.expr(right, env)?);
                self.binop(*op, &a, &b, false)?
            }
            Expr::Ifexp { test, body, orelse } => {
                let t = self.expr(test, env)?;
                if self.truthy(&t)? {
                    self.expr(body, env)?
                } else {
                    self.expr(orelse, env)?
                }
            }
            Expr::List { elts } => Py::list(self.exprs(elts, env)?),
            Expr::Tuple { elts } => Py::tuple(self.exprs(elts, env)?),
            Expr::Set { elts } => {
                let items = self.exprs(elts, env)?;
                Py::Set(Rc::new(RefCell::new(self.dedup(items)?)))
            }
            Expr::Dict { keys, values } => {
                let mut out: Vec<(Py, Py)> = Vec::new();
                for (k, v) in keys.iter().zip(values) {
                    let (k, v) = (self.expr(k, env)?, self.expr(v, env)?);
                    self.dict_insert(&mut out, k, v)?;
                }
                Py::Dict(Rc::new(RefCell::new(out)))
            }
            Expr::Listcomp { elt, generators } | Expr::Genexp { elt, generators } => {
                let mut out = Vec::new();
                self.comprehension(generators, env, &mut |this, env| {
                    out.push(this.expr(elt, env)?);
                    Ok(true)
                })?;
                Py::list(out)
            }
            Expr::Setcomp { elt, generators } => {
                let mut out = Vec::new();
                self.comprehension(generators, env, &mut |this, env| {
                    out.push(this.expr(elt, env)?);
                    Ok(true)
                })?;
                Py::Set(Rc::new(RefCell::new(self.dedup(out)?)))
            }
            Expr::Dictcomp {
                key,
                value,
                generators,
            } => {
                let mut out = Vec::new();
                self.comprehension(generators, env, &mut |this, env| {
                    let (k, v) = (this.expr(key, env)?, this.expr(value, env)?);
                    this.dict_insert(&mut out, k, v)?;
                    Ok(true)
                })?;
                Py::Dict(Rc::new(RefCell::new(out)))
            }
            Expr::Lambda { params, body } => {
                Py::Lambda(Rc::new((params.clone(), (**body).clone())))
            }
            Expr::Fstr { parts } => {
                let mut s = String::new();
                for p in parts {
                    let v = self.expr(p, env)?;
                    match self.concrete(&v)? {
                        Py::Str(x) => s.push_str(&x),
                        other => s.push_str(&self.to_str(&other)?),
                    }
                }
                Py::str(&s)
            }
            Expr::Exception { ty } => Py::Exception(Rc::from(ty.as_str())),
        })
    }

    fn exprs(&mut self, es: &[Expr], env: &mut Env) -> R<Vec<Py>> {
        es.iter().map(|e| self.expr(e, env)).collect()
    }

    fn dedup(&self, items: Vec<Py>) -> R<Vec<Py>> {
        let mut out: Vec<Py> = Vec::new();
        for item in items {
            if !self.contains_seq(&out, &item)? {
                out.push(item);
            }
        }
        Ok(out)
    }

    fn dict_insert(&self, out: &mut Vec<(Py, Py)>, k: Py, v: Py) -> R<()> {
        let k = self.concrete(&k)?;
        for entry in out.iter_mut() {
            if self.eq(&entry.0, &k)? {
                entry.1 = v;
                return Ok(());
            }
        }
        out.push((k, v));
        Ok(())
    }

    /// Run `body` for each binding of the generators; it returns `false`
    /// to stop early (`any` / `all`). Comprehension variables are restored
    /// afterwards, as their own scope would leave the enclosing one.
    fn comprehension(
        &mut self,
        gens: &[Generator],
        env: &mut Env,
        body: &mut dyn FnMut(&mut Self, &mut Env) -> R<bool>,
    ) -> R<bool> {
        let mut names = Vec::new();
        for g in gens {
            target_names(&g.target, &mut names);
        }
        let saved: Vec<(String, Option<Py>)> = names
            .iter()
            .map(|n| (n.clone(), env.get(n).cloned()))
            .collect();
        let result = self.generate(gens, env, body);
        for (n, v) in saved {
            match v {
                Some(v) => env.insert(n, v),
                None => env.remove(&n),
            };
        }
        result
    }

    fn generate(
        &mut self,
        gens: &[Generator],
        env: &mut Env,
        body: &mut dyn FnMut(&mut Self, &mut Env) -> R<bool>,
    ) -> R<bool> {
        let Some((g, rest)) = gens.split_first() else {
            return body(self, env);
        };
        let it = self.expr(&g.iter, env)?;
        'items: for item in self.iterate(&it)? {
            self.assign(&g.target, item, env)?;
            for cond in &g.ifs {
                let c = self.expr(cond, env)?;
                if !self.truthy(&c)? {
                    continue 'items;
                }
            }
            if !self.generate(rest, env, body)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn slice(&self, c: &Py, lo: Option<i64>, hi: Option<i64>, step: Option<i64>) -> R<Py> {
        let step = step.unwrap_or(1);
        if step == 0 {
            return exc("ValueError");
        }
        let pick = |len: usize| -> Vec<usize> {
            let len = len as i64;
            let clamp = |x: i64, low: i64, high: i64| x.max(low).min(high);
            let norm = |x: i64| if x < 0 { x + len } else { x };
            let mut out = Vec::new();
            if step > 0 {
                let mut i = clamp(lo.map_or(0, norm), 0, len);
                let end = clamp(hi.map_or(len, norm), 0, len);
                while i < end {
                    out.push(i as usize);
                    i += step;
                }
            } else {
                let mut i = clamp(lo.map_or(len - 1, norm), -1, len - 1);
                let end = clamp(hi.map_or(-1, norm), -1, len - 1);
                while i > end {
                    out.push(i as usize);
                    i += step;
                }
            }
            out
        };
        Ok(match self.concrete(c)? {
            Py::List(l) => {
                let items = l.borrow();
                Py::list(
                    pick(items.len())
                        .into_iter()
                        .map(|i| items[i].clone())
                        .collect(),
                )
            }
            Py::Tuple(t) => Py::tuple(pick(t.len()).into_iter().map(|i| t[i].clone()).collect()),
            Py::Str(s) => {
                let chars: Vec<char> = s.chars().collect();
                Py::str(
                    &pick(chars.len())
                        .into_iter()
                        .map(|i| chars[i])
                        .collect::<String>(),
                )
            }
            _ => return exc("TypeError"),
        })
    }

    fn binop(&self, op: BinOp, a: &Py, b: &Py, in_place: bool) -> R<Py> {
        let (a, b) = (self.concrete(a)?, self.concrete(b)?);
        match (&a, &b, op) {
            (Py::Str(x), Py::Str(y), BinOp::Add) => return Ok(Py::str(&format!("{x}{y}"))),
            (Py::List(x), Py::List(y), BinOp::Add) => {
                if in_place {
                    let extra = y.borrow().clone();
                    x.borrow_mut().extend(extra);
                    return Ok(a.clone());
                }
                let mut out = x.borrow().clone();
                out.extend(y.borrow().iter().cloned());
                return Ok(Py::list(out));
            }
            (Py::Tuple(x), Py::Tuple(y), BinOp::Add) => {
                return Ok(Py::tuple(x.iter().chain(y.iter()).cloned().collect()));
            }
            (Py::Str(s), Py::Int(n), BinOp::Mul) | (Py::Int(n), Py::Str(s), BinOp::Mul) => {
                return Ok(Py::str(&s.repeat((*n).max(0) as usize)));
            }
            (Py::Str(_), _, BinOp::Mod) => return unsupported("printf-style formatting"),
            _ => {}
        }
        let int = |v: &Py| match v {
            Py::Int(i) => Some(*i),
            Py::Bool(b) => Some(*b as i64),
            _ => None,
        };
        if let (Some(x), Some(y)) = (int(&a), int(&b)) {
            return Ok(match op {
                BinOp::Add => Py::Int(x.checked_add(y).ok_or_else(overflow)?),
                BinOp::Sub => Py::Int(x.checked_sub(y).ok_or_else(overflow)?),
                BinOp::Mul => Py::Int(x.checked_mul(y).ok_or_else(overflow)?),
                BinOp::Div => {
                    if y == 0 {
                        return exc("ZeroDivisionError");
                    }
                    Py::Float(x as f64 / y as f64)
                }
                BinOp::Floordiv => {
                    if y == 0 {
                        return exc("ZeroDivisionError");
                    }
                    Py::Int(
                        x.div_euclid(y)
                            - if (x.rem_euclid(y) != 0) && (y < 0) {
                                1
                            } else {
                                0
                            },
                    )
                }
                BinOp::Mod => {
                    if y == 0 {
                        return exc("ZeroDivisionError");
                    }
                    let r = x % y;
                    Py::Int(if r != 0 && (r < 0) != (y < 0) {
                        r + y
                    } else {
                        r
                    })
                }
                BinOp::Pow => {
                    if y < 0 {
                        Py::Float((x as f64).powf(y as f64))
                    } else {
                        Py::Int(
                            x.checked_pow(y.try_into().map_err(|_| overflow())?)
                                .ok_or_else(overflow)?,
                        )
                    }
                }
            });
        }
        match (number(&a), number(&b)) {
            (Some(x), Some(y)) => Ok(Py::Float(match op {
                BinOp::Add => x + y,
                BinOp::Sub => x - y,
                BinOp::Mul => x * y,
                BinOp::Div if y == 0.0 => return exc("ZeroDivisionError"),
                BinOp::Div => x / y,
                BinOp::Floordiv if y == 0.0 => return exc("ZeroDivisionError"),
                BinOp::Floordiv => (x / y).floor(),
                BinOp::Mod if y == 0.0 => return exc("ZeroDivisionError"),
                BinOp::Mod => x - y * (x / y).floor(),
                BinOp::Pow => x.powf(y),
            })),
            _ => exc("TypeError"),
        }
    }

    // -- calls -----------------------------------------------------------

    fn call(
        &mut self,
        func: &Func,
        args: &[Expr],
        kwargs: &[(String, Expr)],
        env: &mut Env,
    ) -> R<Py> {
        // `any` / `all` over a generator stop at the first decisive element,
        // as Python's lazy iteration does.
        if let Func::Builtin { builtin } = func
            && (builtin == "any" || builtin == "all")
            && let [Expr::Genexp { elt, generators }] = args
            && kwargs.is_empty()
        {
            let want = builtin == "any";
            let mut found = false;
            self.comprehension(generators, env, &mut |this, env| {
                let v = this.expr(elt, env)?;
                if this.truthy(&v)? == want {
                    found = true;
                    return Ok(false);
                }
                Ok(true)
            })?;
            return Ok(Py::Bool(if want { found } else { !found }));
        }
        let receiver = match func {
            Func::Method { obj, .. } => Some(self.expr(obj, env)?),
            _ => None,
        };
        let args = self.exprs(args, env)?;
        let mut kw = Vec::new();
        for (k, e) in kwargs {
            kw.push((k.clone(), self.expr(e, env)?));
        }
        match func {
            Func::Builtin { builtin } => self.builtin(builtin, args, kw),
            Func::Func { func } => self.call_function(func, args, kw),
            Func::Local { local } => {
                let f = self.lookup(local, env)?;
                self.call_value(&f, args)
            }
            Func::Method { method, .. } => {
                self.method(receiver.expect("receiver"), method, args, kw)
            }
        }
    }

    fn call_function(&mut self, key: &str, args: Vec<Py>, kwargs: Vec<(String, Py)>) -> R<Py> {
        let program = self.program;
        let Some(f) = program.functions.get(key) else {
            return unsupported(format!("undefined function {key}"));
        };
        let mut env = Env::new();
        if args.len() > f.params.len() {
            return exc("TypeError");
        }
        for (p, a) in f.params.iter().zip(args.iter()) {
            env.insert(p.clone(), a.clone());
        }
        for (k, v) in kwargs {
            if !f.params.contains(&k) || env.contains_key(&k) {
                return exc("TypeError");
            }
            env.insert(k, v);
        }
        for (i, p) in f.params.iter().enumerate() {
            if !env.contains_key(p) {
                match f.defaults.get(i).and_then(Option::as_ref) {
                    Some(d) => {
                        let v = self.expr(d, &mut Env::new())?;
                        env.insert(p.clone(), v);
                    }
                    None => return exc("TypeError"),
                }
            }
        }
        match self.block(&f.body, &mut env) {
            Ok(()) => Ok(Py::None),
            Err(Flow::Return(v)) => Ok(v),
            Err(Flow::Break | Flow::Continue) => unsupported("break outside a loop"),
            Err(f) => Err(f),
        }
    }

    /// Call a function value (a lambda, e.g. a sort key).
    fn call_value(&mut self, f: &Py, args: Vec<Py>) -> R<Py> {
        match f {
            Py::FuncRef(key) => self.call_function(key, args, Vec::new()),
            Py::Builtin(name) | Py::Type(name) => {
                let name = name.clone();
                self.builtin(&name, args, Vec::new())
            }
            Py::Lambda(l) => {
                let (params, body) = &**l;
                if params.len() != args.len() {
                    return exc("TypeError");
                }
                let mut env: Env = params.iter().cloned().zip(args).collect();
                self.expr(body, &mut env)
            }
            _ => exc("TypeError"),
        }
    }

    fn arg(args: &[Py], kwargs: &[(String, Py)], i: usize, name: &str) -> Option<Py> {
        args.get(i).cloned().or_else(|| {
            kwargs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    }

    fn builtin(&mut self, name: &str, args: Vec<Py>, kwargs: Vec<(String, Py)>) -> R<Py> {
        let a0 = args.first().cloned();
        Ok(match name {
            "len" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                Py::Int(match v {
                    Py::Str(s) => s.chars().count(),
                    Py::List(l) | Py::Set(l) => l.borrow().len(),
                    Py::Tuple(t) => t.len(),
                    Py::Dict(d) => d.borrow().len(),
                    Py::Range(a, b, s) => range_len(a, b, s),
                    _ => return exc("TypeError"),
                } as i64)
            }
            "isinstance" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                let types = match args.get(1).map(|t| self.concrete(t)).transpose()? {
                    Some(Py::Type(t)) => vec![t],
                    Some(Py::Tuple(ts)) => ts
                        .iter()
                        .map(|t| match self.concrete(t)? {
                            Py::Type(t) => Ok(t),
                            _ => exc("TypeError"),
                        })
                        .collect::<R<_>>()?,
                    _ => return exc("TypeError"),
                };
                let actual = v.type_name();
                Py::Bool(
                    types
                        .iter()
                        .any(|t| **t == *actual || (&**t == "int" && actual == "bool")),
                )
            }
            "any" | "all" => {
                let want = name == "any";
                let items = self.iterate(&a0.ok_or_else(type_error)?)?;
                let mut hit = false;
                for item in &items {
                    if self.truthy(item)? == want {
                        hit = true;
                        break;
                    }
                }
                Py::Bool(if want { hit } else { !hit })
            }
            "enumerate" => {
                let start = match Self::arg(&args, &kwargs, 1, "start") {
                    Some(v) => match self.concrete(&v)? {
                        Py::Int(i) => i,
                        _ => return exc("TypeError"),
                    },
                    None => 0,
                };
                let items = self.iterate(&a0.ok_or_else(type_error)?)?;
                Py::list(
                    items
                        .into_iter()
                        .enumerate()
                        .map(|(i, v)| Py::tuple(vec![Py::Int(start + i as i64), v]))
                        .collect(),
                )
            }
            "range" => {
                let ints: Vec<i64> = args
                    .iter()
                    .map(|a| match self.concrete(a)? {
                        Py::Int(i) => Ok(i),
                        Py::Bool(b) => Ok(b as i64),
                        _ => exc("TypeError"),
                    })
                    .collect::<R<_>>()?;
                match ints[..] {
                    [b] => Py::Range(0, b, 1),
                    [a, b] => Py::Range(a, b, 1),
                    [_, _, 0] => return exc("ValueError"),
                    [a, b, s] => Py::Range(a, b, s),
                    _ => return exc("TypeError"),
                }
            }
            "sorted" => {
                let items = self.iterate(&a0.ok_or_else(type_error)?)?;
                let out = Py::list(items);
                self.method(out.clone(), "sort", Vec::new(), kwargs)?;
                out
            }
            "reversed" => {
                let mut items = self.iterate(&a0.ok_or_else(type_error)?)?;
                items.reverse();
                Py::list(items)
            }
            "min" | "max" => {
                let items = if args.len() == 1 {
                    self.iterate(&args[0])?
                } else {
                    args.clone()
                };
                let key = kwargs
                    .iter()
                    .find(|(k, _)| k == "key")
                    .map(|(_, v)| v.clone());
                let mut best: Option<(Py, Py)> = None;
                for item in items {
                    let k = match &key {
                        Some(f) => self.call_value(f, vec![item.clone()])?,
                        None => item.clone(),
                    };
                    let better = match &best {
                        None => true,
                        Some((bk, _)) => {
                            let o = self.order(&k, bk)?;
                            if name == "min" { o.is_lt() } else { o.is_gt() }
                        }
                    };
                    if better {
                        best = Some((k, item));
                    }
                }
                match best {
                    Some((_, v)) => v,
                    None => match kwargs.iter().find(|(k, _)| k == "default") {
                        Some((_, d)) => d.clone(),
                        None => return exc("ValueError"),
                    },
                }
            }
            "sum" => {
                let mut total = Self::arg(&args, &kwargs, 1, "start").unwrap_or(Py::Int(0));
                for item in self.iterate(&a0.ok_or_else(type_error)?)? {
                    total = self.binop(BinOp::Add, &total, &item, false)?;
                }
                total
            }
            "zip" => {
                let lists: Vec<Vec<Py>> = args.iter().map(|a| self.iterate(a)).collect::<R<_>>()?;
                let n = lists.iter().map(Vec::len).min().unwrap_or(0);
                Py::list(
                    (0..n)
                        .map(|i| Py::tuple(lists.iter().map(|l| l[i].clone()).collect()))
                        .collect(),
                )
            }
            "list" | "tuple" | "set" => {
                let items = match a0 {
                    Some(v) => self.iterate(&v)?,
                    None => Vec::new(),
                };
                match name {
                    "list" => Py::list(items),
                    "tuple" => Py::tuple(items),
                    _ => Py::Set(Rc::new(RefCell::new(self.dedup(items)?))),
                }
            }
            "dict" => {
                let mut out = Vec::new();
                if let Some(v) = a0 {
                    match self.concrete(&v)? {
                        Py::Dict(d) => out = d.borrow().clone(),
                        other => {
                            for pair in self.iterate(&other)? {
                                let kv = self.iterate(&pair)?;
                                let [k, v] = &kv[..] else {
                                    return exc("ValueError");
                                };
                                self.dict_insert(&mut out, k.clone(), v.clone())?;
                            }
                        }
                    }
                }
                for (k, v) in kwargs {
                    self.dict_insert(&mut out, Py::str(&k), v)?;
                }
                Py::Dict(Rc::new(RefCell::new(out)))
            }
            "bool" => Py::Bool(match a0 {
                Some(v) => self.truthy(&v)?,
                None => false,
            }),
            "str" => match a0 {
                Some(v) => Py::str(&self.to_str(&self.concrete(&v)?)?),
                None => Py::str(""),
            },
            "int" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                match self.to_int(&v)? {
                    Some(i) => Py::Int(i),
                    None => return exc("ValueError"),
                }
            }
            "float" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                match self.to_float(&v)? {
                    Some(f) => Py::Float(f),
                    None => return exc("ValueError"),
                }
            }
            "abs" => match self.concrete(&a0.ok_or_else(type_error)?)? {
                Py::Int(i) => Py::Int(i.checked_abs().ok_or_else(overflow)?),
                Py::Bool(b) => Py::Int(b as i64),
                Py::Float(f) => Py::Float(f.abs()),
                _ => return exc("TypeError"),
            },
            "round" => match self.concrete(&a0.ok_or_else(type_error)?)? {
                Py::Int(i) if args.len() == 1 => Py::Int(i),
                Py::Float(f) if args.len() == 1 => {
                    // Banker's rounding, as Python's round().
                    let r = f.round();
                    let r = if (f - f.trunc()).abs() == 0.5 {
                        2.0 * (f / 2.0).round()
                    } else {
                        r
                    };
                    Py::Int(r as i64)
                }
                _ => return unsupported("round with ndigits"),
            },
            "force_list" => {
                let v = a0.ok_or_else(type_error)?;
                match self.concrete(&v)? {
                    Py::List(_) => v,
                    _ => Py::list(vec![v]),
                }
            }
            "force_int" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                match v {
                    Py::Int(_) | Py::Bool(_) => v,
                    other => match self.to_int(&other) {
                        Ok(Some(i)) => Py::Int(i),
                        Ok(None) | Err(Flow::Exc(_)) => Py::None,
                        Err(f) => return Err(f),
                    },
                }
            }
            "force_float" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                match v {
                    Py::Float(_) => v,
                    other => match self.to_float(&other) {
                        Ok(Some(f)) => Py::Float(f),
                        Ok(None) | Err(Flow::Exc(_)) => Py::None,
                        Err(f) => return Err(f),
                    },
                }
            }
            "re.compile" => match self.concrete(&a0.ok_or_else(type_error)?)? {
                Py::Str(p) | Py::Pattern(p) => {
                    if args.len() > 1 || !kwargs.is_empty() {
                        return unsupported("regex flags");
                    }
                    pyre::translate(&p).map_err(Flow::Unsupported)?;
                    Py::Pattern(p)
                }
                _ => return exc("TypeError"),
            },
            "re.match" | "re.search" | "re.fullmatch" | "re.findall" | "re.sub" | "re.split" => {
                if !kwargs.is_empty() || (name != "re.sub" && args.len() > 2) || args.len() > 3 {
                    return unsupported("regex flags or count");
                }
                let pattern = match self.concrete(&a0.ok_or_else(type_error)?)? {
                    Py::Str(p) | Py::Pattern(p) => p,
                    _ => return exc("TypeError"),
                };
                let subject_at = if name == "re.sub" { 2 } else { 1 };
                let subject = match args.get(subject_at).map(|s| self.concrete(s)).transpose()? {
                    Some(Py::Str(s)) => s,
                    _ => return exc("TypeError"),
                };
                self.regex(name, &pattern, &subject, args.get(1))?
            }
            "fnmatch.fnmatch" => {
                let (Some(n), Some(p)) = (a0, args.get(1)) else {
                    return exc("TypeError");
                };
                match (self.concrete(&n)?, self.concrete(p)?) {
                    (Py::Str(n), Py::Str(p)) => {
                        let re = regex::Regex::new(&fnmatch_regex(&p))
                            .map_err(|e| Flow::Unsupported(e.to_string()))?;
                        Py::Bool(re.is_match(&n))
                    }
                    _ => return exc("TypeError"),
                }
            }
            // Checkov's `is_terraform_variable_dependent`: a string that still
            // reads as a reference. An unresolved reference is abstract here.
            "is_terraform_variable_dependent" => {
                match self.concrete(&a0.ok_or_else(type_error)?)? {
                    Py::Str(s) => {
                        const PREFIXES: &[&str] = &[
                            "var.",
                            "local.",
                            "module.",
                            "data.",
                            "aws_",
                            "azurerm_",
                            "azuread_",
                            "digitalocean_",
                            "google_",
                            "github_",
                            "kubernetes_",
                            "linode_",
                            "oci_",
                            "openstack_",
                            "yandex_",
                            "lookup(",
                            "list(",
                            "file(",
                        ];
                        Py::Bool(PREFIXES.iter().any(|p| s.starts_with(p)) || s.contains("${"))
                    }
                    _ => Py::Bool(false),
                }
            }
            "type" => Py::Type(Rc::from(
                self.concrete(&a0.ok_or_else(type_error)?)?.type_name(),
            )),
            "map" | "filter" => {
                let f = a0.ok_or_else(type_error)?;
                let items = self.iterate(args.get(1).ok_or_else(type_error)?)?;
                let mut out = Vec::new();
                for item in items {
                    if name == "map" {
                        out.push(self.call_value(&f, vec![item])?);
                    } else {
                        let keep = match &f {
                            Py::None => self.truthy(&item)?,
                            f => {
                                let v = self.call_value(f, vec![item.clone()])?;
                                self.truthy(&v)?
                            }
                        };
                        if keep {
                            out.push(item);
                        }
                    }
                }
                Py::list(out)
            }
            "json.loads" => {
                if !kwargs.is_empty() {
                    return unsupported("json.loads with keywords");
                }
                match self.concrete(&a0.ok_or_else(type_error)?)? {
                    Py::Str(s) => match serde_json::from_str::<Json>(&s) {
                        Ok(j) => json_to_py(&j),
                        Err(_) => return exc("JSONDecodeError"),
                    },
                    _ => return exc("TypeError"),
                }
            }
            "json.dumps" => {
                if !kwargs.is_empty() {
                    return unsupported("json.dumps with keywords");
                }
                let v = a0.ok_or_else(type_error)?;
                Py::str(&self.json_dumps(&v)?)
            }
            "value_check" => {
                let check = self
                    .program
                    .value_check
                    .as_ref()
                    .and_then(|m| m.get(&*self.resource.ty))
                    .ok_or_else(|| Flow::Unsupported("no value check for this type".into()))?;
                let v = check.evaluate(self.resource);
                match v.truth {
                    Truth::True => Py::Result(Rc::from("FAILED")),
                    Truth::False => Py::Result(Rc::from("PASSED")),
                    t => match v.witness {
                        Some(w) => return Err(Flow::Abstract(Rc::new(w), t == Truth::Tainted)),
                        None => Py::Result(Rc::from("UNKNOWN")),
                    },
                }
            }
            other => return unsupported(format!("builtin {other}")),
        })
    }

    /// `json.dumps` with its default separators and `ensure_ascii`.
    fn json_dumps(&self, v: &Py) -> R<String> {
        Ok(match self.concrete(v)? {
            Py::None => "null".into(),
            Py::Bool(b) => if b { "true" } else { "false" }.into(),
            Py::Int(i) => i.to_string(),
            Py::Float(f) if f.is_finite() => py::float_repr(f),
            Py::Float(f) if f.is_nan() => "NaN".into(),
            Py::Float(f) => if f > 0.0 { "Infinity" } else { "-Infinity" }.into(),
            Py::Str(s) => {
                let mut out = String::from("\"");
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        '\x08' => out.push_str("\\b"),
                        '\x0c' => out.push_str("\\f"),
                        c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                            let mut buf = [0u16; 2];
                            for unit in c.encode_utf16(&mut buf) {
                                out.push_str(&format!("\\u{unit:04x}"));
                            }
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
                out
            }
            Py::List(l) => {
                let items = l.borrow().clone();
                format!(
                    "[{}]",
                    items
                        .iter()
                        .map(|x| self.json_dumps(x))
                        .collect::<R<Vec<_>>>()?
                        .join(", ")
                )
            }
            Py::Tuple(t) => format!(
                "[{}]",
                t.iter()
                    .map(|x| self.json_dumps(x))
                    .collect::<R<Vec<_>>>()?
                    .join(", ")
            ),
            Py::Dict(d) => {
                let items = d.borrow().clone();
                let mut parts = Vec::new();
                for (k, v) in &items {
                    let key = match self.concrete(k)? {
                        Py::Str(s) => self.json_dumps(&Py::Str(s))?,
                        Py::Int(i) => format!("\"{i}\""),
                        Py::Bool(b) => format!("\"{}\"", if b { "true" } else { "false" }),
                        Py::None => "\"null\"".into(),
                        _ => return exc("TypeError"),
                    };
                    parts.push(format!("{key}: {}", self.json_dumps(v)?));
                }
                format!("{{{}}}", parts.join(", "))
            }
            _ => return exc("TypeError"),
        })
    }

    fn regex(&self, name: &str, pattern: &str, subject: &str, repl: Option<&Py>) -> R<Py> {
        let compile = |p: &str, mode| pyre::compile(p, mode).map_err(Flow::Unsupported);
        let groups = |c: regex::Captures| -> Py {
            Py::Match(Rc::new(
                c.iter().map(|g| g.map(|m| Rc::from(m.as_str()))).collect(),
            ))
        };
        Ok(match name {
            "re.match" => compile(pattern, pyre::Mode::Match)?
                .captures(subject)
                .map_or(Py::None, groups),
            "re.search" => compile(pattern, pyre::Mode::Search)?
                .captures(subject)
                .map_or(Py::None, groups),
            "re.fullmatch" => compile(&format!("(?:{pattern})\\Z"), pyre::Mode::Match)?
                .captures(subject)
                .map_or(Py::None, groups),
            "re.findall" => {
                let re = compile(pattern, pyre::Mode::Search)?;
                let n = re.captures_len() - 1;
                Py::list(
                    re.captures_iter(subject)
                        .map(|c| match n {
                            0 => Py::str(c.get(0).map_or("", |m| m.as_str())),
                            1 => Py::str(c.get(1).map_or("", |m| m.as_str())),
                            _ => Py::tuple(
                                (1..=n)
                                    .map(|i| Py::str(c.get(i).map_or("", |m| m.as_str())))
                                    .collect(),
                            ),
                        })
                        .collect(),
                )
            }
            "re.sub" => {
                let repl = match repl.map(|r| self.concrete(r)).transpose()? {
                    Some(Py::Str(r)) if !r.contains('\\') => r,
                    _ => return unsupported("re.sub replacement"),
                };
                let re = compile(pattern, pyre::Mode::Search)?;
                Py::str(&re.replace_all(subject, regex::NoExpand(&repl)))
            }
            "re.split" => {
                let re = compile(pattern, pyre::Mode::Search)?;
                if re.captures_len() > 1 {
                    return unsupported("re.split with groups");
                }
                Py::list(re.split(subject).map(Py::str).collect())
            }
            _ => unreachable!("regex builtins"),
        })
    }

    fn method(&mut self, recv: Py, name: &str, args: Vec<Py>, kwargs: Vec<(String, Py)>) -> R<Py> {
        let recv = self.concrete(&recv)?;
        let a0 = args.first().cloned();
        Ok(match (&recv, name) {
            (Py::Dict(d), "get") => {
                let key = a0.ok_or_else(type_error)?;
                let items = d.borrow().clone();
                match self.dict_get(&items, &key)? {
                    Some(v) => v,
                    None => Self::arg(&args, &kwargs, 1, "default").unwrap_or(Py::None),
                }
            }
            (Py::Dict(d), "keys") => Py::list(d.borrow().iter().map(|(k, _)| k.clone()).collect()),
            (Py::Dict(d), "values") => {
                Py::list(d.borrow().iter().map(|(_, v)| v.clone()).collect())
            }
            (Py::Dict(d), "items") => Py::list(
                d.borrow()
                    .iter()
                    .map(|(k, v)| Py::tuple(vec![k.clone(), v.clone()]))
                    .collect(),
            ),
            (Py::Dict(d), "copy") => Py::Dict(Rc::new(RefCell::new(d.borrow().clone()))),
            (Py::Dict(d), "pop") => {
                let key = self.concrete(&a0.ok_or_else(type_error)?)?;
                let pos = {
                    let items = d.borrow();
                    let mut found = None;
                    for (i, (k, _)) in items.iter().enumerate() {
                        if self.eq(k, &key)? {
                            found = Some(i);
                            break;
                        }
                    }
                    found
                };
                match pos {
                    Some(i) => d.borrow_mut().remove(i).1,
                    None => match args.get(1) {
                        Some(default) => default.clone(),
                        None => return exc("KeyError"),
                    },
                }
            }
            (Py::Dict(d), "update") => {
                let other = match a0.map(|o| self.concrete(&o)).transpose()? {
                    Some(Py::Dict(o)) => o.borrow().clone(),
                    None => Vec::new(),
                    _ => return unsupported("dict.update from pairs"),
                };
                let mut items = d.borrow().clone();
                for (k, v) in other
                    .into_iter()
                    .chain(kwargs.into_iter().map(|(k, v)| (Py::str(&k), v)))
                {
                    self.dict_insert(&mut items, k, v)?;
                }
                *d.borrow_mut() = items;
                Py::None
            }
            (Py::Dict(d), "setdefault") => {
                let key = a0.ok_or_else(type_error)?;
                let items = d.borrow().clone();
                match self.dict_get(&items, &key)? {
                    Some(v) => v,
                    None => {
                        let v = args.get(1).cloned().unwrap_or(Py::None);
                        let mut items = items;
                        self.dict_insert(&mut items, key, v.clone())?;
                        *d.borrow_mut() = items;
                        v
                    }
                }
            }
            (Py::List(l), "append") => {
                l.borrow_mut().push(a0.ok_or_else(type_error)?);
                Py::None
            }
            (Py::List(l), "extend") => {
                let items = self.iterate(&a0.ok_or_else(type_error)?)?;
                l.borrow_mut().extend(items);
                Py::None
            }
            (Py::List(l), "insert") => {
                let len = l.borrow().len() as i64;
                let i = match self.concrete(&a0.ok_or_else(type_error)?)? {
                    Py::Int(i) => i,
                    _ => return exc("TypeError"),
                };
                let i = if i < 0 { (i + len).max(0) } else { i.min(len) };
                l.borrow_mut()
                    .insert(i as usize, args.get(1).cloned().ok_or_else(type_error)?);
                Py::None
            }
            (Py::List(_) | Py::Tuple(_), "index" | "count") => {
                let items = match &recv {
                    Py::List(l) => l.borrow().clone(),
                    Py::Tuple(t) => t.to_vec(),
                    _ => unreachable!("list or tuple"),
                };
                let needle = a0.ok_or_else(type_error)?;
                let mut hits = Vec::new();
                for (i, item) in items.iter().enumerate() {
                    if self.eq(item, &needle)? {
                        hits.push(i);
                        if name == "index" {
                            break;
                        }
                    }
                }
                if name == "count" {
                    Py::Int(hits.len() as i64)
                } else {
                    match hits.first() {
                        Some(&i) => Py::Int(i as i64),
                        None => return exc("ValueError"),
                    }
                }
            }
            (Py::List(l), "pop") => {
                let len = l.borrow().len();
                if len == 0 {
                    return exc("IndexError");
                }
                let i = match a0 {
                    Some(i) => self.index_of(&i, len)?,
                    None => len - 1,
                };
                l.borrow_mut().remove(i)
            }
            (Py::List(l), "remove") => {
                let needle = a0.ok_or_else(type_error)?;
                let items = l.borrow().clone();
                let mut pos = None;
                for (i, item) in items.iter().enumerate() {
                    if self.eq(item, &needle)? {
                        pos = Some(i);
                        break;
                    }
                }
                match pos {
                    Some(i) => {
                        l.borrow_mut().remove(i);
                        Py::None
                    }
                    None => return exc("ValueError"),
                }
            }
            (Py::List(l), "copy") => Py::list(l.borrow().clone()),
            (Py::List(l), "sort") => {
                let key = kwargs
                    .iter()
                    .find(|(k, _)| k == "key")
                    .map(|(_, v)| v.clone());
                let reverse = match kwargs.iter().find(|(k, _)| k == "reverse") {
                    Some((_, v)) => self.truthy(v)?,
                    None => false,
                };
                let items = l.borrow().clone();
                let mut keyed = Vec::new();
                for item in items {
                    let k = match &key {
                        Some(f) if !matches!(f, Py::None) => {
                            self.call_value(f, vec![item.clone()])?
                        }
                        _ => item.clone(),
                    };
                    keyed.push((k, item));
                }
                // A stable insertion sort that surfaces comparison errors.
                let mut sorted: Vec<(Py, Py)> = Vec::with_capacity(keyed.len());
                for (k, item) in keyed {
                    let mut at = sorted.len();
                    while at > 0 {
                        let o = self.order(&sorted[at - 1].0, &k)?;
                        let after = if reverse { o.is_lt() } else { o.is_gt() };
                        if !after {
                            break;
                        }
                        at -= 1;
                    }
                    sorted.insert(at, (k, item));
                }
                *l.borrow_mut() = sorted.into_iter().map(|(_, v)| v).collect();
                Py::None
            }
            (Py::Set(s), "add") => {
                let v = a0.ok_or_else(type_error)?;
                let items = s.borrow().clone();
                if !self.contains_seq(&items, &v)? {
                    s.borrow_mut().push(v);
                }
                Py::None
            }
            (Py::Set(s), "update") => {
                for v in self.iterate(&a0.ok_or_else(type_error)?)? {
                    let items = s.borrow().clone();
                    if !self.contains_seq(&items, &v)? {
                        s.borrow_mut().push(v);
                    }
                }
                Py::None
            }
            (Py::Set(s), "discard" | "remove") => {
                let v = a0.ok_or_else(type_error)?;
                let items = s.borrow().clone();
                let mut pos = None;
                for (i, item) in items.iter().enumerate() {
                    if self.eq(item, &v)? {
                        pos = Some(i);
                        break;
                    }
                }
                match pos {
                    Some(i) => {
                        s.borrow_mut().remove(i);
                    }
                    None if name == "remove" => return exc("KeyError"),
                    None => {}
                }
                Py::None
            }
            (Py::Set(s), "issubset" | "issuperset" | "intersection" | "difference" | "union") => {
                let other = self.iterate(&a0.ok_or_else(type_error)?)?;
                let mine = s.borrow().clone();
                match name {
                    "issubset" => Py::Bool(self.all_in(&mine, &other)?),
                    "issuperset" => Py::Bool(self.all_in(&other, &mine)?),
                    "union" => {
                        let mut all = mine;
                        all.extend(other);
                        Py::Set(Rc::new(RefCell::new(self.dedup(all)?)))
                    }
                    _ => {
                        let mut out = Vec::new();
                        for x in mine {
                            let inside = self.contains_seq(&other, &x)?;
                            if inside == (name == "intersection") {
                                out.push(x);
                            }
                        }
                        Py::Set(Rc::new(RefCell::new(out)))
                    }
                }
            }
            (Py::Str(s), _) => self.str_method(s, name, &args, &kwargs)?,
            (Py::Match(groups), "group") => {
                let i = match a0.map(|a| self.concrete(&a)).transpose()? {
                    None => 0,
                    Some(Py::Int(i)) => i,
                    _ => return unsupported("named groups"),
                };
                let i = usize::try_from(i).map_err(|_| Flow::Exc(Rc::from("IndexError")))?;
                match groups.get(i) {
                    Some(g) => g.as_deref().map_or(Py::None, Py::str),
                    None => return exc("IndexError"),
                }
            }
            (Py::Match(groups), "groups") => Py::tuple(
                groups[1..]
                    .iter()
                    .map(|g| g.as_deref().map_or(Py::None, Py::str))
                    .collect(),
            ),
            (Py::None | Py::Bool(_) | Py::Int(_) | Py::Float(_), _) => {
                return exc("AttributeError");
            }
            (other, m) => {
                return if matches!(other, Py::List(_) | Py::Dict(_) | Py::Tuple(_) | Py::Set(_)) {
                    // A method these types do not have is AttributeError in
                    // Python; one they have but we do not model is outside the
                    // subset.
                    if known_method(other.type_name(), m) {
                        unsupported(format!("{}.{m}", other.type_name()))
                    } else {
                        exc("AttributeError")
                    }
                } else {
                    unsupported(format!("{}.{m}", other.type_name()))
                };
            }
        })
    }

    fn str_method(
        &mut self,
        s: &Rc<str>,
        name: &str,
        args: &[Py],
        kwargs: &[(String, Py)],
    ) -> R<Py> {
        if !kwargs.is_empty() && !matches!(name, "split" | "rsplit") {
            return unsupported(format!("str.{name} with keywords"));
        }
        let str_arg = |this: &Self, i: usize| -> R<Option<Rc<str>>> {
            match args.get(i).map(|a| this.concrete(a)).transpose()? {
                None | Some(Py::None) => Ok(None),
                Some(Py::Str(x)) => Ok(Some(x)),
                _ => exc("TypeError"),
            }
        };
        Ok(match name {
            "lower" => Py::str(&s.to_lowercase()),
            "upper" => Py::str(&s.to_uppercase()),
            "casefold" => Py::str(&s.to_lowercase()),
            "title" => Py::str(&title(s)),
            "strip" | "lstrip" | "rstrip" => {
                let chars = str_arg(self, 0)?;
                let pred = |c: char| match &chars {
                    Some(set) => set.contains(c),
                    None => c.is_whitespace(),
                };
                Py::str(match name {
                    "strip" => s.trim_matches(pred),
                    "lstrip" => s.trim_start_matches(pred),
                    _ => s.trim_end_matches(pred),
                })
            }
            "startswith" | "endswith" => {
                let prefixes: Vec<Rc<str>> =
                    match args.first().map(|a| self.concrete(a)).transpose()? {
                        Some(Py::Str(p)) => vec![p],
                        Some(Py::Tuple(ps)) => ps
                            .iter()
                            .map(|p| match self.concrete(p)? {
                                Py::Str(p) => Ok(p),
                                _ => exc("TypeError"),
                            })
                            .collect::<R<_>>()?,
                        _ => return exc("TypeError"),
                    };
                if args.len() > 1 {
                    return unsupported("startswith/endswith with bounds");
                }
                Py::Bool(prefixes.iter().any(|p| {
                    if name == "startswith" {
                        s.starts_with(&**p)
                    } else {
                        s.ends_with(&**p)
                    }
                }))
            }
            "split" | "rsplit" => {
                let sep = match Self::arg(args, kwargs, 0, "sep") {
                    None | Some(Py::None) => None,
                    Some(v) => match self.concrete(&v)? {
                        Py::Str(x) if x.is_empty() => return exc("ValueError"),
                        Py::Str(x) => Some(x),
                        _ => return exc("TypeError"),
                    },
                };
                let max = match Self::arg(args, kwargs, 1, "maxsplit") {
                    None => -1,
                    Some(v) => match self.concrete(&v)? {
                        Py::Int(i) => i,
                        _ => return exc("TypeError"),
                    },
                };
                Py::list(
                    split(s, sep.as_deref(), max, name == "rsplit")
                        .into_iter()
                        .map(|x| Py::str(&x))
                        .collect(),
                )
            }
            "replace" => {
                let (Some(old), Some(new)) = (str_arg(self, 0)?, str_arg(self, 1)?) else {
                    return exc("TypeError");
                };
                if args.len() > 2 {
                    return unsupported("str.replace with count");
                }
                Py::str(&s.replace(&*old, &new))
            }
            "join" => {
                let items = self.iterate(args.first().ok_or_else(type_error)?)?;
                let mut parts = Vec::new();
                for item in items {
                    match self.concrete(&item)? {
                        Py::Str(x) => parts.push(x.to_string()),
                        _ => return exc("TypeError"),
                    }
                }
                Py::str(&parts.join(s))
            }
            "find" | "rfind" | "index" | "count" => {
                let Some(sub) = str_arg(self, 0)? else {
                    return exc("TypeError");
                };
                if args.len() > 1 {
                    return unsupported("str search with bounds");
                }
                let chars = |byte: usize| s[..byte].chars().count() as i64;
                match name {
                    "count" => Py::Int(if sub.is_empty() {
                        s.chars().count() as i64 + 1
                    } else {
                        s.matches(&*sub).count() as i64
                    }),
                    "rfind" => Py::Int(s.rfind(&*sub).map_or(-1, chars)),
                    _ => match s.find(&*sub) {
                        Some(b) => Py::Int(chars(b)),
                        None if name == "index" => return exc("ValueError"),
                        None => Py::Int(-1),
                    },
                }
            }
            "isdigit" | "isnumeric" | "isdecimal" => Py::Bool(
                !s.is_empty()
                    && s.chars().all(|c| {
                        if name == "isnumeric" {
                            c.is_numeric()
                        } else {
                            c.is_ascii_digit() || c.is_numeric() && c.is_ascii_digit()
                        }
                    }),
            ),
            "isalpha" => Py::Bool(!s.is_empty() && s.chars().all(char::is_alphabetic)),
            "isalnum" => Py::Bool(!s.is_empty() && s.chars().all(char::is_alphanumeric)),
            "islower" => {
                Py::Bool(s.chars().any(char::is_lowercase) && !s.chars().any(char::is_uppercase))
            }
            "isupper" => {
                Py::Bool(s.chars().any(char::is_uppercase) && !s.chars().any(char::is_lowercase))
            }
            "removeprefix" | "removesuffix" => {
                let Some(fix) = str_arg(self, 0)? else {
                    return exc("TypeError");
                };
                Py::str(if name == "removeprefix" {
                    s.strip_prefix(&*fix).unwrap_or(s)
                } else {
                    s.strip_suffix(&*fix).unwrap_or(s)
                })
            }
            "partition" => {
                let Some(sep) = str_arg(self, 0)? else {
                    return exc("TypeError");
                };
                match s.split_once(&*sep) {
                    Some((a, b)) => Py::tuple(vec![Py::str(a), Py::str(&sep), Py::str(b)]),
                    None => Py::tuple(vec![Py::str(s), Py::str(""), Py::str("")]),
                }
            }
            "zfill" => {
                let width = match args.first().map(|a| self.concrete(a)).transpose()? {
                    Some(Py::Int(w)) => w.max(0) as usize,
                    _ => return exc("TypeError"),
                };
                let n = s.chars().count();
                if n >= width {
                    Py::Str(s.clone())
                } else {
                    let (sign, rest) = match s.chars().next() {
                        Some(c @ ('+' | '-')) => (c.to_string(), &s[1..]),
                        _ => (String::new(), &s[..]),
                    };
                    Py::str(&format!("{sign}{}{rest}", "0".repeat(width - n)))
                }
            }
            "splitlines" => Py::list(s.lines().map(Py::str).collect()),
            "encode" | "decode" | "format" => return unsupported(format!("str.{name}")),
            _ => return exc("AttributeError"),
        })
    }

    /// Python's `str()`.
    fn to_str(&self, v: &Py) -> R<String> {
        Ok(match v {
            Py::Str(s) => s.to_string(),
            other => self.repr(other)?,
        })
    }

    fn repr(&self, v: &Py) -> R<String> {
        Ok(match self.concrete(v)? {
            Py::None => "None".into(),
            Py::Bool(b) => if b { "True" } else { "False" }.into(),
            Py::Int(i) => i.to_string(),
            Py::Float(f) => py::float_repr(f),
            Py::Str(s) => py::repr(&Json::String(s.to_string()))
                .ok_or_else(|| Flow::Unsupported("repr".into()))?,
            Py::List(l) => format!("[{}]", self.reprs(&l.borrow().clone())?),
            Py::Tuple(t) if t.len() == 1 => format!("({},)", self.repr(&t[0])?),
            Py::Tuple(t) => format!("({})", self.reprs(&t)?),
            Py::Dict(d) => {
                let items = d.borrow().clone();
                let parts: Vec<String> = items
                    .iter()
                    .map(|(k, v)| Ok(format!("{}: {}", self.repr(k)?, self.repr(v)?)))
                    .collect::<R<_>>()?;
                format!("{{{}}}", parts.join(", "))
            }
            Py::Result(r) => format!("CheckResult.{r}"),
            Py::Exception(name) => name.to_string(),
            other => return unsupported(format!("str of {}", other.type_name())),
        })
    }

    fn reprs(&self, items: &[Py]) -> R<String> {
        Ok(items
            .iter()
            .map(|x| self.repr(x))
            .collect::<R<Vec<_>>>()?
            .join(", "))
    }

    /// Python's `int(x)`; `None` where it raises ValueError.
    fn to_int(&self, v: &Py) -> R<Option<i64>> {
        Ok(match v {
            Py::Int(i) => Some(*i),
            Py::Bool(b) => Some(*b as i64),
            Py::Float(f) if f.is_finite() => Some(f.trunc() as i64),
            Py::Float(_) => return exc("OverflowError"),
            Py::Str(s) => py::int_str(s).and_then(|i| i64::try_from(i).ok()),
            _ => return exc("TypeError"),
        })
    }

    fn to_float(&self, v: &Py) -> R<Option<f64>> {
        Ok(match v {
            Py::Int(i) => Some(*i as f64),
            Py::Bool(b) => Some(*b as i64 as f64),
            Py::Float(f) => Some(*f),
            Py::Str(s) => parse_float(s),
            _ => return exc("TypeError"),
        })
    }
}

fn known_method(ty: &str, m: &str) -> bool {
    let methods: &[&str] = match ty {
        "list" => &[
            "append", "clear", "copy", "count", "extend", "index", "insert", "pop", "remove",
            "reverse", "sort",
        ],
        "dict" => &[
            "clear",
            "copy",
            "fromkeys",
            "get",
            "items",
            "keys",
            "pop",
            "popitem",
            "setdefault",
            "update",
            "values",
        ],
        "tuple" => &["count", "index"],
        "set" => &[
            "add",
            "clear",
            "copy",
            "difference",
            "discard",
            "intersection",
            "isdisjoint",
            "issubset",
            "issuperset",
            "pop",
            "remove",
            "symmetric_difference",
            "union",
            "update",
        ],
        _ => &[],
    };
    methods.contains(&m)
}

fn type_error() -> Flow {
    Flow::Exc(Rc::from("TypeError"))
}

fn overflow() -> Flow {
    Flow::Unsupported("integer overflow".into())
}

fn number(v: &Py) -> Option<f64> {
    match v {
        Py::Bool(b) => Some(*b as i64 as f64),
        Py::Int(i) => Some(*i as f64),
        Py::Float(f) => Some(*f),
        _ => None,
    }
}

fn range_items(a: i64, b: i64, s: i64) -> Vec<i64> {
    let mut out = Vec::new();
    let mut i = a;
    while (s > 0 && i < b) || (s < 0 && i > b) {
        out.push(i);
        if out.len() > 1_000_000 {
            break;
        }
        i += s;
    }
    out
}

fn range_len(a: i64, b: i64, s: i64) -> usize {
    if s > 0 && b > a {
        ((b - a + s - 1) / s) as usize
    } else if s < 0 && a > b {
        ((a - b - s - 1) / -s) as usize
    } else {
        0
    }
}

fn target_names(t: &Target, out: &mut Vec<String>) {
    match t {
        Target::Name { id } => out.push(id.clone()),
        Target::Tuple { elts } => elts.iter().for_each(|e| target_names(e, out)),
        _ => {}
    }
}

fn title(s: &str) -> String {
    let mut out = String::new();
    let mut prev_cased = false;
    for c in s.chars() {
        if c.is_alphabetic() {
            if prev_cased {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            prev_cased = true;
        } else {
            out.push(c);
            prev_cased = false;
        }
    }
    out
}

/// Python's `str.split` / `rsplit`.
fn split(s: &str, sep: Option<&str>, max: i64, from_right: bool) -> Vec<String> {
    let max = if max < 0 { usize::MAX } else { max as usize };
    match sep {
        Some(sep) => {
            let parts: Vec<&str> = if from_right {
                let mut v: Vec<&str> = s.rsplitn(max.saturating_add(1), sep).collect();
                v.reverse();
                v
            } else {
                s.splitn(max.saturating_add(1), sep).collect()
            };
            parts.into_iter().map(str::to_string).collect()
        }
        None => {
            // Runs of whitespace; leading and trailing whitespace ignored.
            let words: Vec<&str> = s.split_whitespace().collect();
            if words.len() <= max.saturating_add(1) || max == usize::MAX {
                return words.into_iter().map(str::to_string).collect();
            }
            if from_right {
                let keep = &words[words.len() - max..];
                let head_end = {
                    // The remainder keeps its inner whitespace.
                    let mut idx = s.trim_end().len();
                    for w in keep.iter().rev() {
                        idx = s[..idx].rfind(w).unwrap_or(0);
                        idx = s[..idx].trim_end().len();
                    }
                    idx
                };
                let mut out = vec![s[..head_end].trim_start().to_string()];
                out.extend(keep.iter().map(|w| w.to_string()));
                out
            } else {
                let mut out: Vec<String> = Vec::new();
                let mut rest = s.trim_start();
                for _ in 0..max {
                    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                    out.push(rest[..end].to_string());
                    rest = rest[end..].trim_start();
                }
                out.push(rest.to_string());
                out
            }
        }
    }
}

fn parse_float(s: &str) -> Option<f64> {
    let t = s.trim().replace('_', "");
    match t.to_ascii_lowercase().trim_start_matches(['+', '-']) {
        "inf" | "infinity" => Some(if t.starts_with('-') {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        }),
        "nan" => Some(f64::NAN),
        _ => {
            let ok = !t.is_empty() && t.chars().all(|c| c.is_ascii_digit() || "+-.eE".contains(c));
            if ok { t.parse().ok() } else { None }
        }
    }
}

/// `fnmatch.translate` for the subset the checks use: `*`, `?`, `[...]`.
fn fnmatch_regex(p: &str) -> String {
    let mut out = String::from("(?s)\\A");
    let chars: Vec<char> = p.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '[' => match chars[i + 1..].iter().position(|&c| c == ']') {
                Some(end) if end > 0 => {
                    let inner: String = chars[i + 1..i + 1 + end].iter().collect();
                    let inner = inner
                        .strip_prefix('!')
                        .map_or(inner.clone(), |r| format!("^{r}"));
                    out.push('[');
                    out.push_str(&inner.replace('\\', "\\\\"));
                    out.push(']');
                    i += end + 1;
                }
                _ => out.push_str("\\["),
            },
            c => out.push_str(&regex::escape(c.encode_utf8(&mut [0; 4]))),
        }
        i += 1;
    }
    out.push_str("\\z");
    out
}

/// A parsed JSON document as Python's `json.loads` returns it.
fn json_to_py(j: &Json) -> Py {
    match j {
        Json::Null => Py::None,
        Json::Bool(b) => Py::Bool(*b),
        Json::Number(n) => match n.as_i64() {
            Some(i) if !n.is_f64() => Py::Int(i),
            _ => Py::Float(n.as_f64().unwrap_or(f64::NAN)),
        },
        Json::String(s) => Py::str(s),
        Json::Array(a) => Py::list(a.iter().map(json_to_py).collect()),
        Json::Object(m) => Py::Dict(Rc::new(RefCell::new(
            m.iter().map(|(k, v)| (Py::str(k), json_to_py(v))).collect(),
        ))),
    }
}

// -- conversion from the configuration -----------------------------------

struct Converter {
    next_id: usize,
}

impl Converter {
    /// The configured value as Python sees it. Numbers that are integral
    /// are `int`, as Checkov's HCL parser reads them.
    fn py(&mut self, v: &Value) -> Py {
        match &v.kind {
            Kind::Known(k) => match k {
                Known::Null => Py::None,
                Known::Bool(b) => Py::Bool(*b),
                Known::Number(n) => {
                    if n.fract() == 0.0 && n.abs() < 9.0e15 {
                        Py::Int(*n as i64)
                    } else {
                        Py::Float(*n)
                    }
                }
                Known::String(s) => Py::str(s),
                Known::List(items) => Py::list(items.iter().map(|x| self.py(x)).collect()),
                Known::Object(m) => Py::Dict(Rc::new(RefCell::new(
                    m.iter().map(|(k, x)| (Py::str(k), self.py(x))).collect(),
                ))),
                Known::Json(inner) => self.py(inner),
            },
            Kind::Unknown(_) => Py::Abstract(Rc::new(v.clone()), false),
            Kind::Tainted(_) => Py::Abstract(Rc::new(v.clone()), true),
            Kind::OneOf(o) => {
                let id = self.next_id;
                self.next_id += 1;
                let alts = o.alternatives.iter().map(|a| self.py(a)).collect();
                Py::OneOf(id, Rc::new(alts))
            }
        }
    }
}

// -- running a check -----------------------------------------------------

/// Run `program` on `resource`.
pub fn evaluate(program: &Program, resource: &Resource) -> Verdict {
    let conf = crate::checkov::resource_configuration(resource);
    let mut runs = 0;
    run(program, resource, conf, &mut HashMap::new(), &mut runs)
}

fn run(
    program: &Program,
    resource: &Resource,
    conf: &Value,
    choices: &mut HashMap<usize, usize>,
    runs: &mut usize,
) -> Verdict {
    *runs += 1;
    if *runs > RUN_BUDGET {
        return Verdict::new(Truth::Unknown, None);
    }
    // Ids are assigned in a fixed traversal order, so every run sees the
    // same OneOf under the same id.
    let py_conf = Converter { next_id: 0 }.py(conf);
    // Checkov's runner adds the resource's address (and its lines, which
    // no exported check reads).
    if let Py::Dict(d) = &py_conf {
        d.borrow_mut()
            .push((Py::str("__address__"), Py::str(&resource.address)));
    }
    let mut self_attrs: HashMap<String, Py> = program
        .self_attrs
        .iter()
        .filter_map(|(k, v)| Py::from_const(v).ok().map(|p| (k.clone(), p)))
        .collect();
    self_attrs.insert("entity_type".into(), Py::str(&resource.ty));
    let mut interp = Interp {
        program,
        resource,
        self_attrs,
        choices: choices.clone(),
        steps: 0,
    };
    let outcome = interp.call_function(&program.entry, vec![py_conf], Vec::new());
    if std::env::var("OXTF_DEBUG_PYTHON").as_deref() == Ok("2") {
        let what = match &outcome {
            Ok(Py::Result(r)) => r.to_string(),
            Ok(other) => format!("returned {}", other.type_name()),
            Err(Flow::Abstract(w, t)) => format!("abstract (tainted={t}) {:?}", w.kind),
            Err(Flow::Fork(id, n)) => format!("fork {id}/{n}"),
            Err(Flow::Exc(e)) => format!("raised {e}"),
            Err(Flow::Unsupported(u)) => format!("unsupported {u}"),
            Err(_) => "control flow escaped".into(),
        };
        eprintln!(
            "checkov_python {}: {}: {what}",
            program.entry, resource.address
        );
    }
    match outcome {
        Ok(Py::Result(r)) if &*r == "FAILED" => {
            Verdict::new(Truth::True, Some(witness(&mut interp, program, conf)))
        }
        Ok(_) => Verdict::FALSE,
        Err(Flow::Abstract(w, tainted)) => Verdict::new(
            if tainted {
                Truth::Tainted
            } else {
                Truth::Unknown
            },
            Some((*w).clone()),
        ),
        Err(Flow::Fork(id, n)) => {
            let tainted = oneof_tainted(conf, id);
            let verdicts = (0..n)
                .map(|i| {
                    choices.insert(id, i);
                    let v = run(program, resource, conf, choices, runs);
                    choices.remove(&id);
                    v
                })
                .collect();
            truth::combine_one_of(verdicts, tainted)
        }
        Err(Flow::Unsupported(why)) => {
            if std::env::var_os("OXTF_DEBUG_PYTHON").is_some() {
                eprintln!(
                    "checkov_python {}: {}: {why}",
                    program.entry, resource.address
                );
            }
            Verdict::new(Truth::Unknown, None)
        }
        Err(Flow::Exc(name)) => {
            if std::env::var_os("OXTF_DEBUG_PYTHON").is_some() {
                eprintln!(
                    "checkov_python {}: {}: raised {name}",
                    program.entry, resource.address
                );
            }
            Verdict::new(Truth::Unknown, None)
        }
        Err(_) => Verdict::new(Truth::Unknown, None),
    }
}

/// Whether the `OneOf` with traversal id `id` is tainted.
fn oneof_tainted(conf: &Value, id: usize) -> bool {
    fn walk(v: &Value, next: &mut usize, id: usize) -> Option<bool> {
        match &v.kind {
            Kind::Known(Known::List(items)) => items.iter().find_map(|x| walk(x, next, id)),
            Kind::Known(Known::Object(m)) => m.values().find_map(|x| walk(x, next, id)),
            Kind::Known(Known::Json(inner)) => walk(inner, next, id),
            Kind::OneOf(o) => {
                let mine = *next;
                *next += 1;
                if mine == id {
                    return Some(o.tainted);
                }
                o.alternatives.iter().find_map(|a| walk(a, next, id))
            }
            _ => None,
        }
    }
    walk(conf, &mut 0, id).unwrap_or(false)
}

/// The configured value a failing check reported in `evaluated_keys`
/// (paths like `a/[0]/b`), or the whole configuration.
fn witness(interp: &mut Interp, program: &Program, conf: &Value) -> Value {
    let mut keys = interp.self_attrs.get("evaluated_keys").cloned();
    let empty = |k: &Option<Py>| match k {
        Some(Py::List(l)) => l.borrow().is_empty(),
        Some(Py::Str(s)) => s.is_empty(),
        _ => true,
    };
    if empty(&keys)
        && let Some(f) = &program.evaluated_keys
        && let Ok(v) = interp.call_function(f, Vec::new(), Vec::new())
    {
        keys = Some(v);
    }
    let first = match keys {
        Some(Py::List(l)) => l.borrow().first().and_then(|k| match k {
            Py::Str(s) => Some(s.clone()),
            _ => None,
        }),
        Some(Py::Str(s)) => Some(s),
        _ => None,
    };
    let Some(path) = first.filter(|p| !p.is_empty()) else {
        return conf.clone();
    };
    let mut cur = conf.clone();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        let next = if let Some(i) = seg.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            match (&cur.kind, i.parse::<usize>()) {
                (Kind::Known(Known::List(items)), Ok(i)) => items.get(i).cloned(),
                _ => None,
            }
        } else {
            match &cur.kind {
                Kind::Known(Known::Object(m)) => m.get(seg).cloned(),
                // Attributes are wrapped in a one-element list.
                Kind::Known(Known::List(items)) if items.len() == 1 => match &items[0].kind {
                    Kind::Known(Known::Object(m)) => m.get(seg).cloned(),
                    _ => None,
                },
                _ => None,
            }
        };
        match next {
            Some(v) => cur = v,
            None => break,
        }
    }
    cur
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<Program>();
    check::<Arc<Program>>();
}

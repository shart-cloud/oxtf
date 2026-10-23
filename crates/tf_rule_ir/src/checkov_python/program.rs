use super::*;

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
    /// Classes of inlined modules the program instantiates (cloudsplaining's
    /// policy documents, policy_sentry's ARN), by qualified name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub classes: BTreeMap<String, Class>,
}

/// A class: its methods and properties (program functions taking the
/// instance first), through its MRO, and its constant class attributes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Class {
    pub methods: BTreeMap<String, String>,
    pub properties: BTreeMap<String, String>,
    pub attrs: BTreeMap<String, Json>,
    /// Properties that are `cached_property`s: computed once per object.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cached: Vec<String>,
    /// Methods that are `staticmethod`s (called without the instance).
    #[serde(default, rename = "static", skip_serializing_if = "Vec::is_empty")]
    pub statics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    pub params: Vec<String>,
    pub defaults: Vec<Option<Expr>>,
    pub body: Vec<Stmt>,
    /// The `*args` parameter, bound to a tuple of the extra positionals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vararg: Option<String>,
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
    /// An attribute of an object of an inlined class.
    Attr {
        value: Expr,
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
    Bitor,
    Bitand,
    Bitxor,
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
    Builtin {
        builtin: String,
    },
    Func {
        func: String,
    },
    Local {
        local: String,
    },
    Method {
        method: String,
        obj: Box<Expr>,
    },
    /// Instantiate a class of `Program::classes`.
    Class {
        class: String,
    },
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
    /// An attribute of an object of an inlined class.
    Attr {
        value: Box<Expr>,
        attr: String,
    },
    /// A mutable module or class attribute: built from `v` on first use
    /// in a run, then the same object (a cache dict the code fills).
    Static {
        key: String,
        v: Json,
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
        for (name, class) in &self.classes {
            for key in class.methods.values().chain(class.properties.values()) {
                if !self.functions.contains_key(key) {
                    return Err(format!("checkov_python: class {name}: no function {key:?}"));
                }
            }
            for v in class.attrs.values() {
                Py::from_const(v)?;
            }
        }
        Ok(())
    }
}

/// Every program function `stmts` call or reference (`{"func": key}`,
/// a `{"funcref": key}` constant).
pub(super) fn calls(stmts: &[Stmt], f: &mut dyn FnMut(&str)) {
    walk(stmts, &mut |n| match n {
        Node::Expr(Expr::Const { v }) => {
            if let Some(Json::String(key)) = v.get("funcref") {
                f(key);
            }
        }
        Node::Expr(Expr::Call {
            func: Func::Func { func },
            ..
        }) => f(func),
        _ => {}
    });
}

/// Methods that change their receiver in place.
pub(super) const MUTATING_METHODS: &[&str] = &[
    "append",
    "extend",
    "insert",
    "pop",
    "remove",
    "clear",
    "reverse",
    "sort",
    "update",
    "setdefault",
    "popitem",
    "add",
    "discard",
];

/// Whether `stmts` could change a container reachable from the check's
/// input in place: a subscript assignment, an augmented assignment (which
/// extends a list or set in place), or a mutating method, named as a call
/// or taken as a value. Conservative: any such construct counts, whatever
/// its receiver.
pub(super) fn mutates(stmts: &[Stmt]) -> bool {
    let mut found = false;
    walk(stmts, &mut |n| {
        found |= match n {
            Node::Stmt(Stmt::Aug { .. }) => true,
            Node::Stmt(Stmt::Assign { targets, .. }) => {
                targets.iter().any(|t| matches!(t, Target::Sub { .. }))
            }
            Node::Expr(Expr::Call {
                func: Func::Method { method, .. },
                ..
            }) => MUTATING_METHODS.contains(&method.as_str()),
            Node::Expr(Expr::Attr { attr, .. }) => MUTATING_METHODS.contains(&attr.as_str()),
            _ => false,
        };
    });
    found
}

/// A node of a program, as [`walk`] visits them.
pub(super) enum Node<'a> {
    Stmt(&'a Stmt),
    Expr(&'a Expr),
}

/// Visit every statement and expression of `stmts`, outer first.
#[expect(clippy::too_many_lines)]
pub(super) fn walk(stmts: &[Stmt], f: &mut dyn FnMut(Node<'_>)) {
    fn target(t: &Target, f: &mut dyn FnMut(Node<'_>)) {
        match t {
            Target::Tuple { elts } => elts.iter().for_each(|t| target(t, f)),
            Target::Sub { value, index } => {
                expr(value, f);
                expr(index, f);
            }
            Target::Attr { value, .. } => expr(value, f),
            Target::Name { .. } | Target::SelfAttr { .. } => {}
        }
    }
    fn exprs(es: &[Expr], f: &mut dyn FnMut(Node<'_>)) {
        es.iter().for_each(|e| expr(e, f));
    }
    fn generators(gs: &[Generator], f: &mut dyn FnMut(Node<'_>)) {
        for g in gs {
            target(&g.target, f);
            expr(&g.iter, f);
            exprs(&g.ifs, f);
        }
    }
    fn expr(e: &Expr, f: &mut dyn FnMut(Node<'_>)) {
        f(Node::Expr(e));
        match e {
            Expr::Const { .. } => {}
            Expr::Call { func, args, kwargs } => {
                if let Func::Method { obj, .. } = func {
                    expr(obj, f);
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
            Expr::Attr { value, .. } => expr(value, f),
            Expr::Static { .. } => {}
            Expr::Fstr { parts } => exprs(parts, f),
            Expr::Name { .. } | Expr::SelfAttr { .. } | Expr::Exception { .. } => {}
        }
    }
    for s in stmts {
        f(Node::Stmt(s));
        match s {
            Stmt::Expr { value } => expr(value, f),
            Stmt::Return { value } => {
                if let Some(v) = value {
                    expr(v, f);
                }
            }
            Stmt::If { test, body, orelse } => {
                expr(test, f);
                walk(body, f);
                walk(orelse, f);
            }
            Stmt::For {
                target: t,
                iter,
                body,
                orelse,
            } => {
                target(t, f);
                expr(iter, f);
                walk(body, f);
                walk(orelse, f);
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
                walk(body, f);
                for h in handlers {
                    walk(&h.body, f);
                }
                walk(orelse, f);
                walk(finalbody, f);
            }
            Stmt::Pass | Stmt::Break | Stmt::Continue | Stmt::Raise { .. } => {}
        }
    }
}

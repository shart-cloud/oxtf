//! Expression evaluator over the abstract lattice.
//!
//! The evaluator knows HCL; it does not know Terraform modules. Every
//! reference whose root is not bound lexically (by a `for` expression, a
//! `dynamic` iterator, `each`, `count`, ...) is handed to a [`Resolver`],
//! which the semantic layer implements (`var.*`, `local.*`, resources,
//! `module.*`, `data.*`, `path.*`, `terraform.*`).

use std::sync::Arc;

use tf_ast::{BinaryOperator, Expression, ForExpr, ObjectKey, TraversalOperator, UnaryOperator};
use tf_span::{FileId, FileSpan, GetSpan, Span};

use crate::budget::{BudgetRef, EvaluationBudget};
use crate::collections::{self, Buffer};
use crate::depth::DepthGuard;
pub use crate::depth::EVALUATION_DEPTH_MAX;
use crate::functions;
use crate::prov::Prov;
use crate::text;
use crate::value::{Kind, Known, Map, Value};

mod catches;
mod containers;
mod for_expr;
mod templates;
use containers::failure;

/// Lexical bindings: a linked list of frames on the Rust stack.
#[derive(Clone, Copy, Default)]
pub struct Scope<'s> {
    frame: Option<&'s Frame<'s>>,
}

pub struct Frame<'s> {
    name: &'s str,
    value: &'s Value,
    parent: Option<&'s Frame<'s>>,
}

impl<'s> Scope<'s> {
    pub const EMPTY: Scope<'static> = Scope { frame: None };

    pub fn lookup(&self, name: &str) -> Option<&'s Value> {
        let mut f = self.frame;
        while let Some(fr) = f {
            if fr.name == name {
                return Some(fr.value);
            }
            f = fr.parent;
        }
        None
    }

    /// Run `k` with `name = value` bound on top of this scope.
    /// The binding borrows `value`: a frame is a name and a pointer, so
    /// binding costs no clone of the value.
    pub fn with<R>(&self, name: &str, value: &Value, k: impl FnOnce(Scope<'_>) -> R) -> R {
        let frame = Frame {
            name,
            value,
            parent: self.frame,
        };
        k(Scope {
            frame: Some(&frame),
        })
    }

    /// Bind several names at once.
    pub fn with_all<R>(&self, binds: &[(&str, Value)], k: impl FnOnce(Scope<'_>) -> R) -> R {
        match binds.split_first() {
            None => k(*self),
            Some(((n, v), rest)) => self.with(n, v, |s| s.with_all(rest, k)),
        }
    }
}

/// Resolves references rooted outside the lexical scope.
pub trait Resolver<'a> {
    /// Contextual functions (for example file reads) belong to the resolver.
    fn call(&self, name: &str, args: Vec<Value>, budget: &EvaluationBudget) -> Value {
        functions::call_budgeted(name, args, budget.storage())
    }

    /// `root` is the first name of the reference (`var`, `local`,
    /// `aws_s3_bucket`, ...), `ops` the operators that follow it. Returns the
    /// value and how many leading `ops` it consumed; the evaluator applies
    /// the rest.
    fn resolve(
        &self,
        ev: &Evaluator<'_, 'a>,
        scope: Scope<'_>,
        root: &'a str,
        span: Span,
        ops: &'a [TraversalOperator<'a>],
    ) -> (Value, usize);
}

/// A resolver that knows nothing (for `.tfvars` files and tests).
pub struct NoResolver;

impl<'a> Resolver<'a> for NoResolver {
    fn resolve(
        &self,
        _: &Evaluator<'_, 'a>,
        _: Scope<'_>,
        root: &'a str,
        _: Span,
        _: &'a [TraversalOperator<'a>],
    ) -> (Value, usize) {
        (
            Value::error(format!("reference to \"{root}\" not allowed here")),
            0,
        )
    }
}

/// Cap on the cartesian product when lifting operations over `OneOf`s.
pub use tf_limits::ALTERNATIVES_MAX as MAX_ALTERNATIVES;

pub struct Evaluator<'r, 'a> {
    pub resolver: &'r dyn Resolver<'a>,
    /// File the expressions being evaluated live in.
    pub file: FileId,
    budget: BudgetRef<'r>,
}

impl<'r, 'a> Evaluator<'r, 'a> {
    pub fn new(resolver: &'r dyn Resolver<'a>, file: FileId) -> Self {
        Self {
            resolver,
            file,
            budget: BudgetRef::Owned(EvaluationBudget::new(tf_limits::Limits::default())),
        }
    }

    /// Re-enter evaluation without resetting the root's cumulative allowance.
    pub fn with_budget(
        resolver: &'r dyn Resolver<'a>,
        file: FileId,
        budget: &'r EvaluationBudget,
    ) -> Self {
        Self {
            resolver,
            file,
            budget: BudgetRef::Shared(budget),
        }
    }

    pub fn budget(&self) -> &EvaluationBudget {
        &self.budget
    }

    fn enter(&self, span: Span, steps: u64) -> Result<DepthGuard, Value> {
        let at = FileSpan::new(self.file, span);
        self.budget.charge(at, steps)?;
        DepthGuard::enter().map_err(|limit| self.budget.finish(limit, at))
    }

    fn finish(&self, guard: &DepthGuard, value: Value, span: Span) -> Value {
        self.budget
            .finish(guard.finish(value), FileSpan::new(self.file, span))
    }

    /// Evaluate an expression that has no references (type-constraint
    /// defaults); works for any AST lifetime.
    pub fn eval_static(&self, e: &Expression<'_>) -> Value {
        let guard = match self.enter(e.span(), 1) {
            Ok(guard) => guard,
            Err(limit) => return limit,
        };
        self.finish(&guard, self.eval_static_inner(e), e.span())
    }

    fn eval_static_inner(&self, e: &Expression<'_>) -> Value {
        match e.without_parens() {
            Expression::Null(_) => Value::null(),
            Expression::Bool(b) => Value::bool(b.value),
            Expression::Number(n) => Value::number(n.value),
            Expression::String(s) => text::copy(s.value.as_str(), self.budget.storage())
                .map(Value::string)
                .unwrap_or_else(|v| v),
            Expression::Tuple(t) => self
                .values(t.elements.iter().map(|x| self.eval_static(x)))
                .map(|values| Value::list(values.finish()))
                .unwrap_or_else(|v| v),
            Expression::Object(o) => self.static_object(o),
            Expression::Unary(u) if u.operator == UnaryOperator::Negate => {
                match self.eval_static(&u.operand).as_number() {
                    Some(n) => Value::number(-n),
                    None => Value::other("non-literal default"),
                }
            }
            _ => Value::other("non-literal default"),
        }
    }

    pub fn eval(&self, e: &'a Expression<'a>, sc: Scope<'_>) -> Value {
        let guard = match self.enter(e.span(), 1) {
            Ok(guard) => guard,
            Err(limit) => return limit,
        };
        self.finish(&guard, self.eval_inner(e, sc), e.span())
    }

    fn eval_inner(&self, e: &'a Expression<'a>, sc: Scope<'_>) -> Value {
        match e {
            Expression::Null(_) => Value::null(),
            Expression::Bool(b) => Value::bool(b.value),
            Expression::Number(n) => Value::number(n.value),
            Expression::String(s) => text::copy(s.value.as_str(), self.budget.storage())
                .map(Value::string)
                .unwrap_or_else(|v| v),
            Expression::Template(t) => self.eval_template(&t.template, sc),
            Expression::Heredoc(h) => self.eval_template(&h.template, sc),
            Expression::Variable(v) => match sc.lookup(&v.name) {
                Some(x) => x.clone(),
                None => {
                    self.resolver
                        .resolve(self, sc, v.name.as_str(), v.span, &[])
                        .0
                }
            },
            Expression::Traversal(t) => {
                let (base, ops) = match &t.object {
                    Expression::Variable(v) => match sc.lookup(&v.name) {
                        Some(x) => (x.clone(), &t.operators[..]),
                        None => {
                            let (val, used) = self.resolver.resolve(
                                self,
                                sc,
                                v.name.as_str(),
                                v.span,
                                &t.operators[..],
                            );
                            (val, &t.operators[used.min(t.operators.len())..])
                        }
                    },
                    other => (self.eval(other, sc), &t.operators[..]),
                };
                self.apply_ops(base, ops, sc)
            }
            Expression::FunctionCall(f) => self.eval_function(f, sc),
            Expression::Tuple(t) => self
                .values(t.elements.iter().map(|x| self.eval(x, sc)))
                .map(|values| Value::list(values.finish()))
                .unwrap_or_else(|v| v),
            Expression::Object(o) => self.eval_object(o, sc),
            Expression::For(f) => self.eval_for(f, sc),
            Expression::Conditional(c) => {
                let cond = self.eval(&c.condition, sc);
                self.branch(
                    &cond,
                    || self.eval(&c.true_expr, sc),
                    || self.eval(&c.false_expr, sc),
                )
            }
            Expression::Unary(u) => {
                let v = self.eval(&u.operand, sc);
                self.lift_value(&v, &|x| {
                    if !x.is_known() {
                        return x.clone();
                    }
                    match u.operator {
                        UnaryOperator::Not => match x.as_bool() {
                            Some(b) => Value::bool(!b),
                            None => Value::error("operand of ! is not a bool"),
                        },
                        UnaryOperator::Negate => match x.as_number() {
                            Some(n) => Value::number(-n),
                            None => Value::error("operand of - is not a number"),
                        },
                    }
                })
            }
            Expression::Binary(b) => {
                let l = self.eval(&b.left, sc);
                // Kleene short-circuit for && / ||.
                match (b.operator, l.as_bool()) {
                    (BinaryOperator::And, Some(false)) => {
                        return Value::bool(false).inherit_sensitive(&l);
                    }
                    (BinaryOperator::Or, Some(true)) => {
                        return Value::bool(true).inherit_sensitive(&l);
                    }
                    _ => {}
                }
                let r = self.eval(&b.right, sc);
                match (b.operator, r.as_bool()) {
                    (BinaryOperator::And, Some(false)) => {
                        return Value::bool(false)
                            .inherit_sensitive(&l)
                            .inherit_sensitive(&r);
                    }
                    (BinaryOperator::Or, Some(true)) => {
                        return Value::bool(true)
                            .inherit_sensitive(&l)
                            .inherit_sensitive(&r);
                    }
                    _ => {}
                }
                match dominant_non_known([&l, &r]) {
                    Some(value) => value.inherit_sensitive(&l).inherit_sensitive(&r),
                    None => self.lift_pair(&l, &r, &|a, bvalue| binary(b.operator, a, bvalue)),
                }
            }
            Expression::Parenthesized(p) => self.eval(&p.expression, sc),
            Expression::Error(_) => Value::error("syntax error in expression"),
        }
    }

    fn eval_function(&self, f: &'a tf_ast::FunctionCall<'a>, sc: Scope<'_>) -> Value {
        let name = if f.namespace.is_empty() {
            f.name.name.to_string()
        } else {
            f.full_name()
        };
        match name.as_str() {
            "try" => return self.eval_try(&f.arguments, sc),
            "can" => return self.eval_can(&f.arguments, sc),
            _ => {}
        }
        let mut args = match self.values(f.arguments.iter().map(|a| self.eval(a, sc))) {
            Ok(args) => args,
            Err(value) => return value,
        };
        if f.expand_final
            && let Some(last) = args.pop()
        {
            match last.as_list() {
                Some(items) => {
                    if let Err(value) = args.reserve(items.len()) {
                        return failure(value, args.iter().chain([&last]));
                    }
                    for item in items {
                        if let Err(value) = args.push(item.child_of(&last)) {
                            return failure(value, args.iter().chain([&last]));
                        }
                    }
                }
                None => return non_known_or(&last, "cannot expand non-list"),
            }
        }
        self.resolver.call(&name, args.finish(), &self.budget)
    }

    /// Choose a branch by `cond` (a Known bool), or both (`OneOf`) when the
    /// condition is not known.
    pub fn branch(
        &self,
        cond: &Value,
        t: impl FnOnce() -> Value,
        f: impl FnOnce() -> Value,
    ) -> Value {
        let value = match &cond.kind {
            Kind::Known(_) => match cond.as_bool() {
                Some(true) => t(),
                Some(false) => f(),
                None => Value::error("condition is not a bool"),
            },
            Kind::Tainted(_) => self.branch_alternatives(cond, t, f, true),
            Kind::OneOf(o) => {
                if o.alternatives.iter().all(|a| a.as_bool() == Some(true)) {
                    t()
                } else if o.alternatives.iter().all(|a| a.as_bool() == Some(false)) {
                    f()
                } else {
                    self.branch_alternatives(cond, t, f, o.tainted)
                }
            }
            Kind::Unknown(_)
                if cond.is_error() || matches!(cond.origin(), Some(crate::Origin::Limit(_))) =>
            {
                cond.clone()
            }
            Kind::Unknown(_) => self.branch_alternatives(cond, t, f, false),
        };
        value.inherit_sensitive(cond)
    }

    /// Apply traversal operators to a value.
    pub fn apply_ops(&self, v: Value, ops: &'a [TraversalOperator<'a>], sc: Scope<'_>) -> Value {
        let span = ops.first().map_or(Span::EMPTY, |op| op.span());
        let guard = match self.enter(span, ops.len() as u64) {
            Ok(guard) => guard,
            Err(limit) => return limit,
        };
        self.finish(&guard, self.apply_ops_inner(v, ops, sc), span)
    }

    fn apply_ops_inner(
        &self,
        mut v: Value,
        ops: &'a [TraversalOperator<'a>],
        sc: Scope<'_>,
    ) -> Value {
        let mut i = 0;
        while i < ops.len() {
            match &ops[i] {
                TraversalOperator::GetAttr(g) => {
                    v = self.lift_value(&v, &|value| value.get_attr(&g.name.name))
                }
                TraversalOperator::Index(ix) => {
                    let k = self.eval(&ix.index, sc);
                    v = self.lift_pair(&v, &k, &Value::index);
                }
                TraversalOperator::LegacyIndex(l) => {
                    v = self.lift_pair(&v, &Value::number(l.index as f64), &Value::index)
                }
                TraversalOperator::FullSplat(_) => {
                    let rest = &ops[i + 1..];
                    return self.splat(v, rest, sc);
                }
                // An attribute-only splat (`.*`) carries only the attribute
                // accesses that directly follow it; later operators such as
                // `[0]` apply to the resulting list, as in HCL.
                TraversalOperator::AttrSplat(_) => {
                    let rest = &ops[i + 1..];
                    let n = rest
                        .iter()
                        .take_while(|op| {
                            matches!(
                                op,
                                TraversalOperator::GetAttr(_) | TraversalOperator::LegacyIndex(_)
                            )
                        })
                        .count();
                    let splatted = self.splat(v, &rest[..n], sc);
                    return self.apply_ops(splatted, &rest[n..], sc);
                }
            }
            i += 1;
        }
        v
    }

    fn splat(&self, v: Value, rest: &'a [TraversalOperator<'a>], sc: Scope<'_>) -> Value {
        let attempt = match &v.kind {
            Kind::Known(Known::Null) => Ok(Value::list(vec![])),
            Kind::Known(Known::List(items)) => self
                .values(
                    items
                        .iter()
                        .map(|x| self.apply_ops(x.child_of(&v), rest, sc)),
                )
                .map(|values| Value::list(values.finish())),
            Kind::Known(_) => self
                .values(std::iter::once_with(|| self.apply_ops(v.clone(), rest, sc)))
                .map(|values| Value::list(values.finish())),
            Kind::OneOf(o) => self
                .values(
                    o.alternatives
                        .iter()
                        .map(|a| self.splat(a.child_of(&v), rest, sc)),
                )
                .and_then(|values| self.alternatives(values.finish(), o.tainted)),
            Kind::Unknown(_) | Kind::Tainted(_) => return v,
        };
        match attempt {
            Ok(result) => result.inherit_sensitive(&v),
            Err(result) => failure(result, [&v]),
        }
    }
}

/// `v` itself when it is not Known (Unknown / Tainted / ambiguous OneOf),
/// otherwise an error with `msg`.
pub fn non_known_or(v: &Value, msg: &str) -> Value {
    match &v.kind {
        Kind::Known(Known::Json(j)) if !j.is_wholly_known() => {
            Value::other("jsonencode of a partially unknown value").with_prov(v.prov.clone())
        }
        Kind::Known(_) => Value::error(msg.to_string()),
        Kind::OneOf(o) if o.tainted || o.alternatives.iter().any(|a| a.is_tainted()) => {
            Value::tainted("(conditional)").with_prov(v.prov.clone())
        }
        Kind::OneOf(_) => {
            Value::other("ambiguous value (one of several)").with_prov(v.prov.clone())
        }
        _ => v.clone(),
    }
}

/// Error anywhere inside (used by `try` / `can`).
pub fn contains_error(v: &Value) -> bool {
    match &v.kind {
        Kind::Unknown(_) => v.is_error(),
        Kind::Known(Known::List(l)) => l.iter().any(contains_error),
        Kind::Known(Known::Object(m)) => m.values().any(contains_error),
        Kind::Known(Known::Json(j)) => contains_error(j),
        Kind::OneOf(o) => o.alternatives.iter().all(contains_error),
        _ => false,
    }
}

/// The dominant non-Known input among `vals`: Error > Unknown > Tainted.
pub fn dominant_non_known<'v>(vals: impl IntoIterator<Item = &'v Value>) -> Option<Value> {
    let mut unknown = None;
    let mut tainted = None;
    for v in vals {
        match &v.kind {
            Kind::Unknown(_) if v.is_error() => return Some(v.clone()),
            Kind::Unknown(_) => {
                if unknown.is_none() {
                    unknown = Some(v.clone())
                }
            }
            Kind::Tainted(_) if tainted.is_none() => tainted = Some(v.clone()),
            _ => {}
        }
    }
    unknown.or(tainted)
}

/// Lift a unary operation over OneOf / non-Known values.
pub fn lift1(v: &Value, f: &dyn Fn(&Value) -> Value) -> Value {
    if v.alternative_count() > MAX_ALTERNATIVES {
        return Value::limit_from("too many unary alternatives", [v]);
    }
    let result = match &v.kind {
        Kind::Known(_) => f(v),
        Kind::OneOf(o) => Value::one_of(
            o.alternatives
                .iter()
                .map(|a| lift1(&a.child_of(v), f))
                .collect(),
            o.tainted,
        ),
        _ => v.clone(),
    };
    result.inherit_sensitive(v)
}

/// Lift a binary operation.
pub fn lift2(a: &Value, b: &Value, f: &dyn Fn(&Value, &Value) -> Value) -> Value {
    if let Some(nk) = dominant_non_known([a, b]) {
        return nk.inherit_sensitive(a).inherit_sensitive(b);
    }
    let count = a.alternative_count().checked_mul(b.alternative_count());
    if count.is_none_or(|count| count > MAX_ALTERNATIVES) {
        return Value::limit_from("too many binary alternatives", [a, b]);
    }
    let result = match (&a.kind, &b.kind) {
        (Kind::OneOf(o), _) => Value::one_of(
            o.alternatives
                .iter()
                .map(|x| lift2(&x.child_of(a), b, f))
                .collect(),
            o.tainted,
        ),
        (_, Kind::OneOf(o)) => Value::one_of(
            o.alternatives
                .iter()
                .map(|y| lift2(a, &y.child_of(b), f))
                .collect(),
            o.tainted,
        ),
        _ => f(a, b),
    };
    result.inherit_sensitive(a).inherit_sensitive(b)
}

pub fn binary(op: BinaryOperator, l: &Value, r: &Value) -> Value {
    use BinaryOperator::*;
    match op {
        Equal | NotEqual => {
            // Equality is defined on partially known values when the known
            // parts already differ; keep it simple: wholly known only.
            lift2(l, r, &|a, b| match a.known_eq(b) {
                Some(eq) => Value::bool(if op == Equal { eq } else { !eq }),
                None => match dominant_non_known_deep(a, b) {
                    Some(v) => v,
                    None => Value::other("comparison of partially unknown values"),
                },
            })
        }
        And | Or => lift2(l, r, &|a, b| match (a.as_bool(), b.as_bool()) {
            (Some(x), Some(y)) => Value::bool(if op == And { x && y } else { x || y }),
            _ => Value::error(format!("operands of {} must be bool", op.as_str())),
        }),
        Less | LessEqual | Greater | GreaterEqual | Add | Subtract | Multiply | Divide | Modulo => {
            lift2(l, r, &|a, b| match (a.as_number(), b.as_number()) {
                (Some(x), Some(y)) => match op {
                    Less => Value::bool(x < y),
                    LessEqual => Value::bool(x <= y),
                    Greater => Value::bool(x > y),
                    GreaterEqual => Value::bool(x >= y),
                    Add => Value::number(x + y),
                    Subtract => Value::number(x - y),
                    Multiply => Value::number(x * y),
                    Divide => Value::number(x / y),
                    Modulo => Value::number(x % y),
                    _ => unreachable!(),
                },
                _ => Value::error(format!("operands of {} must be numbers", op.as_str())),
            })
        }
    }
}

fn dominant_non_known_deep(a: &Value, b: &Value) -> Option<Value> {
    fn first(v: &Value) -> Option<Value> {
        match &v.kind {
            Kind::Known(Known::List(l)) => l.iter().find_map(first),
            Kind::Known(Known::Object(m)) => m.values().find_map(first),
            Kind::Known(_) => None,
            _ => Some(non_known_or(v, "")),
        }
    }
    let (x, y) = (first(a), first(b));
    dominant_non_known(x.iter().chain(y.iter()))
}

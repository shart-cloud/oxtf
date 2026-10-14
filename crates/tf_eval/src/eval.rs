//! Expression evaluator over the abstract lattice.
//!
//! The evaluator knows HCL; it does not know Terraform modules. Every
//! reference whose root is not bound lexically (by a `for` expression, a
//! `dynamic` iterator, `each`, `count`, ...) is handed to a [`Resolver`],
//! which the semantic layer implements (`var.*`, `local.*`, resources,
//! `module.*`, `data.*`, `path.*`, `terraform.*`).

use std::sync::Arc;

use tf_ast::{
    BinaryOperator, Expression, ForExpr, ObjectKey, Template, TemplateElement, TraversalOperator,
    UnaryOperator,
};
use tf_span::{FileId, Span};

use crate::functions;
use crate::prov::Prov;
use crate::value::{Kind, Known, Map, Value};

/// Lexical bindings: a linked list of frames on the Rust stack.
#[derive(Clone, Copy, Default)]
pub struct Scope<'s> {
    frame: Option<&'s Frame<'s>>,
}

pub struct Frame<'s> {
    name: &'s str,
    value: Value,
    parent: Option<&'s Frame<'s>>,
}

impl<'s> Scope<'s> {
    pub const EMPTY: Scope<'static> = Scope { frame: None };

    pub fn lookup(&self, name: &str) -> Option<&'s Value> {
        let mut f = self.frame;
        while let Some(fr) = f {
            if fr.name == name {
                return Some(&fr.value);
            }
            f = fr.parent;
        }
        None
    }

    /// Run `k` with `name = value` bound on top of this scope.
    pub fn with<R>(&self, name: &str, value: Value, k: impl FnOnce(Scope<'_>) -> R) -> R {
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
            Some(((n, v), rest)) => self.with(n, v.clone(), |s| s.with_all(rest, k)),
        }
    }
}

/// Resolves references rooted outside the lexical scope.
pub trait Resolver<'a> {
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
pub const MAX_ALTERNATIVES: usize = 16;

pub struct Evaluator<'r, 'a> {
    pub resolver: &'r dyn Resolver<'a>,
    /// File the expressions being evaluated live in.
    pub file: FileId,
}

impl<'r, 'a> Evaluator<'r, 'a> {
    pub fn new(resolver: &'r dyn Resolver<'a>, file: FileId) -> Self {
        Evaluator { resolver, file }
    }

    pub fn eval(&self, e: &'a Expression<'a>, sc: Scope<'_>) -> Value {
        match e {
            Expression::Null(_) => Value::null(),
            Expression::Bool(b) => Value::bool(b.value),
            Expression::Number(n) => Value::number(n.value),
            Expression::String(s) => Value::string(s.value.as_str()),
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
            Expression::FunctionCall(f) => {
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
                let mut args: Vec<Value> = f.arguments.iter().map(|a| self.eval(a, sc)).collect();
                if f.expand_final
                    && let Some(last) = args.pop()
                {
                    match last.as_list() {
                        Some(l) => args.extend(l.iter().map(|x| x.child_of(&last))),
                        None => return non_known_or(&last, "cannot expand non-list"),
                    }
                }
                functions::call(&name, args)
            }
            Expression::Tuple(t) => {
                Value::list(t.elements.iter().map(|x| self.eval(x, sc)).collect())
            }
            Expression::Object(o) => {
                let mut m = Map::new();
                for item in o.items.iter() {
                    let key: Arc<str> = match &item.key {
                        ObjectKey::Identifier(i) => Arc::from(i.name.as_str()),
                        ObjectKey::Expression(k) => {
                            // A bare traversal key like `aws.east` is literal
                            // text in Terraform only for provider maps; treat
                            // parenthesised / other keys as expressions.
                            let kv = self.eval(k, sc);
                            match kv.to_str() {
                                Some(s) => s,
                                None => return non_known_or(&kv, "object key is not a string"),
                            }
                        }
                    };
                    m.insert(key, self.eval(&item.value, sc));
                }
                Value::object(m)
            }
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
                lift1(&v, &|x| match u.operator {
                    UnaryOperator::Not => match x.as_bool() {
                        Some(b) => Value::bool(!b),
                        None => Value::error("operand of ! is not a bool"),
                    },
                    UnaryOperator::Negate => match x.as_number() {
                        Some(n) => Value::number(-n),
                        None => Value::error("operand of - is not a number"),
                    },
                })
            }
            Expression::Binary(b) => {
                let l = self.eval(&b.left, sc);
                // Kleene short-circuit for && / ||.
                match (b.operator, l.as_bool()) {
                    (BinaryOperator::And, Some(false)) => return Value::bool(false),
                    (BinaryOperator::Or, Some(true)) => return Value::bool(true),
                    _ => {}
                }
                let r = self.eval(&b.right, sc);
                match (b.operator, r.as_bool()) {
                    (BinaryOperator::And, Some(false)) => return Value::bool(false),
                    (BinaryOperator::Or, Some(true)) => return Value::bool(true),
                    _ => {}
                }
                binary(b.operator, &l, &r)
            }
            Expression::Parenthesized(p) => self.eval(&p.expression, sc),
            Expression::Error(_) => Value::error("syntax error in expression"),
        }
    }

    /// Choose a branch by `cond` (a Known bool), or both (`OneOf`) when the
    /// condition is not known.
    pub fn branch(
        &self,
        cond: &Value,
        t: impl FnOnce() -> Value,
        f: impl FnOnce() -> Value,
    ) -> Value {
        match &cond.kind {
            Kind::Known(_) => match cond.as_bool() {
                Some(true) => t(),
                Some(false) => f(),
                None => Value::error("condition is not a bool"),
            },
            Kind::Tainted(_) => Value::one_of(vec![t(), f()], true),
            Kind::OneOf(o) => {
                let bools: Vec<Option<bool>> = o.alternatives.iter().map(|a| a.as_bool()).collect();
                if bools.iter().all(|b| *b == Some(true)) {
                    t()
                } else if bools.iter().all(|b| *b == Some(false)) {
                    f()
                } else {
                    Value::one_of(vec![t(), f()], o.tainted)
                }
            }
            Kind::Unknown(_) if cond.is_error() => cond.clone(),
            Kind::Unknown(_) => Value::one_of(vec![t(), f()], false),
        }
    }

    /// Apply traversal operators to a value.
    pub fn apply_ops(
        &self,
        mut v: Value,
        ops: &'a [TraversalOperator<'a>],
        sc: Scope<'_>,
    ) -> Value {
        let mut i = 0;
        while i < ops.len() {
            match &ops[i] {
                TraversalOperator::GetAttr(g) => v = v.get_attr(&g.name.name),
                TraversalOperator::Index(ix) => {
                    let k = self.eval(&ix.index, sc);
                    v = v.index(&k);
                }
                TraversalOperator::LegacyIndex(l) => v = v.index(&Value::number(l.index as f64)),
                TraversalOperator::AttrSplat(_) | TraversalOperator::FullSplat(_) => {
                    let rest = &ops[i + 1..];
                    return self.splat(v, rest, sc);
                }
            }
            i += 1;
        }
        v
    }

    fn splat(&self, v: Value, rest: &'a [TraversalOperator<'a>], sc: Scope<'_>) -> Value {
        match &v.kind {
            Kind::Known(Known::Null) => Value::list(vec![]),
            Kind::Known(Known::List(items)) => Value::list(
                items
                    .iter()
                    .map(|x| self.apply_ops(x.child_of(&v), rest, sc))
                    .collect(),
            ),
            Kind::Known(_) => Value::list(vec![self.apply_ops(v, rest, sc)]),
            Kind::OneOf(o) => Value::one_of(
                o.alternatives
                    .iter()
                    .map(|a| self.splat(a.child_of(&v), rest, sc))
                    .collect(),
                o.tainted,
            ),
            Kind::Unknown(_) | Kind::Tainted(_) => v,
        }
    }

    fn eval_try(&self, args: &'a [Expression<'a>], sc: Scope<'_>) -> Value {
        let mut last = Value::error("try: no arguments succeeded");
        for a in args {
            let v = self.eval(a, sc);
            if !contains_error(&v) {
                return v;
            }
            last = v;
        }
        last
    }

    fn eval_can(&self, args: &'a [Expression<'a>], sc: Scope<'_>) -> Value {
        let Some(a) = args.first() else {
            return Value::error("can: missing argument");
        };
        let v = self.eval(a, sc);
        if contains_error(&v) {
            Value::bool(false)
        } else if v.is_wholly_known() {
            Value::bool(true)
        } else if v.is_tainted() {
            v
        } else {
            // Approximation: partially-unknown values are assumed valid.
            Value::bool(true)
        }
    }

    fn eval_for(&self, f: &'a ForExpr<'a>, sc: Scope<'_>) -> Value {
        let coll = self.eval(&f.collection, sc);
        let items: Vec<(Value, Value)> = match &coll.kind {
            Kind::Known(Known::List(l)) => l
                .iter()
                .enumerate()
                .map(|(i, x)| (Value::number(i as f64), x.child_of(&coll)))
                .collect(),
            Kind::Known(Known::Object(m)) => m
                .iter()
                .map(|(k, x)| (Value::string(k.clone()), x.child_of(&coll)))
                .collect(),
            Kind::Known(Known::Null) => return Value::error("for: iterating over null"),
            Kind::Known(_) => return Value::error("for: collection is not iterable"),
            Kind::OneOf(o) => {
                // Iterate each alternative separately.
                let alts: Vec<Value> = o
                    .alternatives
                    .iter()
                    .map(|a| self.eval_for_over(f, a.child_of(&coll), sc))
                    .collect();
                return Value::one_of(alts, o.tainted);
            }
            Kind::Unknown(_) | Kind::Tainted(_) => return coll,
        };
        self.eval_for_items(f, items, sc)
    }

    fn eval_for_over(&self, f: &'a ForExpr<'a>, coll: Value, sc: Scope<'_>) -> Value {
        let items: Vec<(Value, Value)> = match &coll.kind {
            Kind::Known(Known::List(l)) => l
                .iter()
                .enumerate()
                .map(|(i, x)| (Value::number(i as f64), x.child_of(&coll)))
                .collect(),
            Kind::Known(Known::Object(m)) => m
                .iter()
                .map(|(k, x)| (Value::string(k.clone()), x.child_of(&coll)))
                .collect(),
            Kind::Known(_) => return Value::error("for: collection is not iterable"),
            _ => return coll,
        };
        self.eval_for_items(f, items, sc)
    }

    fn eval_for_items(
        &self,
        f: &'a ForExpr<'a>,
        items: Vec<(Value, Value)>,
        sc: Scope<'_>,
    ) -> Value {
        let mut list = Vec::new();
        let mut obj = Map::new();
        let mut grouped: std::collections::BTreeMap<Arc<str>, Vec<Value>> = Default::default();
        for (k, v) in items {
            let mut binds: Vec<(&str, Value)> = Vec::with_capacity(2);
            if let Some(kv) = &f.key_var {
                binds.push((kv.name.as_str(), k));
            }
            binds.push((f.value_var.name.as_str(), v));
            let res = sc.with_all(&binds, |s| {
                let keep = match &f.condition {
                    None => Some(true),
                    Some(c) => {
                        let cv = self.eval(c, s);
                        match &cv.kind {
                            Kind::Known(_) => match cv.as_bool() {
                                Some(b) => Some(b),
                                None => return Err(Value::error("for: condition is not a bool")),
                            },
                            Kind::Tainted(_) => None,
                            _ if cv.is_error() => return Err(cv),
                            _ => None,
                        }
                        .map_or(Ok(None), |b| Ok(Some(b)))?
                    }
                };
                if keep == Some(false) {
                    return Ok(None);
                }
                let val = self.eval(&f.value_expr, s);
                // An element whose condition is not known may be absent.
                let val = if keep.is_none() {
                    Value::one_of(vec![val, Value::null()], true)
                } else {
                    val
                };
                let key = match &f.key_expr {
                    Some(ke) => {
                        let kv = self.eval(ke, s);
                        match kv.to_str() {
                            Some(x) => Some(x),
                            None => return Err(non_known_or(&kv, "for: key is not a string")),
                        }
                    }
                    None => None,
                };
                Ok(Some((key, val)))
            });
            match res {
                Err(e) => return e,
                Ok(None) => {}
                Ok(Some((None, val))) => list.push(val),
                Ok(Some((Some(key), val))) => {
                    if f.grouping {
                        grouped.entry(key).or_default().push(val);
                    } else {
                        obj.insert(key, val);
                    }
                }
            }
        }
        if f.key_expr.is_none() {
            Value::list(list)
        } else if f.grouping {
            Value::object(
                grouped
                    .into_iter()
                    .map(|(k, v)| (k, Value::list(v)))
                    .collect(),
            )
        } else {
            Value::object(obj)
        }
    }

    // -- templates --------------------------------------------------------

    pub fn eval_template(&self, t: &'a Template<'a>, sc: Scope<'_>) -> Value {
        // A template that is a single interpolation yields the value itself
        // (type preserved), as in Terraform.
        if t.elements.len() == 1
            && let TemplateElement::Interpolation(i) = &t.elements[0]
        {
            return self.eval(&i.expression, sc);
        }
        let mut parts = Vec::new();
        if let Err(v) = self.template_parts(t, sc, false, false, &mut parts) {
            return v;
        }
        concat_parts(&parts)
    }

    fn template_parts(
        &self,
        t: &'a Template<'a>,
        sc: Scope<'_>,
        lead: bool,
        trail: bool,
        out: &mut Vec<Part>,
    ) -> Result<(), Value> {
        let els = &t.elements;
        let n = els.len();
        let mut trim_start = vec![false; n];
        let mut trim_end = vec![false; n];
        for (i, el) in els.iter().enumerate() {
            let (before, after) = match el {
                TemplateElement::Literal(_) => (false, false),
                TemplateElement::Interpolation(x) => (x.strip.start, x.strip.end),
                TemplateElement::If(x) => (x.if_strip.start, x.endif_strip.end),
                TemplateElement::For(x) => (x.for_strip.start, x.endfor_strip.end),
            };
            if before && i > 0 {
                trim_end[i - 1] = true;
            }
            if after && i + 1 < n {
                trim_start[i + 1] = true;
            }
        }
        if n > 0 {
            trim_start[0] |= lead;
            trim_end[n - 1] |= trail;
        }
        for (i, el) in els.iter().enumerate() {
            match el {
                TemplateElement::Literal(l) => {
                    let mut s: &str = &l.value;
                    if trim_start[i] {
                        s = s.trim_start();
                    }
                    if trim_end[i] {
                        s = s.trim_end();
                    }
                    if !s.is_empty() {
                        out.push(Part::Lit(s.to_string()));
                    }
                }
                TemplateElement::Interpolation(x) => {
                    out.push(Part::Val(self.eval(&x.expression, sc)))
                }
                TemplateElement::If(x) => {
                    let c = self.eval(&x.condition, sc);
                    match c.as_bool() {
                        Some(true) => {
                            let trail =
                                x.else_strip.map(|s| s.start).unwrap_or(x.endif_strip.start);
                            self.template_parts(&x.then_template, sc, x.if_strip.end, trail, out)?;
                        }
                        Some(false) => {
                            if let (Some(es), Some(et)) = (&x.else_strip, &x.else_template) {
                                self.template_parts(et, sc, es.end, x.endif_strip.start, out)?;
                            }
                        }
                        None => {
                            return Err(non_known_or(&c, "template if: condition is not a bool"));
                        }
                    }
                }
                TemplateElement::For(x) => {
                    let coll = self.eval(&x.collection, sc);
                    let items: Vec<(Value, Value)> = match &coll.kind {
                        Kind::Known(Known::List(l)) => l
                            .iter()
                            .enumerate()
                            .map(|(i, v)| (Value::number(i as f64), v.child_of(&coll)))
                            .collect(),
                        Kind::Known(Known::Object(m)) => m
                            .iter()
                            .map(|(k, v)| (Value::string(k.clone()), v.child_of(&coll)))
                            .collect(),
                        _ => return Err(non_known_or(&coll, "template for: not iterable")),
                    };
                    for (k, v) in items {
                        let mut binds: Vec<(&str, Value)> = Vec::new();
                        if let Some(kv) = &x.key_var {
                            binds.push((kv.name.as_str(), k));
                        }
                        binds.push((x.value_var.name.as_str(), v));
                        sc.with_all(&binds, |s| {
                            self.template_parts(
                                &x.template,
                                s,
                                x.for_strip.end,
                                x.endfor_strip.start,
                                out,
                            )
                        })?;
                    }
                }
            }
        }
        Ok(())
    }
}

pub(crate) enum Part {
    Lit(String),
    Val(Value),
}

fn concat_parts(parts: &[Part]) -> Value {
    // Lift over OneOf parts (bounded).
    let mut alts: Vec<(String, Prov, bool)> = vec![(String::new(), Prov::EMPTY, false)];
    for p in parts {
        match p {
            Part::Lit(s) => alts.iter_mut().for_each(|a| a.0.push_str(s)),
            Part::Val(v) => {
                let (choices, tainted): (Vec<Value>, bool) = match &v.kind {
                    Kind::OneOf(o) => (
                        o.alternatives.iter().map(|a| a.child_of(v)).collect(),
                        o.tainted,
                    ),
                    _ => (vec![v.clone()], false),
                };
                if alts.len() * choices.len() > MAX_ALTERNATIVES {
                    return Value::other("template: too many alternatives");
                }
                let mut next = Vec::with_capacity(alts.len() * choices.len());
                for a in &alts {
                    for c in &choices {
                        match c.to_str() {
                            Some(s) => {
                                let mut t = a.0.clone();
                                t.push_str(&s);
                                next.push((t, a.1.then(&c.prov), a.2 || tainted));
                            }
                            None => return non_known_or(c, "template: value is not a string"),
                        }
                    }
                }
                alts = next;
            }
        }
    }
    let tainted = alts.iter().any(|a| a.2);
    Value::one_of(
        alts.into_iter()
            .map(|(s, p, _)| Value::string(s).with_prov(p))
            .collect(),
        tainted,
    )
}

/// `v` itself when it is not Known (Unknown / Tainted / ambiguous OneOf),
/// otherwise an error with `msg`.
pub fn non_known_or(v: &Value, msg: &str) -> Value {
    match &v.kind {
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
    match &v.kind {
        Kind::Known(_) => f(v),
        Kind::OneOf(o) => Value::one_of(
            o.alternatives
                .iter()
                .map(|a| lift1(&a.child_of(v), f))
                .collect(),
            o.tainted,
        ),
        _ => v.clone(),
    }
}

/// Lift a binary operation.
pub fn lift2(a: &Value, b: &Value, f: &dyn Fn(&Value, &Value) -> Value) -> Value {
    if let Some(nk) = dominant_non_known([a, b]) {
        return nk;
    }
    match (&a.kind, &b.kind) {
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
    }
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

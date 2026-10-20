//! The abstract value lattice.
//!
//! ```text
//!                 Value { kind, prov }
//!   kind = Known(Known)      a concrete value; containers hold abstract
//!                            children, so `[ "10.0.0.0/8", var.x ]` is a
//!                            Known list whose second element may be Tainted
//!        | Unknown(Origin)   not knowable statically (computed by provider,
//!                            remote module output, unsupported function,
//!                            evaluation error, ...); the origin says why
//!        | Tainted(Taint)    depends on an *unconstrained input*: a root-module
//!                            variable with no default and no tfvars value
//!        | OneOf(OneOf)      one of several values; produced by a conditional
//!                            whose condition is not Known, and by `dynamic` /
//!                            `for_each` whose collection is not Known (as
//!                            `OneOf[element, null]`: "maybe absent")
//! ```
//!
//! **Tainted, precisely.** A value is `Tainted` iff it is the value of an
//! unconstrained input, or the result of an operation that needed the
//! concrete value of one (e.g. `"${var.prefix}-x"`, `var.cidrs[0]`,
//! `lookup(m, var.k)`). Operations that do not need it keep the taint local:
//! `[var.x, "a"]` is a Known list with one Tainted element, `length([var.x])`
//! is Known 1. When an operation combines a Tainted and an Unknown input, the
//! result is Unknown: the value is then not chosen by whoever sets the
//! variable alone. Rules map "insecure iff the tainted value is insecure"
//! to *conditional* severity (see `truth.rs`).
//!
//! A `OneOf` remembers whether its ambiguity came from a tainted source
//! (`tainted: true`) or from an unknown one.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use crate::prov::{Prov, Step};

/// Why a value is Unknown.
#[derive(Clone, Debug, PartialEq)]
pub enum Origin {
    /// A resource / data-source attribute that only the provider knows
    /// (computed-only, or optional+computed and not set). `resource` is the
    /// address without instance key (`aws_s3_bucket.data`,
    /// `module.m.aws_s3_bucket.this`, `data.aws_caller_identity.cur`), so
    /// cross-resource joins can match `bucket = aws_s3_bucket.data.id`.
    Computed {
        resource: Arc<str>,
        key: Option<Arc<str>>,
        attr: Arc<str>,
    },
    /// Output of a remote (registry / git / http) module.
    RemoteModule { module: Arc<str>, output: Arc<str> },
    /// A function the evaluator does not implement.
    UnsupportedFunction(Arc<str>),
    /// Evaluation stopped at a bounded expansion or recursion limit.
    Limit(Arc<str>),
    /// Evaluation error (type error, missing attribute, bad index...).
    /// `try()` / `can()` treat this differently from other unknowns.
    Error(Arc<str>),
    /// Anything else: `count.index` when instances are not expanded,
    /// `terraform.workspace`, `self`, `file()`, ...
    Other(Arc<str>),
}

impl Origin {
    /// Short category for statistics.
    pub fn category(&self) -> String {
        match self {
            Origin::Computed { attr, resource, .. } => {
                if resource.starts_with("data.") || resource.contains(".data.") {
                    format!("computed by provider (data source .{attr})")
                } else {
                    "computed by provider".to_string()
                }
            }
            Origin::RemoteModule { .. } => "remote module".to_string(),
            Origin::UnsupportedFunction(f) => format!("unsupported function {f}"),
            Origin::Limit(m) => format!("analysis limit: {m}"),
            Origin::Error(m) => format!("error: {}", m.split(':').next().unwrap_or(m)),
            Origin::Other(m) => m.to_string(),
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Computed {
                resource,
                key,
                attr,
            } => match key {
                Some(k) => write!(f, "computed by provider: {resource}[{k}].{attr}"),
                None => write!(f, "computed by provider: {resource}.{attr}"),
            },
            Origin::RemoteModule { module, output } => {
                write!(f, "remote module: {module}.{output}")
            }
            Origin::UnsupportedFunction(n) => write!(f, "unsupported function {n}"),
            Origin::Limit(m) => write!(f, "analysis limit: {m}"),
            Origin::Error(m) => write!(f, "error: {m}"),
            Origin::Other(m) => f.write_str(m),
        }
    }
}

/// An unconstrained input.
#[derive(Clone, Debug, PartialEq)]
pub struct Taint {
    /// The (first) unconstrained variable the value depends on.
    pub variable: Arc<str>,
}

#[derive(Clone, Debug)]
pub struct OneOf {
    pub alternatives: Vec<Value>,
    /// The ambiguity comes from a Tainted source (condition / collection).
    pub tainted: bool,
}

/// A concrete value. Children are abstract [`Value`]s.
#[derive(Clone, Debug)]
pub enum Known {
    Null,
    Bool(bool),
    Number(f64),
    String(Arc<str>),
    /// Tuple, list or set.
    List(Arc<Vec<Value>>),
    /// Object or map, keys sorted.
    Object(Arc<BTreeMap<Arc<str>, Value>>),
    /// `jsonencode(v)`: a string whose text is the JSON encoding of `v`. Kept
    /// structured so rules can inspect the document (with per-element
    /// provenance) even when parts of it are not known.
    Json(Arc<Value>),
}

#[derive(Clone, Debug)]
pub enum Kind {
    Known(Known),
    Unknown(Arc<Origin>),
    Tainted(Arc<Taint>),
    OneOf(Arc<OneOf>),
}

/// An abstract value plus its provenance.
#[derive(Clone)]
pub struct Value {
    pub kind: Kind,
    pub prov: Prov,
}

pub type Map = BTreeMap<Arc<str>, Value>;

impl Value {
    /// Sensitivity is independent of whether the value is known. Evaluators
    /// still read its real contents; presentation must redact it.
    pub fn is_sensitive(&self) -> bool {
        self.prov.is_sensitive()
    }

    #[must_use]
    pub fn sensitive(mut self) -> Self {
        self.prov = self.prov.with_sensitive(true);
        self
    }

    /// Explicit Terraform `nonsensitive()` declassification, including
    /// descendants; ordinary transformations never clear the mark.
    #[must_use]
    pub fn nonsensitive(&self) -> Self {
        let kind = match &self.kind {
            Kind::Known(Known::List(v)) => Kind::Known(Known::List(Arc::new(
                v.iter().map(Self::nonsensitive).collect(),
            ))),
            Kind::Known(Known::Object(m)) => Kind::Known(Known::Object(Arc::new(
                m.iter()
                    .map(|(k, v)| (k.clone(), v.nonsensitive()))
                    .collect(),
            ))),
            Kind::Known(Known::Json(v)) => Kind::Known(Known::Json(Arc::new(v.nonsensitive()))),
            Kind::OneOf(o) => Kind::OneOf(Arc::new(OneOf {
                alternatives: o.alternatives.iter().map(Self::nonsensitive).collect(),
                tainted: o.tainted,
            })),
            k => k.clone(),
        };
        Value {
            kind,
            prov: self.prov.clone().with_sensitive(false),
        }
    }

    #[must_use]
    pub fn inherit_sensitive(mut self, from: &Value) -> Self {
        if from.is_sensitive() {
            self.prov = self.prov.with_sensitive(true);
        }
        self
    }

    pub fn new(kind: Kind) -> Self {
        Value {
            kind,
            prov: Prov::EMPTY,
        }
    }
    pub fn known(k: Known) -> Self {
        let prov = match &k {
            Known::List(items) => Prov::union_of(items.iter().map(|v| &v.prov)),
            Known::Object(items) => Prov::union_of(items.values().map(|v| &v.prov)),
            Known::Json(value) => Prov::union_of([&value.prov]),
            _ => Prov::EMPTY,
        };
        Value {
            kind: Kind::Known(k),
            prov,
        }
    }
    pub fn null() -> Self {
        Value::known(Known::Null)
    }
    pub fn bool(b: bool) -> Self {
        Value::known(Known::Bool(b))
    }
    pub fn number(n: f64) -> Self {
        Value::known(Known::Number(n))
    }
    pub fn string(s: impl Into<Arc<str>>) -> Self {
        Value::known(Known::String(s.into()))
    }
    pub fn list(v: Vec<Value>) -> Self {
        Value::known(Known::List(Arc::new(v)))
    }
    pub fn object(m: Map) -> Self {
        Value::known(Known::Object(Arc::new(m)))
    }
    pub fn json(v: Value) -> Self {
        Value::known(Known::Json(Arc::new(v)))
    }
    pub fn unknown(o: Origin) -> Self {
        Value::new(Kind::Unknown(Arc::new(o)))
    }
    pub fn other(msg: impl Into<Arc<str>>) -> Self {
        Value::unknown(Origin::Other(msg.into()))
    }
    pub fn limit(msg: impl Into<Arc<str>>) -> Self {
        Value::unknown(Origin::Limit(msg.into()))
    }
    pub fn error(msg: impl Into<Arc<str>>) -> Self {
        Value::unknown(Origin::Error(msg.into()))
    }
    pub fn tainted(var: impl Into<Arc<str>>) -> Self {
        Value::new(Kind::Tainted(Arc::new(Taint {
            variable: var.into(),
        })))
    }

    /// `OneOf` over `alts`: nested OneOfs are flattened, alternatives that
    /// are structurally equal Known values are merged, and a single
    /// alternative collapses to itself.
    pub fn one_of(alts: Vec<Value>, tainted: bool) -> Self {
        let sensitive = alts.iter().any(Value::is_sensitive);
        // A traversal present in only some alternatives is only a possible
        // graph edge. Compute this before structurally equal values collapse.
        let mut dependencies = Vec::<crate::prov::ResourceDependency>::new();
        for a in &alts {
            for d in a.prov.dependencies() {
                if dependencies
                    .iter()
                    .any(|old| old.resource == d.resource && old.key == d.key)
                {
                    continue;
                }
                let outcomes: Vec<_> = alts
                    .iter()
                    .map(|a| {
                        a.prov
                            .dependencies()
                            .iter()
                            .filter(|x| x.resource == d.resource && x.key == d.key)
                            .fold(crate::Truth::False, |t, x| t.or(x.certainty))
                    })
                    .collect();
                let certainty = if outcomes.iter().all(|t| *t == outcomes[0]) {
                    outcomes[0]
                } else if tainted || outcomes.contains(&crate::Truth::Tainted) {
                    crate::Truth::Tainted
                } else {
                    crate::Truth::Unknown
                };
                dependencies.push(crate::prov::ResourceDependency {
                    certainty,
                    ..d.clone()
                });
            }
        }
        let mut flat: Vec<Value> = Vec::with_capacity(alts.len());
        let mut tainted = tainted;
        for a in alts {
            match &a.kind {
                Kind::OneOf(o) => {
                    tainted |= o.tainted;
                    for x in &o.alternatives {
                        push_unique(&mut flat, x.child_of(&a));
                    }
                }
                _ => push_unique(&mut flat, a),
            }
        }
        if flat.len() == 1 {
            let mut value = flat.pop().unwrap();
            if !dependencies.is_empty() {
                value.prov = value.prov.referencing(dependencies);
            }
            value.prov = value.prov.with_sensitive(sensitive);
            return value;
        }
        let mut value = Value::new(Kind::OneOf(Arc::new(OneOf {
            alternatives: flat,
            tainted,
        })));
        if !dependencies.is_empty() {
            value.prov = value.prov.referencing(dependencies);
        }
        value.prov = value.prov.with_sensitive(sensitive);
        value
    }

    #[must_use]
    pub fn with_prov(mut self, prov: Prov) -> Self {
        let mut prov = prov;
        prov.join_dependencies(&self.prov);
        self.prov = prov;
        self
    }

    #[must_use]
    pub fn push(mut self, step: Step) -> Self {
        self.prov = self.prov.push(step);
        self
    }

    /// `self` taken out of `container`: provenance joined.
    #[must_use]
    pub fn child_of(&self, container: &Value) -> Value {
        Value {
            kind: self.kind.clone(),
            prov: self.prov.then(&container.prov),
        }
    }

    // -- classification ---------------------------------------------------

    pub fn as_known(&self) -> Option<&Known> {
        match &self.kind {
            Kind::Known(k) => Some(k),
            _ => None,
        }
    }
    pub fn is_known(&self) -> bool {
        matches!(self.kind, Kind::Known(_))
    }
    pub fn is_null(&self) -> bool {
        matches!(self.kind, Kind::Known(Known::Null))
    }
    pub fn is_tainted(&self) -> bool {
        matches!(self.kind, Kind::Tainted(_))
    }
    pub fn is_unknown(&self) -> bool {
        matches!(self.kind, Kind::Unknown(_))
    }
    pub fn origin(&self) -> Option<&Origin> {
        match &self.kind {
            Kind::Unknown(o) => Some(o),
            _ => None,
        }
    }
    pub fn is_error(&self) -> bool {
        matches!(&self.kind, Kind::Unknown(o) if matches!(**o, Origin::Error(_)))
    }

    /// Known all the way down (no Unknown / Tainted / OneOf anywhere).
    pub fn is_wholly_known(&self) -> bool {
        match &self.kind {
            Kind::Known(k) => match k {
                Known::List(v) => v.iter().all(Value::is_wholly_known),
                Known::Object(m) => m.values().all(Value::is_wholly_known),
                Known::Json(v) => v.is_wholly_known(),
                _ => true,
            },
            _ => false,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self.as_known()? {
            Known::Bool(b) => Some(*b),
            Known::String(s) if &**s == "true" => Some(true),
            Known::String(s) if &**s == "false" => Some(false),
            _ => None,
        }
    }
    pub fn as_number(&self) -> Option<f64> {
        match self.as_known()? {
            Known::Number(n) => Some(*n),
            Known::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
    /// A Known string (not `Json`, not a number). See [`Value::to_str`] for
    /// conversion.
    pub fn as_str(&self) -> Option<&str> {
        match self.as_known()? {
            Known::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&[Value]> {
        match self.as_known()? {
            Known::List(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&Map> {
        match self.as_known()? {
            Known::Object(m) => Some(m),
            _ => None,
        }
    }

    /// Terraform's string conversion of a primitive: strings as-is, numbers
    /// in shortest form, bools as `true`/`false`, `jsonencode` results
    /// rendered. `None` for anything else or anything not wholly known.
    pub fn to_str(&self) -> Option<Arc<str>> {
        match self.as_known()? {
            Known::String(s) => Some(s.clone()),
            Known::Number(n) => Some(fmt_number(*n).into()),
            Known::Bool(b) => Some(if *b { "true" } else { "false" }.into()),
            Known::Json(v) => to_json(v).map(|j| Arc::from(j.to_string())),
            _ => None,
        }
    }

    /// Field `name` of an object (provenance joined), with the lattice rules
    /// for non-Known receivers.
    pub fn get_attr(&self, name: &str) -> Value {
        let value = match &self.kind {
            Kind::Known(Known::Object(m)) => match m.get(name) {
                Some(v) => v.child_of(self),
                None => Value::error(format!("object has no attribute \"{name}\"")),
            },
            Kind::Known(Known::Null) => {
                Value::error(format!("attempt to get attribute \"{name}\" from null"))
            }
            Kind::Known(_) => Value::error(format!(
                "unsupported attribute \"{name}\" on non-object value"
            )),
            Kind::OneOf(o) => Value::one_of(
                o.alternatives
                    .iter()
                    .map(|a| a.child_of(self).get_attr(name))
                    .collect(),
                o.tainted,
            ),
            Kind::Unknown(_) | Kind::Tainted(_) => self.clone(),
        };
        value.inherit_sensitive(self)
    }

    /// Field `name` of an object, where a missing field of a Known object
    /// is null (attributes not written in a block are unset). Lifts over
    /// `OneOf`; Unknown and Tainted receivers stay themselves. The lenient
    /// accessor rules use; [`Value::get_attr`] is the strict one the
    /// evaluator uses.
    pub fn field_or_null(&self, name: &str) -> Value {
        crate::eval::lift1(self, &|v| match v.as_known() {
            Some(Known::Object(m)) => m
                .get(name)
                .map(|x| x.child_of(v))
                .unwrap_or_else(Value::null),
            Some(Known::Null) => Value::null(),
            _ => v.get_attr(name),
        })
    }

    /// `self[key]`.
    pub fn index(&self, key: &Value) -> Value {
        let value = match (&self.kind, &key.kind) {
            (Kind::OneOf(o), _) => Value::one_of(
                o.alternatives
                    .iter()
                    .map(|a| a.child_of(self).index(key))
                    .collect(),
                o.tainted,
            ),
            (_, Kind::OneOf(o)) => Value::one_of(
                o.alternatives
                    .iter()
                    .map(|k| self.index(&k.child_of(key)))
                    .collect(),
                o.tainted,
            ),
            (Kind::Unknown(_), _) => self.clone(),
            (_, Kind::Unknown(_)) => key.clone(),
            (Kind::Tainted(_), _) => self.clone(),
            (Kind::Known(Known::List(v)), Kind::Known(_)) => match key.as_number() {
                Some(n) if n >= 0.0 && n.fract() == 0.0 && (n as usize) < v.len() => {
                    v[n as usize].child_of(self)
                }
                Some(n) => Value::error(format!("index {n} out of range for list of {}", v.len())),
                None => Value::error("list index must be a number"),
            },
            (Kind::Known(Known::List(_)), Kind::Tainted(_)) => key.clone(),
            (Kind::Known(Known::Object(m)), _) => match key.to_str() {
                Some(k) => match m.get(&*k) {
                    Some(v) => v.child_of(self),
                    None => Value::error(format!("key \"{k}\" not found")),
                },
                None if key.is_tainted() => key.clone(),
                None => Value::error("object key must be a string"),
            },
            (Kind::Known(Known::Null), _) => Value::error("attempt to index null value"),
            (Kind::Known(_), _) => Value::error("value cannot be indexed"),
        };
        value.inherit_sensitive(self).inherit_sensitive(key)
    }

    /// Structural equality of wholly-known values; `None` if either side is
    /// not wholly known.
    pub fn known_eq(&self, other: &Value) -> Option<bool> {
        let (a, b) = (self.as_known()?, other.as_known()?);
        Some(match (a, b) {
            (Known::Null, Known::Null) => true,
            (Known::Bool(x), Known::Bool(y)) => x == y,
            (Known::Number(x), Known::Number(y)) => x == y,
            (Known::String(x), Known::String(y)) => x == y,
            (Known::List(x), Known::List(y)) => {
                if x.len() != y.len() {
                    return Some(false);
                }
                for (p, q) in x.iter().zip(y.iter()) {
                    if !p.known_eq(q)? {
                        return Some(false);
                    }
                }
                true
            }
            (Known::Object(x), Known::Object(y)) => {
                if x.len() != y.len() || !x.keys().eq(y.keys()) {
                    return Some(false);
                }
                for (p, q) in x.values().zip(y.values()) {
                    if !p.known_eq(q)? {
                        return Some(false);
                    }
                }
                true
            }
            (Known::Json(_), _) | (_, Known::Json(_)) => {
                return Some(self.to_str()? == other.to_str()?);
            }
            _ => false,
        })
    }

    /// Short type name for messages.
    pub fn type_name(&self) -> &'static str {
        match &self.kind {
            Kind::Known(k) => match k {
                Known::Null => "null",
                Known::Bool(_) => "bool",
                Known::Number(_) => "number",
                Known::String(_) | Known::Json(_) => "string",
                Known::List(_) => "list",
                Known::Object(_) => "object",
            },
            Kind::Unknown(_) => "unknown",
            Kind::Tainted(_) => "tainted",
            Kind::OneOf(_) => "one-of",
        }
    }
}

fn push_unique(v: &mut Vec<Value>, x: Value) {
    if x.is_wholly_known() && v.iter().any(|y| y.known_eq(&x) == Some(true)) {
        return;
    }
    v.push(x);
}

/// Terraform-style number formatting: integers without a fraction.
pub fn fmt_number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e17 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// Wholly-known value → JSON (`None` otherwise).
pub fn to_json(v: &Value) -> Option<serde_json::Value> {
    use serde_json::Value as J;
    Some(match v.as_known()? {
        Known::Null => J::Null,
        Known::Bool(b) => J::Bool(*b),
        Known::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 9.0e15 {
                J::from(*n as i64)
            } else {
                serde_json::Number::from_f64(*n).map(J::Number)?
            }
        }
        Known::String(s) => J::String(s.to_string()),
        Known::List(l) => J::Array(l.iter().map(to_json).collect::<Option<_>>()?),
        Known::Object(m) => J::Object(
            m.iter()
                .map(|(k, v)| Some((k.to_string(), to_json(v)?)))
                .collect::<Option<_>>()?,
        ),
        Known::Json(inner) => J::String(to_json(inner)?.to_string()),
    })
}

/// JSON → Known value; every node gets `prov`.
pub fn from_json(j: &serde_json::Value, prov: &Prov) -> Value {
    use serde_json::Value as J;
    let v = match j {
        J::Null => Value::null(),
        J::Bool(b) => Value::bool(*b),
        J::Number(n) => Value::number(n.as_f64().unwrap_or(f64::NAN)),
        J::String(s) => Value::string(s.as_str()),
        J::Array(a) => Value::list(a.iter().map(|x| from_json(x, &Prov::EMPTY)).collect()),
        J::Object(o) => Value::object(
            o.iter()
                .map(|(k, x)| (Arc::from(k.as_str()), from_json(x, &Prov::EMPTY)))
                .collect(),
        ),
    };
    v.with_prov(prov.clone())
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")?;
        if !self.prov.is_empty() {
            write!(f, " @{:?}", self.prov)?;
        }
        Ok(())
    }
}

/// Compact HCL-like rendering: `["0.0.0.0/0"]`, `{a = 1}`, `<unknown: ...>`,
/// `<tainted: var.x>`, `<one of: a | b>`.
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_sensitive() {
            return f.write_str("(sensitive)");
        }
        match &self.kind {
            Kind::Known(k) => match k {
                Known::Null => f.write_str("null"),
                Known::Bool(b) => write!(f, "{b}"),
                Known::Number(n) => f.write_str(&fmt_number(*n)),
                Known::String(s) => write!(f, "{s:?}"),
                Known::List(v) => {
                    f.write_str("[")?;
                    for (i, x) in v.iter().enumerate() {
                        if i > 0 {
                            f.write_str(", ")?;
                        }
                        write!(f, "{x}")?;
                    }
                    f.write_str("]")
                }
                Known::Object(m) => {
                    f.write_str("{")?;
                    for (i, (k, x)) in m.iter().enumerate() {
                        if i > 0 {
                            f.write_str(", ")?;
                        }
                        write!(f, "{k} = {x}")?;
                    }
                    f.write_str("}")
                }
                Known::Json(v) => write!(f, "jsonencode({v})"),
            },
            Kind::Unknown(o) => write!(f, "<unknown: {o}>"),
            Kind::Tainted(t) => write!(f, "<tainted: var.{}>", t.variable),
            Kind::OneOf(o) => {
                f.write_str("<one of: ")?;
                for (i, x) in o.alternatives.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" | ")?;
                    }
                    write!(f, "{x}")?;
                }
                f.write_str(">")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(std::mem::size_of::<Value>(), 32);
    }

    #[test]
    fn one_of_flattens() {
        let v = Value::one_of(
            vec![
                Value::string("a"),
                Value::one_of(vec![Value::string("a"), Value::string("b")], true),
            ],
            false,
        );
        match &v.kind {
            Kind::OneOf(o) => {
                assert_eq!(o.alternatives.len(), 2);
                assert!(o.tainted);
            }
            _ => panic!(),
        }
        assert_eq!(
            Value::one_of(vec![Value::bool(true), Value::bool(true)], false).as_bool(),
            Some(true)
        );
    }
}

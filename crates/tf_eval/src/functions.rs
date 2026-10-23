//! Terraform built-in functions over the abstract lattice.
//!
//! Conventions:
//! - A top-level `OneOf` argument is lifted generically: the function runs
//!   once per combination (bounded by [`MAX_ALTERNATIVES`]) and the results
//!   form a `OneOf`.
//! - A function that needs a concrete argument and gets Unknown / Tainted
//!   returns that argument's kind (Error > Unknown > Tainted when several).
//! - Functions that only shuffle structure (`concat`, `merge`, `flatten`,
//!   `lookup`, `element`, `jsonencode`, ...) keep non-Known *elements* in
//!   place, so taint and provenance survive per element.
//! - A primitive result with no provenance of its own inherits the joined
//!   provenance of the arguments (`lower(var.x)` still points at `var.x`).
//! - Anything not implemented returns `Unknown { origin: UnsupportedFunction }`.
//!   `try` and `can` need lazy arguments and live in the evaluator.

use crate::collections::{self, Buffer};
use crate::meter;
use crate::text::{self, Text};
use std::collections::BTreeMap;
use std::sync::Arc;
use tf_limits::input::InputBudget;

use crate::eval::{MAX_ALTERNATIVES, dominant_non_known, non_known_or};
use crate::prov::Prov;
use crate::value::{Kind, Known, Map, Origin, Value, from_json};

mod conversions;
mod encoding;
mod networking;
mod numbers;
mod strings;
mod structural;
use conversions::*;
pub use encoding::*;
use networking::*;
use numbers::*;
use strings::*;
use structural::*;

/// Every function name `call` implements (plus `try` / `can` in the
/// evaluator).
pub const SUPPORTED: &[&str] = &[
    "abs",
    "alltrue",
    "anytrue",
    "base64decode",
    "base64encode",
    "base64sha256",
    "base64sha512",
    "basename",
    "can",
    "ceil",
    "chomp",
    "chunklist",
    "cidrhost",
    "cidrnetmask",
    "cidrsubnet",
    "cidrsubnets",
    "coalesce",
    "coalescelist",
    "compact",
    "concat",
    "contains",
    "dirname",
    "distinct",
    "element",
    "endswith",
    "flatten",
    "floor",
    "format",
    "formatlist",
    "indent",
    "index",
    "join",
    "jsondecode",
    "jsonencode",
    "keys",
    "length",
    "log",
    "lookup",
    "lower",
    "matchkeys",
    "max",
    "merge",
    "min",
    "md5",
    "nonsensitive",
    "one",
    "parseint",
    "pow",
    "range",
    "regex",
    "replace",
    "reverse",
    "sensitive",
    "setintersection",
    "setproduct",
    "setsubtract",
    "setunion",
    "sha1",
    "sha256",
    "sha512",
    "signum",
    "slice",
    "sort",
    "split",
    "startswith",
    "strcontains",
    "strrev",
    "substr",
    "sum",
    "title",
    "tobool",
    "tolist",
    "tomap",
    "tonumber",
    "toset",
    "tostring",
    "transpose",
    "trim",
    "trimprefix",
    "trimspace",
    "trimsuffix",
    "try",
    "upper",
    "urlencode",
    "values",
    "zipmap",
];

pub fn is_supported(name: &str) -> bool {
    SUPPORTED.contains(&name) || CONTEXTUAL.contains(&name)
}

/// Implemented by the module resolver, which owns file access and root paths.
pub const CONTEXTUAL: &[&str] = &[
    "abspath",
    "file",
    "filebase64",
    "filemd5",
    "filesha1",
    "filesha256",
    "filesha512",
    "filebase64sha256",
    "filebase64sha512",
    "templatefile",
];

type R = Result<Value, Value>;

/// Bound both indentation workspace and the final string, as for regex inputs.
pub use tf_limits::INDENT_BYTES_MAX;
/// Retain the existing row ceiling, and bound wide tuples independently.
pub use tf_limits::PRODUCT_ROWS_MAX;
/// At 32 bytes per Value, at most 2 MiB of tuple elements are materialized.
pub use tf_limits::PRODUCT_VALUES_MAX;

// Parser vectors need at most four slots per element; the abstract copy needs
// one. Include both map-entry representations. JSON nodes cannot outnumber bytes.
const JSON_COLLECTION_BYTES_PER_INPUT_BYTE: usize = 4 * std::mem::size_of::<serde_json::Value>()
    + std::mem::size_of::<Value>()
    + std::mem::size_of::<(String, serde_json::Value)>()
    + std::mem::size_of::<(Arc<str>, Value)>();

const _: () = assert!(PRODUCT_ROWS_MAX <= PRODUCT_VALUES_MAX);
const _: () = assert!(INDENT_BYTES_MAX < u32::MAX as usize);

pub fn call(name: &str, args: Vec<Value>) -> Value {
    call_budgeted(name, args, &InputBudget::default())
}

pub fn call_budgeted(name: &str, args: Vec<Value>, budget: &InputBudget) -> Value {
    call_with_budget(
        name,
        args,
        budget,
        &|name, args| match dispatch(name, args, budget) {
            Ok(v) | Err(v) => v,
        },
    )
}

/// Lift a contextual function over alternatives and retain argument marks.
/// Filesystem functions use the same uncertainty and provenance rules as pure ones.
pub fn call_with(
    name: &str,
    args: Vec<Value>,
    dispatch: &dyn Fn(&str, &[Value]) -> Value,
) -> Value {
    call_with_budget(name, args, &InputBudget::default(), dispatch)
}

pub fn call_with_budget(
    name: &str,
    args: Vec<Value>,
    budget: &InputBudget,
    dispatch: &dyn Fn(&str, &[Value]) -> Value,
) -> Value {
    match lift_call(name, &args, budget, dispatch) {
        Ok(value) => value,
        Err(value) => match value.origin() {
            Some(Origin::Limit(message)) => {
                Value::limit_from(message.clone(), args.iter().chain([&value]))
            }
            _ => value,
        },
    }
}

fn lift_call(
    name: &str,
    args: &[Value],
    budget: &InputBudget,
    dispatch: &dyn Fn(&str, &[Value]) -> Value,
) -> R {
    collections::admit::<Value>(0, budget)?;
    if !args.iter().any(|a| matches!(a.kind, Kind::OneOf(_))) {
        return Ok(call1(name, args, budget, dispatch));
    }
    let count = args
        .iter()
        .try_fold(1usize, |count, value| {
            count
                .checked_mul(value.alternative_count())
                .filter(|&n| n <= MAX_ALTERNATIVES)
        })
        .ok_or_else(|| Value::limit(format!("{name}: too many alternatives")))?;
    let mut results = Buffer::with_capacity(count, budget)?;
    let tainted = count != 0
        && args
            .iter()
            .any(|a| matches!(&a.kind, Kind::OneOf(o) if o.tainted));
    let mut established = None;
    let attempt = (|| {
        // Enumerate each complete argument row once, avoiding repeated prefix copies.
        for index in 0..count {
            let mut divisor = count;
            let row = collections::collect(
                args.iter().map(|arg| {
                    divisor /= arg.alternative_count();
                    match &arg.kind {
                        Kind::OneOf(o) => {
                            o.alternatives[index / divisor % o.alternatives.len()].child_of(arg)
                        }
                        _ => arg.clone(),
                    }
                }),
                budget,
            )?;
            let result = call1(name, &row, budget, dispatch);
            if established.is_none() && crate::eval::contains_error(&result) {
                established = Some(result.clone());
            }
            if budget.exhaustion().is_some() {
                return Ok(established.take().unwrap_or(result));
            }
            results.push(result)?;
        }
        collections::one_of(results.finish(), tainted, budget)
    })();
    attempt.map_err(|limit| established.unwrap_or(limit))
}

fn call1(
    name: &str,
    args: &[Value],
    budget: &InputBudget,
    dispatch: &dyn Fn(&str, &[Value]) -> Value,
) -> Value {
    let mut r = dispatch(name, args);
    if let Some(error) = budget.exhaustion()
        && !crate::eval::contains_error(&r)
    {
        return Value::limit_from(error.to_string(), args.iter().chain([&r]));
    }
    if let Some(Origin::Limit(message)) = r.origin() {
        return Value::limit_from(message.clone(), args.iter().chain([&r]));
    }
    if name == "nonsensitive" {
        return r;
    }
    for a in args {
        r = r.inherit_sensitive(a);
    }
    // Primitive results inherit the arguments' provenance.
    if r.prov.is_empty()
        && matches!(
            r.kind,
            Kind::Known(Known::String(_) | Known::Number(_) | Known::Bool(_))
                | Kind::Tainted(_)
                | Kind::Unknown(_)
        )
    {
        let mut p = Prov::EMPTY;
        for a in args {
            p = p.joined(&a.prov);
        }
        return r.with_prov(p);
    }
    r
}

fn dispatch(name: &str, a: &[Value], budget: &InputBudget) -> R {
    budget
        .admit_text(0)
        .map_err(|e| Value::limit(e.to_string()))?;
    // Each group falls through to the next; the last reports the function unsupported.
    structural(name, a, budget)
}

// ---- argument helpers ------------------------------------------------------
fn num(n: f64) -> Value {
    Value::number(n)
}

fn arity(a: &[Value], n: usize) -> Result<(), Value> {
    if a.len() == n {
        Ok(())
    } else {
        Err(Value::error(format!(
            "expected {n} arguments, got {}",
            a.len()
        )))
    }
}

fn one_arg(a: &[Value]) -> Result<&Value, Value> {
    arity(a, 1)?;
    Ok(&a[0])
}

fn known(v: &Value) -> Result<&Known, Value> {
    v.as_known().ok_or_else(|| non_known_or(v, ""))
}

fn number(v: &Value) -> Result<f64, Value> {
    match &v.kind {
        Kind::Known(_) => v
            .as_number()
            .ok_or_else(|| Value::error(format!("expected number, got {}", v.type_name()))),
        _ => Err(non_known_or(v, "")),
    }
}

fn list(v: &Value) -> Result<&[Value], Value> {
    match &v.kind {
        Kind::Known(Known::List(l)) => Ok(l),
        Kind::Known(_) => Err(Value::error(format!(
            "expected list, got {}",
            v.type_name()
        ))),
        _ => Err(non_known_or(v, "")),
    }
}

fn obj(v: &Value) -> Result<&Map, Value> {
    match &v.kind {
        Kind::Known(Known::Object(m)) => Ok(m),
        Kind::Known(_) => Err(Value::error(format!(
            "expected map/object, got {}",
            v.type_name()
        ))),
        _ => Err(non_known_or(v, "")),
    }
}

fn flatten_into(v: &Value, out: &mut Buffer<Value>, budget: &InputBudget) -> Result<(), Value> {
    let mut stack = Buffer::new(budget);
    stack.push((v.clone(), 0usize))?;
    while let Some((parent, index)) = stack.last_mut() {
        let items = list(parent)?;
        let Some(item) = items.get(*index) else {
            stack.pop();
            continue;
        };
        *index += 1;
        let item = item.child_of(parent);
        match &item.kind {
            Kind::Known(Known::List(_)) => {
                if stack.len() >= tf_limits::EVALUATION_DEPTH_MAX {
                    return Err(Value::limit("flatten: collection nesting limit"));
                }
                stack.push((item, 0))?;
            }
            Kind::Known(_) => out.push(item)?,
            _ => return Err(non_known_or(&item, "")),
        }
    }
    Ok(())
}

/// Index lookups do not scan their collection, so they are not metered by size.
pub(crate) fn scans_arguments(name: &str) -> bool {
    !matches!(name, "lookup" | "element")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        assert_eq!(cidrsubnet("10.0.0.0/16", 8, 2).unwrap(), "10.0.2.0/24");
        assert_eq!(cidrsubnet("172.16.0.0/12", 4, 15).unwrap(), "172.31.0.0/16");
        assert_eq!(
            cidrsubnet("fd00:fd12:3456:7890::/56", 16, 162).unwrap(),
            "fd00:fd12:3456:7800:a200::/72"
        );
        assert_eq!(cidrhost("10.12.112.0/20", 16).unwrap(), "10.12.112.16");
        assert_eq!(cidrhost("10.12.112.0/20", 268).unwrap(), "10.12.113.12");
        assert_eq!(
            cidrsubnets("10.1.0.0/16", &[4, 4, 8, 4]).unwrap(),
            [
                "10.1.0.0/20",
                "10.1.16.0/20",
                "10.1.32.0/24",
                "10.1.48.0/20"
            ]
        );
    }

    #[test]
    fn b64() {
        assert_eq!(b64encode(b"Hello World"), "SGVsbG8gV29ybGQ=");
        assert_eq!(
            b64decode("SGVsbG8gV29ybGQ=", &InputBudget::default())
                .unwrap()
                .unwrap(),
            b"Hello World"
        );
    }

    #[test]
    fn fmt() {
        let r = format(
            "%s-%d-%v %%",
            &[Value::string("a"), Value::number(3.0), Value::bool(true)],
            &InputBudget::default(),
        )
        .unwrap();
        assert_eq!(&*r, "a-3-true %");
    }
}

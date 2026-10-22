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

#[expect(clippy::too_many_lines)]
fn dispatch(name: &str, a: &[Value], budget: &InputBudget) -> R {
    budget
        .admit_text(0)
        .map_err(|e| Value::limit(e.to_string()))?;
    let string = |value: &Value| text::coerce(value, budget);
    match name {
        // ---- structural / collections
        "length" => {
            arity(a, 1)?;
            match known(&a[0])? {
                Known::List(l) => Ok(num(l.len() as f64)),
                Known::Object(m) => Ok(num(m.len() as f64)),
                Known::String(s) => Ok(num(s.chars().count() as f64)),
                _ => Err(Value::error(
                    "length: argument must be a collection or string",
                )),
            }
        }
        "concat" => {
            let mut out = Buffer::new(budget);
            for x in a {
                let items = list(x)?;
                out.reserve(items.len())?;
                for item in items {
                    out.push(item.child_of(x))?;
                }
            }
            Ok(Value::list(out.finish()))
        }
        "merge" => {
            let mut m = Map::new();
            for x in a {
                if x.is_null() {
                    continue;
                }
                for (k, v) in obj(x)? {
                    collections::insert(&mut m, k.clone(), v.child_of(x), budget)?;
                }
            }
            Ok(Value::object(m))
        }
        "lookup" => {
            if a.len() < 2 || a.len() > 3 {
                return Err(Value::error("lookup: wrong number of arguments"));
            }
            let m = obj(&a[0])?;
            match string(&a[1]) {
                Ok(k) => match m.get(&*k) {
                    Some(v) => Ok(v.child_of(&a[0])),
                    None => match a.get(2) {
                        Some(d) => Ok(d.clone()),
                        None => Err(Value::error(format!("lookup: key \"{k}\" not found"))),
                    },
                },
                Err(limit) if budget.exhaustion().is_some() => Err(limit),
                Err(_) if a[1].is_known() => Err(Value::error("lookup: key must be a string")),
                Err(_) => {
                    // Unknown key into a known map: any of its values, or the default.
                    if m.len().saturating_add(usize::from(a.len() == 3)) > MAX_ALTERNATIVES {
                        return Err(Value::limit("lookup: too many alternatives"));
                    }
                    let mut alts = Buffer::with_capacity(
                        m.len().saturating_add(usize::from(a.len() == 3)),
                        budget,
                    )?;
                    for value in m.values() {
                        alts.push(value.child_of(&a[0]))?;
                    }
                    if let Some(d) = a.get(2) {
                        alts.push(d.clone())?;
                    }
                    if alts.is_empty() {
                        return Err(a[1].clone());
                    }
                    collections::one_of(alts.finish(), a[1].is_tainted(), budget)
                }
            }
        }
        "element" => {
            arity(a, 2)?;
            let l = list(&a[0])?;
            let i = number(&a[1])?;
            if l.is_empty() {
                return Err(Value::error("element: empty list"));
            }
            let idx = (i.floor() as i64).rem_euclid(l.len() as i64) as usize;
            Ok(l[idx].child_of(&a[0]))
        }
        "keys" => {
            arity(a, 1)?;
            Ok(Value::list(collections::collect(
                obj(&a[0])?.keys().map(|k| Value::string(k.clone())),
                budget,
            )?))
        }
        "values" => {
            arity(a, 1)?;
            Ok(Value::list(collections::collect(
                obj(&a[0])?.values().map(|v| v.child_of(&a[0])),
                budget,
            )?))
        }
        "contains" => {
            arity(a, 2)?;
            let l = list(&a[0])?;
            let mut pending = Buffer::new(budget);
            for e in l {
                let equal = e.known_eq(&a[1]);
                meter::check()?;
                match equal {
                    Some(true) => return Ok(Value::bool(true)),
                    Some(false) => {}
                    None => pending.push(e.clone())?,
                }
            }
            if let Some(v) = dominant_non_known(pending.iter().chain(std::iter::once(&a[1]))) {
                return Err(v);
            }
            if !pending.is_empty() {
                return Err(Value::other("contains: partially unknown element"));
            }
            Ok(Value::bool(false))
        }
        "index" => {
            arity(a, 2)?;
            let l = list(&a[0])?;
            for (i, e) in l.iter().enumerate() {
                let equal = e.known_eq(&a[1]);
                meter::check()?;
                match equal {
                    Some(true) => return Ok(num(i as f64)),
                    Some(false) => {}
                    None => return Err(non_known_or(e, "index: unknown element")),
                }
            }
            Err(Value::error("index: item not found"))
        }
        "flatten" => {
            arity(a, 1)?;
            let mut out = Buffer::new(budget);
            flatten_into(&a[0], &mut out, budget)?;
            Ok(Value::list(out.finish()))
        }
        "distinct" | "toset" => {
            arity(a, 1)?;
            if a[0].is_null() && name == "toset" {
                return Ok(Value::null());
            }
            let l = list(&a[0])?;
            let mut out: Buffer<Value> = Buffer::new(budget);
            for e in l {
                if e.is_wholly_known() && contains_equal(&out, e)? {
                    continue;
                }
                out.push(e.child_of(&a[0]))?;
            }
            if name == "toset" && out.iter().all(|e| e.as_str().is_some()) {
                out.sort_unstable_by(|x, y| x.as_str().cmp(&y.as_str()));
            }
            Ok(Value::list(out.finish()))
        }
        "tolist" => {
            arity(a, 1)?;
            if a[0].is_null() {
                return Ok(Value::null());
            }
            list(&a[0])?;
            Ok(a[0].clone())
        }
        "tomap" => {
            arity(a, 1)?;
            if a[0].is_null() {
                return Ok(Value::null());
            }
            obj(&a[0])?;
            Ok(a[0].clone())
        }
        "compact" => {
            arity(a, 1)?;
            let l = list(&a[0])?;
            let mut out = Buffer::with_capacity(l.len(), budget)?;
            for e in l {
                if !(e.is_null() || e.as_str() == Some("")) {
                    out.push(e.child_of(&a[0]))?;
                }
            }
            Ok(Value::list(out.finish()))
        }
        "coalesce" => {
            for x in a {
                match &x.kind {
                    Kind::Known(Known::Null) => continue,
                    Kind::Known(Known::String(s)) if s.is_empty() => continue,
                    Kind::Known(_) => return Ok(x.clone()),
                    _ => return Err(x.clone()),
                }
            }
            Err(Value::error("coalesce: no non-null, non-empty argument"))
        }
        "coalescelist" => {
            for x in a {
                match list(x) {
                    Ok([]) => continue,
                    Ok(_) => return Ok(x.clone()),
                    Err(e) => return Err(e),
                }
            }
            Err(Value::error("coalescelist: all lists empty"))
        }
        "reverse" => {
            arity(a, 1)?;
            let mut l =
                collections::collect(list(&a[0])?.iter().map(|e| e.child_of(&a[0])), budget)?;
            l.reverse();
            Ok(Value::list(l))
        }
        "slice" => {
            arity(a, 3)?;
            let l = list(&a[0])?;
            let (s, e) = (number(&a[1])? as usize, number(&a[2])? as usize);
            if s > e || e > l.len() {
                return Err(Value::error("slice: index out of range"));
            }
            Ok(Value::list(collections::collect(
                l[s..e].iter().map(|x| x.child_of(&a[0])),
                budget,
            )?))
        }
        "sort" => {
            arity(a, 1)?;
            let l = list(&a[0])?;
            let mut ss = Buffer::with_capacity(l.len(), budget)?;
            for e in l {
                ss.push(string(e)?)?;
            }
            ss.sort_unstable();
            Ok(Value::list(collections::collect(
                ss.finish().into_iter().map(Value::string),
                budget,
            )?))
        }
        "range" => {
            let ns = collections::try_collect(a.iter().map(number), budget)?;
            let (start, end, step) = match ns.as_slice() {
                [e] => (0.0, *e, 1.0),
                [s, e] => (*s, *e, if s <= e { 1.0 } else { -1.0 }),
                [s, e, st] => (*s, *e, *st),
                _ => return Err(Value::error("range: wrong number of arguments")),
            };
            if step == 0.0 {
                return Err(Value::error("range: step must not be zero"));
            }
            let mut out = Buffer::new(budget);
            let mut x = start;
            while (step > 0.0 && x < end) || (step < 0.0 && x > end) {
                if out.len() == 1024 {
                    return Err(Value::limit("range: too large"));
                }
                out.push(num(x))?;
                x += step;
            }
            Ok(Value::list(out.finish()))
        }
        "zipmap" => {
            arity(a, 2)?;
            let (ks, vs) = (list(&a[0])?, list(&a[1])?);
            if ks.len() != vs.len() {
                return Err(Value::error("zipmap: lists differ in length"));
            }
            let mut m = Map::new();
            for (k, v) in ks.iter().zip(vs.iter()) {
                collections::insert(&mut m, string(k)?, v.child_of(&a[1]), budget)?;
            }
            Ok(Value::object(m))
        }
        "one" => {
            arity(a, 1)?;
            let l = list(&a[0])?;
            match l.len() {
                0 => Ok(Value::null()),
                1 => Ok(l[0].child_of(&a[0])),
                _ => Err(Value::error("one: more than one element")),
            }
        }
        "chunklist" => {
            arity(a, 2)?;
            let l = list(&a[0])?;
            let n = number(&a[1])? as usize;
            if n == 0 {
                return Ok(Value::list(collections::collect(
                    std::iter::once(a[0].clone()),
                    budget,
                )?));
            }
            Ok(Value::list(collections::try_collect(
                l.chunks(n).map(|c| {
                    collections::collect(c.iter().map(|x| x.child_of(&a[0])), budget)
                        .map(Value::list)
                }),
                budget,
            )?))
        }
        "setunion" | "setintersection" | "setsubtract" => {
            if a.is_empty() {
                return Err(Value::error("set function: no arguments"));
            }
            let mut sets = Buffer::with_capacity(a.len(), budget)?;
            for x in a {
                let l = list(x)?;
                if let Some(nk) = dominant_non_known(l.iter()) {
                    return Err(nk);
                }
                sets.push(collections::collect(
                    l.iter().map(|e| e.child_of(x)),
                    budget,
                )?)?;
            }
            let has = contains_equal;
            let mut out: Buffer<Value> = Buffer::new(budget);
            match name {
                "setunion" => {
                    for s in sets.iter() {
                        for v in s {
                            if !has(&out, v)? {
                                out.push(v.clone())?;
                            }
                        }
                    }
                }
                "setintersection" => {
                    for v in &sets[0] {
                        if all_contain(&sets[1..], v)? && !has(&out, v)? {
                            out.push(v.clone())?;
                        }
                    }
                }
                _ => {
                    for v in &sets[0] {
                        if !any_contains(&sets[1..], v)? && !has(&out, v)? {
                            out.push(v.clone())?;
                        }
                    }
                }
            }
            Ok(Value::list(out.finish()))
        }
        "setproduct" => setproduct(a, budget),
        "matchkeys" => {
            arity(a, 3)?;
            let (vals, keys, search) = (list(&a[0])?, list(&a[1])?, list(&a[2])?);
            let mut out = Buffer::new(budget);
            for (v, k) in vals.iter().zip(keys.iter()) {
                let mut hit = false;
                for s in search {
                    let equal = k.known_eq(s);
                    meter::check()?;
                    match equal {
                        Some(true) => hit = true,
                        Some(false) => {}
                        None => return Err(non_known_or(k, "matchkeys: unknown key")),
                    }
                }
                if hit {
                    out.push(v.child_of(&a[0]))?;
                }
            }
            Ok(Value::list(out.finish()))
        }
        "transpose" => {
            arity(a, 1)?;
            let mut m: BTreeMap<Arc<str>, Buffer<Value>> = BTreeMap::new();
            for (k, v) in obj(&a[0])? {
                for e in list(v)? {
                    let key = string(e)?;
                    if !m.contains_key(&key) {
                        collections::insert(&mut m, key.clone(), Buffer::new(budget), budget)?;
                    }
                    m.get_mut(&key)
                        .expect("inserted group")
                        .push(Value::string(k.clone()))?;
                }
            }
            let mut out = Map::new();
            for (key, group) in m {
                collections::insert(&mut out, key, Value::list(group.finish()), budget)?;
            }
            Ok(Value::object(out))
        }
        "sum" => {
            arity(a, 1)?;
            let mut s = 0.0;
            for e in list(&a[0])? {
                s += number(e)?;
            }
            Ok(num(s))
        }
        "alltrue" | "anytrue" => {
            arity(a, 1)?;
            let all = name == "alltrue";
            let mut pending = Buffer::new(budget);
            for e in list(&a[0])? {
                match e.as_bool() {
                    Some(b) if b != all => return Ok(Value::bool(!all)),
                    Some(_) => {}
                    None => pending.push(e.clone())?,
                }
            }
            match dominant_non_known(pending.iter()) {
                Some(v) => Err(v),
                None if pending.is_empty() => Ok(Value::bool(all)),
                None => Err(Value::error(format!("{name}: non-bool element"))),
            }
        }
        // ---- numbers
        "max" | "min" => {
            let ns = collections::try_collect(a.iter().map(number), budget)?;
            if ns.is_empty() {
                return Err(Value::error(format!("{name}: no arguments")));
            }
            let r = if name == "max" {
                ns.iter().cloned().fold(f64::MIN, f64::max)
            } else {
                ns.iter().cloned().fold(f64::MAX, f64::min)
            };
            Ok(num(r))
        }
        "abs" => Ok(num(number(one_arg(a)?)?.abs())),
        "ceil" => Ok(num(number(one_arg(a)?)?.ceil())),
        "floor" => Ok(num(number(one_arg(a)?)?.floor())),
        "signum" => {
            let n = number(one_arg(a)?)?;
            Ok(num(if n > 0.0 {
                1.0
            } else if n < 0.0 {
                -1.0
            } else {
                0.0
            }))
        }
        "pow" => {
            arity(a, 2)?;
            Ok(num(number(&a[0])?.powf(number(&a[1])?)))
        }
        "log" => {
            arity(a, 2)?;
            Ok(num(number(&a[0])?.log(number(&a[1])?)))
        }
        "parseint" => {
            arity(a, 2)?;
            let s = string(&a[0])?;
            let base = number(&a[1])?;
            if !(2.0..=36.0).contains(&base) || base.fract() != 0.0 {
                return Err(Value::error(
                    "parseint: base must be a whole number between 2 and 36",
                ));
            }
            i64::from_str_radix(&s, base as u32)
                .map(|n| num(n as f64))
                .map_err(|_| Value::error("parseint: invalid number"))
        }
        // ---- strings
        "lower" | "upper" | "title" | "strrev" | "urlencode" => {
            let s = string(one_arg(a)?)?;
            let mut out = Text::new(budget);
            match name {
                "lower" => {
                    // str::to_lowercase preserves context-sensitive Greek final sigma.
                    // UTF-8 case mapping expands by at most three output bytes per input byte.
                    let maximum = s.len().checked_mul(3).ok_or_else(|| out.refused())?;
                    budget
                        .admit_text(maximum as u64)
                        .map_err(|e| Value::limit(e.to_string()))?;
                    let lowered = s.to_lowercase();
                    assert!(lowered.len() <= maximum);
                    return Ok(Value::string(text::copy(&lowered, budget)?));
                }
                "upper" => {
                    for c in s.chars().flat_map(char::to_uppercase) {
                        out.push(c)?;
                    }
                }
                "title" => {
                    let mut start = true;
                    for c in s.chars() {
                        if start && c.is_alphabetic() {
                            for c in c.to_uppercase() {
                                out.push(c)?;
                            }
                        } else {
                            out.push(c)?;
                        }
                        start = !c.is_alphanumeric();
                    }
                }
                "strrev" => {
                    for c in s.chars().rev() {
                        out.push(c)?;
                    }
                }
                "urlencode" => {
                    for b in s.bytes() {
                        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                            out.push(b as char)?;
                        } else {
                            out.formatted(format_args!("%{b:02X}"))?;
                        }
                    }
                }
                _ => unreachable!(),
            }
            Ok(Value::string(out.finish()?))
        }
        "basename" | "dirname" | "trimspace" | "chomp" => {
            let s = string(one_arg(a)?)?;
            let result = match name {
                "basename" => s.trim_end_matches('/').rsplit('/').next().unwrap_or(""),
                "dirname" => {
                    let t = s.trim_end_matches('/');
                    match t.rfind('/') {
                        Some(0) => "/",
                        Some(i) => &t[..i],
                        None => ".",
                    }
                }
                "trimspace" => s.trim(),
                "chomp" => s.trim_end_matches(['\n', '\r']),
                _ => unreachable!(),
            };
            Ok(Value::string(text::copy(result, budget)?))
        }
        "strcontains" | "startswith" | "endswith" => {
            arity(a, 2)?;
            let (s, p) = (string(&a[0])?, string(&a[1])?);
            Ok(Value::bool(match name {
                "strcontains" => s.contains(&*p),
                "startswith" => s.starts_with(&*p),
                "endswith" => s.ends_with(&*p),
                _ => unreachable!(),
            }))
        }
        "indent" => indent(a, budget),
        "md5" | "sha1" | "sha256" | "sha512" | "base64sha256" | "base64sha512" => {
            let input = string(one_arg(a)?)?;
            hash_budgeted(name, input.as_bytes(), budget)
        }
        "base64encode" => Ok(Value::string(b64encode_budgeted(
            string(one_arg(a)?)?.as_bytes(),
            budget,
        )?)),
        "base64decode" => {
            let s = string(one_arg(a)?)?;
            // Decoded bytes and UTF-8 output are each no larger than the encoded input.
            let decoded = b64decode(&s, budget)?
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| Value::error("base64decode: invalid input"))?;
            Ok(Value::string(text::copy(&decoded, budget)?))
        }
        "trim" | "trimprefix" | "trimsuffix" => {
            arity(a, 2)?;
            let (s, p) = (string(&a[0])?, string(&a[1])?);
            let result = match name {
                "trim" => s.trim_matches(|c| p.contains(c)),
                "trimprefix" => s.strip_prefix(&*p).unwrap_or(&s),
                "trimsuffix" => s.strip_suffix(&*p).unwrap_or(&s),
                _ => unreachable!(),
            };
            Ok(Value::string(text::copy(result, budget)?))
        }
        "replace" => replace(a, budget),
        "regex" => regex(a, budget),
        "split" => {
            arity(a, 2)?;
            let (sep, s) = (string(&a[0])?, string(&a[1])?);
            let mut out = Buffer::new(budget);
            for part in s.split(&*sep) {
                out.push(Value::string(text::copy(part, budget)?))?;
            }
            Ok(Value::list(out.finish()))
        }
        "join" => {
            if a.len() < 2 {
                return Err(Value::error("join: wrong number of arguments"));
            }
            let sep = string(&a[0])?;
            let mut out = Text::new(budget);
            let mut first = true;
            for l in &a[1..] {
                for e in list(l)? {
                    if !first {
                        out.push_str(&sep)?;
                    }
                    out.push_str(&string(e)?)?;
                    first = false;
                }
            }
            Ok(Value::string(out.finish()?))
        }
        "substr" => {
            arity(a, 3)?;
            let s = string(&a[0])?;
            let off = number(&a[1])? as i64;
            let len = number(&a[2])? as i64;
            let n = s.chars().count() as i64;
            let start = if off < 0 {
                n.saturating_add(off).max(0)
            } else {
                off.min(n)
            } as usize;
            let count = if len < 0 { usize::MAX } else { len as usize };
            let mut out = Text::new(budget);
            for c in s.chars().skip(start).take(count) {
                out.push(c)?;
            }
            Ok(Value::string(out.finish()?))
        }
        "format" => {
            if a.is_empty() {
                return Err(Value::error("format: missing format string"));
            }
            format(&string(&a[0])?, &a[1..], budget).map(Value::string)
        }
        "formatlist" => {
            if a.is_empty() {
                return Err(Value::error("formatlist: missing format string"));
            }
            let f = string(&a[0])?;
            let mut n = None;
            for x in &a[1..] {
                if let Kind::Known(Known::List(l)) = &x.kind {
                    n = Some(l.len());
                } else if !x.is_known() {
                    return Err(x.clone());
                }
            }
            let mut out = Buffer::new(budget);
            for i in 0..n.unwrap_or(1) {
                let row = collections::collect(
                    a[1..].iter().map(|x| match x.as_list() {
                        Some(l) => l.get(i).cloned().unwrap_or_else(Value::null),
                        None => x.clone(),
                    }),
                    budget,
                )?;
                out.push(Value::string(format(&f, &row, budget)?))?;
            }
            Ok(Value::list(out.finish()))
        }
        // ---- conversions
        "tostring" => {
            let v = one_arg(a)?;
            if v.is_null() {
                return Ok(Value::null());
            }
            Ok(Value::string(string(v)?))
        }
        "tonumber" => {
            let v = one_arg(a)?;
            if v.is_null() {
                return Ok(Value::null());
            }
            Ok(num(number(v)?))
        }
        "tobool" => {
            let v = one_arg(a)?;
            if v.is_null() {
                return Ok(Value::null());
            }
            match &v.kind {
                Kind::Known(_) => v
                    .as_bool()
                    .map(Value::bool)
                    .ok_or_else(|| Value::error("tobool: not a bool")),
                _ => Err(v.clone()),
            }
        }
        "sensitive" => Ok(one_arg(a)?.clone().sensitive()),
        "nonsensitive" => {
            let value = one_arg(a)?;
            collections::admit_tree_copy(value, budget)?;
            Ok(value.nonsensitive())
        }
        // ---- encoding
        "jsonencode" => {
            arity(a, 1)?;
            match &a[0].kind {
                Kind::Known(_) => encoded(a[0].clone(), budget),
                _ => Err(a[0].clone()),
            }
        }
        "jsondecode" => {
            arity(a, 1)?;
            if let Kind::Known(Known::Json(inner)) = &a[0].kind {
                return Ok((**inner).clone());
            }
            let s = string(&a[0])?;
            // Parser scratch, decoded strings/keys and their abstract-value copies.
            // Reserve parser and abstract container payload before either tree exists.
            collections::admit::<[u8; JSON_COLLECTION_BYTES_PER_INPUT_BYTE]>(s.len(), budget)?;
            let maximum = (s.len() as u64)
                .checked_mul(4)
                .ok_or_else(|| Value::limit(budget.text_refused().to_string()))?;
            budget
                .admit_text(maximum)
                .map_err(|e| Value::limit(e.to_string()))?;
            match serde_json::from_str::<serde_json::Value>(&s) {
                Ok(j) => Ok(from_json(&j, &a[0].prov)),
                Err(e) => Err(Value::error(format!("jsondecode: {e}"))),
            }
        }
        // ---- networking
        "cidrsubnet" => {
            network_text(budget, a.len())?;
            arity(a, 3)?;
            let (p, bits, n) = (string(&a[0])?, number(&a[1])?, number(&a[2])?);
            cidrsubnet(&p, bits as u32, n as u128)
                .map(Value::string)
                .map_err(Value::error)
        }
        "cidrsubnets" => {
            network_text(budget, a.len())?;
            if a.is_empty() {
                return Err(Value::error("cidrsubnets: missing prefix"));
            }
            let p = string(&a[0])?;
            let bits = collections::try_collect(
                a[1..].iter().map(|x| number(x).map(|n| n as u32)),
                budget,
            )?;
            // The network helper grows a Vec<String> geometrically, up to twice its length.
            collections::admit::<[String; 2]>(bits.len().max(2), budget)?;
            let subnets = cidrsubnets(&p, &bits).map_err(Value::error)?;
            Ok(Value::list(collections::collect(
                subnets.into_iter().map(Value::string),
                budget,
            )?))
        }
        "cidrhost" => {
            network_text(budget, a.len())?;
            arity(a, 2)?;
            let (p, h) = (string(&a[0])?, number(&a[1])?);
            cidrhost(&p, h as i128)
                .map(Value::string)
                .map_err(Value::error)
        }
        "cidrnetmask" => {
            network_text(budget, a.len())?;
            let p = string(one_arg(a)?)?;
            let (_, len, v6) = parse_cidr(&p).map_err(Value::error)?;
            if v6 {
                return Err(Value::error("cidrnetmask: IPv6 not supported"));
            }
            let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            Ok(Value::string(std::net::Ipv4Addr::from(mask).to_string()))
        }
        _ => Err(Value::unknown(Origin::UnsupportedFunction(name.into()))),
    }
}

// ---- argument helpers ------------------------------------------------------

fn setproduct(args: &[Value], budget: &InputBudget) -> R {
    if args.is_empty() {
        return Err(Value::error("setproduct: no arguments"));
    }
    if args.len() > PRODUCT_VALUES_MAX {
        return Err(Value::limit("setproduct: too many tuple elements"));
    }
    let lists = collections::try_collect(args.iter().map(list), budget)?;
    // An empty factor makes even an otherwise huge product empty.
    if lists.iter().any(|items| items.is_empty()) {
        return Ok(Value::list(Vec::new()));
    }
    let rows = lists.iter().try_fold(1usize, |rows, items| {
        rows.checked_mul(items.len())
            .filter(|&rows| rows <= PRODUCT_ROWS_MAX)
    });
    let rows = rows.ok_or_else(|| Value::limit("setproduct: too large"))?;
    let values = rows.checked_mul(args.len());
    if values.is_none_or(|values| values > PRODUCT_VALUES_MAX) {
        return Err(Value::limit("setproduct: too many tuple elements"));
    }
    assert!(rows <= PRODUCT_ROWS_MAX);
    let mut result = Buffer::with_capacity(rows, budget)?;
    let mut indices = collections::collect(std::iter::repeat_n(0, args.len()), budget)?;
    for _ in 0..rows {
        // Construct each final row once; repeated prefix cloning is quadratic in tuple width.
        let row = collections::collect(
            lists
                .iter()
                .zip(args)
                .zip(&indices)
                .map(|((items, arg), &index)| items[index].child_of(arg)),
            budget,
        )?;
        assert_eq!(row.len(), args.len());
        result.push(Value::list(row))?;
        for (index, items) in indices.iter_mut().zip(&lists).rev() {
            *index += 1;
            if *index < items.len() {
                break;
            }
            *index = 0;
        }
    }
    assert_eq!(result.len(), rows);
    Ok(Value::list(result.finish()))
}

fn indent(args: &[Value], budget: &InputBudget) -> R {
    let string = |v: &Value| text::coerce(v, budget);
    arity(args, 2)?;
    let width = number(&args[0])?;
    if !width.is_finite() || width < 0.0 || width.fract() != 0.0 {
        return Err(Value::error(
            "indent: width must be a nonnegative whole number",
        ));
    }
    let text = string(&args[1])?;
    if width > INDENT_BYTES_MAX as f64 {
        return Err(Value::limit("indent: padding too large"));
    }
    if text.len() > INDENT_BYTES_MAX {
        return Err(Value::limit("indent: input too large"));
    }
    let width = width as usize;
    let lines = text.bytes().filter(|&byte| byte == b'\n').count();
    let bytes = lines
        .checked_mul(width)
        .and_then(|padding| text.len().checked_add(padding));
    let bytes = bytes
        .filter(|&bytes| bytes <= INDENT_BYTES_MAX)
        .ok_or_else(|| Value::limit("indent: output too large"))?;
    assert!(width <= INDENT_BYTES_MAX);
    assert!(bytes <= INDENT_BYTES_MAX);
    if lines == 0 || width == 0 {
        return Ok(Value::string(text));
    }
    let mut result = Text::new(budget);
    result.reserve(bytes)?;
    for line in text.split_inclusive('\n') {
        result.push_str(line)?;
        if line.ends_with('\n') {
            for _ in 0..width {
                result.push(' ')?;
            }
        }
    }
    assert_eq!(result.as_str().len(), bytes);
    Ok(Value::string(result.finish()?))
}

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

/// Go-style `format` with the verbs Terraform supports most often.
fn format(f: &str, args: &[Value], budget: &InputBudget) -> Result<Arc<str>, Value> {
    let mut out = Text::new(budget);
    let mut it = f.char_indices().peekable();
    let mut ai = 0usize;
    while let Some((start, c)) = it.next() {
        if c != '%' {
            out.push(c)?;
            continue;
        }
        while let Some(&(_, d)) = it.peek() {
            if d.is_ascii_digit() || matches!(d, '.' | '-' | '+' | '#' | ' ') {
                it.next();
            } else {
                break;
            }
        }
        let Some((end, verb)) = it.next() else { break };
        if verb == '%' {
            out.push('%')?;
            continue;
        }
        let Some(arg) = args.get(ai) else {
            return Err(Value::error("format: not enough arguments"));
        };
        ai += 1;
        format_argument(&mut out, &f[start + 1..end], verb, arg, budget)?;
    }
    out.finish()
}

fn format_argument(
    out: &mut Text<'_>,
    spec: &str,
    verb: char,
    arg: &Value,
    budget: &InputBudget,
) -> Result<(), Value> {
    match verb {
        's' | 'v' => {
            let s = if verb == 'v'
                && matches!(arg.kind, Kind::Known(Known::List(_) | Known::Object(_)))
            {
                text::json(arg, budget)?
            } else {
                text::coerce(arg, budget)?
            };
            out.push_str(&s)
        }
        'q' => out.formatted(format_args!("{:?}", text::coerce(arg, budget)?)),
        'd' => out.formatted(format_args!("{}", number(arg)? as i64)),
        'f' | 'g' | 'e' => {
            let n = number(arg)?;
            match spec.split('.').nth(1) {
                Some(p) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
                    let p = p.parse::<usize>().map_err(|_| out.refused())?;
                    // Rust's formatter may allocate precision scratch internally. Reserve
                    // its maximum fixed-point payload before entering the formatter.
                    let maximum = p.checked_add(330).ok_or_else(|| out.refused())?;
                    budget
                        .admit_text(maximum as u64)
                        .map_err(|e| Value::limit(e.to_string()))?;
                    out.reserve(maximum)?;
                    out.formatted(format_args!("{n:.p$}"))
                }
                _ => out.push_str(&text::coerce(&Value::number(n), budget)?),
            }
        }
        't' => out.push_str(
            if arg
                .as_bool()
                .ok_or_else(|| non_known_or(arg, "format: %t needs bool"))?
            {
                "true"
            } else {
                "false"
            },
        ),
        _ => Err(Value::unknown(Origin::UnsupportedFunction(
            format!("format %{verb}").into(),
        ))),
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64encode(data: &[u8]) -> String {
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b64decode(s: &str, budget: &InputBudget) -> Result<Option<Vec<u8>>, Value> {
    budget
        .admit_text(s.len() as u64)
        .map_err(|e| Value::limit(e.to_string()))?;
    let mut out = Vec::new();
    out.try_reserve_exact(s.len())
        .map_err(|_| Value::limit(budget.text_refused().to_string()))?;
    let mut buf = 0u32;
    let mut bits = 0;
    for ch in s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=') {
        let Some(v) = B64.iter().position(|&x| x == ch) else {
            return Ok(None);
        };
        let v = v as u32;
        buf = buf << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits & 0xff) as u8);
        }
    }
    Ok(Some(out))
}

// ---- CIDR math -------------------------------------------------------------

fn parse_cidr(p: &str) -> Result<(u128, u32, bool), String> {
    let (addr, len) = p
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR \"{p}\""))?;
    let len: u32 = len
        .parse()
        .map_err(|_| format!("invalid prefix length in \"{p}\""))?;
    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        if len > 32 {
            return Err("prefix length > 32".into());
        }
        Ok((u32::from(v4) as u128, len, false))
    } else if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
        if len > 128 {
            return Err("prefix length > 128".into());
        }
        Ok((u128::from(v6), len, true))
    } else {
        Err(format!("invalid IP address in \"{p}\""))
    }
}

fn render(addr: u128, v6: bool) -> String {
    if v6 {
        std::net::Ipv6Addr::from(addr).to_string()
    } else {
        std::net::Ipv4Addr::from(addr as u32).to_string()
    }
}

fn cidrsubnet(p: &str, newbits: u32, netnum: u128) -> Result<String, String> {
    let (addr, len, v6) = parse_cidr(p)?;
    let total = if v6 { 128 } else { 32 };
    let nl = len + newbits;
    if nl > total {
        return Err(format!(
            "cidrsubnet: insufficient address space to extend prefix of {len} by {newbits}"
        ));
    }
    if newbits < 128 && netnum >= (1u128 << newbits) {
        return Err(format!(
            "cidrsubnet: netnum {netnum} does not fit in {newbits} bits"
        ));
    }
    let host_bits = total - nl;
    let mask = if len == 0 {
        0
    } else {
        (!0u128) << (128 - len) >> (128 - total)
    };
    let base = addr & mask & if v6 { !0u128 } else { 0xffff_ffff };
    let sub = if host_bits >= 128 {
        0
    } else {
        netnum << host_bits
    };
    Ok(format!("{}/{}", render(base | sub, v6), nl))
}

fn cidrsubnets(p: &str, bits: &[u32]) -> Result<Vec<String>, String> {
    let (addr, len, v6) = parse_cidr(p)?;
    let total = if v6 { 128 } else { 32 };
    let mask = if len == 0 {
        0
    } else {
        (!0u128) << (128 - len) >> (128 - total)
    };
    // Allocation starts at the network address and must stay inside the prefix.
    let base = addr & mask;
    let end = base
        + if total - len >= 128 {
            u128::MAX
        } else {
            (1u128 << (total - len)) - 1
        };
    let mut out = Vec::new();
    let mut cur = base;
    for &b in bits {
        let nl = len + b;
        if b == 0 || nl > total {
            return Err("cidrsubnets: not enough space".into());
        }
        let size = 1u128 << (total - nl);
        // align
        if cur % size != 0 {
            cur = (cur / size + 1)
                .checked_mul(size)
                .ok_or("cidrsubnets: not enough remaining address space")?;
        }
        if cur > end || end - cur < size - 1 {
            return Err("cidrsubnets: not enough remaining address space".into());
        }
        out.push(format!("{}/{}", render(cur, v6), nl));
        cur = cur.saturating_add(size);
    }
    Ok(out)
}

fn cidrhost(p: &str, h: i128) -> Result<String, String> {
    let (addr, len, v6) = parse_cidr(p)?;
    let total = if v6 { 128 } else { 32 };
    let host_bits = total - len;
    let size: i128 = if host_bits >= 127 {
        i128::MAX
    } else {
        1i128 << host_bits
    };
    if h >= size || h < -size {
        return Err("cidrhost: host number out of range".into());
    }
    let mask = if len == 0 {
        0
    } else {
        (!0u128) << (128 - len) >> (128 - total)
    };
    let base = addr & mask;
    let off = if h >= 0 { h } else { size + h } as u128;
    Ok(render(base + off, v6))
}

fn regex_limit() -> Value {
    Value::unknown(Origin::Limit("regular expression budget exceeded".into()))
}

fn regex_input(input: &str) -> Result<(), Value> {
    if input.len() > 1_048_576 {
        Err(regex_limit())
    } else {
        Ok(())
    }
}

/// RE2 uses ASCII Perl classes and word boundaries, with Unicode literals and
/// explicit Unicode properties. Translate those escapes before compiling.
fn terraform_regex(pattern: &str) -> Result<regex::Regex, Value> {
    if pattern.len() > 16_384 {
        return Err(regex_limit());
    }
    let mut translated = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            translated.push(ch);
            continue;
        }
        match chars.next() {
            Some('Q') => {
                let mut quoted = String::new();
                while let Some(ch) = chars.next() {
                    if ch == '\\' && chars.peek() == Some(&'E') {
                        chars.next();
                        break;
                    }
                    quoted.push(ch);
                }
                translated.push_str(&regex::escape(&quoted));
            }
            Some('d') => translated.push_str("[0-9]"),
            Some('D') => translated.push_str("[^0-9]"),
            Some('w') => translated.push_str("[0-9A-Za-z_]"),
            Some('W') => translated.push_str("[^0-9A-Za-z_]"),
            Some('s') => translated.push_str("[\\t\\n\\f\\r ]"),
            Some('S') => translated.push_str("[^\\t\\n\\f\\r ]"),
            Some(ch @ ('b' | 'B')) => translated.push_str(&format!("(?-u:\\{ch})")),
            Some(ch) => {
                translated.push('\\');
                translated.push(ch);
            }
            None => translated.push('\\'),
        }
    }
    regex::RegexBuilder::new(&translated)
        .size_limit(1_048_576)
        .dfa_size_limit(1_048_576)
        .build()
        .map_err(|e| match e {
            regex::Error::CompiledTooBig(_) => regex_limit(),
            _ => Value::error("invalid regular expression"),
        })
}

/// Hash raw file bytes without decoding binary files as UTF-8.
pub fn hash_bytes(name: &str, bytes: &[u8]) -> Option<String> {
    use sha2::Digest;
    let digest = match name {
        "md5" => md5::Md5::digest(bytes).to_vec(),
        "sha1" => sha1::Sha1::digest(bytes).to_vec(),
        "sha256" | "base64sha256" => sha2::Sha256::digest(bytes).to_vec(),
        "sha512" | "base64sha512" => sha2::Sha512::digest(bytes).to_vec(),
        _ => return None,
    };
    Some(if name.starts_with("base64") {
        b64encode(&digest)
    } else {
        digest.iter().map(|b| format!("{b:02x}")).collect()
    })
}

fn replace(a: &[Value], budget: &InputBudget) -> R {
    arity(a, 3)?;
    let (s, sub, rep) = (
        text::coerce(&a[0], budget)?,
        text::coerce(&a[1], budget)?,
        text::coerce(&a[2], budget)?,
    );
    if sub.len() > 1 && sub.starts_with('/') && sub.ends_with('/') {
        return replace_regex(&s, &sub[1..sub.len() - 1], &rep, budget);
    }
    let mut out = Text::new(budget);
    let mut end = 0;
    for (start, matched) in s.match_indices(&*sub) {
        out.push_str(&s[end..start])?;
        out.push_str(&rep)?;
        end = start + matched.len();
    }
    out.push_str(&s[end..])?;
    Ok(Value::string(out.finish()?))
}

fn replace_regex(s: &str, pattern: &str, rep: &str, budget: &InputBudget) -> R {
    let re = terraform_regex(pattern)?;
    regex_input(s)?;
    regex_input(rep)?;
    let mut out = Text::new(budget);
    let mut end = 0;
    for (i, captures) in re.captures_iter(s).enumerate() {
        if i >= 16_384 {
            return Err(regex_limit());
        }
        let longest = captures
            .iter()
            .flatten()
            .map(|m| m.len())
            .max()
            .unwrap_or(0);
        let maximum = rep.len().saturating_mul(longest.saturating_add(1));
        if maximum > 1_048_576 {
            return Err(regex_limit());
        }
        let matched = captures.get(0).unwrap();
        out.push_str(&s[end..matched.start()])?;
        out.generated(maximum, |output| captures.expand(rep, output))?;
        regex_input(out.as_str())?;
        end = matched.end();
    }
    out.push_str(&s[end..])?;
    regex_input(out.as_str())?;
    Ok(Value::string(out.finish()?))
}

fn regex(a: &[Value], budget: &InputBudget) -> R {
    arity(a, 2)?;
    let (pattern, input) = (text::coerce(&a[0], budget)?, text::coerce(&a[1], budget)?);
    let re = terraform_regex(&pattern)?;
    regex_input(&input)?;
    let names = collections::collect(re.capture_names().skip(1), budget)?;
    if names.iter().any(Option::is_some) && names.iter().any(Option::is_none) {
        return Err(Value::error(
            "regex: cannot mix named and unnamed capture groups",
        ));
    }
    let captures = re
        .captures(&input)
        .ok_or_else(|| Value::error("regex: pattern did not match"))?;
    let capture = |i| -> R {
        match captures.get(i) {
            Some(m) => Ok(Value::string(text::copy(m.as_str(), budget)?)),
            None => Ok(Value::null()),
        }
    };
    Ok(if names.is_empty() {
        capture(0)?
    } else if names[0].is_some() {
        let mut out = Map::new();
        for (i, name) in names.iter().enumerate() {
            collections::insert(
                &mut out,
                text::copy(name.unwrap(), budget)?,
                capture(i + 1)?,
                budget,
            )?;
        }
        Value::object(out)
    } else {
        Value::list(collections::try_collect(
            (1..captures.len()).map(capture),
            budget,
        )?)
    })
}

pub fn b64encode_budgeted(data: &[u8], budget: &InputBudget) -> Result<Arc<str>, Value> {
    let mut out = Text::new(budget);
    let bytes = data
        .len()
        .checked_add(2)
        .and_then(|n| (n / 3).checked_mul(4))
        .ok_or_else(|| out.refused())?;
    out.reserve(bytes)?;
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() {
                B64[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            })?;
        }
    }
    assert_eq!(out.as_str().len(), bytes);
    out.finish()
}

pub fn hash_budgeted(name: &str, bytes: &[u8], budget: &InputBudget) -> R {
    // Digests are fixed size; include encoding temporaries and final string payload.
    budget
        .admit_text(1024)
        .map_err(|e| Value::limit(e.to_string()))?;
    Ok(Value::string(
        hash_bytes(name, bytes).expect("validated hash function"),
    ))
}

fn network_text(budget: &InputBudget, count: usize) -> Result<(), Value> {
    let bytes = (count as u64)
        .checked_mul(128)
        .and_then(|n| n.checked_add(512))
        .ok_or_else(|| Value::limit(budget.text_refused().to_string()))?;
    budget
        .admit_text(bytes)
        .map_err(|e| Value::limit(e.to_string()))
}

/// Admit potential JSON text before exposing a structured encoding to predicates
/// and projections that may materialize it later. Unknown children stay structured.
pub fn encoded(value: Value, budget: &InputBudget) -> R {
    if let Err(stopped) = text::json(&value, budget)
        && let Some(Origin::Limit(message)) = stopped.origin()
    {
        return Err(Value::limit_from(message.clone(), [&value]));
    }
    Ok(Value::json(value.clone()).with_prov(value.prov))
}

/// Whether `items` holds a value known equal to `v`; stops at the work allowance.
fn contains_equal(items: &[Value], v: &Value) -> Result<bool, Value> {
    for item in items {
        let equal = item.known_eq(v);
        meter::check()?;
        if equal == Some(true) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn all_contain<S: std::ops::Deref<Target = [Value]>>(sets: &[S], v: &Value) -> Result<bool, Value> {
    for set in sets {
        if !contains_equal(set, v)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn any_contains<S: std::ops::Deref<Target = [Value]>>(
    sets: &[S],
    v: &Value,
) -> Result<bool, Value> {
    for set in sets {
        if contains_equal(set, v)? {
            return Ok(true);
        }
    }
    Ok(false)
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

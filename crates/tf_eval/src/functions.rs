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

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::eval::{MAX_ALTERNATIVES, dominant_non_known, non_known_or};
use crate::prov::Prov;
use crate::value::{Kind, Known, Map, Origin, Value, fmt_number, from_json, to_json};

/// Every function name `call` implements (plus `try` / `can` in the
/// evaluator).
pub const SUPPORTED: &[&str] = &[
    "abs",
    "alltrue",
    "anytrue",
    "base64decode",
    "base64encode",
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
    "nonsensitive",
    "one",
    "parseint",
    "pow",
    "range",
    "replace",
    "reverse",
    "sensitive",
    "setintersection",
    "setproduct",
    "setsubtract",
    "setunion",
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
    SUPPORTED.contains(&name)
}

type R = Result<Value, Value>;

pub fn call(name: &str, args: Vec<Value>) -> Value {
    // Generic OneOf lifting over top-level arguments.
    if args.iter().any(|a| matches!(a.kind, Kind::OneOf(_))) {
        let mut combos: Vec<(Vec<Value>, bool)> = vec![(Vec::new(), false)];
        for a in &args {
            let (choices, t): (Vec<Value>, bool) = match &a.kind {
                Kind::OneOf(o) => (
                    o.alternatives.iter().map(|x| x.child_of(a)).collect(),
                    o.tainted,
                ),
                _ => (vec![a.clone()], false),
            };
            if combos.len() * choices.len() > MAX_ALTERNATIVES {
                return Value::other(format!("{name}: too many alternatives"));
            }
            let mut next = Vec::new();
            for (c, ct) in &combos {
                for ch in &choices {
                    let mut c2 = c.clone();
                    c2.push(ch.clone());
                    next.push((c2, *ct || t));
                }
            }
            combos = next;
        }
        let tainted = combos.iter().any(|c| c.1);
        return Value::one_of(
            combos.into_iter().map(|(c, _)| call1(name, c)).collect(),
            tainted,
        );
    }
    call1(name, args)
}

fn call1(name: &str, args: Vec<Value>) -> Value {
    let r = match dispatch(name, &args) {
        Ok(v) | Err(v) => v,
    };
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
        for a in &args {
            p = p.joined(&a.prov);
        }
        return r.with_prov(p);
    }
    r
}

fn dispatch(name: &str, a: &[Value]) -> R {
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
            let mut out = Vec::new();
            for x in a {
                out.extend(list(x)?.iter().map(|e| e.child_of(x)));
            }
            Ok(Value::list(out))
        }
        "merge" => {
            let mut m = Map::new();
            for x in a {
                if x.is_null() {
                    continue;
                }
                for (k, v) in obj(x)? {
                    m.insert(k.clone(), v.child_of(x));
                }
            }
            Ok(Value::object(m))
        }
        "lookup" => {
            if a.len() < 2 || a.len() > 3 {
                return Err(Value::error("lookup: wrong number of arguments"));
            }
            let m = obj(&a[0])?;
            match a[1].to_str() {
                Some(k) => match m.get(&*k) {
                    Some(v) => Ok(v.child_of(&a[0])),
                    None => match a.get(2) {
                        Some(d) => Ok(d.clone()),
                        None => Err(Value::error(format!("lookup: key \"{k}\" not found"))),
                    },
                },
                None if a[1].is_known() => Err(Value::error("lookup: key must be a string")),
                None => {
                    // Unknown key into a known map: any of its values, or the default.
                    let mut alts: Vec<Value> = m.values().map(|v| v.child_of(&a[0])).collect();
                    if let Some(d) = a.get(2) {
                        alts.push(d.clone());
                    }
                    if alts.is_empty() {
                        return Err(a[1].clone());
                    }
                    Ok(Value::one_of(alts, a[1].is_tainted()))
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
            Ok(Value::list(
                obj(&a[0])?
                    .keys()
                    .map(|k| Value::string(k.clone()))
                    .collect(),
            ))
        }
        "values" => {
            arity(a, 1)?;
            Ok(Value::list(
                obj(&a[0])?.values().map(|v| v.child_of(&a[0])).collect(),
            ))
        }
        "contains" => {
            arity(a, 2)?;
            let l = list(&a[0])?;
            let mut pending = Vec::new();
            for e in l {
                match e.known_eq(&a[1]) {
                    Some(true) => return Ok(Value::bool(true)),
                    Some(false) => {}
                    None => pending.push(e.clone()),
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
                match e.known_eq(&a[1]) {
                    Some(true) => return Ok(num(i as f64)),
                    Some(false) => {}
                    None => return Err(non_known_or(e, "index: unknown element")),
                }
            }
            Err(Value::error("index: item not found"))
        }
        "flatten" => {
            arity(a, 1)?;
            let mut out = Vec::new();
            flatten_into(&a[0], &mut out)?;
            Ok(Value::list(out))
        }
        "distinct" | "toset" => {
            arity(a, 1)?;
            if a[0].is_null() && name == "toset" {
                return Ok(Value::null());
            }
            let l = list(&a[0])?;
            let mut out: Vec<Value> = Vec::new();
            for e in l {
                if e.is_wholly_known() && out.iter().any(|o| o.known_eq(e) == Some(true)) {
                    continue;
                }
                out.push(e.child_of(&a[0]));
            }
            if name == "toset" && out.iter().all(|e| e.as_str().is_some()) {
                out.sort_by(|x, y| x.as_str().cmp(&y.as_str()));
            }
            Ok(Value::list(out))
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
            Ok(Value::list(
                l.iter()
                    .filter(|e| !(e.is_null() || e.as_str() == Some("")))
                    .map(|e| e.child_of(&a[0]))
                    .collect(),
            ))
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
            let mut l: Vec<Value> = list(&a[0])?.iter().map(|e| e.child_of(&a[0])).collect();
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
            Ok(Value::list(
                l[s..e].iter().map(|x| x.child_of(&a[0])).collect(),
            ))
        }
        "sort" => {
            arity(a, 1)?;
            let l = list(&a[0])?;
            let mut ss = Vec::new();
            for e in l {
                ss.push(string(e)?);
            }
            ss.sort();
            Ok(Value::list(ss.into_iter().map(Value::string).collect()))
        }
        "range" => {
            let ns: Vec<f64> = a.iter().map(number).collect::<Result<_, _>>()?;
            let (start, end, step) = match ns.as_slice() {
                [e] => (0.0, *e, 1.0),
                [s, e] => (*s, *e, if s <= e { 1.0 } else { -1.0 }),
                [s, e, st] => (*s, *e, *st),
                _ => return Err(Value::error("range: wrong number of arguments")),
            };
            if step == 0.0 {
                return Err(Value::error("range: step must not be zero"));
            }
            let mut out = Vec::new();
            let mut x = start;
            while (step > 0.0 && x < end) || (step < 0.0 && x > end) {
                out.push(num(x));
                x += step;
                if out.len() > 1024 {
                    return Err(Value::other("range: too large"));
                }
            }
            Ok(Value::list(out))
        }
        "zipmap" => {
            arity(a, 2)?;
            let (ks, vs) = (list(&a[0])?, list(&a[1])?);
            if ks.len() != vs.len() {
                return Err(Value::error("zipmap: lists differ in length"));
            }
            let mut m = Map::new();
            for (k, v) in ks.iter().zip(vs.iter()) {
                m.insert(string(k)?, v.child_of(&a[1]));
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
                return Ok(Value::list(vec![a[0].clone()]));
            }
            Ok(Value::list(
                l.chunks(n)
                    .map(|c| Value::list(c.iter().map(|x| x.child_of(&a[0])).collect()))
                    .collect(),
            ))
        }
        "setunion" | "setintersection" | "setsubtract" => {
            if a.is_empty() {
                return Err(Value::error("set function: no arguments"));
            }
            let mut sets: Vec<Vec<Value>> = Vec::new();
            for x in a {
                let l = list(x)?;
                if let Some(nk) = dominant_non_known(l.iter()) {
                    return Err(nk);
                }
                sets.push(l.iter().map(|e| e.child_of(x)).collect());
            }
            let has = |s: &Vec<Value>, v: &Value| s.iter().any(|y| y.known_eq(v) == Some(true));
            let mut out: Vec<Value> = Vec::new();
            match name {
                "setunion" => {
                    for s in &sets {
                        for v in s {
                            if !has(&out, v) {
                                out.push(v.clone());
                            }
                        }
                    }
                }
                "setintersection" => {
                    for v in &sets[0] {
                        if sets[1..].iter().all(|s| has(s, v)) && !has(&out, v) {
                            out.push(v.clone());
                        }
                    }
                }
                _ => {
                    for v in &sets[0] {
                        if !sets[1..].iter().any(|s| has(s, v)) && !has(&out, v) {
                            out.push(v.clone());
                        }
                    }
                }
            }
            Ok(Value::list(out))
        }
        "setproduct" => {
            let mut rows: Vec<Vec<Value>> = vec![vec![]];
            for x in a {
                let l = list(x)?;
                let mut next = Vec::new();
                for r in &rows {
                    for e in l {
                        let mut r2 = r.clone();
                        r2.push(e.child_of(x));
                        next.push(r2);
                    }
                }
                if next.len() > 4096 {
                    return Err(Value::other("setproduct: too large"));
                }
                rows = next;
            }
            if a.is_empty() {
                return Err(Value::error("setproduct: no arguments"));
            }
            Ok(Value::list(rows.into_iter().map(Value::list).collect()))
        }
        "matchkeys" => {
            arity(a, 3)?;
            let (vals, keys, search) = (list(&a[0])?, list(&a[1])?, list(&a[2])?);
            let mut out = Vec::new();
            for (v, k) in vals.iter().zip(keys.iter()) {
                let mut hit = false;
                for s in search {
                    match k.known_eq(s) {
                        Some(true) => hit = true,
                        Some(false) => {}
                        None => return Err(non_known_or(k, "matchkeys: unknown key")),
                    }
                }
                if hit {
                    out.push(v.child_of(&a[0]));
                }
            }
            Ok(Value::list(out))
        }
        "transpose" => {
            arity(a, 1)?;
            let mut m: BTreeMap<Arc<str>, Vec<Value>> = BTreeMap::new();
            for (k, v) in obj(&a[0])? {
                for e in list(v)? {
                    m.entry(string(e)?)
                        .or_default()
                        .push(Value::string(k.clone()));
                }
            }
            Ok(Value::object(
                m.into_iter().map(|(k, v)| (k, Value::list(v))).collect(),
            ))
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
            let mut pending = Vec::new();
            for e in list(&a[0])? {
                match e.as_bool() {
                    Some(b) if b != all => return Ok(Value::bool(!all)),
                    Some(_) => {}
                    None => pending.push(e.clone()),
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
            let ns: Vec<f64> = a.iter().map(number).collect::<Result<_, _>>()?;
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
        "lower" => Ok(Value::string(string(one_arg(a)?)?.to_lowercase())),
        "upper" => Ok(Value::string(string(one_arg(a)?)?.to_uppercase())),
        "title" => {
            let s = string(one_arg(a)?)?;
            let mut out = String::with_capacity(s.len());
            let mut start = true;
            for c in s.chars() {
                if start && c.is_alphabetic() {
                    out.extend(c.to_uppercase());
                } else {
                    out.push(c);
                }
                start = !c.is_alphanumeric();
            }
            Ok(Value::string(out))
        }
        "basename" => {
            let p = string(one_arg(a)?)?;
            Ok(Value::string(
                p.trim_end_matches('/').rsplit('/').next().unwrap_or(""),
            ))
        }
        "dirname" => {
            let p = string(one_arg(a)?)?;
            let t = p.trim_end_matches('/');
            Ok(Value::string(match t.rfind('/') {
                Some(0) => "/",
                Some(i) => &t[..i],
                None => ".",
            }))
        }
        "strcontains" => {
            arity(a, 2)?;
            Ok(Value::bool(string(&a[0])?.contains(&*string(&a[1])?)))
        }
        "indent" => {
            arity(a, 2)?;
            let n = number(&a[0])? as usize;
            let s = string(&a[1])?;
            let pad = " ".repeat(n);
            Ok(Value::string(s.replace('\n', &format!("\n{pad}"))))
        }
        "base64encode" => Ok(Value::string(b64encode(string(one_arg(a)?)?.as_bytes()))),
        "base64decode" => {
            let s = string(one_arg(a)?)?;
            b64decode(&s)
                .and_then(|b| String::from_utf8(b).ok())
                .map(Value::string)
                .ok_or_else(|| Value::error("base64decode: invalid input"))
        }
        "urlencode" => {
            let s = string(one_arg(a)?)?;
            let mut out = String::new();
            for b in s.bytes() {
                if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                    out.push(b as char);
                } else {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
            Ok(Value::string(out))
        }
        "trimspace" => Ok(Value::string(string(one_arg(a)?)?.trim())),
        "chomp" => Ok(Value::string(
            string(one_arg(a)?)?.trim_end_matches(['\n', '\r']),
        )),
        "strrev" => Ok(Value::string(
            string(one_arg(a)?)?.chars().rev().collect::<String>(),
        )),
        "trim" => {
            arity(a, 2)?;
            let (s, cs) = (string(&a[0])?, string(&a[1])?);
            Ok(Value::string(s.trim_matches(|c| cs.contains(c))))
        }
        "trimprefix" | "trimsuffix" => {
            arity(a, 2)?;
            let (s, p) = (string(&a[0])?, string(&a[1])?);
            let r = if name == "trimprefix" {
                s.strip_prefix(&*p).unwrap_or(&s)
            } else {
                s.strip_suffix(&*p).unwrap_or(&s)
            };
            Ok(Value::string(r))
        }
        "startswith" | "endswith" => {
            arity(a, 2)?;
            let (s, p) = (string(&a[0])?, string(&a[1])?);
            Ok(Value::bool(if name == "startswith" {
                s.starts_with(&*p)
            } else {
                s.ends_with(&*p)
            }))
        }
        "replace" => {
            arity(a, 3)?;
            let (s, sub, rep) = (string(&a[0])?, string(&a[1])?, string(&a[2])?);
            if sub.len() > 1 && sub.starts_with('/') && sub.ends_with('/') {
                return Err(Value::unknown(Origin::UnsupportedFunction(
                    "replace (regex)".into(),
                )));
            }
            Ok(Value::string(s.replace(&*sub, &rep)))
        }
        "split" => {
            arity(a, 2)?;
            let (sep, s) = (string(&a[0])?, string(&a[1])?);
            // Like Terraform (Go's strings.Split), "" splits to [""].
            Ok(Value::list(s.split(&*sep).map(Value::string).collect()))
        }
        "join" => {
            if a.len() < 2 {
                return Err(Value::error("join: wrong number of arguments"));
            }
            let sep = string(&a[0])?;
            let mut parts = Vec::new();
            for l in &a[1..] {
                for e in list(l)? {
                    parts.push(string(e)?.to_string());
                }
            }
            Ok(Value::string(parts.join(&sep)))
        }
        "substr" => {
            arity(a, 3)?;
            let s = string(&a[0])?;
            let off = number(&a[1])? as i64;
            let len = number(&a[2])? as i64;
            let chars: Vec<char> = s.chars().collect();
            let n = chars.len() as i64;
            let start = if off < 0 {
                (n + off).max(0)
            } else {
                off.min(n)
            } as usize;
            let end = if len < 0 {
                n as usize
            } else {
                (start + len as usize).min(n as usize)
            };
            Ok(Value::string(chars[start..end].iter().collect::<String>()))
        }
        "format" => {
            if a.is_empty() {
                return Err(Value::error("format: missing format string"));
            }
            let f = string(&a[0])?;
            format(&f, &a[1..]).map(Value::string)
        }
        "formatlist" => {
            if a.is_empty() {
                return Err(Value::error("formatlist: missing format string"));
            }
            let f = string(&a[0])?;
            let mut n: Option<usize> = None;
            for x in &a[1..] {
                if let Kind::Known(Known::List(l)) = &x.kind {
                    n = Some(l.len());
                } else if !x.is_known() {
                    return Err(x.clone());
                }
            }
            let n = n.unwrap_or(1);
            let mut out = Vec::new();
            for i in 0..n {
                let row: Vec<Value> = a[1..]
                    .iter()
                    .map(|x| match x.as_list() {
                        Some(l) => l.get(i).cloned().unwrap_or_else(Value::null),
                        None => x.clone(),
                    })
                    .collect();
                out.push(Value::string(format(&f, &row)?));
            }
            Ok(Value::list(out))
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
        "sensitive" | "nonsensitive" => Ok(one_arg(a)?.clone()),
        // ---- encoding
        "jsonencode" => {
            arity(a, 1)?;
            match &a[0].kind {
                Kind::Known(_) => Ok(Value::json(a[0].clone()).with_prov(a[0].prov.clone())),
                _ => Err(a[0].clone()),
            }
        }
        "jsondecode" => {
            arity(a, 1)?;
            if let Kind::Known(Known::Json(inner)) = &a[0].kind {
                return Ok((**inner).clone());
            }
            let s = string(&a[0])?;
            match serde_json::from_str::<serde_json::Value>(&s) {
                Ok(j) => Ok(from_json(&j, &a[0].prov)),
                Err(e) => Err(Value::error(format!("jsondecode: {e}"))),
            }
        }
        // ---- networking
        "cidrsubnet" => {
            arity(a, 3)?;
            let (p, bits, n) = (string(&a[0])?, number(&a[1])?, number(&a[2])?);
            cidrsubnet(&p, bits as u32, n as u128)
                .map(Value::string)
                .map_err(Value::error)
        }
        "cidrsubnets" => {
            if a.is_empty() {
                return Err(Value::error("cidrsubnets: missing prefix"));
            }
            let p = string(&a[0])?;
            let bits: Vec<u32> = a[1..]
                .iter()
                .map(|x| number(x).map(|n| n as u32))
                .collect::<Result<_, _>>()?;
            cidrsubnets(&p, &bits)
                .map(|v| Value::list(v.into_iter().map(Value::string).collect()))
                .map_err(Value::error)
        }
        "cidrhost" => {
            arity(a, 2)?;
            let (p, h) = (string(&a[0])?, number(&a[1])?);
            cidrhost(&p, h as i128)
                .map(Value::string)
                .map_err(Value::error)
        }
        "cidrnetmask" => {
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

fn string(v: &Value) -> Result<Arc<str>, Value> {
    match &v.kind {
        Kind::Known(Known::Null) => Err(Value::error("expected string, got null")),
        Kind::Known(_) => v.to_str().ok_or_else(|| match v.as_known() {
            Some(Known::Json(_)) => non_known_or(v, ""),
            _ => Value::error(format!("expected string, got {}", v.type_name())),
        }),
        _ => Err(non_known_or(v, "")),
    }
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

fn flatten_into(v: &Value, out: &mut Vec<Value>) -> Result<(), Value> {
    for e in list(v)? {
        let e = e.child_of(v);
        match &e.kind {
            Kind::Known(Known::List(_)) => flatten_into(&e, out)?,
            Kind::Known(_) => out.push(e),
            // An unknown element may itself be a list: the length is unknown.
            _ => return Err(non_known_or(&e, "")),
        }
    }
    Ok(())
}

/// Go-style `format` with the verbs Terraform supports most often.
fn format(f: &str, args: &[Value]) -> Result<String, Value> {
    let mut out = String::new();
    let mut it = f.chars().peekable();
    let mut ai = 0usize;
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut spec = String::new();
        while let Some(&d) = it.peek() {
            if d.is_ascii_digit() || d == '.' || d == '-' || d == '+' || d == '#' || d == ' ' {
                spec.push(d);
                it.next();
            } else {
                break;
            }
        }
        let Some(verb) = it.next() else { break };
        if verb == '%' {
            out.push('%');
            continue;
        }
        let Some(arg) = args.get(ai) else {
            return Err(Value::error("format: not enough arguments"));
        };
        ai += 1;
        match verb {
            's' | 'v' => match &arg.kind {
                Kind::Known(Known::List(_) | Known::Object(_)) if verb == 'v' => out.push_str(
                    &to_json(arg)
                        .ok_or_else(|| non_known_or(arg, ""))?
                        .to_string(),
                ),
                _ => out.push_str(&string(arg)?),
            },
            'q' => out.push_str(&format!("{:?}", string(arg)?.to_string())),
            'd' => out.push_str(&format!("{}", number(arg)? as i64)),
            'f' | 'g' | 'e' => {
                let n = number(arg)?;
                match spec.split('.').nth(1).and_then(|p| p.parse::<usize>().ok()) {
                    Some(p) => out.push_str(&format!("{n:.p$}")),
                    None => out.push_str(&fmt_number(n)),
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
            _ => {
                return Err(Value::unknown(Origin::UnsupportedFunction(
                    format!("format %{verb}").into(),
                )));
            }
        }
    }
    Ok(out)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64encode(data: &[u8]) -> String {
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

fn b64decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for ch in s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=') {
        let v = B64.iter().position(|&x| x == ch)? as u32;
        buf = buf << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits & 0xff) as u8);
        }
    }
    Some(out)
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
        assert_eq!(b64decode("SGVsbG8gV29ybGQ=").unwrap(), b"Hello World");
    }

    #[test]
    fn fmt() {
        let r = format(
            "%s-%d-%v %%",
            &[Value::string("a"), Value::number(3.0), Value::bool(true)],
        )
        .unwrap();
        assert_eq!(r, "a-3-true %");
    }
}

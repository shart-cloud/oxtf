//! YAML documents as OPA loads them: go-yaml v2 decoding into
//! `interface{}`, then sigs.k8s.io/yaml's conversion to JSON.
//!
//! go-yaml v2 is YAML 1.1 in its own way, and differs from PyYAML
//! ([`crate::pyyaml`]) in places that matter:
//!
//! - plain `y`/`n` are booleans as well as `yes`/`on`/`off`/`no`;
//! - numbers follow Go's `strconv.ParseInt(s, 0, 64)` after removing every
//!   `_`, so `0o17` and `017` are 15, `1e3` is 1000, `08` is the float 8,
//!   and `1:30` (no sexagesimal) and timestamps stay strings;
//! - a merge key `<<` applies where it appears, overwriting keys before
//!   it, and an earlier map in a merge sequence wins;
//! - only the first document of a stream is read.
//!
//! What OPA would fail on (NaN, infinities, `null` or float keys) is an
//! error, and so are tags it would accept but are not supported here
//! (`!!binary`, `!!set`, local tags on collections).

use serde_json::{Map, Value as Json};
use yaml_rust2::parser::Tag;
use yaml_rust2::scanner::{Marker, TScalarStyle};

use crate::pyyaml::{self, Error, Node, error};

/// Load the first document in `text` (`None` for an empty stream).
pub fn load(text: &str) -> Result<Option<Json>, Error> {
    let docs = pyyaml::documents(text)?;
    docs.first().map(|(root, _)| construct(root)).transpose()
}

enum Tagged<'a> {
    None,
    Core(&'a str),
    /// `!`, `!foo`: the scalar is a string.
    Local,
}

fn tagged<'a>(tag: &'a Option<Tag>, mark: Marker) -> Result<Tagged<'a>, Error> {
    match tag {
        None => Ok(Tagged::None),
        Some(t) if t.handle == "tag:yaml.org,2002:" => Ok(Tagged::Core(&t.suffix)),
        Some(t) if t.handle == "!" => Ok(Tagged::Local),
        Some(t) => Err(error(
            mark,
            format!("unsupported YAML tag {}{}", t.handle, t.suffix),
        )),
    }
}

/// go-yaml v2 `resolve` for a plain scalar.
fn resolve(s: &str) -> Json {
    match s {
        "y" | "Y" | "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => {
            return Json::Bool(true);
        }
        "n" | "N" | "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => {
            return Json::Bool(false);
        }
        "" | "~" | "null" | "Null" | "NULL" => return Json::Null,
        _ => {}
    }
    match s.as_bytes()[0] {
        b'.' => float(s).unwrap_or_else(|| Json::String(s.into())),
        b'+' | b'-' | b'0'..=b'9' => {
            let plain = s.replace('_', "");
            parse_int(&plain)
                .or_else(|| yaml_style_float(&plain).then(|| float(&plain)).flatten())
                .unwrap_or_else(|| Json::String(s.into()))
        }
        _ => Json::String(s.into()),
    }
}

/// `strconv.ParseInt(s, 0, 64)`, else `strconv.ParseUint(s, 0, 64)`.
fn parse_int(s: &str) -> Option<Json> {
    let (neg, signed, digits) = match s.as_bytes().first()? {
        b'-' => (true, true, &s[1..]),
        b'+' => (false, true, &s[1..]),
        _ => (false, false, s),
    };
    let magnitude = parse_uint(digits)?;
    if !signed {
        return Some(Json::from(magnitude));
    }
    if neg {
        (magnitude <= 1u64 << 63).then(|| Json::from((magnitude as i128).wrapping_neg() as i64))
    } else {
        i64::try_from(magnitude).ok().map(Json::from)
    }
}

/// `strconv.ParseUint(s, 0, 64)` without underscores.
fn parse_uint(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let b = s.as_bytes();
    let (radix, digits) = if b[0] == b'0' {
        match b.get(1).map(u8::to_ascii_lowercase) {
            Some(b'b') if b.len() >= 3 => (2, &s[2..]),
            Some(b'o') if b.len() >= 3 => (8, &s[2..]),
            Some(b'x') if b.len() >= 3 => (16, &s[2..]),
            _ => (8, &s[1..]),
        }
    } else {
        (10, s)
    };
    if digits.is_empty() {
        return Some(0);
    }
    // from_str_radix would accept a sign here; Go does not.
    if !digits.bytes().all(|c| (c as char).is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// `^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`
fn yaml_style_float(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = usize::from(matches!(b.first(), Some(b'-' | b'+')));
    let digits = |i: &mut usize| {
        let start = *i;
        while b.get(*i).is_some_and(u8::is_ascii_digit) {
            *i += 1;
        }
        *i - start
    };
    if b.get(i) == Some(&b'.') {
        i += 1;
        if digits(&mut i) == 0 {
            return false;
        }
    } else {
        if digits(&mut i) == 0 {
            return false;
        }
        if b.get(i) == Some(&b'.') {
            i += 1;
            digits(&mut i);
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'-' | b'+')) {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return false;
        }
    }
    i == b.len()
}

/// `strconv.ParseFloat(s, 64)` for decimal spellings; out of range is a
/// failure. Integral values are written as JSON integers, as Go's encoder
/// writes them.
fn float(s: &str) -> Option<Json> {
    let b = s.as_bytes();
    let body = s.strip_prefix(['-', '+']).unwrap_or(s);
    // Rust also parses `inf`, `nan` and `infinity`; Go's only reach here
    // through the resolve table, which has already handled them.
    if !body.starts_with(|c: char| c == '.' || c.is_ascii_digit())
        || b.iter()
            .any(|c| c.is_ascii_alphabetic() && !matches!(c, b'e' | b'E'))
    {
        return None;
    }
    let f: f64 = s.parse().ok()?;
    if !f.is_finite() {
        return None;
    }
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        return Some(Json::from(f as i64));
    }
    serde_json::Number::from_f64(f).map(Json::Number)
}

fn scalar(
    value: &str,
    style: TScalarStyle,
    tag: &Option<Tag>,
    mark: Marker,
) -> Result<Json, Error> {
    let plain = style == TScalarStyle::Plain;
    let want = match tagged(tag, mark)? {
        Tagged::None if plain => return finite(resolve(value), value, mark),
        Tagged::None | Tagged::Local => return Ok(Json::String(value.into())),
        Tagged::Core(t) => t,
    };
    let resolved = resolve(value);
    let ok = match want {
        "str" | "timestamp" => return Ok(Json::String(value.into())),
        "int" => resolved.is_i64() || resolved.is_u64(),
        "float" => resolved.is_number(),
        "bool" => resolved.is_boolean(),
        "null" => resolved.is_null(),
        other => return Err(error(mark, format!("unsupported YAML tag !!{other}"))),
    };
    if !ok {
        return Err(error(
            mark,
            format!("cannot decode `{value}` as a !!{want}"),
        ));
    }
    finite(resolved, value, mark)
}

fn finite(v: Json, value: &str, mark: Marker) -> Result<Json, Error> {
    if v.is_string()
        && matches!(
            value.strip_prefix(['-', '+']).unwrap_or(value),
            ".nan" | ".NaN" | ".NAN" | ".inf" | ".Inf" | ".INF"
        )
    {
        return Err(error(
            mark,
            format!("{value}: NaN and infinite values are not supported"),
        ));
    }
    Ok(v)
}

/// A mapping key as sigs.k8s.io/yaml writes it, or `None` for `<<`.
fn key(node: &Node) -> Result<Option<String>, Error> {
    let Node::Scalar {
        value,
        style,
        tag,
        mark,
    } = node
    else {
        return Err(error(node.mark(), "invalid map key: a collection"));
    };
    if *style == TScalarStyle::Plain
        && value == "<<"
        && matches!(tagged(tag, *mark)?, Tagged::None | Tagged::Core("merge"))
    {
        return Ok(None);
    }
    match scalar(value, *style, tag, *mark)? {
        Json::String(s) => Ok(Some(s)),
        Json::Bool(b) => Ok(Some(b.to_string())),
        Json::Number(n) if !n.is_f64() => Ok(Some(n.to_string())),
        Json::Number(_) => Err(error(
            *mark,
            format!("float map key {value} is not supported"),
        )),
        _ => Err(error(*mark, "unsupported map key: null")),
    }
}

fn merge(value: &Node, out: &mut Map<String, Json>) -> Result<(), Error> {
    match value {
        Node::Map { .. } => {
            let Json::Object(m) = construct(value)? else {
                unreachable!("a mapping constructs an object")
            };
            out.extend(m);
        }
        Node::Seq { items, .. } => {
            for item in items.iter().rev() {
                if !matches!(item, Node::Map { .. }) {
                    return Err(error(
                        item.mark(),
                        "map merge requires map or sequence of maps",
                    ));
                }
                merge(item, out)?;
            }
        }
        _ => {
            return Err(error(
                value.mark(),
                "map merge requires map or sequence of maps",
            ));
        }
    }
    Ok(())
}

fn construct(node: &Node) -> Result<Json, Error> {
    match node {
        Node::Scalar {
            value,
            style,
            tag,
            mark,
        } => scalar(value, *style, tag, *mark),
        Node::Seq { items, tag, mark } => {
            if !matches!(tagged(tag, *mark)?, Tagged::None | Tagged::Core("seq")) {
                return Err(error(*mark, "unsupported tag on a sequence"));
            }
            items
                .iter()
                .map(construct)
                .collect::<Result<_, _>>()
                .map(Json::Array)
        }
        Node::Map { pairs, tag, mark } => {
            if !matches!(tagged(tag, *mark)?, Tagged::None | Tagged::Core("map")) {
                return Err(error(*mark, "unsupported tag on a mapping"));
            }
            let mut map = Map::new();
            for (k, v) in pairs {
                match key(k)? {
                    Some(k) => {
                        map.insert(k, construct(v)?);
                    }
                    None => merge(v, &mut map)?,
                }
            }
            Ok(Json::Object(map))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(s: &str) -> Json {
        load(s).unwrap().unwrap()
    }

    /// Each expectation is what `opa eval -d` (OPA 1.17.0) loads.
    #[test]
    fn scalars_follow_opa() {
        assert_eq!(
            v(
                "k: [y, n, Y, NO, Off, TRUE, tRue, 0o17, 017, 0x_1F, 1_000, -0b11, 0b11, 1.5e3, 1e+3, .5, 1., +12, 0.1e-2, 1__0, 08, 0x, 1_, _1, 9223372036854775807, 9223372036854775808, 1e400, 0b2]"
            )["k"],
            json!([
                true,
                false,
                true,
                false,
                false,
                true,
                "tRue",
                15,
                15,
                31,
                1000,
                -3,
                3,
                1500,
                1000,
                0.5,
                1,
                12,
                0.001,
                10,
                8,
                "0x",
                1,
                "_1",
                9223372036854775807i64,
                9223372036854775808u64,
                "1e400",
                "0b2"
            ])
        );
        assert_eq!(
            v(
                "a: 0o\nb: +0x10\nc: -0x10\nd: 0x8000000000000000\ne: 0xFFFFFFFFFFFFFFFFF\nf: +.5\ng: 1.5E3\nh: 0X1F\ni: 0B11\nj: 0O17\nk: 1:2:3\nl: 1.10\nm: 2001-12-14\nnn: 0.0\no: -0\np:\nq: ~\n"
            ),
            json!({"a": "0o", "b": 16, "c": -16, "d": 9223372036854775808u64, "e": "0xFFFFFFFFFFFFFFFFF", "f": 0.5, "g": 1500, "h": 31, "i": 3, "j": 15, "k": "1:2:3", "l": 1.1, "m": "2001-12-14", "nn": 0, "o": 0, "p": null, "q": null})
        );
        assert_eq!(
            v(
                "a: !!str 12\nb: !!int \"12\"\nc: !!float 1\nd: !!bool yes\ne: !foo 12\nf: !!str\ng: !!timestamp 2001-12-14\n"
            ),
            json!({"a": "12", "b": 12, "c": 1, "d": true, "e": "12", "f": "", "g": "2001-12-14"})
        );
    }

    #[test]
    fn keys_and_merges_follow_opa() {
        assert_eq!(v("1: a\ntrue: b\n"), json!({"1": "a", "true": "b"}));
        assert_eq!(v("3: a\n03: b\n"), json!({"3": "b"}));
        assert_eq!(v("a: 1\na: 2\n"), json!({"a": 2}));
        assert_eq!(
            v("m: {k: 1, <<: {k: 2, j: 2}}")["m"],
            json!({"j": 2, "k": 2})
        );
        assert_eq!(
            v("m: {<<: {k: 2, j: 2}, k: 1}")["m"],
            json!({"j": 2, "k": 1})
        );
        assert_eq!(
            v("m: {<<: [{k: 1}, {k: 2, j: 3}]}")["m"],
            json!({"j": 3, "k": 1})
        );
        assert_eq!(
            v("m: {<<: [{k: 1}, {k: 2}], <<: {k: 3}}")["m"],
            json!({"k": 3})
        );
        assert_eq!(
            v("b: &b {x: 1}\nm: {<<: *b, y: 2}\n")["m"],
            json!({"true": 2, "x": 1})
        );
        assert_eq!(v("? |\n  multi\n: v\n"), json!({"multi\n": "v"}));
        assert_eq!(v("a: 1\n---\nb: 2\n"), json!({"a": 1}));
        assert_eq!(load("").unwrap(), None);
    }

    #[test]
    fn rejects_what_opa_rejects_or_is_unsupported() {
        for bad in [
            "a: .inf",
            "a: -.inf",
            "a: .nan",
            "~: a",
            "[1]: a",
            "1.5: a",
            "a: !!null x",
            "a: !!int x",
            "a: !!binary aGk=",
            "a: !!set {x}",
        ] {
            assert!(load(bad).is_err(), "{bad}");
        }
    }
}

//! YAML documents as Checkov loads them: `json.loads(json.dumps(yaml.safe_load(f)))`.
//!
//! PyYAML's `safe_load` is YAML 1.1, so plain `on`/`yes`/`off`/`no` are
//! booleans, `012` is octal, `1:30` is sexagesimal and `1e3` (no dot, no
//! exponent sign) is a string. yaml-rust2 supplies the event stream; scalar
//! resolution and mapping construction here follow PyYAML's resolver and
//! `SafeConstructor`. The JSON round trip then stringifies non-string keys.
//!
//! Anything PyYAML would construct but JSON cannot carry (timestamps,
//! binary, sets, NaN, infinities) is an error, as it would be for Checkov.
//! Every node's start position is recorded by JSON Pointer for diagnostics.

use std::collections::HashMap;

use serde_json::{Map, Value as Json};
use yaml_rust2::parser::{Event, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// A 1-based line and column in the source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub line: usize,
    pub col: usize,
}

/// A loaded document and the start position of each node, keyed by JSON
/// Pointer (`""` is the root). Pointer segments are not escaped, matching
/// the paths in importer blockers.
#[derive(Debug)]
pub struct Document {
    pub value: Json,
    pub positions: HashMap<String, Position>,
}

#[derive(Debug, PartialEq)]
pub struct Error {
    pub position: Option<Position>,
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.position {
            Some(p) => write!(f, "{}:{}: {}", p.line, p.col, self.message),
            None => f.write_str(&self.message),
        }
    }
}

pub(crate) fn position(mark: Marker) -> Position {
    Position {
        line: mark.line(),
        col: mark.col() + 1,
    }
}

pub(crate) fn error(mark: Marker, message: impl Into<String>) -> Error {
    Error {
        position: Some(position(mark)),
        message: message.into(),
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Node {
    Scalar {
        value: String,
        style: TScalarStyle,
        tag: Option<Tag>,
        mark: Marker,
    },
    Seq {
        items: Vec<Node>,
        tag: Option<Tag>,
        mark: Marker,
    },
    Map {
        pairs: Vec<(Node, Node)>,
        tag: Option<Tag>,
        mark: Marker,
    },
}

impl Node {
    pub(crate) fn mark(&self) -> Marker {
        match self {
            Node::Scalar { mark, .. } | Node::Seq { mark, .. } | Node::Map { mark, .. } => *mark,
        }
    }
}

/// Load a single YAML document. An empty stream is `null`, and more than
/// one document is an error, as for `safe_load`.
pub fn load(text: &str) -> Result<Document, Error> {
    let mut docs = documents(text)?;
    if docs.len() > 1 {
        return Err(error(docs[1].1, "expected a single document in the stream"));
    }
    let mut positions = HashMap::new();
    let Some((root, _)) = docs.pop() else {
        return Ok(Document {
            value: Json::Null,
            positions,
        });
    };
    let value = construct(&root, String::new(), &mut positions)?;
    Ok(Document { value, positions })
}

/// Every document in the stream as a node tree (aliases expanded), with
/// the mark of its `---` (or first event).
pub(crate) fn documents(text: &str) -> Result<Vec<(Node, Marker)>, Error> {
    let mut parser = Parser::new_from_str(text);
    let mut anchors: HashMap<usize, Node> = HashMap::new();
    let mut next = || {
        parser.next_token().map_err(|e| Error {
            position: Some(position(*e.marker())),
            message: e.info().to_string(),
        })
    };
    let mut docs = Vec::new();
    loop {
        let (event, mark) = next()?;
        match event {
            Event::StreamStart | Event::DocumentEnd | Event::Nothing => {}
            Event::StreamEnd => break,
            Event::DocumentStart => {
                let (event, m) = next()?;
                docs.push((node(event, m, &mut next, &mut anchors)?, mark));
            }
            _ => return Err(error(mark, "unexpected YAML event")),
        }
    }
    Ok(docs)
}

fn node(
    event: Event,
    mark: Marker,
    next: &mut impl FnMut() -> Result<(Event, Marker), Error>,
    anchors: &mut HashMap<usize, Node>,
) -> Result<Node, Error> {
    let (node, anchor) = match event {
        Event::Alias(id) => {
            return anchors
                .get(&id)
                .cloned()
                .ok_or_else(|| error(mark, "found undefined alias"));
        }
        Event::Scalar(value, style, anchor, tag) => (
            Node::Scalar {
                value,
                style,
                tag,
                mark,
            },
            anchor,
        ),
        Event::SequenceStart(anchor, tag) => {
            let mut items = Vec::new();
            loop {
                let (event, m) = next()?;
                if event == Event::SequenceEnd {
                    break;
                }
                items.push(node(event, m, next, anchors)?);
            }
            (Node::Seq { items, tag, mark }, anchor)
        }
        Event::MappingStart(anchor, tag) => {
            let mut pairs = Vec::new();
            loop {
                let (event, m) = next()?;
                if event == Event::MappingEnd {
                    break;
                }
                let key = node(event, m, next, anchors)?;
                let (event, m) = next()?;
                pairs.push((key, node(event, m, next, anchors)?));
            }
            (Node::Map { pairs, tag, mark }, anchor)
        }
        _ => return Err(error(mark, "unexpected YAML event")),
    };
    if anchor != 0 {
        anchors.insert(anchor, node.clone());
    }
    Ok(node)
}

/// The resolved tag of a node, as a `tag:yaml.org,2002:` suffix.
fn tag_name(tag: &Option<Tag>, mark: Marker) -> Result<Option<&str>, Error> {
    match tag {
        None => Ok(None),
        Some(t) if t.handle == "tag:yaml.org,2002:" => Ok(Some(&t.suffix)),
        Some(t) => Err(error(
            mark,
            format!("unsupported YAML tag {}{}", t.handle, t.suffix),
        )),
    }
}

/// PyYAML's implicit resolver for plain scalars.
fn implicit(s: &str) -> &'static str {
    if is_bool(s) {
        "bool"
    } else if is_float(s) {
        "float"
    } else if is_int(s) {
        "int"
    } else if s == "<<" {
        "merge"
    } else if matches!(s, "~" | "null" | "Null" | "NULL" | "") {
        "null"
    } else if is_timestamp(s) {
        "timestamp"
    } else if s == "=" {
        "value"
    } else {
        "str"
    }
}

fn is_bool(s: &str) -> bool {
    matches!(
        s,
        "yes"
            | "Yes"
            | "YES"
            | "no"
            | "No"
            | "NO"
            | "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
            | "on"
            | "On"
            | "ON"
            | "off"
            | "Off"
            | "OFF"
    )
}

fn bool_value(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" => Some(true),
        "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

/// A small cursor for hand-written versions of PyYAML's resolver regexes.
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(s: &'a str) -> Self {
        Cur {
            b: s.as_bytes(),
            i: 0,
        }
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn eat_if(&mut self, f: impl Fn(u8) -> bool) -> bool {
        match self.b.get(self.i) {
            Some(&c) if f(c) => {
                self.i += 1;
                true
            }
            _ => false,
        }
    }
    fn many(&mut self, f: impl Fn(u8) -> bool) -> usize {
        let start = self.i;
        while self.eat_if(&f) {}
        self.i - start
    }
    fn sign(&mut self) {
        let _ = self.eat(b'-') || self.eat(b'+');
    }
    fn done(&self) -> bool {
        self.i == self.b.len()
    }
    fn rest(&self) -> &'a [u8] {
        &self.b[self.i..]
    }
}

fn digit(c: u8) -> bool {
    c.is_ascii_digit()
}
fn digit_(c: u8) -> bool {
    c.is_ascii_digit() || c == b'_'
}

/// `(?::[0-5]?[0-9])+`, consumed greedily as the regex would.
fn sexagesimal_tail(c: &mut Cur) -> bool {
    let mut any = false;
    loop {
        let save = c.i;
        if !c.eat(b':') {
            break;
        }
        // `[0-5]?[0-9]`: one or two digits, the first 0-5 when two.
        let rest = c.rest();
        let n = match rest {
            [a, b, ..] if (b'0'..=b'5').contains(a) && digit(*b) => 2,
            [a, ..] if digit(*a) => 1,
            _ => 0,
        };
        if n == 0 {
            c.i = save;
            break;
        }
        c.i += n;
        any = true;
    }
    any
}

/// `[eE][-+][0-9]+`, optional.
fn exponent(c: &mut Cur) {
    let save = c.i;
    if c.eat_if(|x| x == b'e' || x == b'E')
        && c.eat_if(|x| x == b'-' || x == b'+')
        && c.many(digit) > 0
    {
        return;
    }
    c.i = save;
}

fn is_float(s: &str) -> bool {
    let alt = |f: &dyn Fn(&mut Cur) -> bool| {
        let mut c = Cur::new(s);
        f(&mut c) && c.done()
    };
    // [-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?
    alt(&|c| {
        c.sign();
        c.eat_if(digit) && {
            c.many(digit_);
            c.eat(b'.')
        } && {
            c.many(digit_);
            exponent(c);
            true
        }
    })
    // \.[0-9][0-9_]*(?:[eE][-+][0-9]+)?
    || alt(&|c| {
        c.eat(b'.') && c.eat_if(digit) && {
            c.many(digit_);
            exponent(c);
            true
        }
    })
    // [-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*
    || alt(&|c| {
        c.sign();
        c.eat_if(digit) && {
            c.many(digit_);
            sexagesimal_tail(c)
        } && c.eat(b'.') && {
            c.many(digit_);
            true
        }
    })
    // [-+]?\.(?:inf|Inf|INF) | \.(?:nan|NaN|NAN)
    || {
        let t = s.strip_prefix(['-', '+']).unwrap_or(s);
        matches!(t, ".inf" | ".Inf" | ".INF")
    }
    || matches!(s, ".nan" | ".NaN" | ".NAN")
}

fn is_int(s: &str) -> bool {
    let alt = |f: &dyn Fn(&mut Cur) -> bool| {
        let mut c = Cur::new(s);
        f(&mut c) && c.done()
    };
    // [-+]?0b[0-1_]+
    alt(&|c| {
        c.sign();
        c.eat(b'0') && c.eat(b'b') && c.many(|x| matches!(x, b'0' | b'1' | b'_')) > 0
    })
    // [-+]?0[0-7_]+
    || alt(&|c| {
        c.sign();
        c.eat(b'0') && c.many(|x| matches!(x, b'0'..=b'7' | b'_')) > 0
    })
    // [-+]?(?:0|[1-9][0-9_]*)
    || alt(&|c| {
        c.sign();
        c.eat(b'0') || (c.eat_if(|x| matches!(x, b'1'..=b'9')) && {
            c.many(digit_);
            true
        })
    })
    // [-+]?0x[0-9a-fA-F_]+
    || alt(&|c| {
        c.sign();
        c.eat(b'0') && c.eat(b'x') && c.many(|x| x.is_ascii_hexdigit() || x == b'_') > 0
    })
    // [-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+
    || alt(&|c| {
        c.sign();
        c.eat_if(|x| matches!(x, b'1'..=b'9')) && {
            c.many(digit_);
            sexagesimal_tail(c)
        }
    })
}

fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    let d = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_digit());
    // [0-9]{4}-[0-9]{2}-[0-9]{2}
    if b.len() == 10
        && (0..4).all(d)
        && b[4] == b'-'
        && d(5)
        && d(6)
        && b[7] == b'-'
        && d(8)
        && d(9)
    {
        return true;
    }
    // [0-9]{4}-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9]{2}:[0-9]{2}
    //   (?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?
    let mut c = Cur::new(s);
    let two = |c: &mut Cur| {
        c.eat_if(digit) && {
            c.eat_if(digit);
            true
        }
    };
    let head = (0..4).all(|_| c.eat_if(digit))
        && c.eat(b'-')
        && two(&mut c)
        && c.eat(b'-')
        && two(&mut c)
        && (c.eat_if(|x| x == b'T' || x == b't') || c.many(|x| x == b' ' || x == b'\t') > 0)
        && two(&mut c)
        && c.eat(b':')
        && c.eat_if(digit)
        && c.eat_if(digit)
        && c.eat(b':')
        && c.eat_if(digit)
        && c.eat_if(digit);
    if !head {
        return false;
    }
    if c.eat(b'.') {
        c.many(digit);
    }
    if c.done() {
        return true;
    }
    c.many(|x| x == b' ' || x == b'\t');
    if c.eat(b'Z') {
        return c.done();
    }
    if !(c.eat_if(|x| x == b'-' || x == b'+') && two(&mut c)) {
        return false;
    }
    if c.eat(b':') && !(c.eat_if(digit) && c.eat_if(digit)) {
        return false;
    }
    c.done()
}

/// `construct_yaml_int`, then the JSON round trip: integers outside
/// i64/u64 become the nearest double, as `serde_json` reads them.
fn int_value(s: &str, mark: Marker) -> Result<Json, Error> {
    let too_big = || error(mark, format!("integer {s} is out of range"));
    let v = s.replace('_', "");
    let (neg, v) = match v.as_bytes()[0] {
        b'-' => (true, &v[1..]),
        b'+' => (false, &v[1..]),
        _ => (false, &v[..]),
    };
    let magnitude: i128 = if v == "0" {
        0
    } else if let Some(bin) = v.strip_prefix("0b") {
        i128::from_str_radix(bin, 2).map_err(|_| too_big())?
    } else if let Some(hex) = v.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).map_err(|_| too_big())?
    } else if v.starts_with('0') {
        i128::from_str_radix(v, 8).map_err(|_| too_big())?
    } else if v.contains(':') {
        let mut total: i128 = 0;
        for part in v.split(':') {
            let digit: i128 = part.parse().map_err(|_| too_big())?;
            total = total
                .checked_mul(60)
                .and_then(|t| t.checked_add(digit))
                .ok_or_else(too_big)?;
        }
        total
    } else {
        v.parse().map_err(|_| too_big())?
    };
    let n = if neg { -magnitude } else { magnitude };
    serde_json::from_str(&n.to_string()).map_err(|_| too_big())
}

/// `construct_yaml_float`, then the JSON round trip.
fn float_value(s: &str, mark: Marker) -> Result<Json, Error> {
    let v = s.replace('_', "").to_ascii_lowercase();
    let (sign, v) = match v.as_bytes()[0] {
        b'-' => (-1.0, &v[1..]),
        b'+' => (1.0, &v[1..]),
        _ => (1.0, &v[..]),
    };
    let f = if v == ".inf" || v == ".nan" {
        f64::NAN
    } else if v.contains(':') {
        // Summed from the last part, as PyYAML does, so rounding matches.
        let (mut total, mut base) = (0.0, 1.0);
        for part in v.split(':').rev() {
            total += part
                .parse::<f64>()
                .map_err(|_| error(mark, "invalid float"))?
                * base;
            base *= 60.0;
        }
        sign * total
    } else {
        sign * v
            .parse::<f64>()
            .map_err(|_| error(mark, format!("invalid float {s}")))?
    };
    serde_json::Number::from_f64(f)
        .map(Json::Number)
        .ok_or_else(|| {
            error(
                mark,
                format!("{s}: NaN and infinite values are not supported"),
            )
        })
}

/// Python's `repr(float)` (what `json.dumps` writes for a float key):
/// shortest round-trip digits, positional for exponents in -4..16.
fn py_float_repr(f: f64) -> String {
    let sci = format!("{f:e}"); // shortest digits: `-1.5e-7`, `1e16`
    let (mantissa, exp) = sci.split_once('e').expect("{:e} has an exponent");
    let exp: i32 = exp.parse().expect("integer exponent");
    if (-4..16).contains(&exp) {
        let s = format!("{f}");
        if s.contains('.') { s } else { format!("{s}.0") }
    } else {
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exp.abs())
    }
}

fn scalar(
    value: &str,
    style: TScalarStyle,
    tag: &Option<Tag>,
    mark: Marker,
) -> Result<Json, Error> {
    let kind = match tag_name(tag, mark)? {
        Some(t) => match t {
            "str" | "int" | "float" | "bool" | "null" => t,
            other => return Err(error(mark, format!("unsupported YAML tag !!{other}"))),
        },
        None if style == TScalarStyle::Plain => implicit(value),
        None => "str",
    };
    match kind {
        "str" => Ok(Json::String(value.to_string())),
        "null" => Ok(Json::Null),
        "bool" => bool_value(value)
            .map(Json::Bool)
            .ok_or_else(|| error(mark, format!("invalid boolean {value}"))),
        "int" => int_value(value, mark),
        "float" => float_value(value, mark),
        "timestamp" => Err(error(
            mark,
            format!("{value}: timestamps are not supported (Checkov cannot serialize them)"),
        )),
        "merge" => Err(error(mark, "merge key << outside a mapping key")),
        _ => Err(error(
            mark,
            format!("{value}: cannot construct a YAML value node"),
        )),
    }
}

/// A mapping key after the JSON round trip, or `None` for a merge key.
fn key(node: &Node) -> Result<Option<String>, Error> {
    let Node::Scalar {
        value,
        style,
        tag,
        mark,
    } = node
    else {
        return Err(error(node.mark(), "found unhashable key"));
    };
    let plain = *style == TScalarStyle::Plain && tag.is_none();
    if plain && value == "<<" || tag_name(tag, *mark)? == Some("merge") {
        return Ok(None);
    }
    // `=` as a key is a string (flatten_mapping); elsewhere it is an error.
    if plain && value == "=" {
        return Ok(Some("=".into()));
    }
    Ok(Some(match scalar(value, *style, tag, *mark)? {
        Json::String(s) => s,
        Json::Null => "null".into(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() => py_float_repr(f),
            _ => n.to_string(),
        },
        _ => unreachable!(),
    }))
}

/// `flatten_mapping`: merged pairs come first (later sources in a merge
/// sequence first), then explicit pairs; later pairs win.
fn flatten<'n>(
    pairs: &'n [(Node, Node)],
    out: &mut Vec<(&'n Node, &'n Node)>,
) -> Result<(), Error> {
    let mut merged = Vec::new();
    let mut own = Vec::new();
    for (k, v) in pairs {
        if key(k)?.is_some() {
            own.push((k, v));
            continue;
        }
        match v {
            Node::Map { pairs, .. } => flatten(pairs, &mut merged)?,
            Node::Seq { items, .. } => {
                let mut parts = Vec::new();
                for item in items {
                    let Node::Map { pairs, .. } = item else {
                        return Err(error(item.mark(), "expected a mapping for merging"));
                    };
                    let mut part = Vec::new();
                    flatten(pairs, &mut part)?;
                    parts.push(part);
                }
                for part in parts.into_iter().rev() {
                    merged.extend(part);
                }
            }
            _ => {
                return Err(error(
                    v.mark(),
                    "expected a mapping or list of mappings for merging",
                ));
            }
        }
    }
    out.extend(merged);
    out.extend(own);
    Ok(())
}

fn construct(
    node: &Node,
    ptr: String,
    positions: &mut HashMap<String, Position>,
) -> Result<Json, Error> {
    positions.insert(ptr.clone(), position(node.mark()));
    match node {
        Node::Scalar {
            value,
            style,
            tag,
            mark,
        } => scalar(value, *style, tag, *mark),
        Node::Seq { items, tag, mark } => {
            match tag_name(tag, *mark)? {
                None | Some("seq") => {}
                Some(other) => return Err(error(*mark, format!("unsupported YAML tag !!{other}"))),
            }
            items
                .iter()
                .enumerate()
                .map(|(i, n)| construct(n, format!("{ptr}/{i}"), positions))
                .collect::<Result<_, _>>()
                .map(Json::Array)
        }
        Node::Map { pairs, tag, mark } => {
            match tag_name(tag, *mark)? {
                None | Some("map") => {}
                Some(other) => return Err(error(*mark, format!("unsupported YAML tag !!{other}"))),
            }
            let mut flat = Vec::new();
            flatten(pairs, &mut flat)?;
            let mut map = Map::new();
            for (k, v) in flat {
                let k = key(k)?.expect("merge keys are flattened");
                let v = construct(v, format!("{ptr}/{k}"), positions)?;
                map.insert(k, v);
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
        load(s).unwrap().value
    }

    #[test]
    fn yaml_1_1_scalars() {
        assert_eq!(
            v(
                "[on, off, yes, no, True, y, n, '1', 012, 0x1f, 0b11, 1_000, 1:30, 1e3, 1.5e+3, 1., .5, ~, null, '']"
            ),
            json!([
                true, false, true, false, true, "y", "n", "1", 10, 31, 3, 1000, 90, "1e3", 1500.0,
                1.0, 0.5, null, null, ""
            ])
        );
    }

    #[test]
    fn keys_round_trip_through_json() {
        assert_eq!(
            v("{1: a, true: b, null: c, on: d}"),
            json!({"1": "a", "true": "d", "null": "c"})
        );
        assert_eq!(
            v("{1.5: a, 1.: b, 1.0e+16: c, 1.5e-5: d, 0.0001: e}"),
            json!({"1.5": "a", "1.0": "b", "1e+16": "c", "1.5e-05": "d", "0.0001": "e"})
        );
    }

    #[test]
    fn merge_keys_and_aliases() {
        let doc = "base: &b {x: 1, y: 2}\nother: &o {y: 3, z: 4}\nm:\n  <<: [*b, *o]\n  x: 9\n";
        assert_eq!(v(doc)["m"], json!({"x": 9, "y": 2, "z": 4}));
    }

    #[test]
    fn rejects_what_json_cannot_carry() {
        for bad in [
            "a: 2026-10-16",
            "a: .nan",
            "a: !!binary aGk=",
            "a: !!set {x}",
            "a: =",
            "[a]: 1",
        ] {
            assert!(load(bad).is_err(), "{bad}");
        }
        assert!(load("a: 1\n---\nb: 2\n").is_err());
        assert_eq!(v(""), Json::Null);
    }

    #[test]
    fn positions_by_pointer() {
        let doc =
            load("metadata:\n  id: X\ndefinition:\n  and:\n    - cond_type: attribute\n").unwrap();
        assert_eq!(
            doc.positions["/definition/and/0/cond_type"],
            Position { line: 5, col: 18 }
        );
    }
}

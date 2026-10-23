use super::*;

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

pub(crate) fn eval(
    engine: &regorus::Engine,
    input: Json,
    rule: &str,
) -> Result<regorus::Value, String> {
    eval_value(engine, regorus::Value::from(input), rule)
}

pub(super) fn eval_value(
    engine: &regorus::Engine,
    input: regorus::Value,
    rule: &str,
) -> Result<regorus::Value, String> {
    let mut engine = engine.clone();
    engine.set_input(input);
    engine
        .eval_rule(rule.to_string())
        .map_err(|e| e.to_string())
}

pub(super) fn to_serde(v: &regorus::Value) -> Result<Json, String> {
    serde_json::from_str(&v.to_json_str().map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// Whether an `exception` set's value names the rule.
pub(super) fn exception_names(v: &regorus::Value, e: &Exception) -> Result<bool, String> {
    if matches!(v, regorus::Value::Undefined) {
        return Ok(false);
    }
    Ok(match to_serde(v)? {
        Json::Array(items) => items.iter().any(|inner| match inner {
            Json::Array(names) => names.iter().any(|n| n.as_str() == Some(&e.name)),
            Json::Object(m) => m.values().any(|n| n.as_str() == Some(&e.name)),
            _ => false,
        }),
        Json::Object(m) => m.values().any(|inner| match inner {
            Json::Array(names) => names.iter().any(|n| n.as_str() == Some(&e.name)),
            Json::Object(m) => m.values().any(|n| n.as_str() == Some(&e.name)),
            _ => false,
        }),
        _ => false,
    })
}

/// One violation an entry rule produced.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Violation {
    pub msg: String,
    /// The resource the violation is about (`address`).
    pub address: Option<String>,
    /// The attribute it is about (`path`): `a.b[0].c` or `["a", "b", 0, "c"]`.
    pub path: Option<Vec<Segment>>,
    /// A mechanical fix (`fix`): set top-level `attribute` to `value`.
    pub fix: Option<(String, Json)>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Segment {
    Key(String),
    Index(usize),
}

/// The violations an entry rule produced, read as Conftest reads them: a
/// set or array whose strings are messages and whose objects need a `msg`
/// string (optional `address`, `path`, `fix`; other keys are metadata).
/// An empty message is a pass and other values are ignored, as in
/// Conftest.
pub(crate) fn violations(result: &regorus::Value) -> Result<Vec<Violation>, String> {
    if matches!(result, regorus::Value::Undefined) {
        return Ok(Vec::new());
    }
    let items = match to_serde(result)? {
        Json::Array(items) => items,
        Json::Bool(false) | Json::Null => Vec::new(),
        other => {
            return Err(format!(
                "entry rule must produce a set of violations, got {other}"
            ));
        }
    };
    let mut out = Vec::new();
    for item in items {
        if let Some(v) = violation(item)?
            && !v.msg.is_empty()
        {
            out.push(v);
        }
    }
    Ok(out)
}

pub(super) fn violation(item: Json) -> Result<Option<Violation>, String> {
    let o = match item {
        Json::String(msg) => {
            return Ok(Some(Violation {
                msg,
                address: None,
                path: None,
                fix: None,
            }));
        }
        Json::Object(o) => o,
        _ => return Ok(None),
    };
    let msg = match o.get("msg") {
        Some(Json::String(s)) => s.clone(),
        _ => {
            return Err(format!(
                "\"msg\" field must be present and a string in {}",
                Json::Object(o)
            ));
        }
    };
    let address = match o.get("address") {
        None | Some(Json::Null) => None,
        Some(Json::String(s)) => Some(s.clone()),
        Some(other) => return Err(format!("violation address must be a string, got {other}")),
    };
    let path = match o.get("path") {
        None | Some(Json::Null) => None,
        Some(Json::String(s)) => {
            Some(parse_path(s).ok_or_else(|| format!("invalid violation path {s:?}"))?)
        }
        Some(Json::Array(items)) => Some(
            items
                .iter()
                .map(|s| match s {
                    Json::String(k) => Some(Segment::Key(k.clone())),
                    Json::Number(n) => n.as_u64().map(|i| Segment::Index(i as usize)),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| format!("invalid violation path {}", Json::Array(items.clone())))?,
        ),
        Some(other) => {
            return Err(format!(
                "violation path must be a string or list, got {other}"
            ));
        }
    };
    let fix = match o.get("fix") {
        None | Some(Json::Null) => None,
        Some(Json::Object(f)) => match (f.get("attribute"), f.get("value")) {
            (Some(Json::String(a)), Some(v)) if !a.is_empty() && !a.contains(['.', '[']) => {
                Some((a.clone(), v.clone()))
            }
            _ => {
                return Err(format!(
                    "violation fix must be {{\"attribute\": <top-level name>, \"value\": <literal>}}, got {}",
                    Json::Object(f.clone())
                ));
            }
        },
        Some(other) => return Err(format!("violation fix must be an object, got {other}")),
    };
    Ok(Some(Violation {
        msg,
        address,
        path,
        fix,
    }))
}

/// `a.b[0].c`
pub(super) fn parse_path(s: &str) -> Option<Vec<Segment>> {
    let mut out = Vec::new();
    for part in s.split('.') {
        let (name, mut rest) = part.split_once('[').map_or((part, ""), |(n, r)| (n, r));
        if name.is_empty() {
            return None;
        }
        out.push(Segment::Key(name.to_string()));
        while !rest.is_empty() {
            let (index, tail) = rest.split_once(']')?;
            out.push(Segment::Index(index.parse().ok()?));
            rest = tail.strip_prefix('[').unwrap_or(tail);
            if !tail.is_empty() && !tail.starts_with('[') {
                return None;
            }
        }
    }
    Some(out)
}

/// The configured value at `path` in a resource body, with provenance.
pub(super) fn locate(body: &Body, path: &[Segment]) -> Option<Value> {
    let (Segment::Key(first), rest) = path.split_first()? else {
        return None;
    };
    if let Some(v) = body.value(first) {
        return descend(v, rest);
    }
    let blocks: Vec<&Body> = body
        .blocks
        .iter()
        .filter(|b| *b.ty == **first && b.existence == Truth::True)
        .map(|b| &b.body)
        .collect();
    match rest.split_first() {
        Some((Segment::Index(i), rest)) => locate(blocks.get(*i)?, rest),
        _ => None,
    }
}

pub(super) fn descend(v: &Value, path: &[Segment]) -> Option<Value> {
    let Some((seg, rest)) = path.split_first() else {
        return Some(v.clone());
    };
    match (&v.kind, seg) {
        (Kind::Known(Known::Object(m)), Segment::Key(k)) => {
            descend(&m.get(k.as_str())?.child_of(v), rest)
        }
        (Kind::Known(Known::List(l)), Segment::Index(i)) => descend(&l.get(*i)?.child_of(v), rest),
        _ => None,
    }
}

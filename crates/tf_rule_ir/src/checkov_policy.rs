//! Checkov YAML/JSON policies (graph checks and custom policies), read
//! directly into rule IR.
//!
//! This is the native front-end for Checkov's policy format: `metadata`,
//! `scope` and a `definition` tree of `attribute`, `connection` and `filter`
//! conditions under `and`/`or`/`not`. It produces exactly the IR the pinned
//! Python importer did (`tfscan.checkov._translate_graph`), and every shape
//! that importer rejected is rejected here, with the same blocker codes and
//! JSON Pointer paths. YAML is read as Checkov reads it ([`crate::pyyaml`]).
//!
//! Where Checkov's own loader and the old importer disagree, this follows
//! Checkov: `resource_types: all` (which the importer treated as "any
//! type") expands from Checkov's provider table for `scope.provider`, and
//! `*` (which Checkov matches literally) is rejected. Beyond the importer,
//! every attribute operator in the pinned registry is admitted.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use serde_json::{Value as Json, json};

use crate::RuleSpec;
use crate::checkov::{AttributeCheck, AttributeOp};
use crate::jsonpath::field_name;
use crate::pyyaml::{self, Position};

/// One reason a policy cannot be translated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blocker {
    /// JSON Pointer into the policy document (segments unescaped).
    pub path: String,
    pub code: &'static str,
    pub reason: String,
}

/// Whether a parsed JSON document is a Checkov policy rather than rule IR.
pub fn is_policy(doc: &Json) -> bool {
    doc.get("definition").is_some() && doc.get("metadata").is_some() && doc.get("clauses").is_none()
}

/// Python's `str()` of a JSON value, for messages that interpolate one.
fn py_str(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => "None".into(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Bool(true)) => "True".into(),
        Some(Json::Bool(false)) => "False".into(),
        Some(other) => other.to_string(),
    }
}

const META_ARGS: &[&str] = &[
    "lifecycle",
    "provisioner",
    "connection",
    "count",
    "for_each",
    "provider",
    "depends_on",
];

/// Python's `int(value)` for a JSON operand, limited to signed 64 bits.
fn py_int(v: &Json) -> Option<i64> {
    match v {
        Json::Bool(b) => Some(*b as i64),
        Json::Number(n) => n.as_i64().or_else(|| {
            let f = n.as_f64()?.trunc();
            (f >= -(2f64.powi(63)) && f < 2f64.powi(63)).then_some(f as i64)
        }),
        Json::String(s) => {
            // int(str): surrounding whitespace, a sign, ASCII digits with
            // single underscores between them. Other Unicode digits are
            // valid in Python but rejected here rather than guessed.
            let t = s.trim_matches(|c: char| c.is_whitespace());
            let (neg, digits) = match t.as_bytes().first() {
                Some(b'-') => (true, &t[1..]),
                Some(b'+') => (false, &t[1..]),
                _ => (false, t),
            };
            let b = digits.as_bytes();
            let ok = !b.is_empty()
                && b[0].is_ascii_digit()
                && b[b.len() - 1].is_ascii_digit()
                && b.iter().all(|c| c.is_ascii_digit() || *c == b'_')
                && !digits.contains("__");
            if !ok {
                return None;
            }
            let n: i128 = digits.replace('_', "").parse().ok()?;
            i64::try_from(if neg { -n } else { n }).ok()
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// JSONPath
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Tok {
    Id(String),
    Quoted(String),
    Dot,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Star,
    Question,
    At,
    And,
    Op(&'static str),
    Number(i64),
}

/// The tokens of bc_jsonpath_ng's extended lexer that the admitted grammar
/// uses. Anything else, including tokens whose lexing depends on rule order
/// in that lexer (`true…`/`false…` prefixes, keywords), is rejected.
fn lex(s: &str) -> Option<Vec<Tok>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\n' => i += 1,
            b'.' if b.get(i + 1) == Some(&b'.') => return None,
            b'.' => {
                out.push(Tok::Dot);
                i += 1;
            }
            b'[' | b']' | b'(' | b')' | b'*' | b'?' | b'@' => {
                out.push(match c {
                    b'[' => Tok::LBracket,
                    b']' => Tok::RBracket,
                    b'(' => Tok::LParen,
                    b')' => Tok::RParen,
                    b'*' => Tok::Star,
                    b'?' => Tok::Question,
                    _ => Tok::At,
                });
                i += 1;
            }
            b'&' => {
                i += if b.get(i + 1) == Some(&b'&') { 2 } else { 1 };
                out.push(Tok::And);
            }
            b'=' | b'!' | b'<' | b'>' => {
                // FILTER_OP: =~ | ==? | <= | >= | != | < | >
                let next = b.get(i + 1).copied();
                let (op, len) = match (c, next) {
                    (b'=', Some(b'~')) => ("=~", 2),
                    (b'=', Some(b'=')) => ("==", 2),
                    (b'=', _) => ("=", 1),
                    (b'!', Some(b'=')) => ("!=", 2),
                    (b'<', Some(b'=')) => ("<=", 2),
                    (b'>', Some(b'=')) => (">=", 2),
                    (b'<', _) => ("<", 1),
                    (b'>', _) => (">", 1),
                    _ => return None,
                };
                out.push(Tok::Op(op));
                i += len;
            }
            b'0'..=b'9' | b'-' => {
                // NUMBER (-?\d+); a FLOAT (-?\d+\.\d+) is not admitted.
                let start = i;
                if c == b'-' {
                    i += 1;
                    if !b.get(i).is_some_and(u8::is_ascii_digit) {
                        return None;
                    }
                }
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                if b.get(i) == Some(&b'.') && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
                    return None;
                }
                out.push(Tok::Number(s[start..i].parse().ok()?));
            }
            b'\'' | b'"' => {
                let mut v = String::new();
                let mut chars = s[i + 1..].char_indices();
                loop {
                    let (j, ch) = chars.next()?;
                    if ch as u32 == c as u32 {
                        i += 1 + j + 1;
                        break;
                    }
                    if ch == '\\' {
                        v.push(chars.next()?.1);
                    } else {
                        v.push(ch);
                    }
                }
                out.push(Tok::Quoted(v));
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len()
                    && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'-' | b'@'))
                {
                    i += 1;
                }
                let id = &s[start..i];
                if id.starts_with("true")
                    || id.starts_with("false")
                    || id == "where"
                    || id == "contains"
                {
                    return None;
                }
                if !field_name(id) {
                    return None;
                }
                out.push(Tok::Id(id.to_string()));
            }
            _ => return None,
        }
    }
    Some(out)
}

struct JsonPathParser {
    toks: Vec<Tok>,
    i: usize,
}

impl JsonPathParser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn id(&mut self) -> Option<String> {
        match self.peek() {
            Some(Tok::Id(s)) => {
                let s = s.clone();
                self.i += 1;
                Some(s)
            }
            _ => None,
        }
    }

    /// field ('.' field | '[*]' | '[?' exprs ']')*
    fn path(&mut self) -> Option<Vec<Json>> {
        let mut out = vec![Json::String(self.id()?)];
        loop {
            if self.eat(&Tok::Dot) {
                out.push(Json::String(self.id()?));
            } else if self.eat(&Tok::LBracket) {
                if self.eat(&Tok::Star) {
                    out.push(json!({"kind": "each"}));
                } else if self.eat(&Tok::Question) {
                    let predicates = self.exprs()?;
                    out.push(json!({"kind": "filter", "predicates": predicates}));
                } else {
                    return None;
                }
                if !self.eat(&Tok::RBracket) {
                    return None;
                }
            } else {
                break;
            }
        }
        Some(out)
    }

    /// term (('&' | '&&') term)*
    fn exprs(&mut self) -> Option<Vec<Json>> {
        let mut out = self.term()?;
        while self.eat(&Tok::And) {
            out.extend(self.term()?);
        }
        Some(out)
    }

    /// '(' exprs ')' | target op value
    fn term(&mut self) -> Option<Vec<Json>> {
        if self.eat(&Tok::LParen) {
            let out = self.exprs()?;
            return self.eat(&Tok::RParen).then_some(out);
        }
        // `@.a.b` or `a.b`, both relative to the filtered element.
        let mut path = Vec::new();
        if self.eat(&Tok::At) && !self.eat(&Tok::Dot) {
            return None;
        }
        path.push(self.id()?);
        while self.eat(&Tok::Dot) {
            path.push(self.id()?);
        }
        let op = match self.peek() {
            Some(Tok::Op(op)) => *op,
            _ => return None,
        };
        self.i += 1;
        let value = match self.peek() {
            Some(Tok::Id(s) | Tok::Quoted(s)) => json!(s),
            Some(Tok::Number(n)) => json!(n),
            _ => return None,
        };
        self.i += 1;
        let operator = match (op, value.is_string()) {
            ("==" | "=", _) => "equals",
            ("!=", _) => "not_equals",
            ("=~", true) => "regex",
            ("<", false) => "less_than",
            ("<=", false) => "less_than_or_equal",
            (">", false) => "greater_than",
            (">=", false) => "greater_than_or_equal",
            _ => return None,
        };
        if operator == "regex"
            && crate::pyre::compile(value.as_str()?, crate::pyre::Mode::Search).is_err()
        {
            return None;
        }
        Some(vec![
            json!({"path": path, "operator": operator, "value": value}),
        ])
    }
}

/// Compile a Checkov JSONPath attribute to IR path segments, or `None` for
/// syntax outside the admitted grammar.
pub fn compile_jsonpath(attribute: &str) -> Option<Vec<Json>> {
    let mut p = JsonPathParser {
        toks: lex(attribute)?,
        i: 0,
    };
    let path = p.path()?;
    if p.i != p.toks.len() {
        return None;
    }
    // Preserve the literal-path grammar accepted by existing v3 packs.
    if path.iter().all(Json::is_string) {
        let joined: Vec<&str> = path.iter().filter_map(Json::as_str).collect();
        if attribute != joined.join(".") {
            return None;
        }
    }
    Some(path)
}

// ---------------------------------------------------------------------------
// Policy translation
// ---------------------------------------------------------------------------

struct Translator {
    blockers: Vec<Blocker>,
    /// What `resource_types: all` expands to for this policy's scope.
    all_types: Vec<String>,
}

/// Checkov's provider table (`checks_infra/resources_types.py`), generated
/// from the pinned version by `scripts/gen_checkov_resource_types.py`.
fn provider_types(provider: &str) -> Option<Vec<String>> {
    static TABLE: std::sync::OnceLock<HashMap<String, Vec<String>>> = std::sync::OnceLock::new();
    TABLE
        .get_or_init(|| {
            let doc: Json =
                serde_json::from_str(include_str!("../data/checkov_resource_types.json"))
                    .expect("generated table is JSON");
            serde_json::from_value(doc["providers"].clone()).expect("provider table shape")
        })
        .get(provider)
        .cloned()
}

/// Python truthiness of a JSON value.
fn falsy(v: Option<&Json>) -> bool {
    match v {
        None | Some(Json::Null) => true,
        Some(Json::Bool(b)) => !b,
        Some(Json::Number(n)) => n.as_f64() == Some(0.0),
        Some(Json::String(s)) => s.is_empty(),
        Some(Json::Array(a)) => a.is_empty(),
        Some(Json::Object(o)) => o.is_empty(),
    }
}

fn kind(node: &Option<Json>) -> Option<&str> {
    node.as_ref()?.get("kind")?.as_str()
}

fn is_filter(node: &Option<Json>) -> bool {
    matches!(kind(node), Some("filter" | "attribute_filter"))
}

fn has_connection(node: &Json) -> bool {
    match node.get("kind").and_then(Json::as_str) {
        Some("connection") => true,
        Some("not") => node.get("arg").is_some_and(has_connection),
        _ => node
            .get("args")
            .and_then(Json::as_array)
            .is_some_and(|args| args.iter().any(has_connection)),
    }
}

impl Translator {
    fn reject(&mut self, path: impl Into<String>, code: &'static str, reason: impl Into<String>) {
        self.blockers.push(Blocker {
            path: path.into(),
            code,
            reason: reason.into(),
        });
    }

    fn types(&mut self, value: Option<&Json>, path: &str) -> Vec<String> {
        let list = match value {
            Some(Json::String(s)) => vec![Json::String(s.clone())],
            Some(Json::Array(a)) => a.clone(),
            _ => Vec::new(),
        };
        let strings: Vec<String> = list
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect();
        if list.is_empty() || strings.len() != list.len() || strings.iter().any(String::is_empty) {
            self.reject(
                path,
                "resource_types",
                "graph requires nonempty resource types",
            );
            return Vec::new();
        }
        if strings.iter().any(|t| t == "*") {
            self.reject(
                path,
                "resource_selector",
                "graph resource type `*` is matched literally by Checkov; use `all`",
            );
        }
        if strings
            .iter()
            .any(|t| t == "taggable" || t == "provider" || t.contains(['*', '?', '[']))
        {
            self.reject(
                path,
                "resource_selector",
                "graph resource-type wildcard/taggable selector",
            );
        }
        strings
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// An attribute or connection condition's `resource_types`, as
    /// Checkov's parser reads it: missing, empty, `all` or a list starting
    /// with `all` expands from the provider table, or matches every vertex.
    fn leaf_types(&mut self, value: Option<&Json>, path: &str) -> Vec<String> {
        let first_all = match value {
            Some(Json::String(s)) => s.to_lowercase() == "all",
            Some(Json::Array(a)) => match a.first() {
                Some(Json::String(s)) => s.to_lowercase() == "all",
                Some(_) => {
                    self.reject(
                        path,
                        "resource_types",
                        "graph resource types must be strings",
                    );
                    return Vec::new();
                }
                None => false,
            },
            _ => false,
        };
        if falsy(value) || first_all {
            return self.all_types.clone();
        }
        let provider = match value {
            Some(Json::String(s)) => s.contains("provider"),
            Some(Json::Array(a)) => a.iter().any(|t| t.as_str() == Some("provider")),
            _ => false,
        };
        if provider {
            // Checkov selects provider blocks here (a substring match for a
            // string), which oxtf does not evaluate.
            self.reject(path, "resource_selector", "graph provider-block selector");
            return Vec::new();
        }
        self.types(value, path)
    }

    /// `connected_resource_types`: only `"all"` or `["All"]` expand; a
    /// missing or empty value matches every vertex. Checkov keeps any other
    /// string as a string and matches substrings of it, which is rejected.
    fn connected_types(&mut self, value: Option<&Json>, path: &str) -> Vec<String> {
        match value {
            Some(Json::String(s)) if s == "all" => self.all_types.clone(),
            Some(Json::Array(a)) if a.len() == 1 && a[0] == "All" => self.all_types.clone(),
            v if falsy(v) => vec!["*".to_string()],
            Some(Json::String(_)) => {
                self.reject(
                    path,
                    "resource_types",
                    "Checkov matches a string connected_resource_types by substring; use a list",
                );
                Vec::new()
            }
            v => self.types(v, path),
        }
    }

    fn expression(&mut self, node: Option<&Json>, path: &str) -> Option<Json> {
        let Some(Json::Object(obj)) = node else {
            self.reject(path, "structure", "graph condition requires an object");
            return None;
        };
        let logical: Vec<&str> = ["and", "or", "not"]
            .into_iter()
            .filter(|op| obj.contains_key(*op))
            .collect();
        if !logical.is_empty() {
            if obj.len() != 1 {
                self.reject(path, "structure", "unsupported graph boolean structure");
            }
            let mut children: Vec<Option<Json>> = Vec::new();
            // Visit every branch even when a sibling or parent is unsupported.
            for op in &logical {
                let args = &obj[*op];
                let op_path = format!("{path}/{op}");
                if *op == "not" && args.is_object() {
                    children.push(self.expression(Some(args), &op_path));
                    continue;
                }
                let list = args.as_array();
                if list.is_none_or(|l| l.is_empty() || (*op == "not" && l.len() != 1)) {
                    self.reject(&op_path, "structure", "unsupported graph boolean structure");
                }
                if let Some(list) = list {
                    for (i, x) in list.iter().enumerate() {
                        children.push(self.expression(Some(x), &format!("{op_path}/{i}")));
                    }
                }
            }
            let op = logical[0];
            if op == "not" {
                if children.iter().any(is_filter) {
                    self.reject(path, "filter_scope", "cannot negate a graph filter");
                }
                let arg = children.into_iter().next().flatten();
                return Some(json!({"kind": op, "arg": arg}));
            }
            if !children.is_empty() && children.iter().all(is_filter) {
                self.reject(path, "filter_only", "graph filters require a predicate");
            }
            if children.iter().any(|c| kind(c) == Some("attribute_filter"))
                && !children.iter().flatten().any(has_connection)
            {
                self.reject(
                    path,
                    "filter_scope",
                    "graph attribute filters require a connection expression",
                );
            }
            let args: Vec<Json> = children
                .into_iter()
                .map(|c| c.unwrap_or(Json::Null))
                .collect();
            return Some(json!({"kind": op, "args": args}));
        }
        let cond_type = obj.get("cond_type");
        let operator = obj.get("operator");
        let op_str = operator.and_then(Json::as_str);
        let unknown_fields = |allowed: &[&str]| obj.keys().any(|k| !allowed.contains(&k.as_str()));
        match cond_type.and_then(Json::as_str) {
            Some("connection") => {
                if !matches!(op_str, Some("exists" | "not_exists" | "one_exists")) {
                    self.reject(
                        format!("{path}/operator"),
                        "connection_operator",
                        format!("unsupported connection operator: {}", py_str(operator)),
                    );
                }
                // 'attribute' is descriptive metadata; Checkov's connection solver
                // does not use it to restrict an edge to a Terraform attribute.
                if unknown_fields(&[
                    "cond_type",
                    "resource_types",
                    "connected_resource_types",
                    "operator",
                    "attribute",
                ]) {
                    self.reject(path, "fields", "unknown graph connection fields");
                }
                let resource_types =
                    self.leaf_types(obj.get("resource_types"), &format!("{path}/resource_types"));
                let connected = self.connected_types(
                    obj.get("connected_resource_types"),
                    &format!("{path}/connected_resource_types"),
                );
                return Some(json!({
                    "kind": "connection", "resource_types": resource_types,
                    "connected_resource_types": connected, "operator": operator.cloned().unwrap_or(Json::Null),
                }));
            }
            Some("filter") => {
                if unknown_fields(&[
                    "cond_type",
                    "resource_types",
                    "attribute",
                    "operator",
                    "value",
                ]) {
                    self.reject(path, "fields", "unknown graph filter fields");
                }
                // The pinned filter solver ignores resource_types. Other predicates
                // select candidates; filters restrict the resulting vertices only.
                if obj.contains_key("resource_types") {
                    self.types(obj.get("resource_types"), &format!("{path}/resource_types"));
                }
                let attribute = obj.get("attribute");
                let value = obj.get("value");
                if attribute.and_then(Json::as_str) == Some("resource_type") {
                    if !matches!(op_str, Some("within" | "not_within")) {
                        self.reject(
                            format!("{path}/operator"),
                            "filter_operator",
                            "graph resource-type filter requires within/not_within",
                        );
                    }
                    let types = self.types(value, &format!("{path}/value"));
                    return Some(json!({
                        "kind": "filter", "resource_types": types, "exclude": op_str == Some("not_within"),
                    }));
                }
                if op_str != Some("within") {
                    self.reject(
                        format!("{path}/operator"),
                        "filter_operator",
                        "graph attribute filter requires within",
                    );
                }
                let attr = attribute.and_then(Json::as_str);
                if attr.is_none_or(|a| a.is_empty() || a.contains(['.', '*', '?', '[', ']', '/'])) {
                    self.reject(
                        format!("{path}/attribute"),
                        "filter_path",
                        "graph attribute filter requires a literal top-level configured attribute",
                    );
                }
                if attr.is_some_and(|a| META_ARGS.contains(&a.split('.').next().unwrap_or(""))) {
                    self.reject(
                        format!("{path}/attribute"),
                        "meta_argument",
                        "graph filter requires meta-argument support",
                    );
                }
                let scalar_list = value
                    .and_then(Json::as_array)
                    .is_some_and(|l| l.iter().all(|v| !v.is_array() && !v.is_object()));
                if !value.is_some_and(Json::is_string) && !scalar_list {
                    self.reject(
                        format!("{path}/value"),
                        "filter_value",
                        "graph attribute filter expects a string or list of scalars",
                    );
                }
                return Some(json!({
                    "kind": "attribute_filter",
                    "check": {"attribute": attribute.cloned().unwrap_or(Json::Null), "value": value.cloned().unwrap_or(Json::Null)},
                }));
            }
            Some("attribute") => {}
            _ => {
                self.reject(
                    path,
                    "condition",
                    format!("unsupported graph condition: {}", py_str(cond_type)),
                );
                return None;
            }
        }
        let jsonpath = op_str.is_some_and(|o| o.starts_with("jsonpath_"));
        let base_op = op_str.map(|o| o.strip_prefix("jsonpath_").unwrap_or(o));
        let parsed: Option<AttributeOp> =
            base_op.and_then(|o| serde_json::from_value(json!(o)).ok());
        if parsed.is_none() {
            self.reject(
                format!("{path}/operator"),
                "attribute_operator",
                format!("unsupported graph operator: {}", py_str(operator)),
            );
        }
        let attribute = obj.get("attribute");
        let mut compiled: Vec<Json> = Vec::new();
        let attr_path = format!("{path}/attribute");
        match attribute.and_then(Json::as_str) {
            None | Some("") => {
                self.reject(
                    &attr_path,
                    "attribute_path",
                    "graph requires a nonempty attribute path",
                );
            }
            Some(a) if jsonpath => match compile_jsonpath(a) {
                Some(p) => compiled = p,
                None => self.reject(
                    &attr_path,
                    "jsonpath",
                    "unsupported JSONPath syntax or filter predicate",
                ),
            },
            Some(a) if a.contains(['[', ']', '/']) => {
                self.reject(
                    &attr_path,
                    "jsonpath",
                    "graph predicate requires JSONPath support",
                );
            }
            Some(a)
                if a.split('.')
                    .any(|p| p.is_empty() || (p.contains('*') && p != "*")) =>
            {
                self.reject(
                    &attr_path,
                    "attribute_path",
                    "graph path requires literal segments or '*' elements",
                );
            }
            Some(_) => {}
        }
        let root_field = match compiled.first() {
            Some(first) => first.as_str(),
            None => attribute
                .and_then(Json::as_str)
                .map(|a| a.split('.').next().unwrap_or("")),
        };
        if root_field.is_some_and(|f| META_ARGS.contains(&f)) {
            self.reject(
                &attr_path,
                "meta_argument",
                "graph predicate requires meta-argument support",
            );
        }
        let mut value = obj.get("value").cloned().unwrap_or(Json::Null);
        let value_path = format!("{path}/value");
        let scalar_list = |v: &Json| {
            v.as_array()
                .is_some_and(|l| l.iter().all(|v| !v.is_array() && !v.is_object()))
        };
        match parsed {
            Some(
                AttributeOp::Within
                | AttributeOp::NotWithin
                | AttributeOp::Subset
                | AttributeOp::NotSubset,
            ) if !scalar_list(&value) => {
                self.reject(
                    &value_path,
                    "scalar_list",
                    format!("graph {} requires scalar list", base_op.unwrap_or_default()),
                );
            }
            Some(op) if op.is_size() => {
                // Match Checkov's force_int at export time; native operands are
                // canonical integers, with no Python coercion needed at runtime.
                match py_int(&value) {
                    Some(n) => value = Json::from(n),
                    None => self.reject(
                        &value_path,
                        "integer_operand",
                        "graph size comparison requires a signed 64-bit integer threshold",
                    ),
                }
            }
            Some(op) => {
                let check = AttributeCheck {
                    attribute: String::new(),
                    operator: op,
                    value: value.clone(),
                    prepared: Default::default(),
                };
                if let Err(e) = check.validate_operand() {
                    if value.is_array() || value.is_object() {
                        self.reject(
                            &value_path,
                            "composite_comparison",
                            "graph composite comparison",
                        );
                    } else {
                        let reason = e.trim_start_matches("checkov_attribute: ");
                        self.reject(
                            &value_path,
                            "operand",
                            format!("graph {}: {reason}", base_op.unwrap_or_default()),
                        );
                    }
                }
            }
            None => {}
        }
        if unknown_fields(&[
            "cond_type",
            "resource_types",
            "attribute",
            "operator",
            "value",
        ]) {
            self.reject(path, "fields", "unknown graph predicate fields");
        }
        let resource_types =
            self.leaf_types(obj.get("resource_types"), &format!("{path}/resource_types"));
        let operator = operator.cloned().unwrap_or(Json::Null);
        Some(if jsonpath {
            let op = op_str.unwrap_or("").trim_start_matches("jsonpath_");
            json!({"kind": "jsonpath", "resource_types": resource_types,
                   "check": {"path": compiled, "operator": op, "value": value}})
        } else {
            json!({"kind": "attribute", "resource_types": resource_types,
                   "check": {"attribute": attribute.cloned().unwrap_or(Json::Null), "operator": operator, "value": value}})
        })
    }
}

fn targets(node: &Json, out: &mut BTreeSet<String>) {
    let strings = |key: &str| {
        node.get(key)
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
            .filter_map(Json::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    match node.get("kind").and_then(Json::as_str) {
        Some("attribute" | "connection" | "jsonpath") => {
            out.extend(strings("resource_types"));
            out.extend(strings("connected_resource_types"));
        }
        Some("filter" | "attribute_filter") => {}
        Some("not") => targets(&node["arg"], out),
        _ => node
            .get("args")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
            .for_each(|a| targets(a, out)),
    }
}

/// Checkov's severity names on oxtf's impact levels. INFO and NONE have no
/// lower level to go to and become `low`.
fn level(metadata: &serde_json::Map<String, Json>) -> Result<&'static str, Blocker> {
    match metadata.get("severity") {
        None | Some(Json::Null) => Ok("medium"),
        Some(Json::String(s)) => Ok(match s.to_uppercase().as_str() {
            "CRITICAL" => "critical",
            "HIGH" => "high",
            "LOW" | "INFO" | "NONE" => "low",
            // Checkov ignores unknown names (get_severity returns None).
            _ => "medium",
        }),
        Some(_) => Err(Blocker {
            path: "/metadata/severity".into(),
            code: "metadata",
            reason: "metadata.severity must be a string".into(),
        }),
    }
}

/// Translate one parsed policy document.
pub fn translate(doc: &Json) -> Result<RuleSpec, Vec<Blocker>> {
    let mut t = Translator {
        blockers: Vec::new(),
        all_types: vec!["*".to_string()],
    };
    if !doc.is_object() {
        t.reject("", "structure", "policy document must be a mapping");
        return Err(t.blockers);
    }
    // Checkov's registry lowercases `scope.provider` to pick the table for
    // `resource_types: all`; without a table entry, `all` matches everything.
    match doc.get("scope") {
        None => {}
        Some(Json::Object(scope)) => match scope.get("provider") {
            None => {}
            Some(Json::String(p)) => {
                if let Some(types) = provider_types(&p.to_lowercase()) {
                    t.all_types = types;
                }
            }
            Some(_) => t.reject(
                "/scope/provider",
                "scope",
                "scope.provider must be a string",
            ),
        },
        Some(_) => t.reject("/scope", "scope", "scope must be a mapping"),
    }
    // Checkov's validate_check_config: these fields are required.
    let metadata = doc.get("metadata").and_then(Json::as_object);
    let field = |name: &str| metadata.and_then(|m| m.get(name));
    for name in ["id", "name"] {
        if field(name).and_then(Json::as_str).is_none_or(str::is_empty) {
            t.reject(
                format!("/metadata/{name}"),
                "metadata",
                format!("policy requires a nonempty string metadata.{name}"),
            );
        }
    }
    if field("category").is_none() {
        t.reject(
            "/metadata/category",
            "metadata",
            "policy requires metadata.category",
        );
    }
    let level = match metadata.map(level).transpose() {
        Ok(l) => l.unwrap_or("medium"),
        Err(b) => {
            t.blockers.push(b);
            "medium"
        }
    };
    let definition = t.expression(doc.get("definition"), "/definition");
    if is_filter(&definition) {
        t.reject(
            "/definition",
            "filter_only",
            "graph filters require a predicate",
        );
    }
    if !t.blockers.is_empty() {
        return Err(t.blockers);
    }
    let definition = definition.expect("no blockers implies a definition");
    let mut resource_types = BTreeSet::new();
    targets(&definition, &mut resource_types);
    let id = field("id").and_then(Json::as_str).unwrap_or_default();
    let name = field("name").and_then(Json::as_str).unwrap_or_default();
    let rule = json!({
        "version": 3, "name": id, "description": name,
        "message": name.replace('{', "{{").replace('}', "}}"),
        "category": "other", "level": level,
        "clauses": [{"resource_types": resource_types,
                     "condition": {"op": "checkov_graph", "definition": definition}}],
    });
    serde_json::from_value(rule).map_err(|e| {
        vec![Blocker {
            path: "/definition".into(),
            code: "structure",
            reason: format!("translated policy is not valid rule IR: {e}"),
        }]
    })
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// A policy file's document and the source position of each pointer.
pub struct PolicySource {
    pub value: Json,
    positions: HashMap<String, Position>,
}

impl PolicySource {
    /// Read `.yaml`/`.yml` as Checkov does (PyYAML `safe_load`), anything
    /// else as JSON.
    pub fn parse(path: &Path, text: &str) -> Result<Self, String> {
        let yaml = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml" | "yml")
        );
        if yaml {
            let doc = pyyaml::load(text).map_err(|e| e.to_string())?;
            return Ok(PolicySource {
                value: doc.value,
                positions: doc.positions,
            });
        }
        let value: Json = serde_json::from_str(text).map_err(|e| e.to_string())?;
        Ok(Self::from_json(value, text))
    }

    /// A JSON policy already parsed from `text`.
    pub fn from_json(value: Json, text: &str) -> Self {
        PolicySource {
            value,
            positions: json_positions(text),
        }
    }

    /// The position of a pointer, or of its nearest ancestor that has one.
    pub fn position(&self, pointer: &str) -> Option<Position> {
        let mut p = pointer;
        loop {
            if let Some(pos) = self.positions.get(p) {
                return Some(*pos);
            }
            p = &p[..p.rfind('/')?];
        }
    }
}

/// Translate a policy file, formatting blockers as diagnostics against it.
pub fn translate_source(path: &Path, source: &PolicySource) -> Result<RuleSpec, String> {
    translate(&source.value).map_err(|blockers| {
        let id = source
            .value
            .pointer("/metadata/id")
            .and_then(Json::as_str)
            .unwrap_or("<no id>");
        blockers
            .iter()
            .map(|b| {
                let at = match source.position(&b.path) {
                    Some(p) => format!("{}:{}:{}", path.display(), p.line, p.col),
                    None => path.display().to_string(),
                };
                format!("{at}: {id}: {} [{}] at {}", b.reason, b.code, b.path)
            })
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// Start positions of every value in a JSON text, by JSON Pointer. The text
/// has already been parsed successfully, so this scanner does not validate.
fn json_positions(text: &str) -> HashMap<String, Position> {
    struct Scan<'a> {
        b: &'a [u8],
        i: usize,
        line: usize,
        line_start: usize,
        out: HashMap<String, Position>,
    }
    impl Scan<'_> {
        fn ws(&mut self) {
            while let Some(&c) = self.b.get(self.i) {
                match c {
                    b'\n' => {
                        self.i += 1;
                        self.line += 1;
                        self.line_start = self.i;
                    }
                    b' ' | b'\t' | b'\r' => self.i += 1,
                    _ => break,
                }
            }
        }
        fn string(&mut self) -> String {
            let start = self.i;
            self.i += 1;
            while let Some(&c) = self.b.get(self.i) {
                self.i += 1;
                match c {
                    b'\\' => self.i += 1,
                    b'"' => break,
                    _ => {}
                }
            }
            let raw = std::str::from_utf8(&self.b[start..self.i]).unwrap_or("\"\"");
            serde_json::from_str(raw).unwrap_or_default()
        }
        fn value(&mut self, ptr: String) {
            self.ws();
            let col = std::str::from_utf8(&self.b[self.line_start..self.i])
                .map_or(0, |s| s.chars().count());
            self.out.insert(
                ptr.clone(),
                Position {
                    line: self.line,
                    col: col + 1,
                },
            );
            match self.b.get(self.i) {
                Some(b'{') => {
                    self.i += 1;
                    loop {
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b'"') => {
                                let k = self.string();
                                self.ws();
                                self.i += 1; // ':'
                                self.value(format!("{ptr}/{k}"));
                                self.ws();
                                if self.b.get(self.i) == Some(&b',') {
                                    self.i += 1;
                                }
                            }
                            Some(_) => {
                                self.i += 1; // '}'
                                break;
                            }
                            None => break,
                        }
                    }
                }
                Some(b'[') => {
                    self.i += 1;
                    let mut n = 0;
                    loop {
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b']') | None => {
                                self.i += 1;
                                break;
                            }
                            Some(_) => {
                                self.value(format!("{ptr}/{n}"));
                                n += 1;
                                self.ws();
                                if self.b.get(self.i) == Some(&b',') {
                                    self.i += 1;
                                }
                            }
                        }
                    }
                }
                Some(b'"') => {
                    self.string();
                }
                Some(_) => {
                    while self
                        .b
                        .get(self.i)
                        .is_some_and(|c| !b",]} \t\r\n".contains(c))
                    {
                        self.i += 1;
                    }
                }
                None => {}
            }
        }
    }
    let mut s = Scan {
        b: text.as_bytes(),
        i: 0,
        line: 1,
        line_start: 0,
        out: HashMap::new(),
    };
    s.value(String::new());
    s.out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonpath_grammar() {
        let ok = |s: &str| compile_jsonpath(s).map(|p| Json::Array(p).to_string());
        assert_eq!(ok("a.b").as_deref(), Some(r#"["a","b"]"#));
        assert_eq!(
            ok("a[*].b").as_deref(),
            Some(r#"["a",{"kind":"each"},"b"]"#)
        );
        assert_eq!(
            ok("a[?(@.k == 'v' & x.y != \"w\")]").as_deref(),
            Some(
                r#"["a",{"kind":"filter","predicates":[{"operator":"equals","path":["k"],"value":"v"},{"operator":"not_equals","path":["x","y"],"value":"w"}]}]"#
            )
        );
        for bad in [
            "a..b",
            "a . b",
            "$.a",
            "a[0]",
            "[*].a",
            "a[?(@.k =~ 1)]",
            "a[?(@.k > 'v')]",
            "true_x.a",
            "a.where",
        ] {
            assert_eq!(ok(bad), None, "{bad}");
        }
    }

    #[test]
    fn python_int_coercion() {
        assert_eq!(py_int(&json!("1_000")), Some(1000));
        assert_eq!(py_int(&json!(" -7 ")), Some(-7));
        assert_eq!(py_int(&json!(3.9)), Some(3));
        assert_eq!(py_int(&json!(true)), Some(1));
        for bad in [
            json!("1__0"),
            json!("_1"),
            json!("3.0"),
            json!(null),
            json!([1]),
        ] {
            assert_eq!(py_int(&bad), None, "{bad}");
        }
    }

    #[test]
    fn json_pointer_positions() {
        let p = json_positions("{\n  \"a\": [1,\n    {\"b\": \"x\"}]\n}");
        assert_eq!(p["/a/1/b"], Position { line: 3, col: 11 });
    }
}

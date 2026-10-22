//! `cargo run -p tfscan_stubgen -- [ALLOWLIST] [OUT_DIR]`
//!
//! Writes `schema.pyi` (Literal attribute names, TypedDicts and typed
//! `col_of` overloads) and `schema.py` (the same names plus the runtime
//! attribute table and a validating `col_of`) for every resource in the W2
//! typed-view allowlist (`crates/tf_schema_codegen/allowlist.toml`, read
//! only), using the `tf_schema` runtime API: the same embedded schema IR the
//! typed Rust views are generated from.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::Deserialize;
use tf_schema::{Block, CtyType, NestingMode, SchemaKind};

#[derive(Deserialize)]
struct Allowlist {
    view: Vec<View>,
}

#[derive(Deserialize)]
struct View {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    kind: Option<String>,
}

/// Nested levels expanded into TypedDicts; deeper levels are `dict[str, Any]`.
const MAX_DEPTH: usize = 3;

struct Gen {
    /// TypedDict definitions in dependency order.
    defs: String,
    /// Literal aliases.
    lits: String,
    /// scope key (`aws_security_group`, `aws_security_group.ingress`) →
    /// (alias name, member names).
    scopes: BTreeMap<String, (String, Vec<String>)>,
}

fn pascal(s: &str) -> String {
    s.split(['_', '.'])
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn py_ident_ok(s: &str) -> bool {
    const KW: &[&str] = &[
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class",
        "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global",
        "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
        "try", "while", "with", "yield",
    ];
    !KW.contains(&s) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Gen {
    fn cty(&mut self, t: &CtyType<'_>, scope: &str, name: &str, depth: usize) -> String {
        match t {
            CtyType::String => "str".into(),
            CtyType::Number => "float".into(),
            CtyType::Bool => "bool".into(),
            CtyType::Dynamic => "Any".into(),
            CtyType::List(e) | CtyType::Set(e) => {
                format!("list[{}]", self.cty(e, scope, name, depth))
            }
            CtyType::Map(e) => format!("dict[str, {}]", self.cty(e, scope, name, depth)),
            CtyType::Tuple(_) => "list[Any]".into(),
            CtyType::Object(attrs) => {
                if depth >= MAX_DEPTH {
                    return "dict[str, Any]".into();
                }
                let key = format!("{scope}.{name}");
                let members: Vec<(String, String, bool)> = attrs
                    .iter()
                    .map(|a| {
                        let ty = self.cty(&a.ty, &key, a.name, depth + 1);
                        (a.name.to_string(), ty, a.optional)
                    })
                    .collect();
                self.typed_dict(&key, &members)
            }
            CtyType::Nested(mode, b) => {
                if depth >= MAX_DEPTH {
                    return "dict[str, Any]".into();
                }
                let key = format!("{scope}.{name}");
                let td = self.block(&key, b, depth + 1);
                wrap(*mode, td)
            }
        }
    }

    fn block(&mut self, key: &str, b: &Block<'_>, depth: usize) -> String {
        let mut members = Vec::new();
        for a in &b.attributes {
            let ty = self.cty(&a.ty, key, a.name, depth);
            members.push((a.name.to_string(), ty, !a.is_required()));
        }
        for nb in &b.block_types {
            let ty = if depth >= MAX_DEPTH {
                wrap(nb.nesting, "dict[str, Any]".into())
            } else {
                let k = format!("{key}.{}", nb.name);
                let td = self.block(&k, &nb.block, depth + 1);
                wrap(nb.nesting, td)
            };
            members.push((nb.name.to_string(), ty, true));
        }
        self.typed_dict(key, &members)
    }

    fn typed_dict(&mut self, key: &str, members: &[(String, String, bool)]) -> String {
        let name = pascal(key);
        let alias = format!("{name}Attr");
        let mut names: Vec<String> = members.iter().map(|m| m.0.clone()).collect();
        names.sort();
        let _ = writeln!(
            self.lits,
            "{alias} = Literal[{}]",
            names
                .iter()
                .map(|n| format!("{n:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        self.scopes.insert(key.to_string(), (alias, names));
        // Functional TypedDict syntax: attribute names may be keywords.
        let all_ok = members.iter().all(|m| py_ident_ok(&m.0));
        if all_ok {
            let _ = writeln!(self.defs, "class {name}(TypedDict, total=False):");
            if members.is_empty() {
                let _ = writeln!(self.defs, "    pass");
            }
            for (n, t, _) in members {
                let _ = writeln!(self.defs, "    {n}: {t}");
            }
            let _ = writeln!(self.defs);
        } else {
            let fields: Vec<String> = members
                .iter()
                .map(|(n, t, _)| format!("{n:?}: {t}"))
                .collect();
            let _ = writeln!(
                self.defs,
                "{name} = TypedDict({name:?}, {{{}}}, total=False)\n",
                fields.join(", ")
            );
        }
        name
    }
}

fn wrap(mode: NestingMode, td: String) -> String {
    match mode {
        NestingMode::Single | NestingMode::Group => td,
        NestingMode::List | NestingMode::Set => format!("list[{td}]"),
        NestingMode::Map => format!("dict[str, {td}]"),
    }
}

#[expect(clippy::too_many_lines)]
fn main() {
    let mut args = std::env::args().skip(1);
    let ws = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let allowlist = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| ws.join("crates/tf_schema_codegen/allowlist.toml"));
    let out = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| ws.join("crates/tfscan_py/python/tfscan"));
    let text = std::fs::read_to_string(&allowlist).expect("read allowlist");
    let al: Allowlist = toml::from_str(&text).expect("parse allowlist");
    let mut g = Gen {
        defs: String::new(),
        lits: String::new(),
        scopes: BTreeMap::new(),
    };
    let mut types = Vec::new();
    let mut providers = BTreeMap::new();
    for v in &al.view {
        let kind = match v.kind.as_deref() {
            Some("data") => SchemaKind::DataSource,
            _ => SchemaKind::Resource,
        };
        let Some(s) = tf_schema::lookup(kind, &v.ty) else {
            eprintln!("warning: {} not in the schema IR; skipped", v.ty);
            continue;
        };
        providers.insert(s.provider.source(), ());
        let key = if kind == SchemaKind::DataSource {
            format!("data.{}", v.ty)
        } else {
            v.ty.clone()
        };
        g.block(&key, s.block(), 0);
        types.push(key);
    }
    let header = format!(
        "# Generated by `cargo run -p tfscan_stubgen` from the tf_schema IR for the\n\
         # typed-view allowlist ({} entries; providers: {}). Do not edit.\n",
        types.len(),
        providers.keys().copied().collect::<Vec<_>>().join(", ")
    );
    let names = |s: &[String]| {
        s.iter()
            .map(|n| format!("{n:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let shared = format!(
        "{header}\nfrom __future__ import annotations\n\nfrom typing import Any, Literal, TypedDict\n\n\
         ResourceType = Literal[{}]\n\
         # Scopes accepted by col_of: a resource type, or `type.attr[.attr]` for the\n\
         # fields of a nested block / object element (used inside for_each).\n\
         Scope = Literal[{}]\n\n{}\n{}",
        names(&types),
        names(&g.scopes.keys().cloned().collect::<Vec<_>>()),
        g.lits,
        g.defs
    );
    // Runtime module.
    let mut py = shared.clone();
    py.push_str("\nATTRIBUTES: dict[str, frozenset[str]] = {\n");
    for (k, (_, ns)) in &g.scopes {
        let _ = writeln!(py, "    {k:?}: frozenset({{{}}}),", names(ns));
    }
    py.push_str(
        "}\n\n\ndef col_of(scope: str, name: str, *path: str, default: bool = False):\n    \
         \"\"\"`col(name, *path)`, checking `name` against the schema of `scope`.\"\"\"\n    \
         from .expr import col\n\n    \
         names = ATTRIBUTES[scope]\n    \
         if name not in names:\n        \
         raise KeyError(f\"{scope} has no attribute {name!r}\")\n    \
         return col(name, *path, default=default)\n",
    );
    // Stub.
    let mut pyi = shared;
    pyi.push_str("\nfrom typing import overload\n\nfrom .expr import Expr\n\nATTRIBUTES: dict[str, frozenset[str]]\n\n");
    for (k, (alias, _)) in &g.scopes {
        let _ = writeln!(
            pyi,
            "@overload\ndef col_of(scope: Literal[{k:?}], name: {alias}, *path: str, default: bool = ...) -> Expr: ..."
        );
    }
    // No catch-all overload: a name outside the scope's schema is a type
    // error (use `tfscan.col` for untyped access).
    std::fs::write(out.join("schema.py"), &py).expect("write schema.py");
    std::fs::write(out.join("schema.pyi"), &pyi).expect("write schema.pyi");
    println!(
        "wrote {} ({} lines) and {} ({} lines): {} types, {} scopes",
        out.join("schema.py").display(),
        py.lines().count(),
        out.join("schema.pyi").display(),
        pyi.lines().count(),
        types.len(),
        g.scopes.len()
    );
}

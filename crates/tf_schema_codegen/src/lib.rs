//! Generator for `tf_schema`. Reads `schemas/providers/{aws,azurerm,google}.json`
//! (`terraform providers schema -json`), the view allowlist and the defaults
//! overlay, and writes `crates/tf_schema/src/generated/`:
//!
//! * `schema.postcard`: every resource and data source schema, postcard
//!   encoded back to back (one independently decodable record per schema).
//! * `index.rs`: per-entry byte ranges plus `phf` maps name -> entry id.
//! * `views.rs`: typed views for allowlisted resources.
//! * `defaults.rs`: the validated defaults overlay as a `phf` map.
//!
//! Errors (missing allowlisted resource, allowlist `uses` path that no longer
//! exists, a default for an unknown attribute or of the wrong type) abort
//! generation with a non-zero exit.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tf_schema::ir::{
    Attribute, Block, CtyType, NestedBlock, NestingMode, ObjectAttr, Provider, SchemaBody,
    SchemaKind, flags,
};

pub type Error = String;
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// JSON input model
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SchemaFile {
    pub provider_schemas: BTreeMap<String, ProviderSchema>,
}

#[derive(Debug, Deserialize)]
pub struct ProviderSchema {
    #[serde(default)]
    pub resource_schemas: BTreeMap<String, JSchema>,
    #[serde(default)]
    pub data_source_schemas: BTreeMap<String, JSchema>,
}

#[derive(Debug, Deserialize)]
pub struct JSchema {
    #[serde(default)]
    pub version: u32,
    pub block: JBlock,
}

#[derive(Debug, Deserialize, Default)]
pub struct JBlock {
    #[serde(default)]
    pub attributes: BTreeMap<String, JAttr>,
    #[serde(default)]
    pub block_types: BTreeMap<String, JBlockType>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub deprecated: bool,
}

#[derive(Debug, Deserialize)]
pub struct JAttr {
    #[serde(rename = "type", default)]
    pub ty: Option<serde_json::Value>,
    #[serde(default)]
    pub nested_type: Option<JNestedType>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub computed: bool,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default)]
    pub write_only: bool,
}

#[derive(Debug, Deserialize)]
pub struct JNestedType {
    #[serde(default)]
    pub attributes: BTreeMap<String, JAttr>,
    pub nesting_mode: String,
}

#[derive(Debug, Deserialize)]
pub struct JBlockType {
    pub nesting_mode: String,
    #[serde(default)]
    pub block: JBlock,
    #[serde(default)]
    pub min_items: u32,
    #[serde(default)]
    pub max_items: u32,
}

/// One provider's parsed JSON.
pub struct Loaded {
    pub provider: Provider,
    pub schema: ProviderSchema,
}

pub fn provider_from_name(name: &str) -> Option<Provider> {
    Provider::ALL.into_iter().find(|p| p.name() == name)
}

/// Parse one `terraform providers schema -json` file. The provider is taken
/// from the registry address (`registry.terraform.io/hashicorp/<name>`).
pub fn load_schema_file(path: &Path) -> Result<Loaded> {
    let text = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut file: SchemaFile =
        serde_json::from_slice(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if file.provider_schemas.len() != 1 {
        return Err(format!(
            "{}: expected exactly one provider, found {}",
            path.display(),
            file.provider_schemas.len()
        ));
    }
    let (addr, schema) = file.provider_schemas.pop_first().unwrap();
    let short = addr.rsplit('/').next().unwrap_or(&addr);
    let provider = provider_from_name(short)
        .ok_or_else(|| format!("{}: unsupported provider {addr}", path.display()))?;
    Ok(Loaded { provider, schema })
}

pub fn load_all(schemas_dir: &Path) -> Result<Vec<Loaded>> {
    Provider::ALL
        .iter()
        .map(|p| load_schema_file(&schemas_dir.join(format!("{}.json", p.name()))))
        .collect()
}

// ---------------------------------------------------------------------------
// JSON -> IR
// ---------------------------------------------------------------------------

pub fn convert_cty(v: &serde_json::Value) -> Result<CtyType<'_>> {
    use serde_json::Value;
    match v {
        Value::String(s) => match s.as_str() {
            "string" => Ok(CtyType::String),
            "number" => Ok(CtyType::Number),
            "bool" => Ok(CtyType::Bool),
            "dynamic" => Ok(CtyType::Dynamic),
            other => Err(format!("unknown primitive cty type {other:?}")),
        },
        Value::Array(a) if !a.is_empty() => {
            let kind = a[0].as_str().ok_or("cty type tag is not a string")?;
            let arg = a.get(1).ok_or("cty type missing argument")?;
            match kind {
                "list" => Ok(CtyType::List(Box::new(convert_cty(arg)?))),
                "set" => Ok(CtyType::Set(Box::new(convert_cty(arg)?))),
                "map" => Ok(CtyType::Map(Box::new(convert_cty(arg)?))),
                "tuple" => Ok(CtyType::Tuple(
                    arg.as_array()
                        .ok_or("tuple argument is not an array")?
                        .iter()
                        .map(convert_cty)
                        .collect::<Result<_>>()?,
                )),
                "object" => {
                    let obj = arg.as_object().ok_or("object argument is not an object")?;
                    let optional: BTreeSet<&str> = a
                        .get(2)
                        .and_then(|o| o.as_array())
                        .map(|o| o.iter().filter_map(|x| x.as_str()).collect())
                        .unwrap_or_default();
                    let mut attrs = obj
                        .iter()
                        .map(|(k, t)| {
                            Ok(ObjectAttr {
                                name: k.as_str(),
                                ty: convert_cty(t)?,
                                optional: optional.contains(k.as_str()),
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    attrs.sort_by(|a, b| a.name.cmp(b.name));
                    Ok(CtyType::Object(attrs))
                }
                other => Err(format!("unknown cty type constructor {other:?}")),
            }
        }
        other => Err(format!("malformed cty type {other}")),
    }
}

pub fn nesting_mode(s: &str) -> Result<NestingMode> {
    Ok(match s {
        "single" => NestingMode::Single,
        "group" => NestingMode::Group,
        "list" => NestingMode::List,
        "set" => NestingMode::Set,
        "map" => NestingMode::Map,
        other => return Err(format!("unknown nesting mode {other:?}")),
    })
}

fn convert_attr<'a>(name: &'a str, a: &'a JAttr) -> Result<Attribute<'a>> {
    let ty = match (&a.ty, &a.nested_type) {
        (Some(t), _) => convert_cty(t).map_err(|e| format!("attribute {name}: {e}"))?,
        (None, Some(nt)) => {
            let attributes = nt
                .attributes
                .iter()
                .map(|(n, a)| convert_attr(n, a))
                .collect::<Result<Vec<_>>>()?;
            CtyType::Nested(
                nesting_mode(&nt.nesting_mode)?,
                Box::new(Block {
                    attributes,
                    block_types: vec![],
                    deprecated: false,
                }),
            )
        }
        (None, None) => return Err(format!("attribute {name} has neither type nor nested_type")),
    };
    let mut f = 0u8;
    for (on, bit) in [
        (a.required, flags::REQUIRED),
        (a.optional, flags::OPTIONAL),
        (a.computed, flags::COMPUTED),
        (a.sensitive, flags::SENSITIVE),
        (a.deprecated, flags::DEPRECATED),
        (a.write_only, flags::WRITE_ONLY),
    ] {
        if on {
            f |= bit;
        }
    }
    Ok(Attribute { name, ty, flags: f })
}

/// BTreeMap iteration order gives name-sorted members, which the runtime
/// relies on for binary search.
pub fn convert_block(b: &JBlock) -> Result<Block<'_>> {
    Ok(Block {
        attributes: b
            .attributes
            .iter()
            .map(|(n, a)| convert_attr(n, a))
            .collect::<Result<_>>()?,
        block_types: b
            .block_types
            .iter()
            .map(|(n, bt)| {
                Ok(NestedBlock {
                    name: n.as_str(),
                    nesting: nesting_mode(&bt.nesting_mode)?,
                    min_items: bt.min_items,
                    max_items: bt.max_items,
                    block: convert_block(&bt.block).map_err(|e| format!("block {n}: {e}"))?,
                })
            })
            .collect::<Result<_>>()?,
        deprecated: b.deprecated,
    })
}

/// One schema entry, IR plus the JSON it came from (for descriptions).
pub struct Entry<'a> {
    pub name: &'a str,
    pub kind: SchemaKind,
    pub provider: Provider,
    pub json: &'a JSchema,
    pub body: SchemaBody<'a>,
}

/// All entries, ordered by provider, then kind (resources first), then name.
pub fn build_entries(loaded: &[Loaded]) -> Result<Vec<Entry<'_>>> {
    let mut out = Vec::new();
    for l in loaded {
        for (kind, map) in [
            (SchemaKind::Resource, &l.schema.resource_schemas),
            (SchemaKind::DataSource, &l.schema.data_source_schemas),
        ] {
            for (name, js) in map {
                let block = convert_block(&js.block).map_err(|e| format!("{name}: {e}"))?;
                out.push(Entry {
                    name,
                    kind,
                    provider: l.provider,
                    json: js,
                    body: SchemaBody {
                        version: js.version,
                        block,
                    },
                });
            }
        }
    }
    Ok(out)
}

pub fn find_entry<'e, 'a>(
    entries: &'e [Entry<'a>],
    kind: SchemaKind,
    name: &str,
) -> Option<&'e Entry<'a>> {
    entries.iter().find(|e| e.kind == kind && e.name == name)
}

// ---------------------------------------------------------------------------
// Path resolution (shared by allowlist `uses` and defaults validation)
// ---------------------------------------------------------------------------

/// What a dotted path inside a resource body points at.
#[derive(Debug)]
pub enum Target<'s, 'a> {
    Attr(&'s Attribute<'a>),
    ObjectAttr(&'s ObjectAttr<'a>),
    Block(&'s NestedBlock<'a>),
}

impl Target<'_, '_> {
    pub fn ty(&self) -> Option<&CtyType<'_>> {
        match self {
            Target::Attr(a) => Some(&a.ty),
            Target::ObjectAttr(a) => Some(&a.ty),
            Target::Block(_) => None,
        }
    }
}

/// Resolve `a.b.c`: intermediate segments may be nested blocks or
/// attributes-as-blocks (list/set of object) attributes.
pub fn resolve_path<'s, 'a>(block: &'s Block<'a>, path: &str) -> Option<Target<'s, 'a>> {
    enum Cur<'s, 'a> {
        Block(&'s Block<'a>),
        Object(&'s [ObjectAttr<'a>]),
    }
    let mut cur = Cur::Block(block);
    let segs: Vec<&str> = path.split('.').collect();
    for (i, seg) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        let (target, ty) = match cur {
            Cur::Block(b) => {
                if let Some(a) = b.attribute(seg) {
                    (Target::Attr(a), Some(&a.ty))
                } else {
                    let nb = b.block_type(seg)?;
                    if last {
                        return Some(Target::Block(nb));
                    }
                    cur = Cur::Block(&nb.block);
                    continue;
                }
            }
            Cur::Object(attrs) => {
                let a = attrs.iter().find(|a| a.name == *seg)?;
                (Target::ObjectAttr(a), Some(&a.ty))
            }
        };
        if last {
            return Some(target);
        }
        // descend through list/set/map of object, or object
        let mut t = ty?;
        while let Some(e) = t.element() {
            t = e;
        }
        cur = match t {
            CtyType::Object(attrs) => Cur::Object(attrs),
            CtyType::Nested(_, b) => Cur::Block(b),
            _ => return None,
        };
    }
    None
}

// ---------------------------------------------------------------------------
// Blob + index
// ---------------------------------------------------------------------------

pub struct BlobOut {
    pub blob: Vec<u8>,
    /// postcard `Vec<&str>`: the symbol table, most frequent name first.
    pub symbols: Vec<u8>,
    pub symbol_count: usize,
    /// (start, end) per entry, parallel to the entries slice.
    pub ranges: Vec<(u32, u32)>,
}

fn count_names<'a>(b: &Block<'a>, c: &mut BTreeMap<&'a str, u32>) {
    fn ty<'a>(t: &CtyType<'a>, c: &mut BTreeMap<&'a str, u32>) {
        match t {
            CtyType::List(t) | CtyType::Set(t) | CtyType::Map(t) => ty(t, c),
            CtyType::Tuple(ts) => ts.iter().for_each(|t| ty(t, c)),
            CtyType::Object(attrs) => attrs.iter().for_each(|a| {
                *c.entry(a.name).or_default() += 1;
                ty(&a.ty, c)
            }),
            CtyType::Nested(_, b) => count_names(b, c),
            _ => {}
        }
    }
    for a in &b.attributes {
        *c.entry(a.name).or_default() += 1;
        ty(&a.ty, c);
    }
    for nb in &b.block_types {
        *c.entry(nb.name).or_default() += 1;
        count_names(&nb.block, c);
    }
}

/// Symbol table: every member name, most frequent first (ties by name, so
/// output is deterministic).
pub fn build_symbols<'a>(entries: &[Entry<'a>]) -> Vec<&'a str> {
    let mut counts = BTreeMap::new();
    for e in entries {
        count_names(&e.body.block, &mut counts);
    }
    let mut v: Vec<(&str, u32)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.into_iter().map(|(n, _)| n).collect()
}

pub fn build_blob(entries: &[Entry<'_>]) -> Result<BlobOut> {
    let symbols = build_symbols(entries);
    let ids: std::collections::HashMap<String, u32> = symbols
        .iter()
        .enumerate()
        .map(|(i, s)| (s.to_string(), i as u32))
        .collect();
    let mut blob = Vec::new();
    let mut ranges = Vec::with_capacity(entries.len());
    tf_schema::ir::sym::with_encoder(ids, || -> Result<()> {
        for e in entries {
            let start = blob.len();
            let bytes =
                postcard::to_allocvec(&e.body).map_err(|err| format!("{}: {err}", e.name))?;
            blob.extend_from_slice(&bytes);
            ranges.push((start as u32, blob.len() as u32));
        }
        Ok(())
    })?;
    let sym_bytes = postcard::to_allocvec(&symbols).map_err(|e| e.to_string())?;
    Ok(BlobOut {
        blob,
        symbols: sym_bytes,
        symbol_count: symbols.len(),
        ranges,
    })
}

const HEADER: &str = "// @generated by tf_schema_codegen. Do not edit by hand.\n";

fn provider_ident(p: Provider) -> &'static str {
    match p {
        Provider::Aws => "Aws",
        Provider::Azurerm => "Azurerm",
        Provider::Google => "Google",
    }
}

pub fn index_source(entries: &[Entry<'_>], blob: &BlobOut) -> Result<String> {
    if entries.len() > u16::MAX as usize {
        return Err("more than 65535 schemas; widen the index id type".into());
    }
    let mut s = String::new();
    s.push_str(HEADER);
    s.push_str(
        "use crate::EntryMeta;\nuse crate::ir::{Provider::{self, *}, SchemaKind::{self, *}};\n\n",
    );
    s.push_str("pub(crate) static BLOB: &[u8] = include_bytes!(\"schema.postcard\");\n");
    s.push_str("pub(crate) static SYMBOLS: &[u8] = include_bytes!(\"symbols.postcard\");\n");
    let _ = writeln!(s, "pub(crate) const N: usize = {};\n", entries.len());
    s.push_str("const fn e(name: &'static str, kind: SchemaKind, provider: Provider, start: u32, end: u32) -> EntryMeta {\n    EntryMeta { name, kind, provider, start, end }\n}\n\n");
    s.push_str("pub(crate) static ENTRIES: [EntryMeta; N] = [\n");
    for (e, (start, end)) in entries.iter().zip(&blob.ranges) {
        let kind = match e.kind {
            SchemaKind::Resource => "Resource",
            SchemaKind::DataSource => "DataSource",
        };
        let _ = writeln!(
            s,
            "    e({:?}, {kind}, {}, {start}, {end}),",
            e.name,
            provider_ident(e.provider)
        );
    }
    s.push_str("];\n\n");
    for (kind, ident) in [
        (SchemaKind::Resource, "RESOURCES"),
        (SchemaKind::DataSource, "DATA_SOURCES"),
    ] {
        let mut m = phf_codegen::Map::<&str>::new();
        for (i, e) in entries.iter().enumerate() {
            if e.kind == kind {
                m.entry(e.name, i.to_string());
            }
        }
        let _ = writeln!(
            s,
            "pub(crate) static {ident}: phf::Map<&'static str, u16> = {};\n",
            m.build()
        );
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Defaults overlay
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DefaultSpec {
    pub resource: String,
    pub path: String,
    pub value: DefaultLit,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DefaultLit {
    Bool(bool),
    Number(f64),
    String(String),
    Empty,
}

fn parse_default_value(v: &toml::Value) -> Result<(DefaultLit, String)> {
    Ok(match v {
        toml::Value::Boolean(b) => (DefaultLit::Bool(*b), String::new()),
        toml::Value::Integer(i) => (DefaultLit::Number(*i as f64), String::new()),
        toml::Value::Float(f) => (DefaultLit::Number(*f), String::new()),
        toml::Value::String(s) => (DefaultLit::String(s.clone()), String::new()),
        toml::Value::Array(a) if a.is_empty() => (DefaultLit::Empty, String::new()),
        toml::Value::Table(t) => {
            let value = t.get("value").ok_or("inline table needs `value`")?;
            let (lit, _) = parse_default_value(value)?;
            let note = t
                .get("note")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            (lit, note)
        }
        other => return Err(format!("unsupported default value {other}")),
    })
}

/// Parse `defaults/<provider>.toml`: `[resource_type]` tables of
/// `attr = value` or `"block.attr" = { value = ..., note = "..." }`.
pub fn parse_defaults(text: &str, origin: &str) -> Result<Vec<DefaultSpec>> {
    let table: toml::Table = text.parse().map_err(|e| format!("{origin}: {e}"))?;
    let mut out = Vec::new();
    for (resource, attrs) in table {
        let attrs = attrs
            .as_table()
            .ok_or_else(|| format!("{origin}: [{resource}] must be a table"))?;
        for (path, v) in attrs {
            let (value, note) =
                parse_default_value(v).map_err(|e| format!("{origin}: {resource}.{path}: {e}"))?;
            out.push(DefaultSpec {
                resource: resource.clone(),
                path: path.clone(),
                value,
                note,
            });
        }
    }
    Ok(out)
}

pub fn validate_default(entries: &[Entry<'_>], d: &DefaultSpec) -> Result<()> {
    let e = find_entry(entries, SchemaKind::Resource, &d.resource)
        .ok_or_else(|| format!("defaults: unknown resource type {}", d.resource))?;
    let target = resolve_path(&e.body.block, &d.path).ok_or_else(|| {
        format!(
            "defaults: {}.{} does not exist in the schema",
            d.resource, d.path
        )
    })?;
    let ok = match (&d.value, target.ty()) {
        (DefaultLit::Empty, None) => true, // nested block absent
        (DefaultLit::Empty, Some(t)) => t.is_collection(),
        (_, None) => false,
        (DefaultLit::Bool(_), Some(t)) => t.is_bool(),
        (DefaultLit::Number(_), Some(t)) => t.is_number(),
        (DefaultLit::String(_), Some(t)) => t.is_string(),
    };
    if !ok {
        let ty = target
            .ty()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "nested block".into());
        return Err(format!(
            "defaults: {}.{} = {:?} does not match schema type {ty}",
            d.resource, d.path, d.value
        ));
    }
    Ok(())
}

pub fn defaults_source(specs: &[DefaultSpec]) -> String {
    let mut by_res: BTreeMap<&str, Vec<&DefaultSpec>> = BTreeMap::new();
    for d in specs {
        by_res.entry(&d.resource).or_default().push(d);
    }
    let mut m = phf_codegen::Map::<&str>::new();
    for (res, ds) in &by_res {
        let mut v = String::from("&[");
        for d in ds {
            let value = match &d.value {
                DefaultLit::Bool(b) => format!("Bool({b})"),
                DefaultLit::Number(n) => format!("Number({n:?})"),
                DefaultLit::String(s) => format!("String({s:?})"),
                DefaultLit::Empty => "Empty".into(),
            };
            let _ = write!(
                v,
                "D {{ path: {:?}, value: {value}, note: {:?} }}, ",
                d.path, d.note
            );
        }
        v.push(']');
        m.entry(res, v);
    }
    format!(
        "{HEADER}use crate::defaults::{{DefaultEntry as D, DefaultValue::*}};\n\npub(crate) static DEFAULTS: phf::Map<&'static str, &'static [D]> = {};\n",
        m.build()
    )
}

// ---------------------------------------------------------------------------
// Allowlist + typed views
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Allowlist {
    #[serde(default)]
    pub view: Vec<AllowEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AllowEntry {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Attribute paths rules depend on. Generation fails if one disappears.
    #[serde(default)]
    pub uses: Vec<String>,
}

fn default_kind() -> String {
    "resource".into()
}

impl AllowEntry {
    pub fn schema_kind(&self) -> Result<SchemaKind> {
        match self.kind.as_str() {
            "resource" => Ok(SchemaKind::Resource),
            "data" | "data_source" => Ok(SchemaKind::DataSource),
            k => Err(format!("allowlist {}: unknown kind {k:?}", self.ty)),
        }
    }
}

pub fn parse_allowlist(text: &str) -> Result<Allowlist> {
    toml::from_str(text).map_err(|e| format!("allowlist: {e}"))
}

/// Every problem with the allowlist against these schemas (empty = ok).
pub fn check_allowlist(entries: &[Entry<'_>], allow: &Allowlist) -> Vec<String> {
    let mut errs = Vec::new();
    for a in &allow.view {
        let kind = match a.schema_kind() {
            Ok(k) => k,
            Err(e) => {
                errs.push(e);
                continue;
            }
        };
        let Some(e) = find_entry(entries, kind, &a.ty) else {
            errs.push(format!(
                "allowlist: {} {} is not in the schema",
                a.kind, a.ty
            ));
            continue;
        };
        for u in &a.uses {
            if resolve_path(&e.body.block, u).is_none() {
                errs.push(format!(
                    "allowlist: view {} uses `{u}`, which does not exist in the schema",
                    a.ty
                ));
            }
        }
    }
    errs
}

const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "else", "enum", "extern", "false", "fn", "for", "if",
    "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static",
    "struct", "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn",
    "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof", "unsized",
    "virtual", "yield", "try", "gen",
];

fn method_ident(name: &str) -> Option<String> {
    let valid = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !valid {
        return None;
    }
    Some(match name {
        "self" | "super" | "crate" | "_" => format!("{name}_"),
        n if RUST_KEYWORDS.contains(&n) => format!("r#{n}"),
        n => n.to_string(),
    })
}

pub fn camel(name: &str) -> String {
    name.split(['_', '-'])
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut c = s.chars();
            let first = c.next().unwrap().to_ascii_uppercase();
            std::iter::once(first).chain(c).collect::<String>()
        })
        .collect()
}

fn short_doc(desc: Option<&str>) -> Option<String> {
    let d = desc?.trim();
    if d.is_empty() {
        return None;
    }
    // first sentence, capped
    let first = match d.find(". ") {
        Some(i) => &d[..=i],
        None => d,
    };
    let first = first.replace('\n', " ");
    if first.chars().count() > 240 {
        Some(first.chars().take(237).collect::<String>() + "...")
    } else {
        Some(first)
    }
}

fn type_doc(t: &CtyType<'_>) -> String {
    let s = t.to_string();
    if s.chars().count() > 100 {
        s.chars().take(97).collect::<String>() + "..."
    } else {
        s
    }
}

fn flags_doc(f: u8) -> String {
    let mut v = Vec::new();
    for (bit, n) in [
        (flags::REQUIRED, "required"),
        (flags::OPTIONAL, "optional"),
        (flags::COMPUTED, "computed"),
        (flags::SENSITIVE, "sensitive"),
        (flags::DEPRECATED, "deprecated"),
        (flags::WRITE_ONLY, "write-only"),
    ] {
        if f & bit != 0 {
            v.push(n);
        }
    }
    v.join(", ")
}

/// Shape of something a view struct is generated for.
enum Shape<'s, 'a> {
    Block(&'s Block<'a>, Option<&'s JBlock>),
    Object(&'s [ObjectAttr<'a>]),
}

struct ViewGen<'o> {
    out: &'o mut String,
    used_structs: BTreeSet<String>,
    type_name: String,
}

impl ViewGen<'_> {
    fn unique_struct(&mut self, base: String) -> String {
        let mut name = base.clone();
        let mut n = 2;
        while !self.used_structs.insert(name.clone()) {
            name = format!("{base}{n}");
            n += 1;
        }
        name
    }

    fn emit(&mut self, struct_name: &str, path: &[String], shape: Shape<'_, '_>, doc: &str) {
        let mut children: Vec<(String, Vec<String>, Shape<'_, '_>)> = Vec::new();
        let mut methods = String::new();
        let mut used_methods: BTreeSet<String> = BTreeSet::new();
        let uniq = |m: String, used: &mut BTreeSet<String>| {
            let mut m = m;
            while !used.insert(m.clone()) {
                m.push('_');
            }
            m
        };

        // attributes (block attributes or object attributes)
        let attrs: Vec<(&str, &CtyType<'_>, Option<u8>, Option<&str>)> = match &shape {
            Shape::Block(b, j) => b
                .attributes
                .iter()
                .map(|a| {
                    let desc = j
                        .and_then(|j| j.attributes.get(a.name))
                        .and_then(|ja| ja.description.as_deref());
                    (a.name, &a.ty, Some(a.flags), desc)
                })
                .collect(),
            Shape::Object(attrs) => attrs.iter().map(|a| (a.name, &a.ty, None, None)).collect(),
        };
        for (name, ty, fl, desc) in attrs {
            let Some(ident) = method_ident(name) else {
                let _ = writeln!(
                    methods,
                    "    // skipped attribute {name:?}: not a Rust identifier"
                );
                continue;
            };
            let ident = uniq(ident, &mut used_methods);
            let mut d = format!("`{name}`: `{}`", type_doc(ty));
            if let Some(f) = fl {
                let _ = write!(d, " ({})", flags_doc(f));
            }
            if let Some(sd) = short_doc(desc) {
                let _ = write!(d, ". {sd}");
            }
            let _ = writeln!(
                methods,
                "    #[doc = {d:?}]\n    #[inline]\n    pub fn {ident}(&self) -> Option<N::Value> {{\n        self.0.attr({name:?})\n    }}"
            );
            // attributes-as-blocks: list/set of object
            let elem = match ty {
                CtyType::List(t) | CtyType::Set(t) => match &**t {
                    CtyType::Object(o) => Some(o.as_slice()),
                    _ => None,
                },
                _ => None,
            };
            if let Some(obj) = elem {
                let child = self.unique_struct(format!("{struct_name}{}", camel(name)));
                let m = uniq(
                    format!("{}_blocks", ident.trim_start_matches("r#")),
                    &mut used_methods,
                );
                let _ = writeln!(
                    methods,
                    "    #[doc = {:?}]\n    #[inline]\n    pub fn {m}(&self) -> impl Iterator<Item = {child}<N::Block>> {{\n        self.0.blocks({name:?}).map({child})\n    }}",
                    format!(
                        "`{name} {{ ... }}` written in block syntax (attributes-as-blocks). Terraform accepts both forms for `{}`.",
                        type_doc(ty)
                    )
                );
                let mut p = path.to_vec();
                p.push(name.to_string());
                children.push((child, p, Shape::Object(obj)));
            }
        }
        if let Shape::Block(b, j) = &shape {
            for nb in &b.block_types {
                let Some(ident) = method_ident(nb.name) else {
                    let _ = writeln!(
                        methods,
                        "    // skipped block {:?}: not a Rust identifier",
                        nb.name
                    );
                    continue;
                };
                let ident = uniq(ident, &mut used_methods);
                let jb = j
                    .and_then(|j| j.block_types.get(nb.name))
                    .map(|bt| &bt.block);
                let child = self.unique_struct(format!("{struct_name}{}", camel(nb.name)));
                let max = if nb.max_items == 0 {
                    "unbounded".to_string()
                } else {
                    nb.max_items.to_string()
                };
                let mut d = format!(
                    "`{} {{ ... }}` nested block ({:?}, min {}, max {max})",
                    nb.name, nb.nesting, nb.min_items
                );
                if let Some(sd) = short_doc(jb.and_then(|b| b.description.as_deref())) {
                    let _ = write!(d, ". {sd}");
                }
                if nb.is_singleton() {
                    let _ = writeln!(
                        methods,
                        "    #[doc = {d:?}]\n    #[inline]\n    pub fn {ident}(&self) -> Option<{child}<N::Block>> {{\n        self.0.blocks({:?}).next().map({child})\n    }}",
                        nb.name
                    );
                } else {
                    let _ = writeln!(
                        methods,
                        "    #[doc = {d:?}]\n    #[inline]\n    pub fn {ident}(&self) -> impl Iterator<Item = {child}<N::Block>> {{\n        self.0.blocks({:?}).map({child})\n    }}",
                        nb.name
                    );
                }
                let mut p = path.to_vec();
                p.push(nb.name.to_string());
                children.push((child, p, Shape::Block(&nb.block, jb)));
            }
        }

        let path_lit = path
            .iter()
            .map(|p| format!("{p:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = write!(
            self.out,
            "#[doc = {doc:?}]\n#[derive(Debug, Clone, Copy)]\n#[repr(transparent)]\npub struct {struct_name}<N>(pub N);\n\n\
impl<N: ResourceNode> TypedView for {struct_name}<N> {{\n    type Node = N;\n    const TYPE_NAME: &'static str = {:?};\n    const BLOCK_PATH: &'static [&'static str] = &[{path_lit}];\n    #[inline]\n    fn from_node(node: N) -> Self {{\n        Self(node)\n    }}\n    #[inline]\n    fn node(&self) -> &N {{\n        &self.0\n    }}\n    #[inline]\n    fn into_node(self) -> N {{\n        self.0\n    }}\n}}\n\n\
impl<N: ResourceNode> {struct_name}<N> {{\n{methods}}}\n\n",
            self.type_name
        );
        for (child, p, sh) in children {
            let doc = format!("`{}` > `{}`", self.type_name, p.join(" > "));
            self.emit(&child, &p, sh, &doc);
        }
    }
}

/// Generate the views module source for these allowlisted entries.
pub fn views_source(entries: &[Entry<'_>], allow: &[AllowEntry]) -> Result<String> {
    let mut s = String::new();
    s.push_str(HEADER);
    s.push_str("//! Typed views for allowlisted resources (`crates/tf_schema_codegen/allowlist.toml`).\n//!\n//! One module per resource; each root view is re-exported here. Views are\n//! `#[repr(transparent)]` newtypes over any [`ResourceNode`](crate::ResourceNode).\n\n");
    let mut names = Vec::new();
    for a in allow {
        let kind = a.schema_kind()?;
        let e = find_entry(entries, kind, &a.ty)
            .ok_or_else(|| format!("allowlist: {} not in schema", a.ty))?;
        let (modname, root) = match kind {
            SchemaKind::Resource => (a.ty.clone(), camel(&a.ty)),
            SchemaKind::DataSource => (format!("data_{}", a.ty), format!("Data{}", camel(&a.ty))),
        };
        names.push((a.ty.clone(), kind));
        let _ = writeln!(s, "pub use self::{modname}::{root};");
        let mut body = String::new();
        let mut g = ViewGen {
            out: &mut body,
            used_structs: BTreeSet::new(),
            type_name: a.ty.clone(),
        };
        g.used_structs.insert(root.clone());
        let what = match kind {
            SchemaKind::Resource => "resource",
            SchemaKind::DataSource => "data",
        };
        let mut doc = format!(
            "Typed view over `{what} \"{}\"` ({}).",
            a.ty,
            e.provider.name()
        );
        if let Some(sd) = short_doc(e.json.block.description.as_deref()) {
            let _ = write!(doc, " {sd}");
        }
        g.emit(
            &root,
            &[],
            Shape::Block(&e.body.block, Some(&e.json.block)),
            &doc,
        );
        let _ = write!(
            s,
            "pub mod {modname} {{\n    #![allow(clippy::all)]\n    use crate::node::{{ResourceNode, TypedView}};\n\n{body}}}\n\n"
        );
    }
    s.push_str("/// `(type name, kind)` of every allowlisted view.\npub const ALLOWLIST: &[(&str, crate::ir::SchemaKind)] = &[\n");
    for (n, k) in names {
        let _ = writeln!(s, "    ({n:?}, crate::ir::SchemaKind::{k:?}),");
    }
    s.push_str("];\n");
    Ok(s)
}

// ---------------------------------------------------------------------------
// Top-level generation
// ---------------------------------------------------------------------------

pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn schemas_dir(&self) -> PathBuf {
        self.root.join("schemas/providers")
    }
    pub fn allowlist(&self) -> PathBuf {
        self.root.join("crates/tf_schema_codegen/allowlist.toml")
    }
    pub fn rule_targets(&self) -> PathBuf {
        self.root.join("crates/tf_schema_codegen/rule_targets.txt")
    }
    pub fn defaults_dir(&self) -> PathBuf {
        self.root.join("defaults")
    }
    pub fn out_dir(&self) -> PathBuf {
        self.root.join("crates/tf_schema/src/generated")
    }
}

pub struct Generated {
    /// (relative file name, contents)
    pub files: Vec<(String, Vec<u8>)>,
    pub entry_count: usize,
    pub default_count: usize,
}

pub fn read_defaults(dir: &Path) -> Result<Vec<DefaultSpec>> {
    let mut specs = Vec::new();
    for p in Provider::ALL {
        let path = dir.join(format!("{}.toml", p.name()));
        if !path.exists() {
            continue;
        }
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        specs.extend(parse_defaults(&text, &path.display().to_string())?);
    }
    Ok(specs)
}

/// Run the whole generator against already-loaded schemas.
pub fn generate(
    loaded: &[Loaded],
    allow: &Allowlist,
    defaults: &[DefaultSpec],
) -> Result<Generated> {
    let entries = build_entries(loaded)?;
    let mut errs = check_allowlist(&entries, allow);
    for d in defaults {
        if let Err(e) = validate_default(&entries, d) {
            errs.push(e);
        }
    }
    if !errs.is_empty() {
        return Err(errs.join("\n"));
    }
    let blob = build_blob(&entries)?;
    let index = index_source(&entries, &blob)?;
    let views = views_source(&entries, &allow.view)?;
    let defs = defaults_source(defaults);
    Ok(Generated {
        files: vec![
            ("schema.postcard".into(), blob.blob),
            ("symbols.postcard".into(), blob.symbols),
            ("index.rs".into(), index.into_bytes()),
            ("views.rs".into(), views.into_bytes()),
            ("defaults.rs".into(), defs.into_bytes()),
        ],
        entry_count: entries.len(),
        default_count: defaults.len(),
    })
}

pub fn generate_from_disk(paths: &Paths) -> Result<Generated> {
    let loaded = load_all(&paths.schemas_dir())?;
    let allow_text =
        std::fs::read_to_string(paths.allowlist()).map_err(|e| format!("allowlist: {e}"))?;
    let allow = parse_allowlist(&allow_text)?;
    let defaults = read_defaults(&paths.defaults_dir())?;
    generate(&loaded, &allow, &defaults)
}

// ---------------------------------------------------------------------------
// Schema diff + rule coverage
// ---------------------------------------------------------------------------

/// Flatten a block to `path -> signature` for diffing.
pub fn flatten(block: &Block<'_>, prefix: &str, out: &mut BTreeMap<String, String>) {
    for a in &block.attributes {
        out.insert(
            format!("{prefix}{}", a.name),
            format!("{} [{}]", a.ty, flags_doc(a.flags)),
        );
    }
    for b in &block.block_types {
        let p = format!("{prefix}{}", b.name);
        out.insert(
            p.clone(),
            format!(
                "block {:?} min={} max={}",
                b.nesting, b.min_items, b.max_items
            ),
        );
        flatten(&b.block, &format!("{p}."), out);
    }
}

#[derive(Debug, Default)]
pub struct DiffReport {
    pub added: Vec<(SchemaKind, String)>,
    pub removed: Vec<(SchemaKind, String)>,
    /// (kind, resource, path, old sig or "", new sig or "")
    pub changed: Vec<(SchemaKind, String, String, String, String)>,
}

pub fn diff_entries(old: &[Entry<'_>], new: &[Entry<'_>]) -> DiffReport {
    let key = |e: &Entry<'_>| (e.kind == SchemaKind::DataSource, e.name.to_string());
    let om: BTreeMap<_, _> = old.iter().map(|e| (key(e), e)).collect();
    let nm: BTreeMap<_, _> = new.iter().map(|e| (key(e), e)).collect();
    let mut r = DiffReport::default();
    let kind = |ds: bool| {
        if ds {
            SchemaKind::DataSource
        } else {
            SchemaKind::Resource
        }
    };
    for (k, ne) in &nm {
        match om.get(k) {
            None => r.added.push((kind(k.0), k.1.clone())),
            Some(oe) => {
                let (mut a, mut b) = (BTreeMap::new(), BTreeMap::new());
                flatten(&oe.body.block, "", &mut a);
                flatten(&ne.body.block, "", &mut b);
                let paths: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
                for p in paths {
                    let (o, n) = (a.get(p), b.get(p));
                    if o != n {
                        r.changed.push((
                            kind(k.0),
                            k.1.clone(),
                            p.clone(),
                            o.cloned().unwrap_or_default(),
                            n.cloned().unwrap_or_default(),
                        ));
                    }
                }
            }
        }
    }
    for k in om.keys() {
        if !nm.contains_key(k) {
            r.removed.push((kind(k.0), k.1.clone()));
        }
    }
    r
}

/// Rule targets: one resource type per line; `data.<type>` for data sources;
/// `#` comments.
pub fn parse_rule_targets(text: &str) -> BTreeSet<(SchemaKind, String)> {
    text.lines()
        .map(|l| l.split('#').next().unwrap().trim())
        .filter(|l| !l.is_empty())
        .map(|l| match l.strip_prefix("data.") {
            Some(d) => (SchemaKind::DataSource, d.to_string()),
            None => (SchemaKind::Resource, l.to_string()),
        })
        .collect()
}

/// Entries with no rule targeting them.
pub fn uncovered<'e, 'a>(
    entries: &'e [Entry<'a>],
    targets: &BTreeSet<(SchemaKind, String)>,
) -> Vec<&'e Entry<'a>> {
    entries
        .iter()
        .filter(|e| !targets.contains(&(e.kind, e.name.to_string())))
        .collect()
}

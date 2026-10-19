//! The schema IR. These types are both what the generator serializes and what
//! the runtime deserializes (postcard). Names are interned (see [`sym`]) and
//! resolve to `&'static str` slices of the embedded symbol table, so names
//! cost no allocation.
//!
//! Members are sorted by name so lookups are binary searches.

use serde::{Deserialize, Serialize};

/// Name interning. Member names (attribute, object attribute and nested
/// block names) are serialized as varint ids into a symbol table instead of
/// inline strings: 264,725 names but only 25,601 distinct ones across the
/// three providers. Ids are assigned by descending frequency, so common names
/// (`id`, `tags`, `name`, ...) cost one byte.
///
/// The table is passed through a thread-local so the serde derives stay plain.
pub mod sym {
    use serde::{
        Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::Error as _,
    };
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    thread_local! {
        static DECODE: Cell<&'static [&'static str]> = const { Cell::new(&[]) };
        static ENCODE: RefCell<Option<HashMap<String, u32>>> = const { RefCell::new(None) };
    }

    /// Run `f` with `table` as the decoding symbol table.
    pub fn with_decoder<R>(table: &'static [&'static str], f: impl FnOnce() -> R) -> R {
        let prev = DECODE.with(|d| d.replace(table));
        let r = f();
        DECODE.with(|d| d.set(prev));
        r
    }

    /// Run `f` with `ids` (name -> id) as the encoding table.
    pub fn with_encoder<R>(ids: HashMap<String, u32>, f: impl FnOnce() -> R) -> R {
        let prev = ENCODE.with(|e| e.replace(Some(ids)));
        let r = f();
        ENCODE.with(|e| *e.borrow_mut() = prev);
        r
    }

    pub fn ser<S: Serializer>(name: &&str, s: S) -> Result<S::Ok, S::Error> {
        let id = ENCODE.with(|e| e.borrow().as_ref().and_then(|m| m.get(*name).copied()));
        match id {
            Some(id) => id.serialize(s),
            None => Err(S::Error::custom(format!(
                "symbol {name:?} not in encoder table"
            ))),
        }
    }

    pub fn de<'de, 'a, D: Deserializer<'de>>(d: D) -> Result<&'a str, D::Error> {
        let id = u32::deserialize(d)? as usize;
        DECODE
            .with(|t| t.get().get(id).copied())
            .ok_or_else(|| D::Error::custom(format!("symbol id {id} out of range")))
    }
}

/// Which provider a schema belongs to.
///
/// This enum is the single list of supported providers: the generator loads
/// `schemas/providers/<name>.json` for every entry of [`Provider::ALL`],
/// checks that the file's registry address matches [`Provider::source`], and
/// reads `defaults/<name>.toml` if it exists. Adding a provider means adding
/// a variant here (append-only), its `name`/`source` arms, and the JSON
/// snapshot; everything else is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Provider {
    Aws,
    Azurerm,
    Google,
    Cloudflare,
    Kubernetes,
    Github,
}

impl Provider {
    pub const ALL: [Provider; 6] = [
        Provider::Aws,
        Provider::Azurerm,
        Provider::Google,
        Provider::Cloudflare,
        Provider::Kubernetes,
        Provider::Github,
    ];

    /// Local name (the resource type prefix and the snapshot file stem).
    pub fn name(self) -> &'static str {
        match self {
            Provider::Aws => "aws",
            Provider::Azurerm => "azurerm",
            Provider::Google => "google",
            Provider::Cloudflare => "cloudflare",
            Provider::Kubernetes => "kubernetes",
            Provider::Github => "github",
        }
    }

    /// Registry source address (`namespace/type`) the snapshot was taken from.
    pub fn source(self) -> &'static str {
        match self {
            Provider::Aws => "hashicorp/aws",
            Provider::Azurerm => "hashicorp/azurerm",
            Provider::Google => "hashicorp/google",
            Provider::Cloudflare => "cloudflare/cloudflare",
            Provider::Kubernetes => "hashicorp/kubernetes",
            Provider::Github => "integrations/github",
        }
    }

    /// Inverse of [`Provider::name`].
    pub fn from_name(name: &str) -> Option<Provider> {
        Provider::ALL.into_iter().find(|p| p.name() == name)
    }
}

/// Resource (`resource "x" ...`) or data source (`data "x" ...`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SchemaKind {
    Resource,
    DataSource,
}

/// A cty type, as in `terraform providers schema -json`'s `type` field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CtyType<'a> {
    String,
    Number,
    Bool,
    /// `"dynamic"`: any type.
    Dynamic,
    List(Box<CtyType<'a>>),
    Set(Box<CtyType<'a>>),
    Map(Box<CtyType<'a>>),
    /// Object attributes, sorted by name.
    #[serde(borrow)]
    Object(Vec<ObjectAttr<'a>>),
    Tuple(Vec<CtyType<'a>>),
    /// Protocol-6 `nested_type` attribute (terraform-plugin-framework
    /// "nested attributes"; heavily used by cloudflare 5.x). The [`Block`]
    /// holds the child attributes (each with its own required / optional /
    /// computed / sensitive flags) and never has `block_types`. The mode is
    /// `Single` (one object), `List`, `Set` or `Map` (of objects).
    ///
    /// Unlike a nested *block*, a nested attribute is written with attribute
    /// syntax (`rules = [{ ... }]`, `metadata = { ... }`), never as
    /// `rules { ... }`. See [`Attribute::nested`].
    Nested(NestingMode, Box<Block<'a>>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectAttr<'a> {
    #[serde(serialize_with = "sym::ser", deserialize_with = "sym::de")]
    pub name: &'a str,
    #[serde(borrow)]
    pub ty: CtyType<'a>,
    /// Listed in the object type's optional-attributes set.
    pub optional: bool,
}

impl<'a> CtyType<'a> {
    pub fn is_bool(&self) -> bool {
        matches!(self, CtyType::Bool)
    }
    pub fn is_string(&self) -> bool {
        matches!(self, CtyType::String)
    }
    pub fn is_number(&self) -> bool {
        matches!(self, CtyType::Number)
    }
    /// List, set, map or tuple (not object).
    pub fn is_collection(&self) -> bool {
        matches!(
            self,
            CtyType::List(_) | CtyType::Set(_) | CtyType::Map(_) | CtyType::Tuple(_)
        )
    }
    /// Element type of a list, set or map.
    pub fn element(&self) -> Option<&CtyType<'a>> {
        match self {
            CtyType::List(t) | CtyType::Set(t) | CtyType::Map(t) => Some(t),
            _ => None,
        }
    }
    /// Attributes of an object type.
    pub fn object_attrs(&self) -> Option<&[ObjectAttr<'a>]> {
        match self {
            CtyType::Object(a) => Some(a),
            _ => None,
        }
    }
    /// For a nested attribute type: its nesting mode and child attributes.
    pub fn nested(&self) -> Option<(NestingMode, &Block<'a>)> {
        match self {
            CtyType::Nested(mode, b) => Some((*mode, b)),
            _ => None,
        }
    }
    /// For an object type, the type of attribute `name`.
    pub fn object_attr(&self, name: &str) -> Option<&ObjectAttr<'a>> {
        let attrs = self.object_attrs()?;
        attrs
            .binary_search_by(|a| a.name.cmp(name))
            .ok()
            .map(|i| &attrs[i])
    }
}

impl std::fmt::Display for CtyType<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CtyType::String => f.write_str("string"),
            CtyType::Number => f.write_str("number"),
            CtyType::Bool => f.write_str("bool"),
            CtyType::Dynamic => f.write_str("dynamic"),
            CtyType::List(t) => write!(f, "list({t})"),
            CtyType::Set(t) => write!(f, "set({t})"),
            CtyType::Map(t) => write!(f, "map({t})"),
            CtyType::Object(attrs) => {
                f.write_str("object({")?;
                for (i, a) in attrs.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    if a.optional {
                        write!(f, "{}=optional({})", a.name, a.ty)?;
                    } else {
                        write!(f, "{}={}", a.name, a.ty)?;
                    }
                }
                f.write_str("})")
            }
            CtyType::Tuple(ts) => {
                f.write_str("tuple([")?;
                for (i, t) in ts.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{t}")?;
                }
                f.write_str("])")
            }
            CtyType::Nested(mode, _) => write!(f, "nested({mode:?})"),
        }
    }
}

/// Attribute flag bits (see [`Attribute::flags`]).
pub mod flags {
    pub const REQUIRED: u8 = 1 << 0;
    pub const OPTIONAL: u8 = 1 << 1;
    pub const COMPUTED: u8 = 1 << 2;
    pub const SENSITIVE: u8 = 1 << 3;
    pub const DEPRECATED: u8 = 1 << 4;
    pub const WRITE_ONLY: u8 = 1 << 5;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attribute<'a> {
    #[serde(serialize_with = "sym::ser", deserialize_with = "sym::de")]
    pub name: &'a str,
    #[serde(borrow)]
    pub ty: CtyType<'a>,
    /// Bit set of [`flags`].
    pub flags: u8,
}

impl<'a> Attribute<'a> {
    pub fn name(&self) -> &'a str {
        self.name
    }
    pub fn ty(&self) -> &CtyType<'a> {
        &self.ty
    }
    pub fn is_required(&self) -> bool {
        self.flags & flags::REQUIRED != 0
    }
    pub fn is_optional(&self) -> bool {
        self.flags & flags::OPTIONAL != 0
    }
    pub fn is_computed(&self) -> bool {
        self.flags & flags::COMPUTED != 0
    }
    /// Computed and not settable from configuration (`computed` without
    /// `optional`): its value is always unknown before apply.
    pub fn is_computed_only(&self) -> bool {
        self.is_computed() && !self.is_optional() && !self.is_required()
    }
    pub fn is_sensitive(&self) -> bool {
        self.flags & flags::SENSITIVE != 0
    }
    pub fn is_write_only(&self) -> bool {
        self.flags & flags::WRITE_ONLY != 0
    }
    pub fn is_bool(&self) -> bool {
        self.ty.is_bool()
    }
    /// True for a protocol-6 nested attribute (`nested_type`). It is still an
    /// attribute: configuration writes it with `=` (`rules = [{ ... }]`),
    /// never block syntax, and [`Attribute::accepts_block_syntax`] is false.
    pub fn is_nested(&self) -> bool {
        matches!(self.ty, CtyType::Nested(..))
    }
    /// Nesting mode and child attributes of a nested attribute
    /// (`None` for ordinary attributes, including `object(...)`-typed ones).
    pub fn nested(&self) -> Option<(NestingMode, &Block<'a>)> {
        self.ty.nested()
    }
    /// The child attributes of a nested attribute, as a [`Block`] (with no
    /// `block_types`). Same as `self.nested().map(|n| n.1)`.
    pub fn nested_block(&self) -> Option<&Block<'a>> {
        self.ty.nested().map(|(_, b)| b)
    }
    /// True when Terraform also accepts *block* syntax for this attribute
    /// (`ingress { ... }` on `aws_security_group`). Terraform core's
    /// `blocktoattr` fixup allows this for any attribute whose type is a list
    /// or set of objects (SDKv2 `ConfigModeAttr`). The evaluator must treat
    /// such blocks as elements of the attribute's value.
    pub fn accepts_block_syntax(&self) -> bool {
        match &self.ty {
            CtyType::List(t) | CtyType::Set(t) => matches!(**t, CtyType::Object(_)),
            _ => false,
        }
    }
}

/// How a nested block repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NestingMode {
    Single,
    Group,
    List,
    Set,
    Map,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NestedBlock<'a> {
    #[serde(serialize_with = "sym::ser", deserialize_with = "sym::de")]
    pub name: &'a str,
    pub nesting: NestingMode,
    pub min_items: u32,
    /// 0 means unbounded.
    pub max_items: u32,
    #[serde(borrow)]
    pub block: Block<'a>,
}

impl<'a> NestedBlock<'a> {
    pub fn name(&self) -> &'a str {
        self.name
    }
    pub fn nesting(&self) -> NestingMode {
        self.nesting
    }
    pub fn min_items(&self) -> u32 {
        self.min_items
    }
    /// `None` when unbounded.
    pub fn max_items(&self) -> Option<u32> {
        (self.max_items != 0).then_some(self.max_items)
    }
    /// At most one instance (`single`/`group`, or `max_items == 1`).
    pub fn is_singleton(&self) -> bool {
        matches!(self.nesting, NestingMode::Single | NestingMode::Group) || self.max_items == 1
    }
    pub fn block(&self) -> &Block<'a> {
        &self.block
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Block<'a> {
    /// Sorted by name.
    #[serde(borrow)]
    pub attributes: Vec<Attribute<'a>>,
    /// Sorted by name.
    pub block_types: Vec<NestedBlock<'a>>,
    pub deprecated: bool,
}

/// Answer to "what is `name` inside this block?".
#[derive(Debug, Clone, Copy)]
pub enum Member<'s, 'a> {
    Attribute(&'s Attribute<'a>),
    Block(&'s NestedBlock<'a>),
}

impl<'s, 'a> Member<'s, 'a> {
    /// The member's name.
    pub fn name(&self) -> &'a str {
        match self {
            Member::Attribute(a) => a.name,
            Member::Block(b) => b.name,
        }
    }
    /// True for attributes, including nested attributes (written with `=`).
    pub fn is_attribute(&self) -> bool {
        matches!(self, Member::Attribute(_))
    }
    /// The schema one level down: a nested block's body, or a nested
    /// attribute's child attributes. `None` for ordinary attributes.
    pub fn inner(&self) -> Option<&'s Block<'a>> {
        match *self {
            Member::Attribute(a) => a.nested_block(),
            Member::Block(b) => Some(&b.block),
        }
    }
    /// Nesting mode of a nested block or nested attribute.
    pub fn nesting(&self) -> Option<NestingMode> {
        match *self {
            Member::Attribute(a) => a.nested().map(|n| n.0),
            Member::Block(b) => Some(b.nesting),
        }
    }
}

impl<'a> Block<'a> {
    pub fn attributes(&self) -> &[Attribute<'a>] {
        &self.attributes
    }
    pub fn block_types(&self) -> &[NestedBlock<'a>] {
        &self.block_types
    }
    pub fn attribute(&self, name: &str) -> Option<&Attribute<'a>> {
        self.attributes
            .binary_search_by(|a| a.name.cmp(name))
            .ok()
            .map(|i| &self.attributes[i])
    }
    pub fn block_type(&self, name: &str) -> Option<&NestedBlock<'a>> {
        self.block_types
            .binary_search_by(|b| b.name.cmp(name))
            .ok()
            .map(|i| &self.block_types[i])
    }
    /// Attribute, nested block, or neither.
    pub fn member(&self, name: &str) -> Option<Member<'_, 'a>> {
        if let Some(a) = self.attribute(name) {
            return Some(Member::Attribute(a));
        }
        self.block_type(name).map(Member::Block)
    }
    pub fn is_attribute(&self, name: &str) -> bool {
        self.attribute(name).is_some()
    }
    /// Follows a path of nested block names and/or nested attribute names,
    /// e.g. `["lifecycle_rule", "action"]` or (cloudflare) `["rules",
    /// "action_parameters"]`. Use [`Block::member_at`] to learn whether each
    /// step was a block or an attribute, or [`Block::descend_blocks`] to
    /// follow nested blocks only.
    pub fn descend(&self, path: &[&str]) -> Option<&Block<'a>> {
        let mut b = self;
        for p in path {
            b = b.member(p)?.inner()?;
        }
        Some(b)
    }
    /// Like [`Block::descend`] but only through nested blocks (block syntax).
    pub fn descend_blocks(&self, path: &[&str]) -> Option<&Block<'a>> {
        let mut b = self;
        for p in path {
            b = &b.block_type(p)?.block;
        }
        Some(b)
    }
    /// The member at `path`, descending through nested blocks and nested
    /// attributes: `member_at(&["rules", "action"])` on `cloudflare_ruleset`
    /// is the `action` attribute inside the `rules` nested attribute.
    /// Does not descend into `object(...)`-typed attributes (use
    /// [`CtyType::object_attr`] for those).
    pub fn member_at(&self, path: &[&str]) -> Option<Member<'_, 'a>> {
        let (last, init) = path.split_last()?;
        self.descend(init)?.member(last)
    }
}

/// One resource or data source schema, as stored in the blob.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaBody<'a> {
    pub version: u32,
    #[serde(borrow)]
    pub block: Block<'a>,
}

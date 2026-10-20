//! Provider schema IR for hashicorp/aws, hashicorp/azurerm, hashicorp/google,
//! cloudflare/cloudflare, hashicorp/kubernetes and integrations/github (the
//! list is [`Provider::ALL`]).
//!
//! * [`lookup_resource`] / [`lookup_data_source`] → `&'static ResourceSchema`.
//!   Each schema is deserialized lazily from an embedded postcard blob on first
//!   lookup and cached for the life of the process.
//! * [`ResourceSchema`] derefs to [`Block`]: [`Block::attribute`],
//!   [`Block::block_type`], [`Block::member`], [`Attribute::is_computed`],
//!   [`Attribute::is_bool`], ...
//! * [`lookup_provider`] supplies a provider configuration body for JSON
//!   attribute-versus-block mapping.
//! * Nested attributes (protocol-6 `nested_type`, used by framework providers
//!   such as cloudflare 5.x) are [`Member::Attribute`]s whose type is
//!   [`CtyType::Nested`]: [`Attribute::nested`] gives the nesting mode and the
//!   child attributes; [`Block::descend`] and [`Block::member_at`] walk
//!   through them as well as through nested blocks.
//! * [`default_for`] answers "what does the provider use when this attribute
//!   is absent?" from the hand-written overlay in `defaults/*.toml`.
//! * [`views`] holds typed views for the allowlisted resources, generic over
//!   [`ResourceNode`].
//!
//! Everything under `src/generated/` is written by `tf_schema_codegen`
//! (`cargo run -p tf_schema_codegen --release -- generate`); do not edit it.

pub mod defaults;
pub mod ir;
pub mod node;

pub use defaults::{DefaultEntry, DefaultValue};
pub use ir::{
    Attribute, Block, CtyType, Member, NestedBlock, NestingMode, ObjectAttr, Provider, SchemaBody,
    SchemaKind,
};
pub use node::{ResourceNode, TypedView};

#[cfg(feature = "embedded")]
pub use defaults::{default_for, defaults_for};

#[cfg(feature = "embedded")]
mod generated {
    #[rustfmt::skip]
    pub(crate) mod defaults;
    #[rustfmt::skip]
    pub(crate) mod index;
    #[rustfmt::skip]
    pub(crate) mod providers;
}

/// Typed views for allowlisted resources (`crates/tf_schema_codegen/allowlist.toml`).
#[cfg(feature = "embedded")]
#[path = "generated/views.rs"]
#[rustfmt::skip]
pub mod views;

/// Index entry: where one schema lives in the blob.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct EntryMeta {
    pub name: &'static str,
    pub kind: SchemaKind,
    pub provider: Provider,
    pub start: u32,
    pub end: u32,
}

/// A resource or data source schema.
#[derive(Debug)]
pub struct ResourceSchema {
    pub name: &'static str,
    pub kind: SchemaKind,
    pub provider: Provider,
    pub version: u32,
    pub block: Block<'static>,
}

impl ResourceSchema {
    pub fn block(&self) -> &Block<'static> {
        &self.block
    }
}

impl std::ops::Deref for ResourceSchema {
    type Target = Block<'static>;
    fn deref(&self) -> &Block<'static> {
        &self.block
    }
}

/// Decode one schema record from raw postcard bytes, resolving names through
/// `symbols` (used by the runtime and by the generator's round-trip test).
pub fn decode_body(
    bytes: &'static [u8],
    symbols: &'static [&'static str],
) -> Result<SchemaBody<'static>, postcard::Error> {
    ir::sym::with_decoder(symbols, || postcard::from_bytes(bytes))
}

/// Decode a symbol table written by the generator.
pub fn decode_symbols(bytes: &'static [u8]) -> Result<Vec<&'static str>, postcard::Error> {
    postcard::from_bytes(bytes)
}

#[cfg(feature = "embedded")]
mod embedded {
    use super::*;
    use crate::generated::index::{BLOB, DATA_SOURCES, ENTRIES, N, RESOURCES, SYMBOLS};
    use std::sync::OnceLock;

    static CACHE: [OnceLock<ResourceSchema>; N] = [const { OnceLock::new() }; N];
    static SYMS: OnceLock<Vec<&'static str>> = OnceLock::new();

    /// The interned name table (decoded once, on first lookup).
    pub fn symbols() -> &'static [&'static str] {
        SYMS.get_or_init(|| {
            decode_symbols(SYMBOLS)
                .expect("embedded symbol table is corrupt; rerun tf_schema_codegen")
        })
    }

    fn load(id: usize) -> &'static ResourceSchema {
        CACHE[id].get_or_init(|| {
            let m = &ENTRIES[id];
            let body = decode_body(&BLOB[m.start as usize..m.end as usize], symbols())
                .expect("embedded schema blob is corrupt; rerun tf_schema_codegen");
            ResourceSchema {
                name: m.name,
                kind: m.kind,
                provider: m.provider,
                version: body.version,
                block: body.block,
            }
        })
    }

    /// Schema of managed resource type `name` (e.g. `"aws_security_group"`).
    pub fn lookup_resource(name: &str) -> Option<&'static ResourceSchema> {
        RESOURCES.get(name).map(|&id| load(id as usize))
    }

    /// Schema of data source type `name` (e.g. `"aws_iam_policy_document"`).
    pub fn lookup_data_source(name: &str) -> Option<&'static ResourceSchema> {
        DATA_SOURCES.get(name).map(|&id| load(id as usize))
    }

    /// `lookup_resource` or `lookup_data_source` depending on `kind`.
    pub fn lookup(kind: SchemaKind, name: &str) -> Option<&'static ResourceSchema> {
        match kind {
            SchemaKind::Resource => lookup_resource(name),
            SchemaKind::DataSource => lookup_data_source(name),
        }
    }

    /// Cheap existence check that does not deserialize anything.
    pub fn contains(kind: SchemaKind, name: &str) -> bool {
        match kind {
            SchemaKind::Resource => RESOURCES.contains_key(name),
            SchemaKind::DataSource => DATA_SOURCES.contains_key(name),
        }
    }

    /// Every (name, kind, provider) in the index, without deserializing.
    pub fn entries() -> impl Iterator<Item = (&'static str, SchemaKind, Provider)> {
        ENTRIES.iter().map(|m| (m.name, m.kind, m.provider))
    }

    /// Size in bytes of the embedded schema blob and symbol table.
    pub fn blob_len() -> (usize, usize) {
        (BLOB.len(), SYMBOLS.len())
    }
}

#[cfg(feature = "embedded")]
pub use embedded::*;

/// Configuration body for an embedded provider's local name, e.g. `aws`.
#[cfg(feature = "embedded")]
pub fn lookup_provider(name: &str) -> Option<&'static Block<'static>> {
    use generated::providers::{BLOB, ENTRIES, N, SYMBOLS};
    use std::sync::OnceLock;
    static CACHE: [OnceLock<SchemaBody<'static>>; N] = [const { OnceLock::new() }; N];
    static SYMS: OnceLock<Vec<&'static str>> = OnceLock::new();
    let index = ENTRIES.iter().position(|(n, _, _)| *n == name)?;
    let (_, start, end) = ENTRIES[index];
    Some(
        &CACHE[index]
            .get_or_init(|| {
                let symbols = SYMS.get_or_init(|| {
                    decode_symbols(SYMBOLS)
                        .expect("embedded provider symbols are corrupt; rerun tf_schema_codegen")
                });
                decode_body(&BLOB[start..end], symbols)
                    .expect("embedded provider schema is corrupt; rerun tf_schema_codegen")
            })
            .block,
    )
}

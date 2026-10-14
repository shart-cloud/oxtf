//! Defaults overlay. The provider schema protocol does not carry default
//! values, so "attribute absent" has no meaning without this. The data comes
//! from the hand-written `defaults/<provider>.toml` files at the repo root,
//! validated against the schema and compiled into a `phf` map by
//! `tf_schema_codegen`.

/// The value a provider uses when an attribute is absent from configuration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DefaultValue {
    Bool(bool),
    Number(f64),
    String(&'static str),
    /// Absent collection/attributes-as-blocks means "no elements" (e.g.
    /// `aws_security_group.ingress` absent → no inline ingress rules).
    Empty,
}

impl DefaultValue {
    pub fn as_bool(self) -> Option<bool> {
        match self {
            DefaultValue::Bool(b) => Some(b),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DefaultEntry {
    /// Attribute path relative to the resource body; nested block segments
    /// are joined with `.` (e.g. `"versioning.enabled"`).
    pub path: &'static str,
    pub value: DefaultValue,
    /// Where the value came from (doc/source reference), free text.
    pub note: &'static str,
}

/// Default for `path` (an attribute name, or `block.attr` for nested blocks)
/// on resource type `resource`.
#[cfg(feature = "embedded")]
pub fn default_for(resource: &str, path: &str) -> Option<DefaultValue> {
    defaults_for(resource)
        .iter()
        .find(|e| e.path == path)
        .map(|e| e.value)
}

/// All overlay entries for resource type `resource` (empty if none).
#[cfg(feature = "embedded")]
pub fn defaults_for(resource: &str) -> &'static [DefaultEntry] {
    crate::generated::defaults::DEFAULTS
        .get(resource)
        .copied()
        .unwrap_or(&[])
}

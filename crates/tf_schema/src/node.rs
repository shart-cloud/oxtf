//! The seam between generated typed views and the (not yet written) AST /
//! evaluator. W3 implements [`ResourceNode`] for its resource-body node; the
//! generated views in [`crate::views`] are `#[repr(transparent)]` newtypes over
//! any `N: ResourceNode`, so they cost nothing at runtime: every accessor is a
//! `#[inline]` call to `attr`/`blocks` with a string literal.

/// A resource (or nested block) body as seen by a rule.
pub trait ResourceNode {
    /// Whatever the evaluator yields for an attribute (e.g. an abstract
    /// value with provenance).
    type Value;
    /// A nested block body. Nested blocks are themselves nodes.
    type Block: ResourceNode<Value = Self::Value>;

    /// The attribute `name`, if it is set in configuration.
    fn attr(&self, name: &str) -> Option<Self::Value>;

    /// All nested blocks named `name` (including ones produced by `dynamic`
    /// blocks, if the evaluator expanded them), in source order.
    fn blocks(&self, name: &str) -> impl Iterator<Item = Self::Block>;
}

/// Implemented by every generated view struct. Its methods live on a trait
/// (not inherent) so they can never collide with a generated accessor
/// named after a schema attribute.
pub trait TypedView: Sized {
    type Node;
    /// Terraform type name of the resource this view (or its parent) belongs to.
    const TYPE_NAME: &'static str;
    /// Path of nested block names from the resource body (empty for the resource itself).
    const BLOCK_PATH: &'static [&'static str];
    fn from_node(node: Self::Node) -> Self;
    fn node(&self) -> &Self::Node;
    fn into_node(self) -> Self::Node;
}

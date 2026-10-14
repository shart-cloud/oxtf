//! AST node definitions.
//!
//! This file is the single source of truth for the tree shape. The visitor
//! code in `src/generated/` is produced from it by `tf_ast_codegen`
//! (`cargo run -p tf_ast_codegen`); re-run the generator after editing.
//!
//! Codegen conventions (read by `tf_ast_codegen`):
//! - every `struct` with a `span: Span` field is a *node*: it gets an
//!   `AstKind` variant and `visit_*` / `walk_*` methods;
//! - every `enum` with data-carrying variants is a *dispatch enum*: it gets
//!   `visit_*` / `walk_*` methods that forward to the variant;
//! - structs without a span and fieldless enums are *leaves* (not visited).
//!
//! Layout rules, as in oxc: all dispatch enums hold `Box<'a, T>` (8 bytes)
//! so they are 16 bytes; nodes live in a bump arena and never drop.

use tf_allocator::{Atom, Box, Vec};
use tf_span::Span;

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

/// A parsed `.tf` / `.tfvars` / `.hcl` file.
#[derive(Debug)]
pub struct File<'a> {
    pub span: Span,
    pub body: Body<'a>,
}

/// A sequence of attributes and blocks (the file root or a block's `{ ... }`).
#[derive(Debug)]
pub struct Body<'a> {
    pub span: Span,
    pub items: Vec<'a, BodyItem<'a>>,
}

#[derive(Debug)]
pub enum BodyItem<'a> {
    Attribute(Box<'a, Attribute<'a>>),
    Block(Box<'a, Block<'a>>),
}

/// `key = value`
#[derive(Debug)]
pub struct Attribute<'a> {
    pub span: Span,
    pub key: Identifier<'a>,
    pub value: Expression<'a>,
}

/// `type "label" label { body }`
#[derive(Debug)]
pub struct Block<'a> {
    pub span: Span,
    /// The block type, e.g. `resource`, `dynamic`, `moved`.
    pub ident: Identifier<'a>,
    pub labels: Vec<'a, BlockLabel<'a>>,
    pub body: Body<'a>,
}

/// A block label: either a quoted string (`"aws_s3_bucket"`, escapes decoded)
/// or a bare identifier.
#[derive(Debug)]
pub struct BlockLabel<'a> {
    pub span: Span,
    pub value: Atom<'a>,
    pub quoted: bool,
}

/// A name in binding/key position: attribute keys, block types, `for`
/// variables, object keys, attribute names after `.`, function names.
#[derive(Debug)]
pub struct Identifier<'a> {
    pub span: Span,
    pub name: Atom<'a>,
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

/// Every variant is boxed so that `size_of::<Expression>() == 16`.
#[derive(Debug)]
pub enum Expression<'a> {
    Null(Box<'a, NullLiteral>),
    Bool(Box<'a, BooleanLiteral>),
    Number(Box<'a, NumberLiteral<'a>>),
    /// A quoted string with no interpolations or directives.
    String(Box<'a, StringLiteral<'a>>),
    /// A quoted string with at least one `${}` or `%{}`.
    Template(Box<'a, TemplateExpr<'a>>),
    Heredoc(Box<'a, HeredocExpr<'a>>),
    /// A bare identifier in value position: the root of a reference.
    Variable(Box<'a, VariableExpr<'a>>),
    Traversal(Box<'a, Traversal<'a>>),
    FunctionCall(Box<'a, FunctionCall<'a>>),
    Tuple(Box<'a, Tuple<'a>>),
    Object(Box<'a, Object<'a>>),
    For(Box<'a, ForExpr<'a>>),
    Conditional(Box<'a, Conditional<'a>>),
    Unary(Box<'a, UnaryExpr<'a>>),
    Binary(Box<'a, BinaryExpr<'a>>),
    Parenthesized(Box<'a, ParenthesizedExpr<'a>>),
    /// Placeholder produced by error recovery.
    Error(Box<'a, ErrorExpr>),
}

#[derive(Debug)]
pub struct NullLiteral {
    pub span: Span,
}

#[derive(Debug)]
pub struct BooleanLiteral {
    pub span: Span,
    pub value: bool,
}

#[derive(Debug)]
pub struct NumberLiteral<'a> {
    pub span: Span,
    pub value: f64,
    pub raw: Atom<'a>,
}

#[derive(Debug)]
pub struct StringLiteral<'a> {
    pub span: Span,
    /// Escapes decoded.
    pub value: Atom<'a>,
}

/// `"...${x}..."`
#[derive(Debug)]
pub struct TemplateExpr<'a> {
    pub span: Span,
    pub template: Template<'a>,
}

/// `<<EOT ... EOT` or `<<-EOT ... EOT`.
///
/// For `<<-` the common leading whitespace is already removed from the
/// literal parts (HCL/Go semantics, see the parser).
#[derive(Debug)]
pub struct HeredocExpr<'a> {
    pub span: Span,
    pub delimiter: Atom<'a>,
    pub indented: bool,
    pub template: Template<'a>,
}

#[derive(Debug)]
pub struct Template<'a> {
    pub span: Span,
    pub elements: Vec<'a, TemplateElement<'a>>,
}

#[derive(Debug)]
pub enum TemplateElement<'a> {
    Literal(Box<'a, TemplateLiteral<'a>>),
    Interpolation(Box<'a, TemplateInterpolation<'a>>),
    If(Box<'a, TemplateIf<'a>>),
    For(Box<'a, TemplateFor<'a>>),
}

/// Literal template text. Escapes (`\n`, `$${`, `%%{`, ...) are decoded;
/// `~` strip markers are *not* applied (see [`Strip`]).
#[derive(Debug)]
pub struct TemplateLiteral<'a> {
    pub span: Span,
    pub value: Atom<'a>,
}

/// Whitespace strip markers on a template sequence: `start` is `${~` / `%{~`
/// (strip whitespace *before* the sequence), `end` is `~}` (strip after).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Strip {
    pub start: bool,
    pub end: bool,
}

/// `${ expr }`
#[derive(Debug)]
pub struct TemplateInterpolation<'a> {
    pub span: Span,
    pub strip: Strip,
    pub expression: Expression<'a>,
}

/// `%{ if cond }...%{ else }...%{ endif }`
#[derive(Debug)]
pub struct TemplateIf<'a> {
    pub span: Span,
    pub condition: Expression<'a>,
    pub if_strip: Strip,
    pub then_template: Template<'a>,
    pub else_strip: Option<Strip>,
    pub else_template: Option<Template<'a>>,
    pub endif_strip: Strip,
}

/// `%{ for k, v in coll }...%{ endfor }`
#[derive(Debug)]
pub struct TemplateFor<'a> {
    pub span: Span,
    pub key_var: Option<Identifier<'a>>,
    pub value_var: Identifier<'a>,
    pub collection: Expression<'a>,
    pub for_strip: Strip,
    pub template: Template<'a>,
    pub endfor_strip: Strip,
}

/// A bare name used as a value: `var`, `local`, `aws_instance`, `each`, ...
#[derive(Debug)]
pub struct VariableExpr<'a> {
    pub span: Span,
    pub name: Atom<'a>,
}

/// `object` followed by one or more traversal operators.
///
/// `var.a.b[0]` is `Traversal { object: Variable(var), operators: [.a, .b, [0]] }`.
/// Operators after a splat stay in the same flat list (as in `hcl-edit`).
#[derive(Debug)]
pub struct Traversal<'a> {
    pub span: Span,
    pub object: Expression<'a>,
    pub operators: Vec<'a, TraversalOperator<'a>>,
}

#[derive(Debug)]
pub enum TraversalOperator<'a> {
    /// `.name`
    GetAttr(Box<'a, GetAttr<'a>>),
    /// `[expr]`
    Index(Box<'a, IndexOp<'a>>),
    /// `.0` (legacy index syntax)
    LegacyIndex(Box<'a, LegacyIndex>),
    /// `.*`
    AttrSplat(Box<'a, AttrSplat>),
    /// `[*]`
    FullSplat(Box<'a, FullSplat>),
}

#[derive(Debug)]
pub struct GetAttr<'a> {
    pub span: Span,
    pub name: Identifier<'a>,
}

#[derive(Debug)]
pub struct IndexOp<'a> {
    pub span: Span,
    pub index: Expression<'a>,
}

#[derive(Debug)]
pub struct LegacyIndex {
    pub span: Span,
    pub index: u64,
}

#[derive(Debug)]
pub struct AttrSplat {
    pub span: Span,
}

#[derive(Debug)]
pub struct FullSplat {
    pub span: Span,
}

/// `name(args)`, `provider::aws::arn_parse(args)`, `f(list...)`.
#[derive(Debug)]
pub struct FunctionCall<'a> {
    pub span: Span,
    /// `["provider", "aws"]` for `provider::aws::arn_parse`; empty otherwise.
    pub namespace: Vec<'a, Identifier<'a>>,
    pub name: Identifier<'a>,
    pub arguments: Vec<'a, Expression<'a>>,
    /// The final argument is followed by `...`.
    pub expand_final: bool,
}

/// `[a, b, c]`
#[derive(Debug)]
pub struct Tuple<'a> {
    pub span: Span,
    pub elements: Vec<'a, Expression<'a>>,
}

/// `{ k = v, "k2": v2 }`
#[derive(Debug)]
pub struct Object<'a> {
    pub span: Span,
    pub items: Vec<'a, ObjectItem<'a>>,
}

#[derive(Debug)]
pub struct ObjectItem<'a> {
    pub span: Span,
    pub key: ObjectKey<'a>,
    pub value: Expression<'a>,
}

#[derive(Debug)]
pub enum ObjectKey<'a> {
    /// A bare identifier key: a literal string, not a variable reference.
    Identifier(Box<'a, Identifier<'a>>),
    /// Any other key expression (`"quoted"`, `(var.k)`, `aws.east`, ...).
    Expression(Expression<'a>),
}

/// `[for k, v in coll : value if cond]` /
/// `{for k, v in coll : key => value... if cond}`
#[derive(Debug)]
pub struct ForExpr<'a> {
    pub span: Span,
    pub key_var: Option<Identifier<'a>>,
    pub value_var: Identifier<'a>,
    pub collection: Expression<'a>,
    /// `Some` for the object form.
    pub key_expr: Option<Expression<'a>>,
    pub value_expr: Expression<'a>,
    /// `...` grouping (object form only).
    pub grouping: bool,
    pub condition: Option<Expression<'a>>,
}

/// `cond ? a : b`
#[derive(Debug)]
pub struct Conditional<'a> {
    pub span: Span,
    pub condition: Expression<'a>,
    pub true_expr: Expression<'a>,
    pub false_expr: Expression<'a>,
}

#[derive(Debug)]
pub struct UnaryExpr<'a> {
    pub span: Span,
    pub operator: UnaryOperator,
    pub operand: Expression<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOperator {
    /// `!`
    Not,
    /// `-`
    Negate,
}

#[derive(Debug)]
pub struct BinaryExpr<'a> {
    pub span: Span,
    pub operator: BinaryOperator,
    pub left: Expression<'a>,
    pub right: Expression<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    Or,
    And,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
}

/// `( expr )`
#[derive(Debug)]
pub struct ParenthesizedExpr<'a> {
    pub span: Span,
    pub expression: Expression<'a>,
}

/// An expression that failed to parse. A diagnostic was recorded.
#[derive(Debug)]
pub struct ErrorExpr {
    pub span: Span,
}

//! Hand-written, error-recovering HCL parser producing a `tf_ast` tree.
//!
//! ```
//! let allocator = tf_allocator::Allocator::new();
//! let ret = tf_parser::parse(&allocator, "a = 1\n");
//! assert!(ret.errors.is_empty());
//! assert_eq!(ret.file.body.items.len(), 1);
//! ```
//!
//! Design:
//! - a lazy, position-based [`lexer`] (one token of lookahead);
//! - recursive descent for structure, a Pratt loop for binary operators;
//! - a newline-mode stack: newlines terminate items in bodies and objects but
//!   are skipped inside `()`, `[]`, `${}` and `for` expressions;
//! - syntax errors are recorded as a [`Diagnostic`] and the parser
//!   resynchronises (end of line / matching closer), leaving
//!   `Expression::Error` placeholders where an expression was expected;
//! - depth or storage exhaustion returns a typed limit diagnostic with an empty
//!   file or no expression, safe for consumers without another arena allocation.

pub mod dump;
mod json_vars;
pub mod lexer;
mod limits;
mod parser;

use std::fmt;
use tf_allocator::Allocator;
use tf_ast::{Comment, File};
use tf_span::Span;

pub use limits::{AST_DEPTH_MAX, JSON_DEPTH_MAX, PARSE_DEPTH_MAX};

/// Exhaustion is distinct from invalid syntax, including at adapter boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseLimit {
    ParserDepth,
    AstDepth,
    JsonDepth,
    Storage(tf_limits::Exhaustion),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticKind {
    Syntax,
    Limit(ParseLimit),
}

/// A syntax error or resource limit. The message is plain text; the span points at the
/// offending token (or an empty span where something was expected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub span: Span,
    pub message: String,
    pub kind: DiagnosticKind,
}

impl Diagnostic {
    pub fn limit(span: Span, limit: ParseLimit) -> Self {
        if let ParseLimit::Storage(exhaustion) = limit {
            return Self {
                span,
                message: exhaustion.to_string(),
                kind: DiagnosticKind::Limit(limit),
            };
        }
        let (resource, maximum) = match limit {
            ParseLimit::ParserDepth => ("parser nesting", PARSE_DEPTH_MAX),
            ParseLimit::AstDepth => ("AST nesting", AST_DEPTH_MAX),
            ParseLimit::JsonDepth => ("JSON nesting", JSON_DEPTH_MAX),
            ParseLimit::Storage(_) => unreachable!("storage handled above"),
        };
        Self {
            span,
            message: format!("{resource} exceeds limit {maximum}"),
            kind: DiagnosticKind::Limit(limit),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.span, self.message)
    }
}

pub struct ParseResult<'a> {
    pub file: File<'a>,
    /// All comments in source order.
    pub comments: Vec<Comment>,
    /// Empty for a clean parse.
    pub errors: Vec<Diagnostic>,
}

impl<'a> ParseResult<'a> {
    /// Check before indexing, mapping locations, or any recursive consumer.
    /// An omitted file keeps its diagnostic and never exposes a partial tree.
    pub fn bounded(mut self, allocator: &'a Allocator) -> Self {
        if let Some(span) = limits::file_depth(&mut self.file) {
            self.errors
                .push(Diagnostic::limit(span, ParseLimit::AstDepth));
        }
        if self
            .errors
            .iter()
            .any(|e| matches!(e.kind, DiagnosticKind::Limit(_)))
        {
            self.file.body.items = tf_allocator::Vec::new_in(allocator);
        }
        self
    }
}

/// Parse an HCL file (`.tf`, `.tfvars`, `.tftest.hcl`, ...).
///
/// Always returns a tree. Nodes borrow from both `allocator` and `source`.
/// To get `&'a File<'a>` for [`tf_ast::Visit`], move the file into the arena:
/// `let file = allocator.alloc(ret.file)?;`.
pub fn parse<'a>(allocator: &'a Allocator, source: &'a str) -> ParseResult<'a> {
    parser::Parser::new(allocator, source)
        .parse_file()
        .bounded(allocator)
}

/// Parse a JSON variable file into literal attributes. Strings and object
/// keys are never interpreted as templates. Spans refer to the JSON bytes.
pub use json_vars::{parse_json_value, parse_json_vars};

/// Parse a standalone native expression (for JSON type/reference contexts).
/// Returns no expression after depth or storage exhaustion.
pub fn parse_expression<'a>(
    allocator: &'a Allocator,
    source: &'a str,
) -> (Option<tf_ast::Expression<'a>>, Vec<Diagnostic>) {
    let (expression, errors) = parser::Parser::new(allocator, source).parse_expression();
    limits::bounded_expression(allocator, expression, errors)
}

/// Parse decoded template text. JSON decoding has already consumed escapes;
/// quotes, newlines and backslashes in literal text have no special meaning.
/// Returns no expression after depth or storage exhaustion.
pub fn parse_template<'a>(
    allocator: &'a Allocator,
    source: &'a str,
) -> (Option<tf_ast::Expression<'a>>, Vec<Diagnostic>) {
    let (expression, errors) = parser::Parser::new(allocator, source).parse_raw_template();
    limits::bounded_expression(allocator, expression, errors)
}

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
//! - errors never abort: each is recorded as a [`Diagnostic`] and the parser
//!   resynchronises (end of line / matching closer), leaving
//!   `Expression::Error` placeholders where an expression was expected.

pub mod dump;
pub mod lexer;
mod parser;

use std::fmt;
use tf_allocator::Allocator;
use tf_ast::{Comment, File};
use tf_span::Span;

/// A parse error. The message is plain text; the span points at the
/// offending token (or an empty span where something was expected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub span: Span,
    pub message: String,
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

/// Parse an HCL file (`.tf`, `.tfvars`, `.tftest.hcl`, ...).
///
/// Always returns a tree. Nodes borrow from both `allocator` and `source`.
/// To get `&'a File<'a>` for [`tf_ast::Visit`], move the file into the arena:
/// `let file = allocator.alloc(ret.file);`.
pub fn parse<'a>(allocator: &'a Allocator, source: &'a str) -> ParseResult<'a> {
    parser::Parser::new(allocator, source).parse_file()
}

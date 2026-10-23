use tf_allocator::{Allocator, Atom, Box, Vec};
use tf_ast::*;
use tf_span::Span;

use crate::lexer::{Kind, Lexer, LitStop, TemplateCtx, Token};
use crate::{Diagnostic, DiagnosticKind, PARSE_DEPTH_MAX, ParseLimit, ParseResult};

mod body;
mod expressions;
mod templates;

/// Result of synchronising inside a delimited list after an error.
enum Sync {
    /// A `,` was consumed; continue with the next element.
    Comma,
    /// The closer is the current token.
    Closer,
    /// Gave up (EOF, or what looks like the start of the next body item).
    Abort,
}

/// How a run of template elements ended.
#[derive(Clone, Copy)]
enum TplEnd {
    /// Closing quote / heredoc terminator: `(start, end)` of the closer.
    Close(u32, u32),
    /// Unterminated (newline in quoted string, or EOF).
    Unterminated(u32),
    /// `%{ else }`, `%{ endif }`, `%{ endfor }`: span start, span end, strip.
    Else(u32, u32, Strip),
    Endif(u32, u32, Strip),
    Endfor(u32, u32, Strip),
}

pub struct Parser<'a> {
    alloc: &'a Allocator,
    src: &'a str,
    lexer: Lexer<'a>,
    /// Current token (never a comment).
    tok: Token,
    /// End offset of the last consumed token.
    prev_end: u32,
    /// Newline mode stack: `true` = newlines are insignificant.
    modes: std::vec::Vec<bool>,
    comments: std::vec::Vec<Comment>,
    errors: std::vec::Vec<Diagnostic>,
    depth: usize,
    limited: bool,
}

impl<'a> Parser<'a> {
    pub fn new(alloc: &'a Allocator, src: &'a str) -> Self {
        assert!(
            src.len() < u32::MAX as usize,
            "source files must be < 4 GiB"
        );
        let mut p = Parser {
            alloc,
            src,
            lexer: Lexer::new(src),
            tok: Token {
                kind: Kind::Eof,
                span: Span::EMPTY,
            },
            prev_end: 0,
            modes: vec![false],
            comments: std::vec::Vec::new(),
            errors: std::vec::Vec::new(),
            depth: 0,
            limited: false,
        };
        p.tok = p.lex_next();
        p
    }

    pub fn parse_file(mut self) -> ParseResult<'a> {
        let body = match self.parse_body(true, 0) {
            Ok(body) => body,
            Err(error) => {
                self.errors
                    .push(Diagnostic::limit(self.tok.span, ParseLimit::Storage(error)));
                Body {
                    span: Span::new(0, self.src.len() as u32),
                    items: self.vec(),
                }
            }
        };
        let file = File {
            span: Span::new(0, self.src.len() as u32),
            body,
        };
        ParseResult {
            file,
            comments: self.comments,
            errors: self.errors,
        }
    }

    pub fn parse_expression(mut self) -> (Option<Expression<'a>>, std::vec::Vec<Diagnostic>) {
        self.push_mode(true);
        let expression = match self.parse_expr() {
            Ok(expression) => Some(expression),
            Err(error) => {
                self.errors
                    .push(Diagnostic::limit(self.tok.span, ParseLimit::Storage(error)));
                return (None, self.errors);
            }
        };
        if self.tok.kind != Kind::Eof {
            self.error_at_tok("unexpected tokens after expression");
        }
        (expression, self.errors)
    }

    pub fn parse_raw_template(mut self) -> (Option<Expression<'a>>, std::vec::Vec<Diagnostic>) {
        let expression = match self.raw_template() {
            Ok(expression) => Some(expression),
            Err(error) => {
                self.errors
                    .push(Diagnostic::limit(self.tok.span, ParseLimit::Storage(error)));
                None
            }
        };
        (expression, self.errors)
    }

    fn raw_template(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
        self.lexer.pos = 0;
        self.comments.clear();
        let (template, _) = self.parse_template_top(TemplateCtx::Raw, false, 0)?;
        let span = Span::new(0, self.src.len() as u32);
        let expression = if template.elements.is_empty() {
            Expression::String(self.boxed(StringLiteral {
                span,
                value: Atom::EMPTY,
            })?)
        } else if template.elements.len() == 1
            && matches!(template.elements[0], TemplateElement::Literal(_))
        {
            let TemplateElement::Literal(l) = &template.elements[0] else {
                unreachable!()
            };
            Expression::String(self.boxed(StringLiteral {
                span,
                value: l.value,
            })?)
        } else {
            Expression::Template(self.boxed(TemplateExpr { span, template })?)
        };
        Ok(expression)
    }

    // ------------------------------------------------------------------
    // Token plumbing
    // ------------------------------------------------------------------

    /// Stop parsing on exhaustion, so unwinding cannot manufacture syntax errors.
    fn enter_depth(&mut self) -> bool {
        assert!(self.depth <= PARSE_DEPTH_MAX);
        if self.limited {
            return false;
        }
        if self.depth == PARSE_DEPTH_MAX {
            self.errors
                .push(Diagnostic::limit(self.tok.span, ParseLimit::ParserDepth));
            self.limited = true;
            self.lexer.pos = self.src.len();
            self.tok = Token {
                kind: Kind::Eof,
                span: Span::empty(self.src.len() as u32),
            };
            self.prev_end = self.tok.span.end;
            return false;
        }
        self.depth += 1;
        true
    }

    fn leave_depth(&mut self) {
        assert!(self.depth > 0);
        self.depth -= 1;
    }

    fn lex_next(&mut self) -> Token {
        loop {
            let t = self.lexer.next_token();
            if let Kind::Comment(kind) = t.kind {
                self.comments.push(Comment { span: t.span, kind });
                continue;
            }
            return t;
        }
    }

    /// Consume the current token.
    fn bump(&mut self) {
        self.prev_end = self.tok.span.end;
        self.tok = self.lex_next();
    }

    /// Restart normal lexing at `pos` (after a template or a split token).
    fn resync(&mut self, pos: u32) {
        self.prev_end = pos;
        self.lexer.pos = pos as usize;
        self.tok = self.lex_next();
    }

    #[inline]
    fn ignoring_newlines(&self) -> bool {
        *self.modes.last().unwrap()
    }

    /// Current token kind, skipping newlines when they are insignificant.
    #[inline]
    fn peek(&mut self) -> Kind {
        if self.ignoring_newlines() {
            while self.tok.kind == Kind::Newline {
                self.tok = self.lex_next();
            }
        }
        self.tok.kind
    }

    /// Kind of the token after the current one (no comment recording,
    /// newlines not skipped).
    fn peek2(&self) -> Kind {
        let mut lx = self.lexer.clone();
        loop {
            let t = lx.next_token();
            if !matches!(t.kind, Kind::Comment(_)) {
                return t.kind;
            }
        }
    }

    fn at_ident(&mut self, kw: &str) -> bool {
        self.peek() == Kind::Ident && self.tok_text() == kw
    }

    fn tok_text(&self) -> &'a str {
        self.tok.span.source_text(self.src)
    }

    fn start(&mut self) -> u32 {
        self.peek();
        self.tok.span.start
    }

    fn span_from(&self, start: u32) -> Span {
        Span::new(start, self.prev_end.max(start))
    }

    fn error(&mut self, span: Span, message: impl Into<String>) {
        if self.limited {
            return;
        }
        self.errors.push(Diagnostic {
            kind: DiagnosticKind::Syntax,
            span,
            message: message.into(),
        });
    }

    fn error_at_tok(&mut self, message: &str) {
        let span = self.tok.span;
        let found = self.describe_tok();
        self.error(span, format!("{message}, found {found}"));
    }

    fn describe_tok(&self) -> String {
        match self.tok.kind {
            Kind::Eof => "end of file".into(),
            Kind::Newline => "newline".into(),
            Kind::HeredocStart { .. } => "heredoc".into(),
            _ => format!("`{}`", self.tok_text()),
        }
    }

    /// Is there a line break between the last consumed token and the current one?
    fn newline_before_tok(&self) -> bool {
        let a = self.prev_end as usize;
        let b = self.tok.span.start as usize;
        a < b && self.src.as_bytes()[a..b].contains(&b'\n')
    }

    fn push_mode(&mut self, ignore_newlines: bool) {
        self.modes.push(ignore_newlines);
    }

    fn pop_mode(&mut self) {
        self.modes.pop();
        debug_assert!(!self.modes.is_empty());
    }

    /// Expect `kind` as the closer of a bracketed construct opened with an
    /// `ignore newlines` mode push. Pops the mode before consuming so the
    /// following token is seen in the outer mode.
    fn close(&mut self, kind: Kind, what: &str) {
        if self.peek() == kind {
            self.pop_mode();
            self.bump();
        } else {
            self.error_at_tok(&format!("expected `{what}`"));
            self.pop_mode();
        }
    }

    fn ident_from_tok(&mut self) -> Identifier<'a> {
        let id = Identifier {
            span: self.tok.span,
            name: Atom::from(self.tok_text()),
        };
        self.bump();
        id
    }

    fn expect_ident(&mut self, what: &str) -> Identifier<'a> {
        if self.peek() == Kind::Ident {
            self.ident_from_tok()
        } else {
            self.error_at_tok(&format!("expected {what}"));
            Identifier {
                span: Span::empty(self.tok.span.start),
                name: Atom::from(""),
            }
        }
    }

    fn boxed<T>(&self, v: T) -> tf_allocator::AllocResult<Box<'a, T>> {
        Box::new_in(v, self.alloc)
    }

    fn vec<T>(&self) -> Vec<'a, T> {
        Vec::new_in(self.alloc)
    }

    fn error_expr(&self, span: Span) -> tf_allocator::AllocResult<Expression<'a>> {
        Ok(Expression::Error(self.boxed(ErrorExpr { span })?))
    }

    // ------------------------------------------------------------------
    // Recovery
    // ------------------------------------------------------------------

    /// Skip one token, treating strings and heredocs as single units.
    fn skip_token(&mut self) {
        match self.tok.kind {
            Kind::OQuote => {
                self.lexer.skip_quoted();
                let end = self.lexer.pos as u32;
                self.resync(end);
            }
            Kind::HeredocStart { .. } => {
                let delim = self.lexer.heredoc_delimiter(self.tok.span);
                self.lexer.skip_heredoc(delim);
                let end = self.lexer.pos as u32;
                self.resync(end);
            }
            _ => self.bump(),
        }
    }

    /// Body-level recovery: skip to the end of the line (or a `}` closing the
    /// enclosing block, or EOF), keeping bracket nesting balanced.
    fn recover_line(&mut self) {
        let mut depth = 0usize;
        loop {
            match self.tok.kind {
                Kind::Eof => return,
                Kind::Newline if depth == 0 => return,
                Kind::RBrace if depth == 0 => return,
                Kind::LBrace | Kind::LBracket | Kind::LParen => depth += 1,
                Kind::RBrace | Kind::RBracket | Kind::RParen => depth = depth.saturating_sub(1),
                _ => {}
            }
            self.skip_token();
        }
    }

    /// Recovery inside a newline-insensitive list (`[]`, `()` args): skip to
    /// a `,` or `closer` at depth 0. Gives up at EOF, at a `}` that would
    /// close an enclosing block, or when a new line starts with what looks
    /// like a body item (`ident =`, `ident {`, `ident "`), so a missing
    /// closer does not swallow the rest of the file.
    fn recover_list(&mut self, closer: Kind) -> Sync {
        let mut depth = 0usize;
        loop {
            if depth == 0 && self.newline_before_tok() && self.looks_like_body_item() {
                return Sync::Abort;
            }
            match self.tok.kind {
                Kind::Eof => return Sync::Abort,
                k if depth == 0 && k == closer => return Sync::Closer,
                Kind::Comma if depth == 0 => {
                    self.bump();
                    return Sync::Comma;
                }
                Kind::RBrace if depth == 0 => return Sync::Abort,
                Kind::LBrace | Kind::LBracket | Kind::LParen => depth += 1,
                Kind::RBrace | Kind::RBracket | Kind::RParen => depth = depth.saturating_sub(1),
                _ => {}
            }
            let was_nl = self.tok.kind == Kind::Newline;
            self.skip_token();
            if was_nl && depth == 0 && self.looks_like_body_item() {
                return Sync::Abort;
            }
        }
    }

    fn looks_like_body_item(&self) -> bool {
        self.tok.kind == Kind::Ident
            && matches!(self.peek2(), Kind::Eq | Kind::LBrace | Kind::OQuote)
    }

    /// Recovery inside an object: skip to the end of the item (newline or
    /// `,` at depth 0, consumed) or to the closing `}` (not consumed).
    fn recover_object_item(&mut self) {
        let mut depth = 0usize;
        loop {
            match self.tok.kind {
                Kind::Eof => return,
                Kind::Newline | Kind::Comma if depth == 0 => {
                    self.bump();
                    return;
                }
                Kind::RBrace if depth == 0 => return,
                Kind::LBrace | Kind::LBracket | Kind::LParen => depth += 1,
                Kind::RBrace | Kind::RBracket | Kind::RParen => depth = depth.saturating_sub(1),
                _ => {}
            }
            self.skip_token();
        }
    }
}

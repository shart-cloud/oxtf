use tf_allocator::{Allocator, Atom, Box, Vec};
use tf_ast::*;

use crate::lexer::{Kind, Lexer, LitStop, TemplateCtx, Token};
use crate::{Diagnostic, ParseResult};

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
}

impl<'a> Parser<'a> {
    pub fn new(alloc: &'a Allocator, src: &'a str) -> Self {
        assert!(src.len() < u32::MAX as usize, "source files must be < 4 GiB");
        let mut p = Parser {
            alloc,
            src,
            lexer: Lexer::new(src),
            tok: Token { kind: Kind::Eof, span: Span::EMPTY },
            prev_end: 0,
            modes: vec![false],
            comments: std::vec::Vec::new(),
            errors: std::vec::Vec::new(),
        };
        p.tok = p.lex_next();
        p
    }

    pub fn parse_file(mut self) -> ParseResult<'a> {
        let body = self.parse_body(true, 0);
        let file = File { span: Span::new(0, self.src.len() as u32), body };
        ParseResult { file, comments: self.comments, errors: self.errors }
    }

    // ------------------------------------------------------------------
    // Token plumbing
    // ------------------------------------------------------------------

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
        self.errors.push(Diagnostic { span, message: message.into() });
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
        let id = Identifier { span: self.tok.span, name: Atom::from(self.tok_text()) };
        self.bump();
        id
    }

    fn expect_ident(&mut self, what: &str) -> Identifier<'a> {
        if self.peek() == Kind::Ident {
            self.ident_from_tok()
        } else {
            self.error_at_tok(&format!("expected {what}"));
            Identifier { span: Span::empty(self.tok.span.start), name: Atom::from("") }
        }
    }

    fn boxed<T>(&self, v: T) -> Box<'a, T> {
        Box::new_in(v, self.alloc)
    }

    fn vec<T>(&self) -> Vec<'a, T> {
        Vec::new_in(self.alloc)
    }

    fn error_expr(&self, span: Span) -> Expression<'a> {
        Expression::Error(self.boxed(ErrorExpr { span }))
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
        self.tok.kind == Kind::Ident && matches!(self.peek2(), Kind::Eq | Kind::LBrace | Kind::OQuote)
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

    // ------------------------------------------------------------------
    // Structure
    // ------------------------------------------------------------------

    /// Parse body items until EOF (top level) or `}` (block; not consumed).
    fn parse_body(&mut self, top: bool, start: u32) -> Body<'a> {
        let mut items = self.vec();
        loop {
            match self.tok.kind {
                Kind::Newline => self.bump(),
                Kind::Eof => {
                    if !top {
                        // Point at the unclosed `{` (start - 1), not at EOF.
                        let open = Span::new(start.saturating_sub(1), start);
                        self.error(open, "unclosed block: expected `}` before end of file");
                    }
                    break;
                }
                Kind::RBrace => {
                    if top {
                        self.error(self.tok.span, "unexpected `}` at top level");
                        self.bump();
                    } else {
                        break;
                    }
                }
                Kind::Ident => {
                    if let Some(item) = self.parse_body_item() {
                        items.push(item);
                    }
                }
                _ => {
                    self.error_at_tok("expected an attribute or block");
                    self.recover_line();
                }
            }
        }
        let end = if top { self.src.len() as u32 } else { self.tok.span.start };
        Body { span: Span::new(start, end.max(start)), items }
    }

    fn parse_body_item(&mut self) -> Option<BodyItem<'a>> {
        let ident = self.ident_from_tok();
        let start = ident.span.start;
        match self.tok.kind {
            Kind::Eq => {
                self.bump();
                let value = self.parse_expr();
                let failed = matches!(value, Expression::Error(_));
                let attr = Attribute { span: self.span_from(start), key: ident, value };
                if failed {
                    // Already reported; skip the rest of the line quietly.
                    self.recover_line();
                } else {
                    self.expect_item_end("attribute");
                }
                Some(BodyItem::Attribute(self.boxed(attr)))
            }
            Kind::OQuote | Kind::Ident | Kind::LBrace => {
                let mut labels = self.vec();
                loop {
                    match self.tok.kind {
                        Kind::Ident => {
                            labels.push(BlockLabel {
                                span: self.tok.span,
                                value: Atom::from(self.tok_text()),
                                quoted: false,
                            });
                            self.bump();
                        }
                        Kind::OQuote => {
                            let e = self.parse_quoted();
                            let span = e.span();
                            let value = match &e {
                                Expression::String(s) => s.value,
                                _ => {
                                    self.error(span, "block labels cannot contain template sequences");
                                    Atom::from(&self.src[span.start as usize + 1..span.end.saturating_sub(1) as usize])
                                }
                            };
                            labels.push(BlockLabel { span, value, quoted: true });
                        }
                        _ => break,
                    }
                }
                if self.tok.kind != Kind::LBrace {
                    self.error_at_tok("expected `{` to open the block body");
                    self.recover_line();
                    return None;
                }
                let open = self.tok.span;
                self.bump();
                let body = self.parse_body(false, open.end);
                if self.tok.kind == Kind::RBrace {
                    self.bump();
                }
                let block = Block { span: self.span_from(start), ident, labels, body };
                self.expect_item_end("block");
                Some(BodyItem::Block(self.boxed(block)))
            }
            _ => {
                self.error_at_tok(&format!("expected `=` or a block after `{}`", ident.name));
                self.recover_line();
                None
            }
        }
    }

    /// After an attribute or block: newline, EOF, or the `}` of a one-line block.
    fn expect_item_end(&mut self, what: &str) {
        match self.tok.kind {
            Kind::Newline | Kind::Eof | Kind::RBrace => {}
            _ if self.newline_before_tok() => {}
            _ => {
                self.error_at_tok(&format!("expected a newline after the {what}"));
                self.recover_line();
            }
        }
    }

    // ------------------------------------------------------------------
    // Expressions
    // ------------------------------------------------------------------

    pub fn parse_expr(&mut self) -> Expression<'a> {
        let start = self.start();
        let condition = self.parse_binary(1);
        if self.peek() != Kind::Question {
            return condition;
        }
        self.bump();
        let true_expr = self.parse_expr();
        if self.peek() == Kind::Colon {
            self.bump();
        } else {
            self.error_at_tok("expected `:` in conditional expression");
            let span = self.span_from(start);
            let false_expr = self.error_expr(Span::empty(self.prev_end));
            return Expression::Conditional(self.boxed(Conditional { span, condition, true_expr, false_expr }));
        }
        let false_expr = self.parse_expr();
        let span = self.span_from(start);
        Expression::Conditional(self.boxed(Conditional { span, condition, true_expr, false_expr }))
    }

    fn binary_op(kind: Kind) -> Option<BinaryOperator> {
        use BinaryOperator::*;
        Some(match kind {
            Kind::OrOr => Or,
            Kind::AndAnd => And,
            Kind::EqEq => Equal,
            Kind::BangEq => NotEqual,
            Kind::Lt => Less,
            Kind::Le => LessEqual,
            Kind::Gt => Greater,
            Kind::Ge => GreaterEqual,
            Kind::Plus => Add,
            Kind::Minus => Subtract,
            Kind::Star => Multiply,
            Kind::Slash => Divide,
            Kind::Percent => Modulo,
            _ => return None,
        })
    }

    /// Pratt loop: all binary operators are left-associative.
    fn parse_binary(&mut self, min_prec: u8) -> Expression<'a> {
        let start = self.start();
        let mut left = self.parse_unary();
        while let Some(operator) = Self::binary_op(self.peek()) {
            let prec = operator.precedence();
            if prec < min_prec {
                break;
            }
            self.bump();
            let right = self.parse_binary(prec + 1);
            let span = self.span_from(start);
            left = Expression::Binary(self.boxed(BinaryExpr { span, operator, left, right }));
        }
        left
    }

    fn parse_unary(&mut self) -> Expression<'a> {
        let operator = match self.peek() {
            Kind::Bang => UnaryOperator::Not,
            Kind::Minus => UnaryOperator::Negate,
            _ => return self.parse_postfix(),
        };
        let start = self.tok.span.start;
        self.bump();
        let operand = self.parse_unary();
        let span = self.span_from(start);
        Expression::Unary(self.boxed(UnaryExpr { span, operator, operand }))
    }

    fn parse_postfix(&mut self) -> Expression<'a> {
        let start = self.start();
        let object = self.parse_term();
        if matches!(object, Expression::Error(_)) {
            return object;
        }
        let mut operators = self.vec();
        loop {
            match self.peek() {
                Kind::Dot => {
                    let op_start = self.tok.span.start;
                    self.bump();
                    match self.peek() {
                        Kind::Ident => {
                            let name = self.ident_from_tok();
                            let span = self.span_from(op_start);
                            operators.push(TraversalOperator::GetAttr(self.boxed(GetAttr { span, name })));
                        }
                        Kind::Star => {
                            self.bump();
                            let span = self.span_from(op_start);
                            operators.push(TraversalOperator::AttrSplat(self.boxed(AttrSplat { span })));
                        }
                        Kind::Number => {
                            // `.0` legacy index. The lexer may have read `0.1`
                            // as one number: take only the leading digits.
                            let num_start = self.tok.span.start as usize;
                            let n = self.lexer.digit_run_len(num_start);
                            let digits = &self.src[num_start..num_start + n];
                            let index = match digits.parse::<u64>() {
                                Ok(v) => v,
                                Err(_) => {
                                    self.error(self.tok.span, "invalid legacy index");
                                    0
                                }
                            };
                            self.resync((num_start + n) as u32);
                            let span = self.span_from(op_start);
                            operators.push(TraversalOperator::LegacyIndex(self.boxed(LegacyIndex { span, index })));
                        }
                        _ => {
                            self.error_at_tok("expected an attribute name, `*` or index after `.`");
                            break;
                        }
                    }
                }
                Kind::LBracket => {
                    let op_start = self.tok.span.start;
                    self.push_mode(true);
                    self.bump();
                    if self.peek() == Kind::Star && self.peek2_is_rbracket() {
                        self.bump();
                        self.close(Kind::RBracket, "]");
                        let span = self.span_from(op_start);
                        operators.push(TraversalOperator::FullSplat(self.boxed(FullSplat { span })));
                    } else {
                        let index = self.parse_expr();
                        self.close(Kind::RBracket, "]");
                        let span = self.span_from(op_start);
                        operators.push(TraversalOperator::Index(self.boxed(IndexOp { span, index })));
                    }
                }
                _ => break,
            }
        }
        if operators.is_empty() {
            object
        } else {
            let span = self.span_from(start);
            Expression::Traversal(self.boxed(Traversal { span, object, operators }))
        }
    }

    fn peek2_is_rbracket(&self) -> bool {
        let mut lx = self.lexer.clone();
        loop {
            let t = lx.next_token();
            match t.kind {
                Kind::Comment(_) | Kind::Newline => continue,
                k => return k == Kind::RBracket,
            }
        }
    }

    fn parse_term(&mut self) -> Expression<'a> {
        let start = self.start();
        match self.peek() {
            Kind::Number => {
                let raw = self.tok_text();
                let value = raw.parse::<f64>().unwrap_or_else(|_| {
                    self.error(self.tok.span, "invalid number literal");
                    0.0
                });
                let span = self.tok.span;
                self.bump();
                Expression::Number(self.boxed(NumberLiteral { span, value, raw: Atom::from(raw) }))
            }
            Kind::Ident => {
                let span = self.tok.span;
                match self.tok_text() {
                    "true" | "false" => {
                        let value = self.tok_text() == "true";
                        self.bump();
                        return Expression::Bool(self.boxed(BooleanLiteral { span, value }));
                    }
                    "null" => {
                        self.bump();
                        return Expression::Null(self.boxed(NullLiteral { span }));
                    }
                    _ => {}
                }
                let name = self.ident_from_tok();
                match self.tok.kind {
                    Kind::LParen => self.parse_call(start, self.vec(), name),
                    Kind::ColonColon => {
                        let mut namespace = self.vec();
                        let mut name = name;
                        while self.tok.kind == Kind::ColonColon {
                            self.bump();
                            namespace.push(name);
                            name = self.expect_ident("a function name after `::`");
                        }
                        if self.tok.kind == Kind::LParen {
                            self.parse_call(start, namespace, name)
                        } else {
                            self.error_at_tok("expected `(` after a namespaced function name");
                            self.error_expr(self.span_from(start))
                        }
                    }
                    _ => Expression::Variable(self.boxed(VariableExpr { span: name.span, name: name.name })),
                }
            }
            Kind::OQuote => self.parse_quoted(),
            Kind::HeredocStart { indented } => self.parse_heredoc(indented),
            Kind::LBracket => self.parse_bracket(),
            Kind::LBrace => self.parse_brace(),
            Kind::LParen => {
                self.push_mode(true);
                self.bump();
                let expression = self.parse_expr();
                self.close(Kind::RParen, ")");
                let span = self.span_from(start);
                Expression::Parenthesized(self.boxed(ParenthesizedExpr { span, expression }))
            }
            Kind::Invalid if self.tok_text().starts_with("/*") => {
                self.error(self.tok.span, "unterminated block comment");
                let span = self.tok.span;
                self.bump();
                self.error_expr(span)
            }
            _ => {
                self.error_at_tok("expected an expression");
                self.error_expr(Span::empty(self.tok.span.start))
            }
        }
    }

    fn parse_call(&mut self, start: u32, namespace: Vec<'a, Identifier<'a>>, name: Identifier<'a>) -> Expression<'a> {
        self.push_mode(true);
        self.bump(); // (
        let mut arguments = self.vec();
        let mut expand_final = false;
        let mut aborted = false;
        loop {
            if self.peek() == Kind::RParen {
                break;
            }
            arguments.push(self.parse_expr());
            if self.peek() == Kind::Ellipsis {
                self.bump();
                expand_final = true;
            }
            match self.peek() {
                Kind::Comma => {
                    self.bump();
                    if expand_final && self.peek() != Kind::RParen {
                        self.error_at_tok("`...` must follow the final argument");
                    }
                }
                Kind::RParen => break,
                _ => {
                    self.error_at_tok("expected `,` or `)` in function call");
                    match self.recover_list(Kind::RParen) {
                        Sync::Comma => {}
                        Sync::Closer => break,
                        Sync::Abort => {
                            aborted = true;
                            break;
                        }
                    }
                }
            }
        }
        if aborted {
            self.pop_mode();
        } else {
            self.close(Kind::RParen, ")");
        }
        let span = self.span_from(start);
        Expression::FunctionCall(self.boxed(FunctionCall { span, namespace, name, arguments, expand_final }))
    }

    /// `[` : tuple or `[for ...]`.
    fn parse_bracket(&mut self) -> Expression<'a> {
        let start = self.tok.span.start;
        self.push_mode(true);
        self.bump();
        if self.at_for_intro() {
            return self.parse_for(start, Kind::RBracket);
        }
        let mut elements = self.vec();
        let mut aborted = false;
        loop {
            if self.peek() == Kind::RBracket {
                break;
            }
            if self.peek() == Kind::Eof {
                break;
            }
            let e = self.parse_expr();
            let failed = matches!(e, Expression::Error(_));
            elements.push(e);
            match self.peek() {
                Kind::Comma => self.bump(),
                Kind::RBracket => break,
                _ => {
                    if !failed {
                        self.error_at_tok("expected `,` or `]` in tuple");
                    }
                    match self.recover_list(Kind::RBracket) {
                        Sync::Comma => {}
                        Sync::Closer => break,
                        Sync::Abort => {
                            aborted = true;
                            break;
                        }
                    }
                }
            }
        }
        if aborted {
            self.pop_mode();
        } else {
            self.close(Kind::RBracket, "]");
        }
        let span = self.span_from(start);
        Expression::Tuple(self.boxed(Tuple { span, elements }))
    }

    /// At `for <ident>` (newlines skipped)?
    fn at_for_intro(&mut self) -> bool {
        self.at_ident("for") && self.peek2() == Kind::Ident
    }

    /// `{` : object or `{for ...}`.
    fn parse_brace(&mut self) -> Expression<'a> {
        let start = self.tok.span.start;
        // Look past newlines for `for` without committing to a mode yet.
        self.push_mode(true);
        self.bump();
        if self.at_for_intro() {
            return self.parse_for(start, Kind::RBrace);
        }
        self.pop_mode();
        self.push_mode(false);
        let mut items = self.vec();
        loop {
            match self.tok.kind {
                Kind::Newline => {
                    self.bump();
                    continue;
                }
                Kind::RBrace => break,
                Kind::Eof => break,
                _ => {}
            }
            let item_start = self.tok.span.start;
            let key = self.parse_object_key();
            if !matches!(self.tok.kind, Kind::Eq | Kind::Colon) {
                self.error_at_tok("expected `=` or `:` after object key");
                self.recover_object_item();
                continue;
            }
            self.bump();
            let value = self.parse_expr();
            let span = self.span_from(item_start);
            items.push(ObjectItem { span, key, value });
            match self.tok.kind {
                Kind::Comma | Kind::Newline => self.bump(),
                Kind::RBrace => break,
                _ => {
                    self.error_at_tok("expected a newline, `,` or `}` after object item");
                    self.recover_object_item();
                }
            }
        }
        if self.tok.kind == Kind::RBrace {
            self.pop_mode();
            self.bump();
        } else {
            self.error_at_tok("expected `}` to close the object");
            self.pop_mode();
        }
        let span = self.span_from(start);
        Expression::Object(self.boxed(Object { span, items }))
    }

    fn parse_object_key(&mut self) -> ObjectKey<'a> {
        if self.tok.kind == Kind::Ident && matches!(self.peek2(), Kind::Eq | Kind::Colon) {
            let id = self.ident_from_tok();
            return ObjectKey::Identifier(self.boxed(id));
        }
        match self.parse_expr() {
            // A bare identifier key is a literal, as in HCL and hcl-edit.
            Expression::Variable(v) => {
                ObjectKey::Identifier(self.boxed(Identifier { span: v.span, name: v.name }))
            }
            e => ObjectKey::Expression(e),
        }
    }

    /// After `[` / `{` with an ignore-newlines mode pushed, at `for`.
    fn parse_for(&mut self, start: u32, closer: Kind) -> Expression<'a> {
        self.bump(); // for
        let first = self.expect_ident("an iterator name after `for`");
        let (key_var, value_var) = if self.peek() == Kind::Comma {
            self.bump();
            (Some(first), self.expect_ident("a value iterator name"))
        } else {
            (None, first)
        };
        if self.at_ident("in") {
            self.bump();
        } else {
            self.error_at_tok("expected `in` in for expression");
        }
        let collection = self.parse_expr();
        if self.peek() == Kind::Colon {
            self.bump();
        } else {
            self.error_at_tok("expected `:` in for expression");
        }
        let mut key_expr = None;
        let mut grouping = false;
        let value_expr;
        if closer == Kind::RBrace {
            key_expr = Some(self.parse_expr());
            if self.peek() == Kind::FatArrow {
                self.bump();
            } else {
                self.error_at_tok("expected `=>` in object for expression");
            }
            value_expr = self.parse_expr();
            if self.peek() == Kind::Ellipsis {
                self.bump();
                grouping = true;
            }
        } else {
            value_expr = self.parse_expr();
        }
        let condition = if self.at_ident("if") {
            self.bump();
            Some(self.parse_expr())
        } else {
            None
        };
        if self.peek() != closer {
            self.error_at_tok(if closer == Kind::RBrace { "expected `}`" } else { "expected `]`" });
            // Skip to the closer.
            let _ = self.recover_list(closer);
        }
        if self.peek() == closer {
            self.pop_mode();
            self.bump();
        } else {
            self.pop_mode();
        }
        let span = self.span_from(start);
        Expression::For(self.boxed(ForExpr { span, key_var, value_var, collection, key_expr, value_expr, grouping, condition }))
    }

    // ------------------------------------------------------------------
    // Templates
    // ------------------------------------------------------------------

    /// At `"`. Returns `String` if there are no template sequences.
    fn parse_quoted(&mut self) -> Expression<'a> {
        let open = self.tok.span;
        debug_assert_eq!(self.lexer.pos as u32, open.end);
        let (template, end) = self.parse_template_top(TemplateCtx::Quoted, false, open.end);
        let close_end = match end {
            TplEnd::Close(_, e) => e,
            TplEnd::Unterminated(at) => {
                self.error(Span::new(open.start, at), "unterminated string");
                at
            }
            _ => unreachable!(),
        };
        self.resync(close_end);
        let span = Span::new(open.start, close_end);
        let only_literals = template.elements.iter().all(|e| matches!(e, TemplateElement::Literal(_)));
        if only_literals && template.elements.len() <= 1 {
            let value = match template.elements.first() {
                Some(TemplateElement::Literal(l)) => l.value,
                _ => Atom::from(""),
            };
            Expression::String(self.boxed(StringLiteral { span, value }))
        } else {
            Expression::Template(self.boxed(TemplateExpr { span, template }))
        }
    }

    /// At `<<EOT\n`.
    fn parse_heredoc(&mut self, indented: bool) -> Expression<'a> {
        let open = self.tok.span;
        let delimiter = self.lexer.heredoc_delimiter(open);
        let (mut template, end) = self.parse_template_top(TemplateCtx::Heredoc { delimiter }, true, open.end);
        let close_end = match end {
            TplEnd::Close(_, e) => e,
            TplEnd::Unterminated(at) => {
                self.error(Span::new(open.start, open.end), format!("unterminated heredoc, expected `{delimiter}`"));
                at
            }
            _ => unreachable!(),
        };
        if indented {
            self.dedent(&mut template);
            prune_empty_literals(&mut template);
        }
        self.resync(close_end);
        let span = Span::new(open.start, close_end);
        Expression::Heredoc(self.boxed(HeredocExpr { span, delimiter: Atom::from(delimiter), indented, template }))
    }

    /// Top-level template: stray `else`/`endif`/`endfor` are errors and
    /// parsing continues.
    fn parse_template_top(&mut self, ctx: TemplateCtx<'_>, mut at_line_start: bool, start: u32) -> (Template<'a>, TplEnd) {
        let mut elements = self.vec();
        loop {
            let end = self.parse_template_elements(ctx, at_line_start, &mut elements);
            match end {
                TplEnd::Close(s, _) | TplEnd::Unterminated(s) => {
                    let span = Span::new(start, s);
                    return (Template { span, elements }, end);
                }
                TplEnd::Else(s, e, _) | TplEnd::Endif(s, e, _) | TplEnd::Endfor(s, e, _) => {
                    self.error(Span::new(s, e), "template directive without a matching `if` or `for`");
                    at_line_start = false;
                }
            }
        }
    }

    fn push_literal(&mut self, elements: &mut Vec<'a, TemplateElement<'a>>, lit: crate::lexer::Literal) {
        if let Some(span) = lit.bad_escape {
            self.error(span, "invalid escape sequence");
        }
        let value = match &lit.decoded {
            Some(d) => {
                if d.is_empty() {
                    return;
                }
                Atom::from_in(d, self.alloc)
            }
            None => {
                if lit.span.is_empty() {
                    return;
                }
                Atom::from(lit.span.source_text(self.src))
            }
        };
        elements.push(TemplateElement::Literal(self.boxed(TemplateLiteral { span: lit.span, value })));
    }

    /// Parse literal text and template sequences into `elements` until the
    /// template closes or a directive keyword that belongs to an enclosing
    /// `if`/`for` (`else`, `endif`, `endfor`) is reached.
    fn parse_template_elements(
        &mut self,
        ctx: TemplateCtx<'_>,
        mut at_line_start: bool,
        elements: &mut Vec<'a, TemplateElement<'a>>,
    ) -> TplEnd {
        loop {
            let lit = self.lexer.scan_template_literal(ctx, at_line_start);
            at_line_start = false;
            let stop = lit.stop;
            let stop_span = lit.stop_span;
            self.push_literal(elements, lit);
            match stop {
                LitStop::Quote | LitStop::HeredocEnd => return TplEnd::Close(stop_span.start, stop_span.end),
                LitStop::Newline | LitStop::Eof => return TplEnd::Unterminated(stop_span.start),
                LitStop::Interp => {
                    let seq_start = stop_span.start;
                    self.resync(stop_span.end);
                    self.push_mode(true);
                    let strip_start = self.eat_tilde();
                    let expression = self.parse_expr();
                    let strip_end = self.eat_tilde();
                    let end = self.close_template_seq();
                    let span = Span::new(seq_start, end);
                    let strip = Strip { start: strip_start, end: strip_end };
                    elements.push(TemplateElement::Interpolation(self.boxed(TemplateInterpolation { span, strip, expression })));
                }
                LitStop::Directive => {
                    let seq_start = stop_span.start;
                    self.resync(stop_span.end);
                    self.push_mode(true);
                    let strip_start = self.eat_tilde();
                    if self.peek() != Kind::Ident {
                        self.error_at_tok("expected a template directive keyword (`if`, `for`, `else`, `endif`, `endfor`)");
                        self.close_template_seq();
                        continue;
                    }
                    let kw = self.tok_text();
                    match kw {
                        "if" => {
                            self.bump();
                            let condition = self.parse_expr();
                            let strip_end = self.eat_tilde();
                            let then_start = self.close_template_seq();
                            let if_strip = Strip { start: strip_start, end: strip_end };
                            let mut then_elems = self.vec();
                            let mut end = self.parse_template_elements(ctx, false, &mut then_elems);
                            let then_template = Template { span: Span::new(then_start, tpl_end_start(end)), elements: then_elems };
                            let mut else_strip = None;
                            let mut else_template = None;
                            if let TplEnd::Else(_, else_end, strip) = end {
                                else_strip = Some(strip);
                                let mut else_elems = self.vec();
                                end = self.parse_template_elements(ctx, false, &mut else_elems);
                                else_template = Some(Template { span: Span::new(else_end, tpl_end_start(end)), elements: else_elems });
                            }
                            let (endif_strip, node_end, propagate) = match end {
                                TplEnd::Endif(_, e, s) => (s, e, None),
                                other => {
                                    self.error(Span::new(seq_start, then_start), "`%{ if }` without a matching `%{ endif }`");
                                    (Strip::default(), tpl_end_start(other), Some(other))
                                }
                            };
                            let span = Span::new(seq_start, node_end);
                            elements.push(TemplateElement::If(self.boxed(TemplateIf {
                                span,
                                condition,
                                if_strip,
                                then_template,
                                else_strip,
                                else_template,
                                endif_strip,
                            })));
                            if let Some(e) = propagate {
                                return e;
                            }
                        }
                        "for" => {
                            self.bump();
                            let first = self.expect_ident("an iterator name");
                            let (key_var, value_var) = if self.peek() == Kind::Comma {
                                self.bump();
                                (Some(first), self.expect_ident("a value iterator name"))
                            } else {
                                (None, first)
                            };
                            if self.at_ident("in") {
                                self.bump();
                            } else {
                                self.error_at_tok("expected `in` in template for directive");
                            }
                            let collection = self.parse_expr();
                            let strip_end = self.eat_tilde();
                            let body_start = self.close_template_seq();
                            let for_strip = Strip { start: strip_start, end: strip_end };
                            let mut body = self.vec();
                            let end = self.parse_template_elements(ctx, false, &mut body);
                            let template = Template { span: Span::new(body_start, tpl_end_start(end)), elements: body };
                            let (endfor_strip, node_end, propagate) = match end {
                                TplEnd::Endfor(_, e, s) => (s, e, None),
                                other => {
                                    self.error(Span::new(seq_start, body_start), "`%{ for }` without a matching `%{ endfor }`");
                                    (Strip::default(), tpl_end_start(other), Some(other))
                                }
                            };
                            let span = Span::new(seq_start, node_end);
                            elements.push(TemplateElement::For(self.boxed(TemplateFor {
                                span,
                                key_var,
                                value_var,
                                collection,
                                for_strip,
                                template,
                                endfor_strip,
                            })));
                            if let Some(e) = propagate {
                                return e;
                            }
                        }
                        "else" | "endif" | "endfor" => {
                            self.bump();
                            let strip_end = self.eat_tilde();
                            let end = self.close_template_seq();
                            let strip = Strip { start: strip_start, end: strip_end };
                            return match kw {
                                "else" => TplEnd::Else(seq_start, end, strip),
                                "endif" => TplEnd::Endif(seq_start, end, strip),
                                _ => TplEnd::Endfor(seq_start, end, strip),
                            };
                        }
                        _ => {
                            self.error_at_tok("unknown template directive");
                            self.close_template_seq();
                        }
                    }
                }
            }
        }
    }

    fn eat_tilde(&mut self) -> bool {
        if self.peek() == Kind::Tilde {
            self.bump();
            true
        } else {
            false
        }
    }

    /// Expect the `}` closing `${...}` / `%{...}` (mode was pushed at the
    /// opener), pop the mode and leave the lexer right after the `}` for
    /// literal scanning. Returns the end offset. On error, resumes literal
    /// scanning at the offending token.
    fn close_template_seq(&mut self) -> u32 {
        let end = if self.peek() == Kind::RBrace {
            self.tok.span.end
        } else {
            self.error_at_tok("expected `}` to close the template sequence");
            self.tok.span.start
        };
        self.pop_mode();
        self.prev_end = end;
        self.lexer.pos = end as usize;
        end
    }

    /// `<<-` heredoc: remove the common leading whitespace, with the same
    /// rules as HCL's Go implementation (`flushHeredocTemplateParts`):
    /// conceptually split the literal text into lines; a line that is all
    /// whitespace is ignored for counting and left untouched; a template
    /// sequence at the start of a line means nothing is stripped; literals
    /// inside directives count too.
    fn dedent(&mut self, template: &mut Template<'a>) {
        enum Piece<'t, 'a> {
            Lit(&'t mut TemplateLiteral<'a>),
            Seq,
        }
        fn flatten<'t, 'a>(t: &'t mut Template<'a>, out: &mut std::vec::Vec<Piece<'t, 'a>>) {
            for el in t.elements.iter_mut() {
                match el {
                    TemplateElement::Literal(l) => out.push(Piece::Lit(l)),
                    TemplateElement::Interpolation(_) => out.push(Piece::Seq),
                    TemplateElement::If(i) => {
                        let i = &mut **i;
                        out.push(Piece::Seq);
                        flatten(&mut i.then_template, out);
                        if let Some(e) = &mut i.else_template {
                            out.push(Piece::Seq);
                            flatten(e, out);
                        }
                        out.push(Piece::Seq);
                    }
                    TemplateElement::For(f) => {
                        let f = &mut **f;
                        out.push(Piece::Seq);
                        flatten(&mut f.template, out);
                        out.push(Piece::Seq);
                    }
                }
            }
        }
        let mut pieces = std::vec::Vec::new();
        flatten(template, &mut pieces);

        // Pass 1: minimum indentation (in chars) over line-start pieces.
        let mut min = usize::MAX;
        let mut newline = true;
        for p in &pieces {
            match p {
                Piece::Lit(l) => {
                    for line in l.value.split_inclusive('\n') {
                        if newline {
                            let trimmed = line.trim_start();
                            if !(trimmed.is_empty() && line.ends_with('\n')) {
                                let spaces = line.chars().take_while(|c| c.is_whitespace()).count();
                                min = min.min(spaces);
                            }
                        }
                        newline = line.ends_with('\n');
                    }
                }
                Piece::Seq => {
                    if newline {
                        min = 0;
                    }
                    newline = false;
                }
            }
        }
        if min == 0 || min == usize::MAX {
            return;
        }
        // Pass 2: strip.
        let mut newline = true;
        for p in pieces {
            match p {
                Piece::Lit(l) => {
                    let mut out = String::with_capacity(l.value.len());
                    let mut changed = false;
                    for line in l.value.split_inclusive('\n') {
                        let blank = line.trim_start().is_empty() && line.ends_with('\n');
                        if newline && !blank {
                            let cut: usize = line.chars().take(min).map(char::len_utf8).sum();
                            out.push_str(&line[cut..]);
                            changed |= cut > 0;
                        } else {
                            out.push_str(line);
                        }
                        newline = line.ends_with('\n');
                    }
                    if changed {
                        l.value = Atom::from_in(&out, self.alloc);
                    }
                }
                Piece::Seq => newline = false,
            }
        }
    }
}

/// Remove literals that dedenting emptied.
fn prune_empty_literals(t: &mut Template<'_>) {
    t.elements.retain(|e| !matches!(e, TemplateElement::Literal(l) if l.value.is_empty()));
    for el in t.elements.iter_mut() {
        match el {
            TemplateElement::If(i) => {
                prune_empty_literals(&mut i.then_template);
                if let Some(e) = &mut i.else_template {
                    prune_empty_literals(e);
                }
            }
            TemplateElement::For(f) => prune_empty_literals(&mut f.template),
            _ => {}
        }
    }
}

fn tpl_end_start(end: TplEnd) -> u32 {
    match end {
        TplEnd::Close(s, _) | TplEnd::Unterminated(s) | TplEnd::Else(s, _, _) | TplEnd::Endif(s, _, _) | TplEnd::Endfor(s, _, _) => s,
    }
}

use tf_span::Span;

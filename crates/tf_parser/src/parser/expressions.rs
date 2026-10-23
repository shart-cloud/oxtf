use super::*;

impl<'a> Parser<'a> {
    // ------------------------------------------------------------------
    // Expressions
    // ------------------------------------------------------------------

    pub fn parse_expr(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
        if !self.enter_depth() {
            return self.error_expr(self.tok.span);
        }
        let result = self.parse_expr_inner()?;
        self.leave_depth();
        Ok(result)
    }

    pub(super) fn parse_expr_inner(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
        let start = self.start();
        let condition = self.parse_binary(1)?;
        if self.peek() != Kind::Question {
            return Ok(condition);
        }
        self.bump();
        let true_expr = self.parse_expr()?;
        if self.peek() == Kind::Colon {
            self.bump();
        } else {
            self.error_at_tok("expected `:` in conditional expression");
            let span = self.span_from(start);
            let false_expr = self.error_expr(Span::empty(self.prev_end))?;
            return Ok(Expression::Conditional(self.boxed(Conditional {
                span,
                condition,
                true_expr,
                false_expr,
            })?));
        }
        let false_expr = self.parse_expr()?;
        let span = self.span_from(start);
        Ok(Expression::Conditional(self.boxed(Conditional {
            span,
            condition,
            true_expr,
            false_expr,
        })?))
    }

    pub(super) fn binary_op(kind: Kind) -> Option<BinaryOperator> {
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
    pub(super) fn parse_binary(
        &mut self,
        min_prec: u8,
    ) -> tf_allocator::AllocResult<Expression<'a>> {
        let start = self.start();
        let mut left = self.parse_unary()?;
        while let Some(operator) = Self::binary_op(self.peek()) {
            let prec = operator.precedence();
            if prec < min_prec {
                break;
            }
            self.bump();
            let right = self.parse_binary(prec + 1)?;
            let span = self.span_from(start);
            left = Expression::Binary(self.boxed(BinaryExpr {
                span,
                operator,
                left,
                right,
            })?);
        }
        Ok(left)
    }

    pub(super) fn parse_unary(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
        if !self.enter_depth() {
            return self.error_expr(self.tok.span);
        }
        let result = self.parse_unary_inner()?;
        self.leave_depth();
        Ok(result)
    }

    pub(super) fn parse_unary_inner(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
        let operator = match self.peek() {
            Kind::Bang => UnaryOperator::Not,
            Kind::Minus => UnaryOperator::Negate,
            _ => return self.parse_postfix(),
        };
        let start = self.tok.span.start;
        self.bump();
        let operand = self.parse_unary()?;
        let span = self.span_from(start);
        Ok(Expression::Unary(self.boxed(UnaryExpr {
            span,
            operator,
            operand,
        })?))
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn parse_postfix(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
        let start = self.start();
        let object = self.parse_term()?;
        if matches!(object, Expression::Error(_)) {
            return Ok(object);
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
                            operators.push(TraversalOperator::GetAttr(
                                self.boxed(GetAttr { span, name })?,
                            ))?;
                        }
                        Kind::Star => {
                            self.bump();
                            let span = self.span_from(op_start);
                            operators.push(TraversalOperator::AttrSplat(
                                self.boxed(AttrSplat { span })?,
                            ))?;
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
                            operators.push(TraversalOperator::LegacyIndex(
                                self.boxed(LegacyIndex { span, index })?,
                            ))?;
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
                        operators.push(TraversalOperator::FullSplat(
                            self.boxed(FullSplat { span })?,
                        ))?;
                    } else {
                        let index = self.parse_expr()?;
                        self.close(Kind::RBracket, "]");
                        let span = self.span_from(op_start);
                        operators.push(TraversalOperator::Index(
                            self.boxed(IndexOp { span, index })?,
                        ))?;
                    }
                }
                _ => break,
            }
        }
        Ok(if operators.is_empty() {
            object
        } else {
            let span = self.span_from(start);
            Expression::Traversal(self.boxed(Traversal {
                span,
                object,
                operators,
            })?)
        })
    }

    pub(super) fn peek2_is_rbracket(&self) -> bool {
        let mut lx = self.lexer.clone();
        loop {
            let t = lx.next_token();
            match t.kind {
                Kind::Comment(_) | Kind::Newline => continue,
                k => return k == Kind::RBracket,
            }
        }
    }

    pub(super) fn parse_term(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
        let start = self.start();
        Ok(match self.peek() {
            Kind::Number => {
                let raw = self.tok_text();
                let value = raw.parse::<f64>().unwrap_or_else(|_| {
                    self.error(self.tok.span, "invalid number literal");
                    0.0
                });
                let span = self.tok.span;
                self.bump();
                Expression::Number(self.boxed(NumberLiteral {
                    span,
                    value,
                    raw: Atom::from(raw),
                })?)
            }
            Kind::Ident => {
                let span = self.tok.span;
                match self.tok_text() {
                    "true" | "false" => {
                        let value = self.tok_text() == "true";
                        self.bump();
                        return Ok(Expression::Bool(
                            self.boxed(BooleanLiteral { span, value })?,
                        ));
                    }
                    "null" => {
                        self.bump();
                        return Ok(Expression::Null(self.boxed(NullLiteral { span })?));
                    }
                    _ => {}
                }
                let name = self.ident_from_tok();
                match self.tok.kind {
                    Kind::LParen => self.parse_call(start, self.vec(), name)?,
                    Kind::ColonColon => {
                        let mut namespace = self.vec();
                        let mut name = name;
                        while self.tok.kind == Kind::ColonColon {
                            self.bump();
                            namespace.push(name)?;
                            name = self.expect_ident("a function name after `::`");
                        }
                        if self.tok.kind == Kind::LParen {
                            self.parse_call(start, namespace, name)?
                        } else {
                            self.error_at_tok("expected `(` after a namespaced function name");
                            self.error_expr(self.span_from(start))?
                        }
                    }
                    _ => Expression::Variable(self.boxed(VariableExpr {
                        span: name.span,
                        name: name.name,
                    })?),
                }
            }
            Kind::OQuote => self.parse_quoted()?,
            Kind::HeredocStart { indented } => self.parse_heredoc(indented)?,
            Kind::LBracket => self.parse_bracket()?,
            Kind::LBrace => self.parse_brace()?,
            Kind::LParen => {
                self.push_mode(true);
                self.bump();
                let expression = self.parse_expr()?;
                self.close(Kind::RParen, ")");
                let span = self.span_from(start);
                Expression::Parenthesized(self.boxed(ParenthesizedExpr { span, expression })?)
            }
            Kind::Invalid if self.tok_text().starts_with("/*") => {
                self.error(self.tok.span, "unterminated block comment");
                let span = self.tok.span;
                self.bump();
                self.error_expr(span)?
            }
            _ => {
                self.error_at_tok("expected an expression");
                self.error_expr(Span::empty(self.tok.span.start))?
            }
        })
    }

    pub(super) fn parse_call(
        &mut self,
        start: u32,
        namespace: Vec<'a, Identifier<'a>>,
        name: Identifier<'a>,
    ) -> tf_allocator::AllocResult<Expression<'a>> {
        self.push_mode(true);
        self.bump(); // (
        let mut arguments = self.vec();
        let mut expand_final = false;
        let mut aborted = false;
        loop {
            if self.peek() == Kind::RParen {
                break;
            }
            arguments.push(self.parse_expr()?)?;
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
        Ok(Expression::FunctionCall(self.boxed(FunctionCall {
            span,
            namespace,
            name,
            arguments,
            expand_final,
        })?))
    }

    /// `[` : tuple or `[for ...]`.
    pub(super) fn parse_bracket(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
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
            let e = self.parse_expr()?;
            let failed = matches!(e, Expression::Error(_));
            elements.push(e)?;
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
        Ok(Expression::Tuple(self.boxed(Tuple { span, elements })?))
    }

    /// At `for <ident>` (newlines skipped)?
    pub(super) fn at_for_intro(&mut self) -> bool {
        self.at_ident("for") && self.peek2() == Kind::Ident
    }

    /// `{` : object or `{for ...}`.
    pub(super) fn parse_brace(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
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
            let key = self.parse_object_key()?;
            if !matches!(self.tok.kind, Kind::Eq | Kind::Colon) {
                self.error_at_tok("expected `=` or `:` after object key");
                self.recover_object_item();
                continue;
            }
            self.bump();
            let value = self.parse_expr()?;
            let span = self.span_from(item_start);
            items.push(ObjectItem { span, key, value })?;
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
        Ok(Expression::Object(self.boxed(Object { span, items })?))
    }

    pub(super) fn parse_object_key(&mut self) -> tf_allocator::AllocResult<ObjectKey<'a>> {
        if self.tok.kind == Kind::Ident && matches!(self.peek2(), Kind::Eq | Kind::Colon) {
            let id = self.ident_from_tok();
            return Ok(ObjectKey::Identifier(self.boxed(id)?));
        }
        Ok(match self.parse_expr()? {
            // A bare identifier key is a literal, as in HCL and hcl-edit.
            Expression::Variable(v) => ObjectKey::Identifier(self.boxed(Identifier {
                span: v.span,
                name: v.name,
            })?),
            e => ObjectKey::Expression(e),
        })
    }

    /// After `[` / `{` with an ignore-newlines mode pushed, at `for`.
    pub(super) fn parse_for(
        &mut self,
        start: u32,
        closer: Kind,
    ) -> tf_allocator::AllocResult<Expression<'a>> {
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
        let collection = self.parse_expr()?;
        if self.peek() == Kind::Colon {
            self.bump();
        } else {
            self.error_at_tok("expected `:` in for expression");
        }
        let mut key_expr = None;
        let mut grouping = false;
        let value_expr;
        if closer == Kind::RBrace {
            key_expr = Some(self.parse_expr()?);
            if self.peek() == Kind::FatArrow {
                self.bump();
            } else {
                self.error_at_tok("expected `=>` in object for expression");
            }
            value_expr = self.parse_expr()?;
            if self.peek() == Kind::Ellipsis {
                self.bump();
                grouping = true;
            }
        } else {
            value_expr = self.parse_expr()?;
        }
        let condition = if self.at_ident("if") {
            self.bump();
            Some(self.parse_expr()?)
        } else {
            None
        };
        if self.peek() != closer {
            self.error_at_tok(if closer == Kind::RBrace {
                "expected `}`"
            } else {
                "expected `]`"
            });
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
        Ok(Expression::For(self.boxed(ForExpr {
            span,
            key_var,
            value_var,
            collection,
            key_expr,
            value_expr,
            grouping,
            condition,
        })?))
    }
}

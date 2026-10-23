use super::*;

impl<'a> Parser<'a> {
    // ------------------------------------------------------------------
    // Structure
    // ------------------------------------------------------------------

    /// Parse body items until EOF (top level) or `}` (block; not consumed).
    pub(super) fn parse_body(
        &mut self,
        top: bool,
        start: u32,
    ) -> tf_allocator::AllocResult<Body<'a>> {
        if !self.enter_depth() {
            return Ok(Body {
                span: Span::empty(start),
                items: self.vec(),
            });
        }
        let result = self.parse_body_inner(top, start)?;
        self.leave_depth();
        Ok(result)
    }

    pub(super) fn parse_body_inner(
        &mut self,
        top: bool,
        start: u32,
    ) -> tf_allocator::AllocResult<Body<'a>> {
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
                    if let Some(item) = self.parse_body_item()? {
                        items.push(item)?;
                    }
                }
                _ => {
                    self.error_at_tok("expected an attribute or block");
                    self.recover_line();
                }
            }
        }
        let end = if top {
            self.src.len() as u32
        } else {
            self.tok.span.start
        };
        Ok(Body {
            span: Span::new(start, end.max(start)),
            items,
        })
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn parse_body_item(&mut self) -> tf_allocator::AllocResult<Option<BodyItem<'a>>> {
        let ident = self.ident_from_tok();
        let start = ident.span.start;
        Ok(match self.tok.kind {
            Kind::Eq => {
                self.bump();
                let value = self.parse_expr()?;
                let failed = matches!(value, Expression::Error(_));
                let attr = Attribute {
                    span: self.span_from(start),
                    key: ident,
                    value,
                };
                if failed {
                    // Already reported; skip the rest of the line quietly.
                    self.recover_line();
                } else {
                    self.expect_item_end("attribute");
                }
                Some(BodyItem::Attribute(self.boxed(attr)?))
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
                            })?;
                            self.bump();
                        }
                        Kind::OQuote => {
                            let e = self.parse_quoted()?;
                            let span = e.span();
                            let value = match &e {
                                Expression::String(s) => s.value,
                                _ => {
                                    self.error(
                                        span,
                                        "block labels cannot contain template sequences",
                                    );
                                    // Strip the quotes without slicing inside a
                                    // UTF-8 character (the label may be unterminated).
                                    let text = span.source_text(self.src);
                                    let text = text.strip_prefix('"').unwrap_or(text);
                                    Atom::from(text.strip_suffix('"').unwrap_or(text))
                                }
                            };
                            labels.push(BlockLabel {
                                span,
                                value,
                                quoted: true,
                            })?;
                        }
                        _ => break,
                    }
                }
                if self.tok.kind != Kind::LBrace {
                    self.error_at_tok("expected `{` to open the block body");
                    self.recover_line();
                    return Ok(None);
                }
                let open = self.tok.span;
                self.bump();
                let body = self.parse_body(false, open.end)?;
                if self.tok.kind == Kind::RBrace {
                    self.bump();
                }
                let block = Block {
                    span: self.span_from(start),
                    ident,
                    labels,
                    body,
                };
                self.expect_item_end("block");
                Some(BodyItem::Block(self.boxed(block)?))
            }
            _ => {
                self.error_at_tok(&format!("expected `=` or a block after `{}`", ident.name));
                self.recover_line();
                None
            }
        })
    }

    /// After an attribute or block: newline, EOF, or the `}` of a one-line block.
    pub(super) fn expect_item_end(&mut self, what: &str) {
        match self.tok.kind {
            Kind::Newline | Kind::Eof | Kind::RBrace => {}
            _ if self.newline_before_tok() => {}
            _ => {
                self.error_at_tok(&format!("expected a newline after the {what}"));
                self.recover_line();
            }
        }
    }
}

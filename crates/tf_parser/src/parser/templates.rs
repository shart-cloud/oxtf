use super::*;

impl<'a> Parser<'a> {
    // ------------------------------------------------------------------
    // Templates
    // ------------------------------------------------------------------

    /// At `"`. Returns `String` if there are no template sequences.
    pub(super) fn parse_quoted(&mut self) -> tf_allocator::AllocResult<Expression<'a>> {
        let open = self.tok.span;
        debug_assert_eq!(self.lexer.pos as u32, open.end);
        let (template, end) = self.parse_template_top(TemplateCtx::Quoted, false, open.end)?;
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
        let only_literals = template
            .elements
            .iter()
            .all(|e| matches!(e, TemplateElement::Literal(_)));
        Ok(if only_literals && template.elements.len() <= 1 {
            let value = match template.elements.first() {
                Some(TemplateElement::Literal(l)) => l.value,
                _ => Atom::from(""),
            };
            Expression::String(self.boxed(StringLiteral { span, value })?)
        } else {
            Expression::Template(self.boxed(TemplateExpr { span, template })?)
        })
    }

    /// At `<<EOT\n`.
    pub(super) fn parse_heredoc(
        &mut self,
        indented: bool,
    ) -> tf_allocator::AllocResult<Expression<'a>> {
        let open = self.tok.span;
        let delimiter = self.lexer.heredoc_delimiter(open);
        let (mut template, end) =
            self.parse_template_top(TemplateCtx::Heredoc { delimiter }, true, open.end)?;
        let close_end = match end {
            TplEnd::Close(_, e) => e,
            TplEnd::Unterminated(at) => {
                self.error(
                    Span::new(open.start, open.end),
                    format!("unterminated heredoc, expected `{delimiter}`"),
                );
                at
            }
            _ => unreachable!(),
        };
        if indented {
            self.dedent(&mut template)?;
            prune_empty_literals(&mut template);
        }
        self.resync(close_end);
        let span = Span::new(open.start, close_end);
        Ok(Expression::Heredoc(self.boxed(HeredocExpr {
            span,
            delimiter: Atom::from(delimiter),
            indented,
            template,
        })?))
    }

    /// Top-level template: stray `else`/`endif`/`endfor` are errors and
    /// parsing continues.
    pub(super) fn parse_template_top(
        &mut self,
        ctx: TemplateCtx<'_>,
        mut at_line_start: bool,
        start: u32,
    ) -> tf_allocator::AllocResult<(Template<'a>, TplEnd)> {
        let mut elements = self.vec();
        loop {
            let end = self.parse_template_elements(ctx, at_line_start, &mut elements)?;
            match end {
                TplEnd::Close(s, _) | TplEnd::Unterminated(s) => {
                    let span = Span::new(start, s);
                    return Ok((Template { span, elements }, end));
                }
                TplEnd::Else(s, e, _) | TplEnd::Endif(s, e, _) | TplEnd::Endfor(s, e, _) => {
                    self.error(
                        Span::new(s, e),
                        "template directive without a matching `if` or `for`",
                    );
                    at_line_start = false;
                }
            }
        }
    }

    pub(super) fn push_literal(
        &mut self,
        elements: &mut Vec<'a, TemplateElement<'a>>,
        lit: crate::lexer::Literal,
    ) -> tf_allocator::AllocResult<()> {
        if let Some(span) = lit.bad_escape {
            self.error(span, "invalid escape sequence");
        }
        let value = match &lit.decoded {
            Some(d) => {
                if d.is_empty() {
                    return Ok(());
                }
                Atom::from_in(d, self.alloc)?
            }
            None => {
                if lit.span.is_empty() {
                    return Ok(());
                }
                Atom::from(lit.span.source_text(self.src))
            }
        };
        elements.push(TemplateElement::Literal(self.boxed(TemplateLiteral {
            span: lit.span,
            value,
        })?))?;

        Ok(())
    }

    /// Parse literal text and template sequences into `elements` until the
    /// template closes or a directive keyword that belongs to an enclosing
    /// `if`/`for` (`else`, `endif`, `endfor`) is reached.
    pub(super) fn parse_template_elements(
        &mut self,
        ctx: TemplateCtx<'_>,
        at_line_start: bool,
        elements: &mut Vec<'a, TemplateElement<'a>>,
    ) -> tf_allocator::AllocResult<TplEnd> {
        if !self.enter_depth() {
            return Ok(TplEnd::Unterminated(self.src.len() as u32));
        }
        let result = self.parse_template_elements_inner(ctx, at_line_start, elements)?;
        self.leave_depth();
        Ok(result)
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn parse_template_elements_inner(
        &mut self,
        ctx: TemplateCtx<'_>,
        mut at_line_start: bool,
        elements: &mut Vec<'a, TemplateElement<'a>>,
    ) -> tf_allocator::AllocResult<TplEnd> {
        loop {
            let lit = self.lexer.scan_template_literal(ctx, at_line_start);
            at_line_start = false;
            let stop = lit.stop;
            let stop_span = lit.stop_span;
            self.push_literal(elements, lit)?;
            match stop {
                LitStop::Quote | LitStop::HeredocEnd => {
                    return Ok(TplEnd::Close(stop_span.start, stop_span.end));
                }
                LitStop::Newline | LitStop::Eof => {
                    return Ok(TplEnd::Unterminated(stop_span.start));
                }
                LitStop::Interp => {
                    let seq_start = stop_span.start;
                    self.resync(stop_span.end);
                    self.push_mode(true);
                    let strip_start = self.eat_tilde();
                    let expression = self.parse_expr()?;
                    let strip_end = self.eat_tilde();
                    let end = self.close_template_seq();
                    let span = Span::new(seq_start, end);
                    let strip = Strip {
                        start: strip_start,
                        end: strip_end,
                    };
                    elements.push(TemplateElement::Interpolation(self.boxed(
                        TemplateInterpolation {
                            span,
                            strip,
                            expression,
                        },
                    )?))?;
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
                            let condition = self.parse_expr()?;
                            let strip_end = self.eat_tilde();
                            let then_start = self.close_template_seq();
                            let if_strip = Strip {
                                start: strip_start,
                                end: strip_end,
                            };
                            let mut then_elems = self.vec();
                            let mut end =
                                self.parse_template_elements(ctx, false, &mut then_elems)?;
                            let then_template = Template {
                                span: Span::new(then_start, tpl_end_start(end)),
                                elements: then_elems,
                            };
                            let mut else_strip = None;
                            let mut else_template = None;
                            if let TplEnd::Else(_, else_end, strip) = end {
                                else_strip = Some(strip);
                                let mut else_elems = self.vec();
                                end = self.parse_template_elements(ctx, false, &mut else_elems)?;
                                else_template = Some(Template {
                                    span: Span::new(else_end, tpl_end_start(end)),
                                    elements: else_elems,
                                });
                            }
                            let (endif_strip, node_end, propagate) = match end {
                                TplEnd::Endif(_, e, s) => (s, e, None),
                                other => {
                                    self.error(
                                        Span::new(seq_start, then_start),
                                        "`%{ if }` without a matching `%{ endif }`",
                                    );
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
                            })?))?;
                            if let Some(e) = propagate {
                                return Ok(e);
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
                            let collection = self.parse_expr()?;
                            let strip_end = self.eat_tilde();
                            let body_start = self.close_template_seq();
                            let for_strip = Strip {
                                start: strip_start,
                                end: strip_end,
                            };
                            let mut body = self.vec();
                            let end = self.parse_template_elements(ctx, false, &mut body)?;
                            let template = Template {
                                span: Span::new(body_start, tpl_end_start(end)),
                                elements: body,
                            };
                            let (endfor_strip, node_end, propagate) = match end {
                                TplEnd::Endfor(_, e, s) => (s, e, None),
                                other => {
                                    self.error(
                                        Span::new(seq_start, body_start),
                                        "`%{ for }` without a matching `%{ endfor }`",
                                    );
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
                            })?))?;
                            if let Some(e) = propagate {
                                return Ok(e);
                            }
                        }
                        "else" | "endif" | "endfor" => {
                            self.bump();
                            let strip_end = self.eat_tilde();
                            let end = self.close_template_seq();
                            let strip = Strip {
                                start: strip_start,
                                end: strip_end,
                            };
                            return Ok(match kw {
                                "else" => TplEnd::Else(seq_start, end, strip),
                                "endif" => TplEnd::Endif(seq_start, end, strip),
                                _ => TplEnd::Endfor(seq_start, end, strip),
                            });
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

    pub(super) fn eat_tilde(&mut self) -> bool {
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
    pub(super) fn close_template_seq(&mut self) -> u32 {
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
    #[expect(clippy::too_many_lines)]
    pub(super) fn dedent(&mut self, template: &mut Template<'a>) -> tf_allocator::AllocResult<()> {
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
            return Ok(());
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
                        l.value = Atom::from_in(&out, self.alloc)?;
                    }
                }
                Piece::Seq => newline = false,
            }
        }

        Ok(())
    }
}

/// Remove literals that dedenting emptied.
pub(super) fn prune_empty_literals(t: &mut Template<'_>) {
    t.elements
        .retain(|e| !matches!(e, TemplateElement::Literal(l) if l.value.is_empty()));
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

pub(super) fn tpl_end_start(end: TplEnd) -> u32 {
    match end {
        TplEnd::Close(s, _)
        | TplEnd::Unterminated(s)
        | TplEnd::Else(s, _, _)
        | TplEnd::Endif(s, _, _)
        | TplEnd::Endfor(s, _, _) => s,
    }
}

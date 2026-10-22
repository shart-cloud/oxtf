//! Literal JSON input with original source spans. Serde validates the grammar
//! and nesting limit first; the second pass builds arena nodes without losing
//! duplicate keys or byte locations through a JSON map.

use std::collections::HashSet;
use tf_allocator::{Allocator, Atom, Box, Vec};
use tf_ast::*;
use tf_span::Span;

use crate::{Diagnostic, ParseResult};

pub fn parse_json_vars<'a>(alloc: &'a Allocator, source: &'a str) -> ParseResult<'a> {
    let span = Span::new(0, source.len() as u32);
    let mut p = Json {
        alloc,
        source,
        pos: 0,
        errors: std::vec::Vec::new(),
        reject_duplicates: true,
    };
    let mut items = Vec::new_in(alloc);
    if let Some(limit) = crate::limits::json_depth(source) {
        p.errors.push(limit);
    } else if let Err(e) = serde_json::from_str::<serde::de::IgnoredAny>(source) {
        let start = source
            .split_inclusive('\n')
            .take(e.line().saturating_sub(1))
            .map(str::len)
            .sum::<usize>()
            + e.column().saturating_sub(1);
        let mut start = start.min(source.len());
        while !source.is_char_boundary(start) {
            start -= 1;
        }
        p.errors.push(Diagnostic {
            kind: crate::DiagnosticKind::Syntax,
            span: Span::new(start as u32, start as u32),
            message: format!("invalid JSON variable file: {e}"),
        });
    } else {
        p.ws();
        if p.byte() != b'{' {
            p.errors.push(Diagnostic {
                kind: crate::DiagnosticKind::Syntax,
                span,
                message: "JSON variable file must be an object".into(),
            });
        } else if let Err(error) = p.attributes(&mut items) {
            p.errors
                .push(Diagnostic::limit(span, crate::ParseLimit::Storage(error)));
        }
    }
    ParseResult {
        file: File {
            span,
            body: Body { span, items },
        },
        comments: std::vec::Vec::new(),
        errors: p.errors,
    }
    .bounded(alloc)
}

struct Json<'a> {
    alloc: &'a Allocator,
    source: &'a str,
    pos: usize,
    errors: std::vec::Vec<Diagnostic>,
    reject_duplicates: bool,
}

impl<'a> Json<'a> {
    fn attributes(&mut self, items: &mut Vec<'a, BodyItem<'a>>) -> tf_allocator::AllocResult<()> {
        if let Expression::Object(mut object) = self.value(true)? {
            for item in object.items.drain(..) {
                let ObjectKey::Expression(Expression::String(key)) = item.key else {
                    unreachable!()
                };
                if key.value == "//" {
                    continue;
                }
                items.push(BodyItem::Attribute(Box::new_in(
                    Attribute {
                        span: item.span,
                        key: Identifier {
                            span: key.span,
                            name: key.value,
                        },
                        value: item.value,
                    },
                    self.alloc,
                )?))?;
            }
        }
        Ok(())
    }

    fn byte(&self) -> u8 {
        self.source.as_bytes().get(self.pos).copied().unwrap_or(0)
    }

    fn ws(&mut self) {
        while matches!(self.byte(), b' ' | b'\n' | b'\r' | b'\t') {
            self.pos += 1;
        }
    }

    fn span(&self, start: usize) -> Span {
        Span::new(start as u32, self.pos as u32)
    }

    fn string(&mut self) -> tf_allocator::AllocResult<StringLiteral<'a>> {
        let start = self.pos;
        self.pos += 1;
        while self.byte() != b'"' {
            if self.byte() == b'\\' {
                self.pos += 1;
            }
            self.pos += 1;
        }
        self.pos += 1;
        let decoded: String =
            serde_json::from_str(&self.source[start..self.pos]).expect("validated JSON string");
        Ok(StringLiteral {
            span: self.span(start),
            value: Atom::from_in(&decoded, self.alloc)?,
        })
    }

    fn value(&mut self, root: bool) -> tf_allocator::AllocResult<Expression<'a>> {
        self.ws();
        let start = self.pos;
        Ok(match self.byte() {
            b'"' => {
                let string = self.string()?;
                Expression::String(Box::new_in(string, self.alloc)?)
            }
            b'{' => {
                self.pos += 1;
                self.ws();
                let mut items = Vec::new_in(self.alloc);
                let mut keys = HashSet::new();
                while self.byte() != b'}' {
                    let key = self.string()?;
                    let comment = root && key.value == "//";
                    if self.reject_duplicates && !comment && !keys.insert(key.value) {
                        // Do not echo a possibly sensitive object key.
                        self.errors.push(Diagnostic {
                            kind: crate::DiagnosticKind::Syntax,
                            span: key.span,
                            message: "duplicate JSON object key".into(),
                        });
                    }
                    self.ws();
                    self.pos += 1; // colon, checked by serde
                    let errors = self.errors.len();
                    let value = self.value(false)?;
                    if comment {
                        self.errors.truncate(errors);
                    }
                    items.push(ObjectItem {
                        span: Span::new(key.span.start, self.pos as u32),
                        key: ObjectKey::Expression(Expression::String(Box::new_in(
                            key, self.alloc,
                        )?)),
                        value,
                    })?;
                    self.ws();
                    if self.byte() == b',' {
                        self.pos += 1;
                        self.ws();
                    }
                }
                self.pos += 1;
                Expression::Object(Box::new_in(
                    Object {
                        span: self.span(start),
                        items,
                    },
                    self.alloc,
                )?)
            }
            b'[' => {
                self.pos += 1;
                self.ws();
                let mut elements = Vec::new_in(self.alloc);
                while self.byte() != b']' {
                    elements.push(self.value(false)?)?;
                    self.ws();
                    if self.byte() == b',' {
                        self.pos += 1;
                        self.ws();
                    }
                }
                self.pos += 1;
                Expression::Tuple(Box::new_in(
                    Tuple {
                        span: self.span(start),
                        elements,
                    },
                    self.alloc,
                )?)
            }
            b'n' => {
                self.pos += 4;
                Expression::Null(Box::new_in(
                    NullLiteral {
                        span: self.span(start),
                    },
                    self.alloc,
                )?)
            }
            b't' | b'f' => {
                let value = self.byte() == b't';
                self.pos += if value { 4 } else { 5 };
                Expression::Bool(Box::new_in(
                    BooleanLiteral {
                        span: self.span(start),
                        value,
                    },
                    self.alloc,
                )?)
            }
            _ => {
                while matches!(self.byte(), b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                    self.pos += 1;
                }
                let raw = &self.source[start..self.pos];
                let value = raw.parse::<f64>().expect("validated JSON number");
                let span = self.span(start);
                if !value.is_finite() {
                    self.errors.push(Diagnostic {
                        kind: crate::DiagnosticKind::Syntax,
                        span,
                        message: "JSON number exceeds the evaluator's numeric range".into(),
                    });
                    Expression::Error(Box::new_in(ErrorExpr { span }, self.alloc)?)
                } else {
                    Expression::Number(Box::new_in(
                        NumberLiteral {
                            span,
                            value,
                            raw: raw.into(),
                        },
                        self.alloc,
                    )?)
                }
            }
        })
    }
}

/// Parse JSON into literal expression nodes, preserving ordered and repeated
/// properties for a schema-aware configuration frontend. Unlike variable files,
/// the caller decides which properties are attributes, blocks, or comments.
pub fn parse_json_value<'a>(
    alloc: &'a Allocator,
    source: &'a str,
) -> (Option<Expression<'a>>, std::vec::Vec<Diagnostic>) {
    if let Some(limit) = crate::limits::json_depth(source) {
        return (None, vec![limit]);
    }
    if let Err(e) = serde_json::from_str::<serde::de::IgnoredAny>(source) {
        let start = source
            .split_inclusive('\n')
            .take(e.line().saturating_sub(1))
            .map(str::len)
            .sum::<usize>()
            + e.column().saturating_sub(1);
        let mut start = start.min(source.len());
        while !source.is_char_boundary(start) {
            start -= 1;
        }
        return (
            None,
            vec![Diagnostic {
                kind: crate::DiagnosticKind::Syntax,
                span: Span::new(start as u32, start as u32),
                message: format!("invalid JSON configuration: {e}"),
            }],
        );
    }
    let mut p = Json {
        alloc,
        source,
        pos: 0,
        errors: std::vec::Vec::new(),
        reject_duplicates: false,
    };
    let value = match p.value(false) {
        Ok(value) => Some(value),
        Err(error) => {
            p.errors.push(Diagnostic::limit(
                Span::new(0, source.len() as u32),
                crate::ParseLimit::Storage(error),
            ));
            None
        }
    };
    let (value, errors) = crate::limits::bounded_expression(alloc, value, p.errors);
    let limited = errors
        .iter()
        .any(|e| matches!(e.kind, crate::DiagnosticKind::Limit(_)));
    (if limited { None } else { value }, errors)
}

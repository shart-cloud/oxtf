//! Schema-directed Terraform JSON mapping. The literal tree keeps property
//! order and duplicates; only the receiving body decides what is a block.
use std::collections::HashSet;

use tf_allocator::{Allocator, Atom, Box, Vec};
use tf_ast::*;
use tf_parser::{Diagnostic, ParseResult};
use tf_span::{GetSpan, Span};

pub fn parse<'a>(
    alloc: &'a Allocator,
    source: &'a str,
    providers: &rustc_hash::FxHashMap<String, String>,
) -> ParseResult<'a> {
    let (value, errors) = tf_parser::parse_json_value(alloc, source);
    let span = Span::new(0, source.len() as u32);
    let mut p = Mapping {
        alloc,
        source,
        errors,
        providers,
    };
    let body = value
        .and_then(|v| match p.body(v, "", None) {
            Ok(body) => Some(body),
            Err(error) => {
                p.errors.push(Diagnostic::limit(
                    span,
                    tf_parser::ParseLimit::Storage(error),
                ));
                None
            }
        })
        .unwrap_or(Body {
            span,
            items: Vec::new_in(alloc),
        });
    ParseResult {
        file: File { span, body },
        errors: p.errors,
        comments: std::vec::Vec::new(),
    }
    .bounded(alloc)
}

struct Mapping<'a, 'p> {
    alloc: &'a Allocator,
    source: &'a str,
    errors: std::vec::Vec<Diagnostic>,
    providers: &'p rustc_hash::FxHashMap<String, String>,
}

impl<'a> Mapping<'a, '_> {
    fn error(&mut self, span: Span, message: &str) {
        self.errors.push(Diagnostic {
            kind: tf_parser::DiagnosticKind::Syntax,
            span,
            message: message.into(),
        });
    }

    fn body(
        &mut self,
        value: Expression<'a>,
        kind: &str,
        schema: Option<&'static tf_schema::Block<'static>>,
    ) -> tf_allocator::AllocResult<Body<'a>> {
        let span = value.span();
        let mut items = Vec::new_in(self.alloc);
        let properties = match value {
            Expression::Object(mut object) => object.items.drain(..).collect::<std::vec::Vec<_>>(),
            Expression::Tuple(mut array) => {
                let mut properties = std::vec::Vec::new();
                for value in array.elements.drain(..) {
                    if let Expression::Object(mut object) = value {
                        properties.extend(object.items.drain(..));
                    } else {
                        self.error(value.span(), "JSON body array elements must be objects");
                    }
                }
                properties
            }
            _ => {
                self.error(
                    span,
                    "JSON block body must be an object or an array of objects",
                );
                return Ok(Body { span, items });
            }
        };
        let mut attrs = HashSet::new();
        for item in properties {
            let ObjectKey::Expression(Expression::String(key)) = item.key else {
                unreachable!()
            };
            let name = key.value.as_str();
            if name == "//" {
                continue;
            }
            let ident = Identifier {
                span: key.span,
                name: key.value,
            };
            let nested = if kind.is_empty() {
                match name {
                    "resource" | "data" => Some(2),
                    "variable" | "output" | "module" | "provider" | "check" => Some(1),
                    "locals" | "terraform" | "moved" | "removed" | "import" => Some(0),
                    _ => {
                        self.error(key.span, "unsupported JSON configuration block type");
                        continue;
                    }
                }
            } else {
                match (kind, name) {
                    ("resource" | "data", "lifecycle" | "connection")
                    | ("provisioner", "connection")
                    | ("variable", "validation")
                    | ("lifecycle" | "output", "precondition" | "postcondition")
                    | ("check", "assert")
                    | ("dynamic", "content")
                    | ("terraform", "required_providers" | "cloud") => Some(0),
                    ("resource", "provisioner") | ("terraform", "backend" | "provider_meta") => {
                        Some(1)
                    }
                    (_, "dynamic")
                        if matches!(kind, "resource" | "data" | "content") || schema.is_some() =>
                    {
                        Some(1)
                    }
                    _ => schema
                        .and_then(|s| s.block_type(name))
                        .map(|b| usize::from(b.nesting() == tf_schema::NestingMode::Map)),
                }
            };
            if let Some(labels) = nested {
                let child_schema = if name == "dynamic" || (kind == "dynamic" && name == "content")
                {
                    schema
                } else {
                    schema.and_then(|s| s.block_type(name)).map(|b| b.block())
                };
                self.blocks(ident, item.value, labels, &[], child_schema, &mut items)?;
            } else {
                if !attrs.insert(key.value) {
                    self.error(key.span, "duplicate JSON attribute");
                }
                let value = self.attribute_value(kind, name, item.value)?;
                items.push(BodyItem::Attribute(Box::new_in(
                    Attribute {
                        span: item.span,
                        key: ident,
                        value,
                    },
                    self.alloc,
                )?))?;
            }
        }
        Ok(Body { span, items })
    }

    fn attribute_value(
        &mut self,
        kind: &str,
        name: &str,
        value: Expression<'a>,
    ) -> tf_allocator::AllocResult<Expression<'a>> {
        Ok(match (kind, name) {
            ("variable", "type")
            | ("resource" | "data", "provider")
            | ("dynamic", "iterator")
            | ("moved", "from" | "to")
            | ("removed" | "import", "to" | "from") => self.native(value),
            ("resource" | "data" | "module" | "output", "depends_on")
            | ("lifecycle", "ignore_changes" | "replace_triggered_by") => self.references(value)?,
            ("module", "providers") => {
                if let Expression::Object(mut o) = value {
                    let mut items = Vec::new_in(self.alloc);
                    for item in o.items.drain(..) {
                        items.push(ObjectItem {
                            span: item.span,
                            key: item.key,
                            value: self.native(item.value),
                        })?;
                    }
                    Expression::Object(Box::new_in(
                        Object {
                            span: o.span,
                            items,
                        },
                        self.alloc,
                    )?)
                } else {
                    self.error(value.span(), "provider mapping must be a JSON object");
                    value
                }
            }
            ("variable", _)
            | ("terraform" | "required_providers" | "backend" | "cloud", _)
            | ("module", "source" | "version")
            | ("provider", "alias" | "version")
            | ("output", "description" | "sensitive" | "ephemeral")
            | ("connection", "type")
            | ("provisioner", "when" | "on_failure")
            | ("lifecycle", "prevent_destroy" | "create_before_destroy") => {
                self.check_literal(&value);
                value
            }
            _ => self.expression(value)?,
        })
    }

    fn native(&mut self, value: Expression<'a>) -> Expression<'a> {
        if let Expression::String(s) = value {
            self.string_expression(s, true)
        } else {
            self.error(
                value.span(),
                "a native expression must be encoded as a JSON string",
            );
            value
        }
    }

    fn references(&mut self, value: Expression<'a>) -> tf_allocator::AllocResult<Expression<'a>> {
        Ok(if let Expression::Tuple(mut t) = value {
            let mut elements = Vec::new_in(self.alloc);
            elements.extend(t.elements.drain(..).map(|v| self.native(v)))?;
            Expression::Tuple(Box::new_in(
                Tuple {
                    span: t.span,
                    elements,
                },
                self.alloc,
            )?)
        } else {
            self.native(value)
        })
    }

    fn check_literal(&mut self, value: &Expression<'a>) {
        match value {
            Expression::Object(o) => {
                let mut seen = HashSet::new();
                for item in o.items.iter() {
                    if let Some(key) = item.key.as_static_str()
                        && !seen.insert(key)
                    {
                        self.error(item.span, "duplicate JSON object key");
                    }
                    self.check_literal(&item.value);
                }
            }
            Expression::Tuple(t) => t.elements.iter().for_each(|v| self.check_literal(v)),
            _ => {}
        }
    }

    fn blocks(
        &mut self,
        ident: Identifier<'a>,
        value: Expression<'a>,
        remaining: usize,
        labels: &[(Atom<'a>, Span)],
        schema: Option<&'static tf_schema::Block<'static>>,
        out: &mut Vec<'a, BodyItem<'a>>,
    ) -> tf_allocator::AllocResult<()> {
        if let Expression::Tuple(mut array) = value {
            for value in array.elements.drain(..) {
                if !matches!(value, Expression::Object(_)) {
                    self.error(value.span(), "JSON block array elements must be objects");
                    continue;
                }
                self.blocks(
                    Identifier {
                        span: ident.span,
                        name: ident.name,
                    },
                    value,
                    remaining,
                    labels,
                    schema,
                    out,
                )?;
            }
        } else if remaining > 0 {
            let span = value.span();
            let Expression::Object(mut object) = value else {
                self.error(span, "JSON block labels must be represented by objects");
                return Ok(());
            };
            for item in object.items.drain(..) {
                let ObjectKey::Expression(Expression::String(key)) = item.key else {
                    unreachable!()
                };
                let mut next = labels.to_vec();
                next.push((key.value, key.span));
                self.blocks(
                    Identifier {
                        span: ident.span,
                        name: ident.name,
                    },
                    item.value,
                    remaining - 1,
                    &next,
                    schema,
                    out,
                )?;
            }
        } else {
            let schema = match (ident.name.as_str(), labels.first()) {
                ("resource", Some((ty, _))) => tf_schema::lookup_resource(ty).map(|s| s.block()),
                ("data", Some((ty, _))) => tf_schema::lookup_data_source(ty).map(|s| s.block()),
                ("provider", Some((name, _))) => tf_schema::lookup_provider(
                    self.providers
                        .get(name.as_str())
                        .map(String::as_str)
                        .unwrap_or(name),
                ),
                ("dynamic", Some((ty, _))) => {
                    schema.and_then(|s| s.block_type(ty)).map(|b| b.block())
                }
                _ => schema,
            };
            let body = self.body(value, ident.name.as_str(), schema)?;
            let span = Span::new(ident.span.start, body.span.end);
            let mut ast_labels = Vec::new_in(self.alloc);
            ast_labels.extend(labels.iter().map(|(value, span)| BlockLabel {
                span: *span,
                value: *value,
                quoted: true,
            }))?;
            out.push(BodyItem::Block(Box::new_in(
                Block {
                    span,
                    ident,
                    labels: ast_labels,
                    body,
                },
                self.alloc,
            )?))?;
        }

        Ok(())
    }

    fn expression(&mut self, value: Expression<'a>) -> tf_allocator::AllocResult<Expression<'a>> {
        Ok(match value {
            Expression::String(s) => self.string_expression(s, false),
            Expression::Tuple(mut t) => {
                let mut elements = Vec::new_in(self.alloc);
                for value in t.elements.drain(..) {
                    elements.push(self.expression(value)?)?;
                }
                Expression::Tuple(Box::new_in(
                    Tuple {
                        span: t.span,
                        elements,
                    },
                    self.alloc,
                )?)
            }
            Expression::Object(mut o) => {
                let mut items = Vec::new_in(self.alloc);
                let mut seen = HashSet::new();
                for item in o.items.drain(..) {
                    if let Some(key) = item.key.as_static_str()
                        && !seen.insert(key)
                    {
                        self.error(item.span, "duplicate JSON object key");
                    }
                    let key = match item.key {
                        ObjectKey::Expression(e) => ObjectKey::Expression(self.expression(e)?),
                        k => k,
                    };
                    items.push(ObjectItem {
                        span: item.span,
                        key,
                        value: self.expression(item.value)?,
                    })?;
                }
                Expression::Object(Box::new_in(
                    Object {
                        span: o.span,
                        items,
                    },
                    self.alloc,
                )?)
            }
            v => v,
        })
    }

    fn string_expression(
        &mut self,
        string: Box<'a, StringLiteral<'a>>,
        native: bool,
    ) -> Expression<'a> {
        let decoded = string.value.as_str();
        let (mut expr, errors) = if native {
            tf_parser::parse_expression(self.alloc, decoded)
        } else {
            tf_parser::parse_template(self.alloc, decoded)
        };
        let mut mapping = StringLocations::new(self.source, string.span);
        if let Some(expr) = &mut expr {
            mapping.visit_expression(expr);
        }
        self.errors.extend(errors.into_iter().map(|mut e| {
            mapping.visit_span(&mut e.span);
            e
        }));
        expr.unwrap_or(Expression::String(string))
    }
}

/// A boundary for every decoded UTF-8 byte, mapped to original JSON bytes.
/// Escaped Unicode (including surrogate pairs) maps as one original token.
struct StringLocations {
    offsets: std::vec::Vec<u32>,
}

impl StringLocations {
    fn new(source: &str, span: Span) -> Self {
        let mut pos = span.start as usize + 1;
        let end = span.end as usize - 1;
        let mut offsets = vec![pos as u32];
        while pos < end {
            let start = pos;
            let n = if source.as_bytes()[pos] == b'\\' {
                let len = if source.as_bytes()[pos + 1] == b'u' {
                    let code = u16::from_str_radix(&source[pos + 2..pos + 6], 16)
                        .expect("validated escape");
                    if (0xd800..=0xdbff).contains(&code) {
                        12
                    } else {
                        6
                    }
                } else {
                    2
                };
                pos += len;
                let token = format!("\"{}\"", &source[start..pos]);
                serde_json::from_str::<String>(&token)
                    .expect("validated escape")
                    .len()
            } else {
                let n = source[pos..].chars().next().unwrap().len_utf8();
                pos += n;
                n
            };
            for _ in 1..n {
                offsets.push(start as u32);
            }
            offsets.push(pos as u32);
        }
        Self { offsets }
    }
}

impl<'a> VisitMut<'a> for StringLocations {
    fn visit_span(&mut self, span: &mut Span) {
        let last = self.offsets.len() - 1;
        *span = Span::new(
            self.offsets[(span.start as usize).min(last)],
            self.offsets[(span.end as usize).min(last)],
        );
    }
}

//! S-expression dump of a `tf_ast` tree, used by the snapshot tests and the
//! `hcl-edit` differential test.
//!
//! With `normalize = true` the output is trivia-free and canonical:
//! adjacent template literals are merged, `~` strip markers are applied to
//! neighbouring literals, `-<number>` is folded into a negative number, and
//! spans are omitted. The differential test renders `hcl-edit`'s tree in the
//! same format.

use std::fmt::Write;
use tf_ast::*;

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Print `@start..end` after each node.
    pub spans: bool,
    /// Canonicalise for structural comparison (see module docs).
    pub normalize: bool,
}

pub fn dump_file(file: &File<'_>, opts: Options) -> String {
    let mut d = Dumper { out: String::new(), opts, indent: 0 };
    d.body(&file.body);
    d.out
}

pub fn dump_expr(expr: &Expression<'_>, opts: Options) -> String {
    let mut d = Dumper { out: String::new(), opts, indent: 0 };
    d.expr(expr);
    d.out
}

struct Dumper {
    out: String,
    opts: Options,
    indent: usize,
}

/// A normalised template item.
pub enum NItem {
    Lit(String),
    Other(String),
}

/// Format a number canonically.
pub fn fmt_num(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 { format!("{}", v as i64) } else { format!("{v}") }
}

/// Apply strip flags and merge adjacent literals. `items` carry, per
/// element, `(item, strip_before, strip_after)`; `strip_before` trims the
/// literal immediately before a sequence, `strip_after` the one after.
pub fn normalize_template(items: Vec<(NItem, bool, bool)>, lead_trim: bool, trail_trim: bool) -> Vec<NItem> {
    let n = items.len();
    let mut trim_start = vec![false; n];
    let mut trim_end = vec![false; n];
    for (i, (_, before, after)) in items.iter().enumerate() {
        if *before && i > 0 {
            trim_end[i - 1] = true;
        }
        if *after && i + 1 < n {
            trim_start[i + 1] = true;
        }
    }
    if n > 0 {
        trim_start[0] |= lead_trim;
        trim_end[n - 1] |= trail_trim;
    }
    let mut out: Vec<NItem> = Vec::new();
    for (i, (item, _, _)) in items.into_iter().enumerate() {
        match item {
            NItem::Lit(mut s) => {
                if trim_start[i] {
                    s = s.trim_start().to_string();
                }
                if trim_end[i] {
                    s = s.trim_end().to_string();
                }
                if s.is_empty() {
                    continue;
                }
                if let Some(NItem::Lit(prev)) = out.last_mut() {
                    prev.push_str(&s);
                } else {
                    out.push(NItem::Lit(s));
                }
            }
            other => out.push(other),
        }
    }
    out
}

pub fn render_items(items: &[NItem]) -> String {
    let mut s = String::new();
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        match it {
            NItem::Lit(l) => write!(s, "{l:?}").unwrap(),
            NItem::Other(o) => s.push_str(o),
        }
    }
    s
}

impl Dumper {
    fn sp(&mut self, span: Span) {
        if self.opts.spans {
            write!(self.out, "@{}..{}", span.start, span.end).unwrap();
        }
    }

    fn nl(&mut self) {
        self.out.push('\n');
        for _ in 0..self.indent {
            self.out.push_str("  ");
        }
    }

    fn body(&mut self, body: &Body<'_>) {
        self.out.push_str("(body");
        self.sp(body.span);
        self.indent += 1;
        for item in body.items.iter() {
            self.nl();
            match item {
                BodyItem::Attribute(a) => {
                    write!(self.out, "(attr {}", a.key.name).unwrap();
                    self.sp(a.span);
                    self.out.push(' ');
                    self.expr(&a.value);
                    self.out.push(')');
                }
                BodyItem::Block(b) => {
                    write!(self.out, "(block {}", b.ident.name).unwrap();
                    self.sp(b.span);
                    for l in b.labels.iter() {
                        if l.quoted {
                            write!(self.out, " {:?}", l.value.as_str()).unwrap();
                        } else {
                            write!(self.out, " {}", l.value).unwrap();
                        }
                    }
                    self.out.push(' ');
                    self.body(&b.body);
                    self.out.push(')');
                }
            }
        }
        self.indent -= 1;
        self.out.push(')');
    }

    fn sub(&self, e: &Expression<'_>) -> String {
        let mut d = Dumper { out: String::new(), opts: self.opts, indent: self.indent };
        d.expr(e);
        d.out
    }

    fn expr(&mut self, e: &Expression<'_>) {
        match e {
            Expression::Null(n) => {
                self.out.push_str("null");
                self.sp(n.span);
            }
            Expression::Bool(b) => {
                write!(self.out, "{}", b.value).unwrap();
                self.sp(b.span);
            }
            Expression::Number(n) => {
                if self.opts.normalize {
                    self.out.push_str(&fmt_num(n.value));
                } else {
                    write!(self.out, "{}", n.raw).unwrap();
                }
                self.sp(n.span);
            }
            Expression::String(s) => {
                write!(self.out, "{:?}", s.value.as_str()).unwrap();
                self.sp(s.span);
            }
            Expression::Template(t) => {
                self.out.push_str("(tpl");
                self.sp(t.span);
                let s = self.template(&t.template, false, false);
                if !s.is_empty() {
                    self.out.push(' ');
                    self.out.push_str(&s);
                }
                self.out.push(')');
            }
            Expression::Heredoc(h) => {
                write!(self.out, "(heredoc {}{}", if h.indented { "-" } else { "" }, h.delimiter).unwrap();
                self.sp(h.span);
                let s = self.template(&h.template, false, false);
                if !s.is_empty() {
                    self.out.push(' ');
                    self.out.push_str(&s);
                }
                self.out.push(')');
            }
            Expression::Variable(v) => {
                write!(self.out, "{}", v.name).unwrap();
                self.sp(v.span);
            }
            Expression::Traversal(t) => {
                self.out.push_str("(trav");
                self.sp(t.span);
                self.out.push(' ');
                self.expr(&t.object);
                for op in t.operators.iter() {
                    self.out.push(' ');
                    match op {
                        TraversalOperator::GetAttr(g) => write!(self.out, ".{}", g.name.name).unwrap(),
                        TraversalOperator::Index(i) => {
                            self.out.push('[');
                            self.expr(&i.index);
                            self.out.push(']');
                        }
                        TraversalOperator::LegacyIndex(l) => write!(self.out, ".{}", l.index).unwrap(),
                        TraversalOperator::AttrSplat(_) => self.out.push_str(".*"),
                        TraversalOperator::FullSplat(_) => self.out.push_str("[*]"),
                    }
                    self.sp(op.span());
                }
                self.out.push(')');
            }
            Expression::FunctionCall(c) => {
                self.out.push_str("(call ");
                for ns in c.namespace.iter() {
                    write!(self.out, "{}::", ns.name).unwrap();
                }
                write!(self.out, "{}", c.name.name).unwrap();
                self.sp(c.span);
                for a in c.arguments.iter() {
                    self.out.push(' ');
                    self.expr(a);
                }
                if c.expand_final {
                    self.out.push_str(" ...");
                }
                self.out.push(')');
            }
            Expression::Tuple(t) => {
                self.out.push_str("(tuple");
                self.sp(t.span);
                for el in t.elements.iter() {
                    self.out.push(' ');
                    self.expr(el);
                }
                self.out.push(')');
            }
            Expression::Object(o) => {
                self.out.push_str("(object");
                self.sp(o.span);
                self.indent += 1;
                for item in o.items.iter() {
                    self.nl();
                    self.out.push('(');
                    match &item.key {
                        ObjectKey::Identifier(i) => write!(self.out, "{}", i.name).unwrap(),
                        ObjectKey::Expression(k) => {
                            self.out.push_str("(key ");
                            self.expr(k);
                            self.out.push(')');
                        }
                    }
                    self.out.push(' ');
                    self.expr(&item.value);
                    self.out.push(')');
                }
                self.indent -= 1;
                self.out.push(')');
            }
            Expression::For(f) => {
                self.out.push_str("(for");
                self.sp(f.span);
                if let Some(k) = &f.key_var {
                    write!(self.out, " {}", k.name).unwrap();
                }
                write!(self.out, " {} in ", f.value_var.name).unwrap();
                self.expr(&f.collection);
                self.out.push_str(" :");
                if let Some(k) = &f.key_expr {
                    self.out.push(' ');
                    self.expr(k);
                    self.out.push_str(" =>");
                }
                self.out.push(' ');
                self.expr(&f.value_expr);
                if f.grouping {
                    self.out.push_str(" ...");
                }
                if let Some(c) = &f.condition {
                    self.out.push_str(" if ");
                    self.expr(c);
                }
                self.out.push(')');
            }
            Expression::Conditional(c) => {
                self.out.push_str("(?");
                self.sp(c.span);
                self.out.push(' ');
                self.expr(&c.condition);
                self.out.push(' ');
                self.expr(&c.true_expr);
                self.out.push(' ');
                self.expr(&c.false_expr);
                self.out.push(')');
            }
            Expression::Unary(u) => {
                if self.opts.normalize
                    && u.operator == UnaryOperator::Negate
                    && let Expression::Number(n) = &u.operand
                {
                    self.out.push_str(&fmt_num(-n.value));
                    return;
                }
                write!(self.out, "({}", if u.operator == UnaryOperator::Not { "!" } else { "neg" }).unwrap();
                self.sp(u.span);
                self.out.push(' ');
                self.expr(&u.operand);
                self.out.push(')');
            }
            Expression::Binary(b) => {
                write!(self.out, "({}", b.operator.as_str()).unwrap();
                self.sp(b.span);
                self.out.push(' ');
                self.expr(&b.left);
                self.out.push(' ');
                self.expr(&b.right);
                self.out.push(')');
            }
            Expression::Parenthesized(p) => {
                self.out.push_str("(paren");
                self.sp(p.span);
                self.out.push(' ');
                self.expr(&p.expression);
                self.out.push(')');
            }
            Expression::Error(e) => {
                self.out.push_str("(error");
                self.sp(e.span);
                self.out.push(')');
            }
        }
    }

    fn template(&mut self, t: &Template<'_>, lead_trim: bool, trail_trim: bool) -> String {
        let mut items = Vec::new();
        for el in t.elements.iter() {
            match el {
                TemplateElement::Literal(l) => {
                    if self.opts.spans {
                        let s = format!("{:?}@{}..{}", l.value.as_str(), l.span.start, l.span.end);
                        items.push((NItem::Other(s), false, false));
                    } else {
                        items.push((NItem::Lit(l.value.to_string()), false, false));
                    }
                }
                TemplateElement::Interpolation(i) => {
                    let mut s = String::from("${");
                    if !self.opts.normalize && i.strip.start {
                        s.push('~');
                    }
                    s.push_str(&self.sub(&i.expression));
                    if !self.opts.normalize && i.strip.end {
                        s.push('~');
                    }
                    s.push('}');
                    if self.opts.spans {
                        write!(s, "@{}..{}", i.span.start, i.span.end).unwrap();
                    }
                    items.push((NItem::Other(s), i.strip.start, i.strip.end));
                }
                TemplateElement::If(i) => {
                    let n = self.opts.normalize;
                    let mut s = String::from("%{if ");
                    s.push_str(&self.sub(&i.condition));
                    if !n {
                        write!(s, " strip={}{}", i.if_strip.start as u8, i.if_strip.end as u8).unwrap();
                    }
                    let then_trail = i.else_strip.map_or(i.endif_strip.start, |e| e.start);
                    let then = self.template(&i.then_template, i.if_strip.end, then_trail);
                    write!(s, " then[{then}]").unwrap();
                    if let (Some(es), Some(et)) = (i.else_strip, &i.else_template) {
                        let els = self.template(et, es.end, i.endif_strip.start);
                        if !n {
                            write!(s, " else-strip={}{}", es.start as u8, es.end as u8).unwrap();
                        }
                        write!(s, " else[{els}]").unwrap();
                    }
                    if !n {
                        write!(s, " endif-strip={}{}", i.endif_strip.start as u8, i.endif_strip.end as u8).unwrap();
                    }
                    s.push('}');
                    if self.opts.spans {
                        write!(s, "@{}..{}", i.span.start, i.span.end).unwrap();
                    }
                    items.push((NItem::Other(s), i.if_strip.start, i.endif_strip.end));
                }
                TemplateElement::For(f) => {
                    let n = self.opts.normalize;
                    let mut s = String::from("%{for ");
                    if let Some(k) = &f.key_var {
                        write!(s, "{}, ", k.name).unwrap();
                    }
                    write!(s, "{} in {}", f.value_var.name, self.sub(&f.collection)).unwrap();
                    if !n {
                        write!(s, " strip={}{}", f.for_strip.start as u8, f.for_strip.end as u8).unwrap();
                    }
                    let body = self.template(&f.template, f.for_strip.end, f.endfor_strip.start);
                    write!(s, " do[{body}]").unwrap();
                    if !n {
                        write!(s, " endfor-strip={}{}", f.endfor_strip.start as u8, f.endfor_strip.end as u8).unwrap();
                    }
                    s.push('}');
                    if self.opts.spans {
                        write!(s, "@{}..{}", f.span.start, f.span.end).unwrap();
                    }
                    items.push((NItem::Other(s), f.for_strip.start, f.endfor_strip.end));
                }
            }
        }
        if self.opts.normalize {
            render_items(&normalize_template(items, lead_trim, trail_trim))
        } else {
            let items: Vec<NItem> = items.into_iter().map(|(i, _, _)| i).collect();
            render_items(&items)
        }
    }
}

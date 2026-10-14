//! Shared helpers for corpus-based tests: corpus discovery and an
//! `hcl-edit` -> normalised S-expression renderer that mirrors
//! `tf_parser::dump` with `normalize: true`.
#![allow(dead_code)]

use hcl_edit::expr::{Expression as E, ObjectKey, TraversalOperator as Op};
use hcl_edit::structure::{BlockLabel, Body, Structure};
use hcl_edit::template::{Directive, Element, Template};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use tf_parser::dump::{NItem, fmt_num, normalize_template, render_items};

pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/repos")
}

/// All regular `.tf`, `.tfvars` and `.hcl` (`.tftest.hcl`, packer, tflint)
/// files under the corpus, sorted. Symlinks are not followed.
pub fn corpus_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                walk(&p, out);
            } else if ft.is_file() {
                let name = p.file_name().unwrap().to_string_lossy();
                if name.ends_with(".tf") || name.ends_with(".tfvars") || name.ends_with(".hcl") {
                    out.push(p);
                }
            }
        }
    }
    walk(&corpus_dir(), &mut out);
    out.sort();
    out
}

pub fn hcl_body(body: &Body) -> String {
    let mut s = String::new();
    body_into(&mut s, body, 0);
    s
}

fn nl(s: &mut String, indent: usize) {
    s.push('\n');
    for _ in 0..indent {
        s.push_str("  ");
    }
}

fn body_into(s: &mut String, body: &Body, indent: usize) {
    s.push_str("(body");
    for st in body.iter() {
        nl(s, indent + 1);
        match st {
            Structure::Attribute(a) => {
                write!(s, "(attr {} ", a.key.as_str()).unwrap();
                expr_into(s, &a.value, indent + 1);
                s.push(')');
            }
            Structure::Block(b) => {
                write!(s, "(block {}", b.ident.as_str()).unwrap();
                for l in &b.labels {
                    match l {
                        BlockLabel::Ident(i) => write!(s, " {}", i.as_str()).unwrap(),
                        BlockLabel::String(st) => write!(s, " {:?}", st.value().as_str()).unwrap(),
                    }
                }
                s.push(' ');
                body_into(s, &b.body, indent + 1);
                s.push(')');
            }
        }
    }
    s.push(')');
}

fn sub(e: &E, indent: usize) -> String {
    let mut s = String::new();
    expr_into(&mut s, e, indent);
    s
}

pub fn expr_into(s: &mut String, e: &E, indent: usize) {
    match e {
        E::Null(_) => s.push_str("null"),
        E::Bool(b) => write!(s, "{}", b.value()).unwrap(),
        E::Number(n) => s.push_str(&fmt_num(n.value().as_f64().unwrap())),
        E::String(st) => write!(s, "{:?}", st.value().as_str()).unwrap(),
        E::StringTemplate(t) => {
            s.push_str("(tpl");
            let r = template(t, false, false, indent);
            if !r.is_empty() {
                s.push(' ');
                s.push_str(&r);
            }
            s.push(')');
        }
        E::HeredocTemplate(h) => {
            write!(s, "(heredoc {}", h.delimiter.as_str()).unwrap();
            let r = template(&h.template, false, false, indent);
            if !r.is_empty() {
                s.push(' ');
                s.push_str(&r);
            }
            s.push(')');
        }
        E::Parenthesis(p) => {
            s.push_str("(paren ");
            expr_into(s, p.inner(), indent);
            s.push(')');
        }
        E::Variable(v) => s.push_str(v.as_str()),
        E::Conditional(c) => {
            s.push_str("(? ");
            expr_into(s, &c.cond_expr, indent);
            s.push(' ');
            expr_into(s, &c.true_expr, indent);
            s.push(' ');
            expr_into(s, &c.false_expr, indent);
            s.push(')');
        }
        E::FuncCall(f) => {
            s.push_str("(call ");
            for ns in &f.name.namespace {
                write!(s, "{}::", ns.as_str()).unwrap();
            }
            s.push_str(f.name.name.as_str());
            for a in f.args.iter() {
                s.push(' ');
                expr_into(s, a, indent);
            }
            if f.args.expand_final() {
                s.push_str(" ...");
            }
            s.push(')');
        }
        E::Traversal(t) => {
            s.push_str("(trav ");
            expr_into(s, &t.expr, indent);
            for op in &t.operators {
                s.push(' ');
                match op.value() {
                    Op::AttrSplat(_) => s.push_str(".*"),
                    Op::FullSplat(_) => s.push_str("[*]"),
                    Op::GetAttr(i) => write!(s, ".{}", i.as_str()).unwrap(),
                    Op::Index(i) => {
                        s.push('[');
                        expr_into(s, i, indent);
                        s.push(']');
                    }
                    Op::LegacyIndex(i) => write!(s, ".{}", i.value()).unwrap(),
                }
            }
            s.push(')');
        }
        E::UnaryOp(u) => {
            let op = u.operator.value().as_str();
            if op == "-"
                && let E::Number(n) = &u.expr
            {
                s.push_str(&fmt_num(-n.value().as_f64().unwrap()));
                return;
            }
            write!(s, "({} ", if op == "!" { "!" } else { "neg" }).unwrap();
            expr_into(s, &u.expr, indent);
            s.push(')');
        }
        E::BinaryOp(b) => {
            write!(s, "({} ", b.operator.value().as_str()).unwrap();
            expr_into(s, &b.lhs_expr, indent);
            s.push(' ');
            expr_into(s, &b.rhs_expr, indent);
            s.push(')');
        }
        E::ForExpr(f) => {
            s.push_str("(for");
            if let Some(k) = &f.intro.key_var {
                write!(s, " {}", k.as_str()).unwrap();
            }
            write!(s, " {} in ", f.intro.value_var.as_str()).unwrap();
            expr_into(s, &f.intro.collection_expr, indent);
            s.push_str(" :");
            if let Some(k) = &f.key_expr {
                s.push(' ');
                expr_into(s, k, indent);
                s.push_str(" =>");
            }
            s.push(' ');
            expr_into(s, &f.value_expr, indent);
            if f.grouping {
                s.push_str(" ...");
            }
            if let Some(c) = &f.cond {
                s.push_str(" if ");
                expr_into(s, &c.expr, indent);
            }
            s.push(')');
        }
        E::Array(a) => {
            s.push_str("(tuple");
            for el in a.iter() {
                s.push(' ');
                expr_into(s, el, indent);
            }
            s.push(')');
        }
        E::Object(o) => {
            s.push_str("(object");
            for (k, v) in o.iter() {
                nl(s, indent + 1);
                s.push('(');
                match k {
                    ObjectKey::Ident(i) => s.push_str(i.as_str()),
                    ObjectKey::Expression(k) => {
                        s.push_str("(key ");
                        expr_into(s, k, indent + 1);
                        s.push(')');
                    }
                }
                s.push(' ');
                expr_into(s, v.expr(), indent + 1);
                s.push(')');
            }
            s.push(')');
        }
    }
}

fn template(t: &Template, lead: bool, trail: bool, indent: usize) -> String {
    let mut items = Vec::new();
    for el in t.iter() {
        match el {
            Element::Literal(l) => items.push((NItem::Lit(l.value().to_string()), false, false)),
            Element::Interpolation(i) => {
                let s = format!("${{{}}}", sub(&i.expr, indent));
                items.push((NItem::Other(s), i.strip.strip_start(), i.strip.strip_end()));
            }
            Element::Directive(d) => match &**d {
                Directive::If(i) => {
                    let ifs = i.if_expr.strip;
                    let ends = i.endif_expr.strip;
                    let mut s = format!("%{{if {}", sub(&i.if_expr.cond_expr, indent));
                    let then_trail = i
                        .else_expr
                        .as_ref()
                        .map_or(ends.strip_start(), |e| e.strip.strip_start());
                    let then = template(&i.if_expr.template, ifs.strip_end(), then_trail, indent);
                    write!(s, " then[{then}]").unwrap();
                    if let Some(e) = &i.else_expr {
                        let els =
                            template(&e.template, e.strip.strip_end(), ends.strip_start(), indent);
                        write!(s, " else[{els}]").unwrap();
                    }
                    s.push('}');
                    items.push((NItem::Other(s), ifs.strip_start(), ends.strip_end()));
                }
                Directive::For(f) => {
                    let fe = &f.for_expr;
                    let mut s = String::from("%{for ");
                    if let Some(k) = &fe.key_var {
                        write!(s, "{}, ", k.as_str()).unwrap();
                    }
                    write!(
                        s,
                        "{} in {}",
                        fe.value_var.as_str(),
                        sub(&fe.collection_expr, indent)
                    )
                    .unwrap();
                    let body = template(
                        &fe.template,
                        fe.strip.strip_end(),
                        f.endfor_expr.strip.strip_start(),
                        indent,
                    );
                    write!(s, " do[{body}]}}").unwrap();
                    items.push((
                        NItem::Other(s),
                        fe.strip.strip_start(),
                        f.endfor_expr.strip.strip_end(),
                    ));
                }
            },
        }
    }
    render_items(&normalize_template(items, lead, trail))
}

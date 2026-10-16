//! A Terraform file as Conftest's HCL2 parser presents it (tmccombs/hcl2json
//! v0.6.7, `convert.go`): blocks nested by label and always wrapped in a
//! list, attributes as JSON.
//!
//! Two renderings share the walker:
//!
//! - [`raw`] is hcl2json itself: literals pass through (with `${` and `%{`
//!   in strings escaped back to `$${` and `%%{`), and every other
//!   expression is its source text wrapped in `${...}`. This backs
//!   Conftest's `parse_config("hcl2", ...)`.
//! - [`evaluated`] follows oxtf's semantic contract: the structure is
//!   hcl2json's, but values are oxtf's. Resource and data-source bodies come
//!   from the evaluated instances, `locals`, module-call arguments and
//!   outputs from the model, and everything else is constant-folded.
//!   A value oxtf does not know is left out and recorded as an
//!   [`Abstraction`], exactly as in the per-resource projection. Positions
//!   that are syntax rather than values (a variable's `type`, `depends_on`,
//!   `provider`, `ignore_changes`, conditions) keep hcl2json's `${...}`.

use serde_json::{Map, Value as Json, json};
use tf_ast::{Block, Body, Expression, ObjectKey, Template, TemplateElement, UnaryOperator};
use tf_eval::{Evaluator, NoResolver, Scope, Truth, Value};
use tf_linter::ConfigFile;
use tf_semantic::{Mode, Module, Resource};
use tf_span::{FileId, GetSpan, Span};

use crate::projection::{self, Abstraction, Projection, Shape};

/// hcl2json's rendering of a parsed file (Conftest's `parse_config`).
pub fn raw<'a>(ast: &'a tf_ast::File<'a>, text: &str) -> Result<Json, String> {
    let mut r = Renderer {
        text,
        file: FileId(0),
        mode: Mode_::Raw,
        abstractions: Vec::new(),
    };
    r.body(&ast.body, &[], "").map(Json::Object)
}

/// A file of a module instance as a policy sees it under oxtf's semantic
/// contract, and the same for each resource instance on its own (for
/// attributing whole-file results by ablation).
pub struct FileDocument<'m> {
    pub doc: Json,
    /// Every value the policy could not see, anywhere in the file.
    pub abstractions: Vec<Abstraction>,
    pub instances: Vec<InstanceDocument<'m>>,
}

pub struct InstanceDocument<'m> {
    pub resource: &'m Resource,
    /// `{"resource": {type: {name: [body]}}}` with this instance alone.
    pub doc: Json,
}

pub fn evaluated<'m>(cf: &ConfigFile<'m>) -> Result<FileDocument<'m>, String> {
    let mut r = Renderer {
        text: &cf.source.text,
        file: cf.source.id,
        mode: Mode_::Evaluated(cf.module),
        abstractions: Vec::new(),
    };
    let doc = Json::Object(r.body(&cf.ast.body, &[], "")?);
    let mut instances = Vec::new();
    for res in &cf.module.resources {
        if res.span.file != cf.source.id {
            continue;
        }
        let (body, _) = instance_body(res);
        let kind = match res.mode {
            Mode::Managed => "resource",
            Mode::Data => "data",
        };
        instances.push(InstanceDocument {
            resource: res,
            doc: json!({kind: {&*res.ty: {&*res.name: [body]}}}),
        });
    }
    Ok(FileDocument {
        doc,
        abstractions: r.abstractions,
        instances,
    })
}

/// One instance's body: the per-resource projection plus `count` and
/// `for_each` (the analysis keeps them off the body).
fn instance_body(r: &Resource) -> (Map<String, Json>, Vec<Abstraction>) {
    let mut p = projection::project(r, Shape::Hcl);
    for (name, v) in [("count", &r.count), ("for_each", &r.for_each)] {
        if let Some(v) = v
            && let Some(j) = projection::project_value(v, name, &mut p)
        {
            p.attributes.insert(name.into(), j);
        }
    }
    if r.existence != Truth::True {
        p.abstractions.push(Abstraction {
            path: String::new(),
            truth: if r.existence == Truth::Tainted {
                Truth::Tainted
            } else {
                Truth::Unknown
            },
            value: Value::other("resource existence"),
        });
    }
    (p.attributes, p.abstractions)
}

#[derive(Clone, Copy)]
enum Mode_<'m> {
    Raw,
    Evaluated(&'m Module),
}

/// Where in the file an expression sits, for the evaluated rendering.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Site<'s> {
    /// Constant-fold.
    Fold,
    /// Syntax, not a value: hcl2json's text.
    Syntax,
    /// A `locals` entry.
    Local(&'s str),
    /// An argument of `module "<name>"`.
    ModuleArg(&'s str, &'s str),
    /// The `value` of `output "<name>"`.
    Output(&'s str),
}

/// Attributes that hold syntax (references as names, type constraints,
/// conditions), by enclosing block path.
fn syntax(blocks: &[&str], attr: &str) -> bool {
    let last = blocks.last().copied().unwrap_or("");
    matches!(attr, "depends_on")
        || matches!(
            (blocks.first().copied().unwrap_or(""), attr),
            ("variable", "type")
        )
        || matches!(
            (last, attr),
            ("validation", _)
                | ("precondition", _)
                | ("postcondition", _)
                | ("assert", _)
                | ("lifecycle", "ignore_changes" | "replace_triggered_by")
                | ("moved", _)
                | ("removed", "from")
                | ("import", "to")
        )
        || (blocks.len() == 1
            && matches!(blocks[0], "resource" | "data" | "module")
            && attr == "provider")
        || (blocks.len() == 1 && blocks[0] == "module" && attr == "providers")
}

struct Renderer<'t, 'm> {
    text: &'t str,
    file: FileId,
    mode: Mode_<'m>,
    abstractions: Vec<Abstraction>,
}

impl<'t, 'm> Renderer<'t, 'm> {
    /// `ConvertBody`: blocks first, then attributes (an attribute replaces a
    /// block of the same name, as Go map assignment does).
    fn body<'a>(
        &mut self,
        body: &'a Body<'a>,
        blocks: &[&str],
        path: &str,
    ) -> Result<Map<String, Json>, String> {
        let mut out = Map::new();
        for b in body.blocks() {
            self.block(b, &mut out, blocks, path)?;
        }
        for a in body.attributes() {
            let key = a.key.name.to_string();
            let site = match self.mode {
                Mode_::Raw => Site::Fold,
                Mode_::Evaluated(_) => {
                    if syntax(blocks, &key) {
                        Site::Syntax
                    } else {
                        match blocks {
                            ["locals"] => Site::Local(&a.key.name),
                            _ => Site::Fold,
                        }
                    }
                }
            };
            let at = format!("{path}{key}");
            match self.attribute(&a.value, site, &at)? {
                Some(v) => {
                    out.insert(key, v);
                }
                None => {
                    out.remove(&key);
                }
            }
        }
        Ok(out)
    }

    fn block<'a>(
        &mut self,
        b: &'a Block<'a>,
        out: &mut Map<String, Json>,
        blocks: &[&str],
        path: &str,
    ) -> Result<(), String> {
        let ty = &*b.ident.name;
        let labels: Vec<&str> = b.labels.iter().map(|l| &*l.value).collect();
        let mut chain: Vec<&str> = blocks.to_vec();
        chain.push(ty);
        let block_path = format!(
            "{path}{ty}{}",
            labels.iter().map(|l| format!(".{l}")).collect::<String>()
        );
        // Resource and data bodies come from the evaluated instances.
        let value = match (self.mode, blocks.is_empty(), ty, labels.as_slice()) {
            (Mode_::Evaluated(m), true, "resource" | "data", [rty, name]) => {
                let mode = if ty == "resource" {
                    Mode::Managed
                } else {
                    Mode::Data
                };
                match self.instances(m, mode, rty, name, &block_path) {
                    Some(mut body) => {
                        // Meta-arguments and blocks the analysis does not keep.
                        let raw =
                            self.body_syntax_only(&b.body, &chain, &format!("{block_path}."))?;
                        for (k, v) in raw {
                            body.entry(k).or_insert(v);
                        }
                        body
                    }
                    None => return Ok(()), // no instances (`count = 0`)
                }
            }
            (Mode_::Evaluated(_), true, "module", [name]) => {
                self.module_call(&b.body, name, &chain, &format!("{block_path}."))?
            }
            (Mode_::Evaluated(_), true, "output", [name]) => {
                let mut body = self.body(&b.body, &chain, &format!("{block_path}."))?;
                body.remove("value");
                if let Some(v) = self.site_value(Site::Output(name), &format!("{block_path}.value"))
                {
                    body.insert("value".into(), v);
                }
                body
            }
            _ => self.body(&b.body, &chain, &format!("{block_path}."))?,
        };
        // `convertBlock`: each label nests one object deeper.
        let mut slot = out;
        let mut key = ty.to_string();
        for label in &labels {
            let entry = slot
                .entry(key.clone())
                .or_insert_with(|| Json::Object(Map::new()));
            slot = entry.as_object_mut().ok_or_else(|| {
                format!("Unable to convert Block to JSON: {ty}.{}", labels.join("."))
            })?;
            key = label.to_string();
        }
        match slot.get_mut(&key) {
            Some(Json::Array(list)) => list.push(Json::Object(value)),
            Some(_) => {
                return Err(format!(
                    "invalid HCL detected for {key:?} block, cannot have blocks with and without labels"
                ));
            }
            None => {
                slot.insert(key, json!([value]));
            }
        }
        Ok(())
    }

    /// The parts of a resource body the analysis drops: meta-arguments and
    /// `lifecycle`, `provisioner` and `connection` blocks.
    fn body_syntax_only<'a>(
        &mut self,
        body: &'a Body<'a>,
        chain: &[&str],
        path: &str,
    ) -> Result<Map<String, Json>, String> {
        let mut out = Map::new();
        for b in body.blocks() {
            if matches!(&*b.ident.name, "lifecycle" | "provisioner" | "connection") {
                self.block(b, &mut out, chain, path)?;
            }
        }
        for a in body.attributes() {
            let key = &*a.key.name;
            if matches!(key, "depends_on" | "provider")
                && let Some(v) = self.attribute(&a.value, Site::Syntax, &format!("{path}{key}"))?
            {
                out.insert(key.to_string(), v);
            }
        }
        Ok(out)
    }

    fn module_call<'a>(
        &mut self,
        body: &'a Body<'a>,
        name: &str,
        chain: &[&str],
        path: &str,
    ) -> Result<Map<String, Json>, String> {
        let mut out = Map::new();
        for b in body.blocks() {
            self.block(b, &mut out, chain, path)?;
        }
        for a in body.attributes() {
            let key = &*a.key.name;
            let site = if syntax(chain, key) {
                Site::Syntax
            } else {
                Site::ModuleArg(name, key)
            };
            if let Some(v) = self.attribute(&a.value, site, &format!("{path}{key}"))? {
                out.insert(key.to_string(), v);
            }
        }
        Ok(out)
    }

    /// The merged body of every instance of a resource declaration; a key
    /// on which instances disagree is hidden. `None` when there are none.
    fn instances(
        &mut self,
        m: &'m Module,
        mode: Mode,
        ty: &str,
        name: &str,
        path: &str,
    ) -> Option<Map<String, Json>> {
        let insts: Vec<&Resource> = m
            .resources
            .iter()
            .filter(|r| {
                r.mode == mode && *r.ty == *ty && *r.name == *name && r.span.file == self.file
            })
            .collect();
        let (first, rest) = insts.split_first()?;
        let (mut body, abstractions) = instance_body(first);
        self.record(path, abstractions);
        let mut hidden = std::collections::BTreeSet::new();
        for r in rest {
            let (other, abstractions) = instance_body(r);
            self.record(path, abstractions);
            let keys: Vec<String> = body.keys().chain(other.keys()).cloned().collect();
            for k in keys {
                if body.get(&k) != other.get(&k) {
                    body.remove(&k);
                    hidden.insert(k);
                }
            }
        }
        for k in hidden {
            self.abstractions.push(Abstraction {
                path: format!("{path}.{k}"),
                truth: Truth::Unknown,
                value: Value::other("differs between instances"),
            });
        }
        Some(body)
    }

    fn record(&mut self, path: &str, abstractions: Vec<Abstraction>) {
        self.abstractions
            .extend(abstractions.into_iter().map(|mut a| {
                a.path = if a.path.is_empty() {
                    path.to_string()
                } else {
                    format!("{path}.{}", a.path)
                };
                a
            }));
    }

    /// A model value for `site`, Known parts only (the rest recorded).
    fn site_value(&mut self, site: Site<'_>, at: &str) -> Option<Json> {
        let Mode_::Evaluated(m) = self.mode else {
            return None;
        };
        let v = match site {
            Site::Local(name) => m
                .locals
                .iter()
                .find(|l| *l.name == *name)
                .map(|l| l.value.clone()),
            Site::ModuleArg(call, arg) => m
                .module_calls
                .iter()
                .find(|c| *c.name == *call)
                .and_then(|c| c.arguments.iter().find(|(k, _)| **k == *arg))
                .map(|(_, v)| v.clone()),
            Site::Output(name) => m
                .outputs
                .iter()
                .find(|o| *o.name == *name)
                .map(|o| o.value.clone()),
            Site::Fold | Site::Syntax => None,
        }?;
        self.known(&v, at)
    }

    fn known(&mut self, v: &Value, at: &str) -> Option<Json> {
        let mut p = Projection::default();
        let j = projection::project_value(v, at, &mut p);
        self.abstractions.extend(p.abstractions);
        j
    }

    /// An attribute's value, or `None` when it is hidden.
    fn attribute<'e>(
        &mut self,
        e: &'e Expression<'e>,
        site: Site<'_>,
        at: &str,
    ) -> Result<Option<Json>, String> {
        match (self.mode, site) {
            (Mode_::Raw, _) | (Mode_::Evaluated(_), Site::Syntax) => self.expr(e).map(Some),
            (Mode_::Evaluated(m), Site::Fold) => {
                // The analysis's value in this module instance when it has
                // one; else constant folding.
                let v = match m
                    .block_values
                    .get(&tf_span::FileSpan::new(self.file, e.span()))
                {
                    Some(v) => v.clone(),
                    None => Evaluator::new(&NoResolver, self.file).eval(e, Scope::EMPTY),
                };
                Ok(self.known(&v, at))
            }
            (Mode_::Evaluated(_), _) => Ok(self.site_value(site, at)),
        }
    }

    // ---- hcl2json's expression rendering ---------------------------------

    /// `rangeSource`: the source text, plus a following `)` (hcl2json works
    /// around hclsyntax ranges that stop short of it).
    fn source(&self, span: Span) -> &'t str {
        let mut end = span.end as usize;
        if self.text.as_bytes().get(end) == Some(&b')') {
            end += 1;
        }
        &self.text[span.start as usize..end]
    }

    fn wrap(&self, e: &Expression<'_>) -> Json {
        Json::String(format!("${{{}}}", self.source(e.span())))
    }

    fn expr(&self, e: &Expression<'_>) -> Result<Json, String> {
        Ok(match e {
            Expression::Null(_) => Json::Null,
            Expression::Bool(b) => Json::Bool(b.value),
            Expression::Number(n) => number(n.value),
            Expression::String(s) => Json::String(escape(&s.value)),
            Expression::Template(t) => self.template_value(&t.template)?,
            Expression::Heredoc(h) => self.template_value(&h.template)?,
            Expression::Unary(u) => match (&u.operator, &u.operand) {
                (UnaryOperator::Negate, Expression::Number(n)) => number(-n.value),
                (UnaryOperator::Not, Expression::Bool(b)) => Json::Bool(!b.value),
                _ => self.wrap(e),
            },
            Expression::Tuple(t) => Json::Array(
                t.elements
                    .iter()
                    .map(|x| self.expr(x))
                    .collect::<Result<_, _>>()?,
            ),
            Expression::Object(o) => {
                let mut m = Map::new();
                for item in o.items.iter() {
                    let key = match &item.key {
                        ObjectKey::Identifier(id) => id.name.to_string(),
                        ObjectKey::Expression(
                            k @ (Expression::Traversal(_) | Expression::Variable(_)),
                        ) => self.source(k.span()).to_string(),
                        ObjectKey::Expression(k) => self.string_part(k)?,
                    };
                    m.insert(key, self.expr(&item.value)?);
                }
                Json::Object(m)
            }
            _ => self.wrap(e),
        })
    }

    /// `TemplateExpr` / `TemplateWrapExpr`: a lone interpolation is its
    /// expression's rendering; otherwise the parts are concatenated.
    fn template_value(&self, t: &Template<'_>) -> Result<Json, String> {
        if let [TemplateElement::Interpolation(i)] = t.elements.as_slice() {
            return self.expr(&i.expression);
        }
        Ok(Json::String(self.template(t)?))
    }

    fn template(&self, t: &Template<'_>) -> Result<String, String> {
        let els = t.elements.as_slice();
        let mut out = String::new();
        for (i, el) in els.iter().enumerate() {
            match el {
                TemplateElement::Literal(l) => {
                    let mut s: &str = &l.value;
                    if i > 0 && strips_after(&els[i - 1]) {
                        s = s.trim_start();
                    }
                    if els.get(i + 1).is_some_and(strips_before) {
                        s = s.trim_end();
                    }
                    out.push_str(&escape(s));
                }
                TemplateElement::Interpolation(x) => {
                    out.push_str(&self.string_part(&x.expression)?)
                }
                TemplateElement::If(x) => {
                    out.push_str("%{if ");
                    out.push_str(self.source(x.condition.span()));
                    out.push('}');
                    out.push_str(&self.template(&x.then_template)?);
                    if let Some(e) = &x.else_template {
                        let s = self.template(e)?;
                        if !s.is_empty() {
                            out.push_str("%{else}");
                            out.push_str(&s);
                        }
                    }
                    out.push_str("%{endif}");
                }
                TemplateElement::For(x) => {
                    out.push_str("%{for ");
                    if let Some(k) = &x.key_var {
                        out.push_str(&k.name);
                        out.push_str(", ");
                    }
                    out.push_str(&x.value_var.name);
                    out.push_str(" in ");
                    out.push_str(self.source(x.collection.span()));
                    out.push('}');
                    out.push_str(&self.template(&x.template)?);
                    out.push_str("%{endfor}");
                }
            }
        }
        Ok(out)
    }

    /// `convertStringPart`: an expression inside a template.
    fn string_part(&self, e: &Expression<'_>) -> Result<String, String> {
        Ok(match e {
            Expression::Null(_) => "null".into(),
            Expression::Bool(b) => b.value.to_string(),
            Expression::Number(n) => number(n.value).to_string(),
            Expression::String(s) => escape(&s.value),
            Expression::Template(t) => self.template(&t.template)?,
            Expression::Heredoc(h) => self.template(&h.template)?,
            Expression::Conditional(c) => {
                let mut out = format!("%{{if {}}}", self.source(c.condition.span()));
                out.push_str(&self.string_part(&c.true_expr)?);
                let f = self.string_part(&c.false_expr)?;
                if !f.is_empty() {
                    out.push_str("%{else}");
                    out.push_str(&f);
                }
                out.push_str("%{endif}");
                out
            }
            _ => format!("${{{}}}", self.source(e.span())),
        })
    }
}

fn strips_after(el: &TemplateElement<'_>) -> bool {
    match el {
        TemplateElement::Interpolation(i) => i.strip.end,
        TemplateElement::If(x) => x.endif_strip.end,
        TemplateElement::For(x) => x.endfor_strip.end,
        TemplateElement::Literal(_) => false,
    }
}

fn strips_before(el: &TemplateElement<'_>) -> bool {
    match el {
        TemplateElement::Interpolation(i) => i.strip.start,
        TemplateElement::If(x) => x.if_strip.start,
        TemplateElement::For(x) => x.for_strip.start,
        TemplateElement::Literal(_) => false,
    }
}

/// `escapeLiteral`.
fn escape(s: &str) -> String {
    s.replace("${", "$${").replace("%{", "%%{")
}

/// A number as Conftest's document holds it: decoded into a Go `float64`
/// and encoded again, so integral values print without a fraction or
/// exponent (`12345678901234567890` becomes `12345678901234567000`).
fn number(f: f64) -> Json {
    if f.fract() == 0.0 && f.abs() < 1e21 {
        // Go's 'f' formatting: the shortest round-trip digits, then zeros.
        let sci = format!("{:e}", f.abs());
        let (mantissa, exp) = sci.split_once('e').expect("{:e} has an exponent");
        let digits = mantissa.replace('.', "");
        let exp: usize = exp.parse().expect("a nonnegative exponent");
        let text = format!(
            "{}{digits}{}",
            if f < 0.0 { "-" } else { "" },
            "0".repeat(exp + 1 - digits.len())
        );
        if let Ok(n) = text.parse::<i64>() {
            return Json::from(n);
        }
        if let Ok(n) = text.parse::<u64>() {
            return Json::from(n);
        }
    }
    serde_json::Number::from_f64(f).map_or(Json::Null, Json::Number)
}

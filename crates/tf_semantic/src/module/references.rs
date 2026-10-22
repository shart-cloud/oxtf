use super::*;
use tf_ast::{Body, ObjectKey, TemplateElement, TraversalOperator};
use tf_limits::input::InputBudget;

#[cfg(test)]
mod tests;

const IMPLICIT: &[&str] = &["count", "each", "self", "path", "terraform"];

struct RefCollector<'m, 'd> {
    file: FileId,
    origins: &'m crate::compose::Origins,
    from: SymbolRef,
    bound: Vec<&'d str>,
    out: Vec<Reference>,
    vars: &'m HashMap<&'d str, usize>,
    locals: &'m HashMap<&'d str, usize>,
    res: &'m HashMap<(Mode, &'d str, &'d str), usize>,
    calls: &'m HashMap<&'d str, usize>,
    budget: &'m InputBudget,
}

pub(super) fn collect<'a>(def: &mut ModuleDef<'a>, budget: &InputBudget) -> Build<()> {
    tf_eval::collections::admit::<u8>(0, budget)?;
    let mut collector = RefCollector {
        file: FileId(0),
        origins: &def.origins,
        from: SymbolRef::Unresolved(String::new()),
        bound: Vec::new(),
        out: Vec::new(),
        vars: &def.var_index,
        locals: &def.local_index,
        res: &def.res_index,
        calls: &def.call_index,
        budget,
    };
    collector.declarations(def)?;
    assert!(collector.bound.is_empty());
    // Transfer the admitted vector; appending it into a second vector would copy its payload.
    def.references = Arc::new(collector.out);
    Ok(())
}

impl<'d> RefCollector<'_, 'd> {
    fn root(&mut self, root: &str, ops: &[TraversalOperator<'_>], span: Span) -> Build<()> {
        storage::reserve(&mut self.out, 1, self.budget)?;
        let to = self.target(root, ops);
        self.out.push(Reference {
            from: self.from.clone(),
            to,
            at: FileSpan::new(self.file, span),
        });
        assert!(self.out.len() <= self.out.capacity());
        Ok(())
    }

    fn target(&self, root: &str, ops: &[TraversalOperator<'_>]) -> SymbolRef {
        let a0 = ops.first().and_then(|o| o.attr_name());
        let a1 = ops.get(1).and_then(|o| o.attr_name());
        if self.bound.contains(&root) || IMPLICIT.contains(&root) {
            SymbolRef::Implicit(root.to_string())
        } else {
            match (root, a0, a1) {
                ("var", Some(n), _) => {
                    if self.vars.contains_key(n) {
                        SymbolRef::Variable(n.into())
                    } else {
                        SymbolRef::Unresolved(format!("var.{n}"))
                    }
                }
                ("local", Some(n), _) => {
                    if self.locals.contains_key(n) {
                        SymbolRef::Local(n.into())
                    } else {
                        SymbolRef::Unresolved(format!("local.{n}"))
                    }
                }
                ("module", Some(n), _) => {
                    if self.calls.contains_key(n) {
                        SymbolRef::Module(n.into())
                    } else {
                        SymbolRef::Unresolved(format!("module.{n}"))
                    }
                }
                ("data", Some(t), Some(n)) => {
                    if self.res.contains_key(&(Mode::Data, t, n)) {
                        SymbolRef::Data(t.into(), n.into())
                    } else {
                        SymbolRef::Unresolved(format!("data.{t}.{n}"))
                    }
                }
                (t, Some(n), _) if self.res.contains_key(&(Mode::Managed, t, n)) => {
                    SymbolRef::Resource(t.into(), n.into())
                }
                (r, _, _) => SymbolRef::Unresolved(r.to_string()),
            }
        }
    }

    fn scoped(
        &mut self,
        key: Option<&'d str>,
        value: &'d str,
        visit: impl FnOnce(&mut Self) -> Build<()>,
    ) -> Build<()> {
        let start = self.bound.len();
        storage::reserve(&mut self.bound, 1 + usize::from(key.is_some()), self.budget)?;
        if let Some(key) = key {
            self.bound.push(key);
        }
        self.bound.push(value);
        let result = visit(self);
        self.bound.truncate(start);
        assert_eq!(self.bound.len(), start);
        result
    }

    fn expr(&mut self, e: &'d Expression<'d>) -> Build<()> {
        match e {
            Expression::Variable(v) => self.root(&v.name, &[], v.span)?,
            Expression::Traversal(t) => {
                if let Expression::Variable(v) = &t.object {
                    self.root(&v.name, &t.operators, t.span)?;
                } else {
                    self.expr(&t.object)?;
                }
                for op in t.operators.iter() {
                    if let TraversalOperator::Index(ix) = op {
                        self.expr(&ix.index)?;
                    }
                }
            }
            Expression::Template(t) => self.template(&t.template)?,
            Expression::Heredoc(h) => self.template(&h.template)?,
            Expression::FunctionCall(f) => {
                for arg in f.arguments.iter() {
                    self.expr(arg)?;
                }
            }
            Expression::Tuple(t) => {
                for element in t.elements.iter() {
                    self.expr(element)?;
                }
            }
            Expression::Object(o) => {
                for item in o.items.iter() {
                    if let ObjectKey::Expression(key) = &item.key {
                        self.expr(key)?;
                    }
                    self.expr(&item.value)?;
                }
            }
            Expression::For(f) => self.for_expr(f)?,
            Expression::Conditional(c) => {
                self.expr(&c.condition)?;
                self.expr(&c.true_expr)?;
                self.expr(&c.false_expr)?;
            }
            Expression::Unary(u) => self.expr(&u.operand)?,
            Expression::Binary(b) => {
                self.expr(&b.left)?;
                self.expr(&b.right)?;
            }
            Expression::Parenthesized(p) => self.expr(&p.expression)?,
            _ => {}
        }
        Ok(())
    }

    fn for_expr(&mut self, f: &'d tf_ast::ForExpr<'d>) -> Build<()> {
        self.expr(&f.collection)?;
        self.scoped(
            f.key_var.as_ref().map(|k| k.name.as_str()),
            &f.value_var.name,
            |c| {
                if let Some(key) = &f.key_expr {
                    c.expr(key)?;
                }
                c.expr(&f.value_expr)?;
                if let Some(condition) = &f.condition {
                    c.expr(condition)?;
                }
                Ok(())
            },
        )
    }

    fn template(&mut self, t: &'d tf_ast::Template<'d>) -> Build<()> {
        for el in t.elements.iter() {
            match el {
                TemplateElement::Literal(_) => {}
                TemplateElement::Interpolation(i) => self.expr(&i.expression)?,
                TemplateElement::If(i) => {
                    self.expr(&i.condition)?;
                    self.template(&i.then_template)?;
                    if let Some(e) = &i.else_template {
                        self.template(e)?;
                    }
                }
                TemplateElement::For(f) => {
                    self.expr(&f.collection)?;
                    self.scoped(
                        f.key_var.as_ref().map(|k| k.name.as_str()),
                        &f.value_var.name,
                        |c| c.template(&f.template),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn body(&mut self, body: &'d Body<'d>) -> Build<()> {
        let file = self.file;
        let result = self.body_items(body, file);
        self.file = file;
        result
    }

    fn body_items(&mut self, body: &'d Body<'d>, file: FileId) -> Build<()> {
        for attr in body.attributes() {
            self.file = self.origins.file(attr, file);
            self.expr(&attr.value)?;
        }
        for block in body.blocks() {
            self.file = self.origins.file(block, file);
            if block.block_type() == "dynamic" {
                let iterator = block
                    .body
                    .find_attribute("iterator")
                    .and_then(|a| match &a.value {
                        Expression::Variable(v) => Some(v.name.as_str()),
                        _ => None,
                    })
                    .or(block.label(0))
                    .unwrap_or("");
                if let Some(each) = block.body.find_attribute("for_each") {
                    self.expr(&each.value)?;
                }
                self.scoped(None, iterator, |c| {
                    if let Some(content) = block.body.find_block("content") {
                        c.body(&content.body)?;
                    }
                    Ok(())
                })?;
            } else {
                self.body(&block.body)?;
            }
        }
        Ok(())
    }

    fn declarations(&mut self, def: &ModuleDef<'d>) -> Build<()> {
        for variable in &def.variables {
            self.file = variable.file;
            self.from = SymbolRef::Variable(variable.name.into());
            if let Some(default) = variable.default {
                self.file = def.origins.file(default, variable.file);
                self.expr(&default.value)?;
            }
        }
        for local in &def.locals {
            self.file = local.file;
            self.from = SymbolRef::Local(local.name.into());
            self.expr(&local.attr.value)?;
        }
        for resource in &def.resources {
            self.file = resource.file;
            self.from = match resource.mode {
                Mode::Managed => SymbolRef::Resource(resource.ty.into(), resource.name.into()),
                Mode::Data => SymbolRef::Data(resource.ty.into(), resource.name.into()),
            };
            self.body(&resource.block.body)?;
        }
        for module in &def.module_calls {
            self.file = module.file;
            self.from = SymbolRef::Module(module.name.into());
            self.body(&module.block.body)?;
        }
        for output in &def.outputs {
            self.file = output.file;
            self.from = SymbolRef::Output(output.name.into());
            self.body(&output.block.body)?;
        }
        Ok(())
    }
}

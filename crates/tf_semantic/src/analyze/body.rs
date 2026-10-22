use super::*;

type Schema = Option<&'static tf_schema::Block<'static>>;

struct NestedBody<'a> {
    name: &'a str,
    body: model::Body,
    dynamic: bool,
    existence: Truth,
    span: FileSpan,
    as_attr: bool,
}

impl<'a, 'o> Analyzer<'a, 'o> {
    pub(super) fn eval_body(
        &self,
        ctx: &BodyCtx<'a>,
        body: &'a Body<'a>,
        schema: Schema,
        sc: Scope<'_>,
        path: &str,
        top: bool,
    ) -> Build<model::Body> {
        let mut out = model::Body {
            span: FileSpan::new(ctx.origins.file(body, ctx.file), body.span),
            attrs: Vec::new(),
            blocks: Vec::new(),
        };
        let result = (|| {
            for attr in body.attributes() {
                if top && META_ATTRS.contains(&attr.key.name.as_str()) {
                    continue;
                }
                storage::reserve(&mut out.attrs, 1, self.budget.storage())?;
                out.attrs
                    .push(self.eval_attribute(ctx, attr, schema, sc, path));
            }
            let nested = self.eval_blocks(ctx, body, schema, sc, path, top)?;
            self.group_blocks(&mut out, nested)?;
            collections::admit::<u8>(0, self.budget.storage())
        })();
        result.map_err(|stopped| body_failure(stopped, &out))?;
        Ok(out)
    }

    fn eval_attribute(
        &self,
        ctx: &BodyCtx<'a>,
        attr: &'a Attribute<'a>,
        schema: Schema,
        sc: Scope<'_>,
        path: &str,
    ) -> Attr {
        let file = ctx.origins.file(attr, ctx.file);
        let name = attr.key.name.as_str();
        let at = FileSpan::new(file, attr.span);
        let mut value = self.eval(ctx.inst, file, &attr.value, sc).push(
            Step::new(
                StepKind::Attribute,
                at,
                format!("{} {path}{name}", ctx.addr),
            )
            .with_resource(ctx.base.clone())
            .with_attribute(format!("{path}{name}")),
        );
        if schema
            .and_then(|s| s.attribute(name))
            .is_some_and(|a| a.is_sensitive())
        {
            value = value.sensitive();
        }
        self.mark_sensitive(&value);
        self.report_limits(&value, at);
        value = self.strict_bool(ctx, schema, name, path, at, value);
        self.observe(ctx, file, path, name, &attr.value, &value);
        Attr {
            name: name.into(),
            value,
            span: at,
            from_blocks: false,
        }
    }

    fn strict_bool(
        &self,
        ctx: &BodyCtx<'a>,
        schema: Schema,
        name: &str,
        path: &str,
        at: FileSpan,
        value: Value,
    ) -> Value {
        if ctx.strict_bool
            && schema
                .and_then(|s| s.attribute(name))
                .is_some_and(|attr| attr.is_bool())
            && let Some(text @ ("true" | "false")) = value.as_str()
        {
            let message = if value.is_sensitive() {
                format!(
                    concat!(
                        "{} {path}{name}: sensitive string where the AWS provider schema ",
                        "requires a bool"
                    ),
                    ctx.addr,
                    path = path,
                    name = name
                )
            } else {
                format!(
                    concat!(
                        "{} {path}{name}: string \"{text}\" where the AWS provider schema ",
                        "requires a bool; Terraform converts it, but write {text} without quotes"
                    ),
                    ctx.addr,
                    path = path,
                    name = name,
                    text = text
                )
            };
            self.diag(DiagSeverity::Warning, "strict-bool", message, Some(at));
            return Value::bool(text == "true").with_prov(value.prov.clone());
        }
        value
    }

    fn eval_blocks(
        &self,
        ctx: &BodyCtx<'a>,
        body: &'a Body<'a>,
        schema: Schema,
        sc: Scope<'_>,
        path: &str,
        top: bool,
    ) -> Build<Vec<NestedBody<'a>>> {
        let mut out = Buffer::new(self.budget.storage());
        for block in body.blocks() {
            let name = block.block_type();
            if top && META_BLOCKS.contains(&name) {
                continue;
            }
            if name == "dynamic" {
                self.dynamic_block(ctx, block, schema, sc, path, &mut out)?;
            } else {
                let (nested, as_attr) = nested_schema(schema, name);
                out.reserve(1)?;
                let body = self.eval_body(
                    ctx,
                    &block.body,
                    nested,
                    sc,
                    &format!("{path}{name}."),
                    false,
                )?;
                out.push(NestedBody {
                    name,
                    body,
                    dynamic: false,
                    existence: Truth::True,
                    span: FileSpan::new(ctx.origins.file(block, ctx.file), block.span),
                    as_attr,
                })?;
            }
        }
        Ok(out.finish())
    }

    fn dynamic_block(
        &self,
        ctx: &BodyCtx<'a>,
        block: &'a tf_ast::Block<'a>,
        schema: Schema,
        sc: Scope<'_>,
        path: &str,
        out: &mut Buffer<'_, NestedBody<'a>>,
    ) -> Build<()> {
        let Some(name) = block.label(0) else {
            return Ok(());
        };
        let Some(content) = block.body.find_block("content") else {
            return Ok(());
        };
        let Some(each) = block.body.find_attribute("for_each") else {
            return Ok(());
        };
        let iterator = block
            .body
            .find_attribute("iterator")
            .and_then(|attr| match &attr.value {
                Expression::Variable(v) => Some(v.name.as_str()),
                _ => None,
            })
            .unwrap_or(name);
        let file = ctx.origins.file(each, ctx.file);
        let at = FileSpan::new(file, each.span);
        let value = self.eval(ctx.inst, file, &each.value, sc).push(Step::new(
            StepKind::Iteration,
            at,
            format!("{} dynamic \"{name}\" for_each", ctx.addr),
        ));
        self.report_limits(&value, at);
        let (nested, as_attr) = nested_schema(schema, name);
        let span = FileSpan::new(ctx.origins.file(block, ctx.file), block.span);
        let count = collection_items(&value).map_or(1, |items| {
            if items.len() <= self.opts.max_expand {
                items.len()
            } else {
                1
            }
        });
        out.reserve(count)
            .map_err(|stopped| failure(stopped, [&value]))?;
        let mut append = |binding: Value, existence| -> Build<()> {
            out.reserve(1)?;
            let body = sc.with(iterator, &binding, |scope| {
                self.eval_body(
                    ctx,
                    &content.body,
                    nested,
                    scope,
                    &format!("{path}{name}."),
                    false,
                )
            })?;
            out.push(NestedBody {
                name,
                body,
                dynamic: true,
                existence,
                span,
                as_attr,
            })
        };
        self.dynamic_bindings(&value, at, &mut append)
    }

    fn dynamic_bindings(
        &self,
        value: &Value,
        at: FileSpan,
        append: &mut impl FnMut(Value, Truth) -> Build<()>,
    ) -> Build<()> {
        let result = (|| {
            match collection_items(value) {
                Some(items) if items.len() <= self.opts.max_expand => {
                    for (key, value) in items {
                        append(self.obj2(key, value)?, Truth::True)?;
                    }
                }
                other => {
                    if other.is_none() && value.is_null() {
                        return Ok(());
                    }
                    let (binding, existence) = self.dynamic_unknown(value, other.is_some(), at);
                    append(self.obj2(binding.clone(), binding)?, existence)?;
                }
            }
            Ok(())
        })();
        result.map_err(|stopped| failure(stopped, [value]))
    }

    fn dynamic_unknown(&self, value: &Value, too_large: bool, at: FileSpan) -> (Value, Truth) {
        if too_large {
            self.diag(
                DiagSeverity::Warning,
                "coverage-expansion",
                format!(
                    "dynamic block exceeds the {} instance limit",
                    self.opts.max_expand
                ),
                Some(at),
            );
        }
        match (&value.kind, tf_eval::truth::uncertainty(value)) {
            (Kind::Tainted(_), _) => (value.clone(), Truth::Tainted),
            (_, Truth::Tainted) => (
                Value::tainted("(conditional for_each)").with_prov(value.prov.clone()),
                Truth::Tainted,
            ),
            _ if too_large => (
                Value::other("dynamic iterator (too many elements)"),
                Truth::True,
            ),
            _ => (
                Value::other("dynamic iterator (for_each not known)").with_prov(value.prov.clone()),
                Truth::Unknown,
            ),
        }
    }

    fn group_blocks(&self, out: &mut model::Body, nested: Vec<NestedBody<'a>>) -> Build<()> {
        let mut grouped: Buffer<'_, (&str, Vec<Value>, FileSpan)> =
            Buffer::new(self.budget.storage());
        for block in nested {
            if block.as_attr {
                let index = grouped.iter().position(|group| group.0 == block.name);
                let index = match index {
                    Some(index) => index,
                    None => {
                        grouped.push((block.name, Vec::new(), block.span))?;
                        grouped.len() - 1
                    }
                };
                storage::reserve(&mut grouped[index].1, 1, self.budget.storage())?;
                let value = self.block_object(&block)?;
                grouped[index].1.push(value);
            } else {
                storage::reserve(&mut out.blocks, 1, self.budget.storage())?;
                out.blocks.push(model::Block {
                    ty: block.name.into(),
                    body: block.body,
                    dynamic: block.dynamic,
                    existence: block.existence,
                });
            }
        }
        for (name, values, span) in grouped.finish() {
            if out.attrs.iter().any(|attr| &*attr.name == name) {
                continue;
            }
            storage::reserve(&mut out.attrs, 1, self.budget.storage())?;
            out.attrs.push(Attr {
                name: name.into(),
                value: Value::list(values),
                span,
                from_blocks: true,
            });
        }
        Ok(())
    }

    fn block_object(&self, block: &NestedBody<'a>) -> Build<Value> {
        let result = (|| {
            let value = body_to_object(&block.body, self.budget.storage())?;
            if block.existence == Truth::True {
                return Ok(value);
            }
            let choices =
                collections::collect([value, Value::null()].into_iter(), self.budget.storage())?;
            storage::alternatives(
                choices,
                block.existence == Truth::Tainted,
                self.budget.storage(),
            )
        })();
        result.map_err(|stopped| body_failure(stopped, &block.body))
    }
}

/// Existing AST depth admission bounds this traversal even after storage refuses
/// growth. The fixed iterator stack preserves evidence without allocating scratch.
pub(super) fn body_failure(mut stopped: Value, body: &model::Body) -> Value {
    let mut stack: [std::slice::Iter<'_, model::Block>; tf_limits::AST_DEPTH_MAX + 1] =
        std::array::from_fn(|_| [].iter());
    stopped = failure(stopped, body.attrs.iter().map(|attr| &attr.value));
    let mut depth = 0;
    stack[depth] = body.blocks.iter();
    loop {
        match stack[depth].next() {
            Some(block) => {
                stopped = failure(stopped, block.body.attrs.iter().map(|attr| &attr.value));
                depth += 1;
                assert!(depth < stack.len());
                stack[depth] = block.body.blocks.iter();
            }
            None if depth == 0 => break,
            None => depth -= 1,
        }
    }
    stopped
}

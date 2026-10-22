//! Contextual Terraform functions share the scan's file snapshot and overlay.
use std::path::Path;

use tf_ast::{Expression, TraversalOperator, Visit};
use tf_eval::prov::{Prov, Step, StepKind};
use tf_eval::{Evaluator, Kind, Known, Resolver, Scope, Value, functions};
use tf_span::{FileSpan, Span};

use crate::source::{FileTable, normalize};

fn input_error(error: std::io::Error, name: &str) -> Value {
    match tf_limits::input::exhaustion(&error) {
        Some(limit) => Value::limit(limit.to_string()),
        None => Value::error(format!("{name}: file could not be read")),
    }
}

pub(crate) fn call(
    files: &FileTable,
    root: &Path,
    boundary: Option<&Path>,
    name: &str,
    args: Vec<Value>,
    in_template: bool,
    budget: &tf_eval::EvaluationBudget,
) -> Value {
    if !functions::CONTEXTUAL.contains(&name) {
        return functions::call_budgeted(name, args, budget.storage());
    }
    functions::call_with_budget(name, args, budget.storage(), &|name, args| match call_one(
        files,
        root,
        boundary,
        name,
        args,
        in_template,
        budget,
    ) {
        Ok(v) | Err(v) => v,
    })
}

fn call_one(
    files: &FileTable,
    root: &Path,
    boundary: Option<&Path>,
    name: &str,
    args: &[Value],
    in_template: bool,
    budget: &tf_eval::EvaluationBudget,
) -> Result<Value, Value> {
    if name == "templatefile" && in_template {
        return Err(Value::error(
            "templatefile: recursive template calls are not allowed",
        ));
    }
    if args.len() != if name == "templatefile" { 2 } else { 1 } {
        return Err(Value::error(format!("{name}: wrong number of arguments")));
    }
    let path = tf_eval::text::coerce(&args[0], budget.storage())?;
    let path = normalize(&root.join(path.as_ref()));
    if name == "abspath" {
        let absolute = std::path::absolute(&path)
            .map_err(|_| Value::error("abspath: current directory unavailable"))?;
        let normalized = normalize(&absolute);
        // Lossy OS-path conversion may expand a non-UTF-8 byte to three bytes.
        budget
            .storage()
            .admit_text((normalized.as_os_str().len() as u64).saturating_mul(3))
            .map_err(|e| Value::limit(e.to_string()))?;
        return Ok(Value::string(tf_eval::text::copy(
            &normalized.to_string_lossy(),
            budget.storage(),
        )?));
    }
    if boundary.is_some_and(|b| {
        !files
            .canonical_path(&path)
            .starts_with(files.canonical_path(b))
    }) {
        return Err(Value::limit("file read outside fetched package"));
    }
    let bytes = files
        .read_bytes(&path)
        .map_err(|error| input_error(error, name))?;
    if name == "filebase64" {
        return Ok(Value::string(functions::b64encode_budgeted(
            &bytes,
            budget.storage(),
        )?));
    }
    if let Some(hash) = name.strip_prefix("file")
        && matches!(
            hash,
            "md5" | "sha1" | "sha256" | "sha512" | "base64sha256" | "base64sha512"
        )
    {
        return functions::hash_budgeted(hash, &bytes, budget.storage());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Value::error(format!("{name}: file is not UTF-8")))?;
    let source = files
        .load(&path)
        .map_err(|error| input_error(error, name))?;
    let at = FileSpan::new(source.id, Span::new(0, text.len() as u32));
    let provenance = Prov::EMPTY
        .push(Step::new(StepKind::Other, at, name))
        .joined(&args[0].prov);
    if name == "file" {
        return Ok(
            Value::string(tf_eval::text::copy(text, budget.storage())?).with_prov(provenance)
        );
    }
    let vars = match &args[1].kind {
        Kind::Known(Known::Object(vars)) => vars,
        Kind::Known(_) => return Err(Value::error("templatefile: vars must be an object")),
        _ => return Err(args[1].clone()),
    };
    let allocator = files.allocator();
    let (expression, errors) = tf_parser::parse_template(&allocator, text);
    if let Some(error) = allocator.budget().exhaustion() {
        return Err(Value::limit(error.to_string()));
    }
    if errors
        .iter()
        .any(|e| matches!(e.kind, tf_parser::DiagnosticKind::Limit(_)))
    {
        return Err(Value::limit("templatefile: template nesting exceeds limit"));
    }
    if !errors.is_empty() {
        return Err(Value::error("templatefile: invalid template syntax"));
    }
    for key in vars.keys() {
        let (e, errors) = tf_parser::parse_expression(&allocator, key);
        if let Some(error) = allocator.budget().exhaustion() {
            return Err(Value::limit(error.to_string()));
        }
        if !errors.is_empty()
            || !(matches!(e, Some(Expression::Variable(_)))
                || matches!(key.as_ref(), "true" | "false" | "null"))
        {
            return Err(Value::error("templatefile: invalid variable name"));
        }
    }
    let expression = expression.expect("successful template parse has an expression");
    let mut references = TemplateReferences {
        vars,
        bound: Vec::new(),
        missing: false,
    };
    references.visit_expression(&expression);
    if references.missing {
        return Err(Value::error("templatefile: missing template variable"));
    }
    let resolver = TemplateResolver {
        files,
        root,
        boundary,
        vars: &args[1],
    };
    let result =
        Evaluator::with_budget(&resolver, source.id, budget).eval(&expression, Scope::EMPTY);
    Ok(result.clone().with_prov(result.prov.joined(&provenance)))
}

/// Terraform validates every free template variable, even in an unused branch.
struct TemplateReferences<'v, 'a> {
    vars: &'v tf_eval::Map,
    bound: Vec<&'a str>,
    missing: bool,
}

impl<'a> Visit<'a> for TemplateReferences<'_, 'a> {
    fn visit_variable_expr(&mut self, v: &'a tf_ast::VariableExpr<'a>) {
        self.missing |=
            !self.bound.contains(&v.name.as_str()) && !self.vars.contains_key(v.name.as_str());
    }

    fn visit_for_expr(&mut self, f: &'a tf_ast::ForExpr<'a>) {
        self.visit_expression(&f.collection);
        let n = self.bound.len();
        if let Some(key) = &f.key_var {
            self.bound.push(key.name.as_str());
        }
        self.bound.push(f.value_var.name.as_str());
        if let Some(key) = &f.key_expr {
            self.visit_expression(key);
        }
        self.visit_expression(&f.value_expr);
        if let Some(condition) = &f.condition {
            self.visit_expression(condition);
        }
        self.bound.truncate(n);
    }

    fn visit_template_for(&mut self, f: &'a tf_ast::TemplateFor<'a>) {
        self.visit_expression(&f.collection);
        let n = self.bound.len();
        if let Some(key) = &f.key_var {
            self.bound.push(key.name.as_str());
        }
        self.bound.push(f.value_var.name.as_str());
        self.visit_template(&f.template);
        self.bound.truncate(n);
    }
}

struct TemplateResolver<'a> {
    files: &'a FileTable,
    root: &'a Path,
    boundary: Option<&'a Path>,
    vars: &'a Value,
}

impl<'a> Resolver<'a> for TemplateResolver<'_> {
    fn resolve(
        &self,
        _: &Evaluator<'_, 'a>,
        _: Scope<'_>,
        root: &'a str,
        _: Span,
        _: &'a [TraversalOperator<'a>],
    ) -> (Value, usize) {
        (
            self.vars
                .as_object()
                .and_then(|vars| vars.get(root))
                .map(|value| value.child_of(self.vars))
                .unwrap_or_else(|| Value::error("templatefile: missing template variable")),
            0,
        )
    }

    fn call(&self, name: &str, args: Vec<Value>, budget: &tf_eval::EvaluationBudget) -> Value {
        call(
            self.files,
            self.root,
            self.boundary,
            name,
            args,
            true,
            budget,
        )
    }
}

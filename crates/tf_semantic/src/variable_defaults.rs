//! Conversion of concrete variable defaults during override loading. Each
//! override consumes the previous converted value, as Terraform's loader does.
use crate::default_budget::{DefaultContext, DefaultError};
use crate::source::SourceFile;
use tf_ast::{Block, Expression};
use tf_eval::{Evaluator, Kind, Known, Map, NoResolver, Scope, Value};
use tf_span::GetSpan;

mod common_type;
mod conversion;
use common_type::CommonType;
use conversion::convert;

#[cfg(test)]
mod tests;

/// Evaluation uses shared list/object values, but override conversion must
/// retain Terraform's concrete collection types between declarations.
pub struct DefaultValue {
    pub value: Value,
    ty: CommonType,
}

impl DefaultValue {
    pub fn clone_with_context(&self, cx: DefaultContext<'_>) -> Result<Self, DefaultError> {
        Ok(Self {
            value: self.value.clone(),
            ty: self.ty.clone_with_context(cx)?,
        })
    }
    pub fn literal(value: Value, cx: DefaultContext<'_>) -> Result<Self, DefaultError> {
        let ty = CommonType::infer(&[&value], None, cx)?;
        Ok(Self { value, ty })
    }

    pub fn failed(error: DefaultError) -> Self {
        let value = match error {
            DefaultError::Invalid => Value::error("invalid variable default"),
            DefaultError::Limit => {
                Value::limit("module default preparation exceeded its allowance")
            }
        };
        Self {
            value,
            ty: CommonType::Null,
        }
    }
}

/// Terraform retains the original declaration's optional defaults when an
/// override replaces its type constraint. Keep this tree independent of the
/// composed AST and apply it to runtime inputs before their final conversion.
#[derive(Default)]
pub struct TypeDefaults {
    defaults: Map,
    children: std::collections::BTreeMap<String, Self>,
}

impl TypeDefaults {
    pub(crate) fn from_type(
        ty: &Expression<'_>,
        cx: DefaultContext<'_>,
    ) -> Result<Self, DefaultError> {
        cx.charge(1)?;
        let mut out = Self::default();
        let Expression::FunctionCall(f) = ty.without_parens() else {
            return Ok(out);
        };
        match (f.name.name.as_str(), f.arguments.first()) {
            ("object", Some(Expression::Object(o))) => {
                for item in o.items.iter() {
                    let key = item.key.as_static_str().ok_or(DefaultError::Invalid)?;
                    let inner = optional_type(&item.value);
                    if !out.children.contains_key(key) {
                        cx.admit::<(String, Self)>(1)?;
                    }
                    if let Expression::FunctionCall(optional) = item.value.without_parens()
                        && optional.name.name == "optional"
                        && let Some(default) = optional.arguments.get(1)
                    {
                        if !out.defaults.contains_key(key) {
                            cx.admit::<(std::sync::Arc<str>, Value)>(1)?;
                        }
                        let value = cx.at_expression(default).eval_static(default)?;
                        out.defaults
                            .insert(key.into(), convert(&value, inner, true, cx)?);
                    }
                    out.children.insert(key.into(), Self::from_type(inner, cx)?);
                }
            }
            ("tuple", Some(Expression::Tuple(t))) => {
                cx.admit::<(String, Self)>(t.elements.len())?;
                for (i, ty) in t.elements.iter().enumerate() {
                    out.children.insert(i.to_string(), Self::from_type(ty, cx)?);
                }
            }
            ("list" | "set" | "map", Some(element)) => {
                cx.admit::<(String, Self)>(1)?;
                out.children
                    .insert(String::new(), Self::from_type(element, cx)?);
            }
            _ => {}
        }
        Ok(out)
    }

    pub(crate) fn apply(
        &self,
        value: &Value,
        cx: crate::input_conversion::InputContext<'_>,
    ) -> Result<Value, Value> {
        use crate::input_conversion::{collect_list, retain_input};
        let result = cx.charge(1).and_then(|()| match &value.kind {
            Kind::Known(Known::List(items)) => {
                collect_list(items, cx, |i, v| self.apply_child(&i.to_string(), v, cx))
            }
            Kind::Known(Known::Object(items)) => self.apply_object(items, cx),
            _ => Ok(value.clone()),
        });
        retain_input(value, result)
    }

    fn apply_object(
        &self,
        items: &Map,
        cx: crate::input_conversion::InputContext<'_>,
    ) -> Result<Value, Value> {
        use crate::input_conversion::retain_input;
        cx.charge(items.len())?;
        cx.charge(self.defaults.len())?;
        cx.admit_map(items.len())?;
        let mut items = items.clone();
        for (key, default) in &self.defaults {
            match items.get(key) {
                Some(v) if !v.is_null() => continue,
                Some(v) => {
                    items.insert(key.clone(), default.child_of(v));
                }
                None => {
                    cx.admit_map(1)?;
                    items.insert(key.clone(), default.clone());
                }
            }
        }
        let count = items.len();
        cx.charge(count)?;
        cx.admit_map(count)?;
        let mut out = Map::new();
        for (key, value) in items {
            match self.apply_child(&key, &value, cx) {
                Ok(value) => {
                    out.insert(key, value);
                }
                Err(stopped) => return retain_input(&Value::object(out), Err(stopped)),
            }
        }
        assert_eq!(out.len(), count);
        Ok(Value::object(out))
    }

    fn apply_child(
        &self,
        key: &str,
        value: &Value,
        cx: crate::input_conversion::InputContext<'_>,
    ) -> Result<Value, Value> {
        match self.children.get(key).or_else(|| self.children.get("")) {
            Some(defaults) => defaults.apply(value, cx),
            None => Ok(value.clone()),
        }
    }
}

pub fn literal(
    block: &Block<'_>,
    file: &SourceFile,
    cx: DefaultContext<'_>,
) -> Result<Option<Value>, DefaultError> {
    let Some(attr) = block.body.find_attribute("default") else {
        return Ok(None);
    };
    cx.check()?;
    if file.path.extension().is_some_and(|e| e == "json") {
        return cx
            .at_expression(&attr.value)
            .eval_static(&attr.value)
            .map(Some);
    }
    // Composition moves AST nodes, so evaluation borrows a short-lived reparse.
    let alloc = file.allocator();
    let source = attr.value.span().source_text(&file.text);
    let (expr, errors) = tf_parser::parse_expression(&alloc, source);
    if errors
        .iter()
        .any(|error| error.kind == tf_parser::DiagnosticKind::Syntax)
    {
        return Err(DefaultError::Invalid);
    }
    if !errors.is_empty() {
        return Err(DefaultError::Limit);
    }
    let evaluator = Evaluator::with_budget(&NoResolver, file.id, cx.budget);
    let value = evaluator.eval(&expr.ok_or(DefaultError::Invalid)?, Scope::EMPTY);
    cx.budget
        .locate_limit(tf_span::FileSpan::new(file.id, attr.span));
    cx.evaluated(value).map(Some)
}

pub fn convert_default(
    default: DefaultValue,
    block: &Block<'_>,
    apply_defaults: bool,
    cx: DefaultContext<'_>,
) -> Result<DefaultValue, DefaultError> {
    cx.charge(1)?;
    let value = &default.value;
    if !value.is_wholly_known() {
        return Err(DefaultError::Invalid);
    }
    if value.is_null()
        && block
            .body
            .find_attribute("nullable")
            .is_some_and(|a| matches!(&a.value, Expression::Bool(b) if !b.value))
    {
        return Err(DefaultError::Invalid);
    }
    match block.body.find_attribute("type") {
        Some(ty) => {
            default.ty.check_conversion(&ty.value, cx)?;
            let value = convert(value, &ty.value, apply_defaults, cx)?;
            let ty = CommonType::infer_typed(&[&value], Some(&ty.value), &[Some(&default.ty)], cx)?;
            Ok(DefaultValue { value, ty })
        }
        None => Ok(default),
    }
}

pub fn valid_type(ty: &Expression<'_>) -> bool {
    match ty.without_parens() {
        Expression::Variable(v) => matches!(
            v.name.as_str(),
            "any" | "bool" | "number" | "string" | "list" | "map"
        ),
        Expression::FunctionCall(f) if f.arguments.len() == 1 => {
            match (f.name.name.as_str(), &f.arguments[0]) {
                ("list" | "set" | "map", element) => valid_type(element),
                ("tuple", Expression::Tuple(t)) => t.elements.iter().all(valid_type),
                ("object", Expression::Object(o)) => o.items.iter().all(|i| {
                    i.key.as_static_str().is_some()
                        && match i.value.without_parens() {
                            Expression::FunctionCall(f) if f.name.name == "optional" => {
                                (1..=2).contains(&f.arguments.len()) && valid_type(&f.arguments[0])
                            }
                            ty => valid_type(ty),
                        }
                }),
                _ => false,
            }
        }
        _ => false,
    }
}

fn optional_type<'a, 'v>(ty: &'v Expression<'a>) -> &'v Expression<'a> {
    match ty.without_parens() {
        Expression::FunctionCall(f) if f.name.name == "optional" => {
            f.arguments.first().unwrap_or(ty)
        }
        _ => ty,
    }
}

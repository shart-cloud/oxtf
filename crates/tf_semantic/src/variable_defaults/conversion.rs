use super::common_type::CommonType;
use crate::default_budget::{DefaultContext, DefaultError};
use tf_ast::{Expression, Object, ObjectItem};
use tf_eval::{Kind, Known, Map, Value};

pub(super) fn convert(
    value: &Value,
    ty: &Expression<'_>,
    apply_defaults: bool,
    cx: DefaultContext<'_>,
) -> Result<Value, DefaultError> {
    cx.charge(1)?;
    if value.is_null() {
        return Ok(value.clone());
    }
    let converted = match ty.without_parens() {
        Expression::Variable(t) => primitive(value, t.name.as_str(), ty, cx)?,
        Expression::FunctionCall(f) if f.arguments.len() == 1 => collection(
            value,
            f.name.name.as_str(),
            &f.arguments[0],
            apply_defaults,
            cx,
        )?,
        _ => return Err(DefaultError::Invalid),
    };
    Ok(converted.with_prov(value.prov.clone()))
}

fn primitive(
    value: &Value,
    name: &str,
    ty: &Expression<'_>,
    cx: DefaultContext<'_>,
) -> Result<Value, DefaultError> {
    match (name, &value.kind) {
        ("any", _)
        | ("bool", Kind::Known(Known::Bool(_)))
        | ("number", Kind::Known(Known::Number(_)))
        | ("string", Kind::Known(Known::String(_))) => Ok(value.clone()),
        ("list", Kind::Known(Known::List(_))) | ("map", Kind::Known(Known::Object(_))) => {
            CommonType::infer(&[value], Some(ty), cx)?.convert(value, cx)
        }
        ("bool", Kind::Known(Known::String(s))) if matches!(s.as_ref(), "true" | "false") => {
            Ok(Value::bool(s.as_ref() == "true"))
        }
        ("number", Kind::Known(Known::String(s))) => {
            let n: f64 = s.trim().parse().map_err(|_| DefaultError::Invalid)?;
            if !n.is_finite() {
                return Err(DefaultError::Invalid);
            }
            Ok(Value::number(n))
        }
        ("string", Kind::Known(Known::Bool(_) | Known::Number(_))) => {
            Ok(Value::string(cx.string(value)?))
        }
        _ => Err(DefaultError::Invalid),
    }
}

fn collection(
    value: &Value,
    name: &str,
    arg: &Expression<'_>,
    apply_defaults: bool,
    cx: DefaultContext<'_>,
) -> Result<Value, DefaultError> {
    match (name, &value.kind, arg) {
        ("list" | "set", Kind::Known(Known::List(values)), _) => {
            let mut result =
                cx.try_collect(values.iter().map(|v| convert(v, arg, apply_defaults, cx)))?;
            unify_elements(&mut result, arg, cx)?;
            if name == "set" {
                unique(&mut result, cx)?;
            }
            Ok(Value::list(result))
        }
        ("map", Kind::Known(Known::Object(values)), _) => {
            let mut converted =
                cx.try_collect(values.values().map(|v| convert(v, arg, apply_defaults, cx)))?;
            unify_elements(&mut converted, arg, cx)?;
            Ok(Value::object(
                cx.map(values.keys().cloned().zip(converted).map(Ok))?,
            ))
        }
        ("tuple", Kind::Known(Known::List(values)), Expression::Tuple(types))
            if values.len() == types.elements.len() =>
        {
            Ok(Value::list(
                cx.try_collect(
                    values
                        .iter()
                        .zip(types.elements.iter())
                        .map(|(v, t)| convert(v, t, apply_defaults, cx)),
                )?,
            ))
        }
        ("object", Kind::Known(Known::Object(values)), Expression::Object(types)) => {
            object(values, types, apply_defaults, cx)
        }
        _ => Err(DefaultError::Invalid),
    }
}

fn object(
    values: &Map,
    types: &Object<'_>,
    apply_defaults: bool,
    cx: DefaultContext<'_>,
) -> Result<Value, DefaultError> {
    let fields = cx.map(types.items.iter().map(|item| {
        let key = item.key.as_static_str().ok_or(DefaultError::Invalid)?;
        let value = field(values.get(key), item, apply_defaults, cx)?;
        Ok((key.into(), value))
    }))?;
    Ok(Value::object(fields))
}

fn field(
    value: Option<&Value>,
    item: &ObjectItem<'_>,
    apply_defaults: bool,
    cx: DefaultContext<'_>,
) -> Result<Value, DefaultError> {
    let (ty, default, optional) = match item.value.without_parens() {
        Expression::FunctionCall(f)
            if f.name.name == "optional" && (1..=2).contains(&f.arguments.len()) =>
        {
            (&f.arguments[0], f.arguments.get(1), true)
        }
        ty => (ty, None, false),
    };
    match value {
        Some(v) if !v.is_null() || !optional || !apply_defaults => {
            convert(v, ty, apply_defaults, cx)
        }
        _ if optional => match default.filter(|_| apply_defaults) {
            Some(d) => convert(&cx.at_expression(d).eval_static(d)?, ty, apply_defaults, cx),
            None => Ok(Value::null()),
        },
        _ => Err(DefaultError::Invalid),
    }
}

/// `any` denotes one common element type, even inside a nested constraint.
fn unify_elements(
    values: &mut [Value],
    constraint: &Expression<'_>,
    cx: DefaultContext<'_>,
) -> Result<(), DefaultError> {
    cx.charge(values.len())?;
    let references = cx.collect(values.iter())?;
    let ty = CommonType::infer(&references, Some(constraint), cx)?;
    for value in values {
        *value = ty.convert(value, cx)?;
    }
    Ok(())
}

/// Compact in place so deduplication and sorting need no second payload buffer.
pub(super) fn unique(values: &mut Vec<Value>, cx: DefaultContext<'_>) -> Result<(), DefaultError> {
    let count = values.len();
    let mut written = 0;
    for read in 0..count {
        assert!(written <= read);
        cx.charge(written)?;
        if !values[..written]
            .iter()
            .any(|u| u.known_eq(&values[read]) == Some(true))
        {
            values.swap(written, read);
            written += 1;
        }
    }
    assert!(written <= count);
    values.truncate(written);
    if values.iter().all(|v| v.as_str().is_some()) {
        // Equal strings were removed, so an unstable sort preserves lexical order.
        values.sort_unstable_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
    Ok(())
}

use super::{conversion::unique, optional_type};
use crate::default_budget::{DefaultContext, DefaultError};
use std::{collections::BTreeMap, sync::Arc};
use tf_ast::Expression;
use tf_eval::{Kind, Known, Value};

mod inference;

#[derive(Clone, PartialEq)]
pub(super) enum CommonType {
    Null,
    Bool,
    Number,
    String,
    Tuple(Vec<Self>),
    List(Box<Self>, bool),
    Object(BTreeMap<Arc<str>, Self>),
    Map(Box<Self>),
}

impl CommonType {
    pub(super) fn clone_with_context(&self, cx: DefaultContext<'_>) -> Result<Self, DefaultError> {
        // Admit both the traversal scratch and every payload before the derived clone.
        cx.charge(1)?;
        let mut pending = cx.buffer(1)?;
        cx.storage(pending.push(self))?;
        while let Some(ty) = pending.pop() {
            match ty {
                Self::Tuple(items) => {
                    cx.charge(items.len())?;
                    cx.admit::<Self>(items.len())?;
                    cx.storage(pending.reserve(items.len()))?;
                    for item in items {
                        cx.storage(pending.push(item))?;
                    }
                }
                Self::Object(items) => {
                    cx.charge(items.len())?;
                    cx.admit::<(Arc<str>, Self)>(items.len())?;
                    cx.storage(pending.reserve(items.len()))?;
                    for item in items.values() {
                        cx.storage(pending.push(item))?;
                    }
                }
                Self::List(item, _) | Self::Map(item) => {
                    cx.charge(1)?;
                    cx.admit::<Self>(1)?;
                    cx.storage(pending.push(item))?;
                }
                Self::Null | Self::Bool | Self::Number | Self::String => {}
            }
        }
        assert!(pending.is_empty());
        Ok(self.clone())
    }

    pub(super) fn infer(
        values: &[&Value],
        constraint: Option<&Expression<'_>>,
        cx: DefaultContext<'_>,
    ) -> Result<Self, DefaultError> {
        Self::infer_typed(values, constraint, &[], cx)
    }

    pub(super) fn infer_typed(
        values: &[&Value],
        constraint: Option<&Expression<'_>>,
        sources: &[Option<&Self>],
        cx: DefaultContext<'_>,
    ) -> Result<Self, DefaultError> {
        inference::infer(values, constraint, sources, cx)
    }

    fn element(&self, i: usize) -> Option<&Self> {
        match self {
            Self::Tuple(items) => items.get(i),
            Self::List(ty, _) => Some(ty),
            _ => None,
        }
    }

    fn field(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields.get(key),
            Self::Map(ty) => Some(ty),
            _ => None,
        }
    }

    /// Nulls and empty collections still carry concrete types across overrides.
    pub(super) fn check_conversion(
        &self,
        constraint: &Expression<'_>,
        cx: DefaultContext<'_>,
    ) -> Result<(), DefaultError> {
        cx.charge(1)?;
        if matches!(self, Self::Null) {
            return Ok(());
        }
        let constraint = constraint.without_parens();
        if let Expression::Variable(v) = constraint {
            return match v.name.as_str() {
                "any" => Ok(()),
                "string" if matches!(self, Self::String | Self::Bool | Self::Number) => Ok(()),
                "bool" if matches!(self, Self::Bool | Self::String) => Ok(()),
                "number" if matches!(self, Self::Number | Self::String) => Ok(()),
                "list" if matches!(self, Self::List(..) | Self::Tuple(_)) => Ok(()),
                "map" if matches!(self, Self::Map(_) | Self::Object(_)) => Ok(()),
                _ => Err(DefaultError::Invalid),
            };
        }
        let Expression::FunctionCall(f) = constraint else {
            return Err(DefaultError::Invalid);
        };
        let Some(arg) = f.arguments.first() else {
            return Err(DefaultError::Invalid);
        };
        self.check_collection(f.name.name.as_str(), arg, cx)
    }

    fn check_collection(
        &self,
        name: &str,
        arg: &Expression<'_>,
        cx: DefaultContext<'_>,
    ) -> Result<(), DefaultError> {
        match (name, arg, self) {
            ("tuple", Expression::Tuple(t), Self::Tuple(items))
                if items.len() == t.elements.len() =>
            {
                for (source, ty) in items.iter().zip(t.elements.iter()) {
                    source.check_conversion(ty, cx)?;
                }
            }
            ("list" | "set", ty, Self::Tuple(items)) => {
                for source in items {
                    source.check_conversion(ty, cx)?;
                }
            }
            ("list" | "set", ty, Self::List(source, _)) => source.check_conversion(ty, cx)?,
            ("object", Expression::Object(o), Self::Object(_) | Self::Map(_)) => {
                for item in o.items.iter() {
                    let ty = optional_type(&item.value);
                    let optional = matches!(
                        item.value.without_parens(),
                        Expression::FunctionCall(f) if f.name.name == "optional"
                    );
                    match self.field(item.key.as_static_str().ok_or(DefaultError::Invalid)?) {
                        // A map may omit an optional field with an incompatible element type.
                        Some(_) if optional && matches!(self, Self::Map(_)) => {}
                        Some(source) => source.check_conversion(ty, cx)?,
                        None if optional => {}
                        None => return Err(DefaultError::Invalid),
                    }
                }
            }
            ("map", ty, Self::Object(fields)) => {
                for source in fields.values() {
                    source.check_conversion(ty, cx)?;
                }
            }
            ("map", ty, Self::Map(source)) => source.check_conversion(ty, cx)?,
            _ => return Err(DefaultError::Invalid),
        }
        Ok(())
    }

    pub(super) fn convert(
        &self,
        value: &Value,
        cx: DefaultContext<'_>,
    ) -> Result<Value, DefaultError> {
        cx.charge(1)?;
        if value.is_null() {
            return Ok(value.clone());
        }
        let result = match (self, &value.kind) {
            (Self::String, _) => Value::string(cx.string(value)?),
            (Self::Bool, Kind::Known(Known::Bool(_)))
            | (Self::Number, Kind::Known(Known::Number(_))) => value.clone(),
            (Self::Tuple(types), Kind::Known(Known::List(values))) => Value::list(
                cx.try_collect(
                    types
                        .iter()
                        .zip(values.iter())
                        .map(|(t, v)| t.convert(v, cx)),
                )?,
            ),
            (Self::List(ty, set), Kind::Known(Known::List(values))) => {
                let mut result = cx.try_collect(values.iter().map(|v| ty.convert(v, cx)))?;
                if *set {
                    unique(&mut result, cx)?;
                }
                Value::list(result)
            }
            (Self::Object(types), Kind::Known(Known::Object(values))) => {
                Value::object(cx.map(types.iter().map(|(k, t)| {
                    Ok((
                        k.clone(),
                        t.convert(values.get(k).ok_or(DefaultError::Invalid)?, cx)?,
                    ))
                }))?)
            }
            (Self::Map(ty), Kind::Known(Known::Object(values))) => Value::object(
                cx.map(
                    values
                        .iter()
                        .map(|(k, v)| Ok((k.clone(), ty.convert(v, cx)?))),
                )?,
            ),
            _ => return Err(DefaultError::Invalid),
        };
        Ok(result.with_prov(value.prov.clone()))
    }
}

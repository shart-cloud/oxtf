//! Runtime inputs share the root allowance, including cached optional defaults.
//! Recursive descent follows the type tree, bounded by the validated AST depth.
use tf_ast::{Expression, Object, ObjectItem};
use tf_eval::collections::{self, Buffer};
use tf_eval::{EvaluationBudget, Evaluator, Kind, Known, Map, NoResolver, Value};
use tf_span::FileSpan;

use crate::variable_defaults::TypeDefaults;

#[derive(Clone, Copy)]
pub(crate) struct InputContext<'b> {
    pub budget: &'b EvaluationBudget,
    pub at: FileSpan,
}

pub(crate) fn convert_input(
    value: Value,
    ty: Option<&Expression<'_>>,
    defaults: Option<&TypeDefaults>,
    cx: InputContext<'_>,
) -> Value {
    let prepared = match defaults {
        Some(defaults) => defaults.apply(&value, cx),
        None => Ok(value.clone()),
    };
    let converted = prepared.and_then(|v| match ty {
        Some(ty) => cx.convert(&v, ty, defaults.is_none()),
        None => Ok(v),
    });
    let result = retain_input(&value, converted).unwrap_or_else(|stopped| stopped);
    cx.budget.finish(result, cx.at)
}

/// A stopped conversion must retain errors and evidence already present in its input.
pub(crate) fn retain_input(value: &Value, result: Result<Value, Value>) -> Result<Value, Value> {
    match result {
        Ok(converted) => Ok(converted.with_prov(value.prov.clone())),
        Err(_) if tf_eval::eval::contains_error(value) => Err(value.clone()),
        Err(stopped) => Err(stopped.with_prov(value.prov.clone())),
    }
}

pub(crate) fn collect_list(
    items: &[Value],
    cx: InputContext<'_>,
    convert: impl Fn(usize, &Value) -> Result<Value, Value>,
) -> Result<Value, Value> {
    cx.charge(items.len())?;
    let mut out = Buffer::with_capacity(items.len(), cx.budget.storage())?;
    for (index, value) in items.iter().enumerate() {
        match convert(index, value) {
            Ok(value) => out.push(value)?,
            Err(stopped) => return retain_input(&Value::list(out.finish()), Err(stopped)),
        }
    }
    assert_eq!(out.len(), items.len());
    Ok(Value::list(out.finish()))
}

impl InputContext<'_> {
    pub fn admit_map(self, count: usize) -> Result<(), Value> {
        collections::admit::<(std::sync::Arc<str>, Value)>(count, self.budget.storage())
    }

    pub fn charge(self, steps: usize) -> Result<(), Value> {
        self.budget.charge(self.at, steps as u64)
    }

    fn convert(
        self,
        value: &Value,
        ty: &Expression<'_>,
        apply_defaults: bool,
    ) -> Result<Value, Value> {
        let result = self.charge(1).and_then(|()| match ty.without_parens() {
            Expression::Variable(t) => convert_primitive(value, t.name.as_str(), self),
            Expression::FunctionCall(f) => self.convert_collection(
                value,
                f.name.name.as_str(),
                f.arguments.first(),
                apply_defaults,
            ),
            _ => Ok(value.clone()),
        });
        retain_input(value, result)
    }

    fn convert_collection(
        self,
        value: &Value,
        name: &str,
        arg: Option<&Expression<'_>>,
        apply_defaults: bool,
    ) -> Result<Value, Value> {
        match (name, &value.kind, arg) {
            ("list" | "set", Kind::Known(Known::List(items)), Some(element)) => {
                collect_list(items, self, |_, v| self.convert(v, element, apply_defaults))
            }
            ("map", Kind::Known(Known::Object(items)), Some(element)) => {
                self.convert_map(items, element, apply_defaults)
            }
            ("tuple", Kind::Known(Known::List(items)), Some(Expression::Tuple(types))) => {
                collect_list(items, self, |i, v| match types.elements.get(i) {
                    Some(ty) => self.convert(v, ty, apply_defaults),
                    None => Ok(v.clone()),
                })
            }
            ("object", Kind::Known(Known::Object(items)), Some(Expression::Object(ty))) => {
                self.convert_object(items, ty, apply_defaults)
            }
            _ => Ok(value.clone()),
        }
    }

    fn convert_map(
        self,
        items: &Map,
        element: &Expression<'_>,
        apply_defaults: bool,
    ) -> Result<Value, Value> {
        self.charge(items.len())?;
        self.admit_map(items.len())?;
        let mut out = Map::new();
        for (key, value) in items {
            match self.convert(value, element, apply_defaults) {
                Ok(value) => {
                    out.insert(key.clone(), value);
                }
                Err(stopped) => return retain_input(&Value::object(out), Err(stopped)),
            }
        }
        assert_eq!(out.len(), items.len());
        Ok(Value::object(out))
    }

    fn convert_object(
        self,
        items: &Map,
        ty: &Object<'_>,
        apply_defaults: bool,
    ) -> Result<Value, Value> {
        self.charge(ty.items.len())?;
        self.admit_map(ty.items.len())?;
        let mut out = Map::new();
        for item in &ty.items {
            let Some(key) = item.key.as_static_str() else {
                continue;
            };
            match self.convert_field(items.get(key), item, apply_defaults) {
                Ok(Some(value)) => {
                    out.insert(key.into(), value);
                }
                Ok(None) => {}
                Err(stopped) => return retain_input(&Value::object(out), Err(stopped)),
            }
        }
        assert!(out.len() <= ty.items.len());
        Ok(Value::object(out))
    }

    fn convert_field(
        self,
        value: Option<&Value>,
        item: &ObjectItem<'_>,
        apply_defaults: bool,
    ) -> Result<Option<Value>, Value> {
        let (inner, default, optional) = match item.value.without_parens() {
            Expression::FunctionCall(c) if c.name.name.as_str() == "optional" => {
                (c.arguments.first(), c.arguments.get(1), true)
            }
            other => (Some(other), None, false),
        };
        let value = match value {
            Some(v) if !(optional && v.is_null() && apply_defaults) => v.clone(),
            _ if optional => match default.filter(|_| apply_defaults) {
                Some(d) => {
                    Evaluator::with_budget(&NoResolver, self.at.file, self.budget).eval_static(d)
                }
                None => return Ok(Some(Value::null())),
            },
            _ => return Ok(None),
        };
        match inner {
            Some(ty) => self.convert(&value, ty, apply_defaults).map(Some),
            None => Ok(Some(value)),
        }
    }
}

fn convert_primitive(value: &Value, name: &str, cx: InputContext<'_>) -> Result<Value, Value> {
    Ok(match (name, &value.kind) {
        ("bool", Kind::Known(Known::String(s))) if &**s == "true" || &**s == "false" => {
            Value::bool(&**s == "true")
        }
        ("number", Kind::Known(Known::String(s))) => match s.trim().parse::<f64>() {
            Ok(n) => Value::number(n),
            Err(_) => value.clone(),
        },
        ("string", Kind::Known(Known::Number(_) | Known::Bool(_))) => {
            Value::string(tf_eval::text::coerce(value, cx.budget.storage())?)
        }
        _ => value.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_eval::{Origin, Prov, Truth, prov::ResourceDependency};
    use tf_span::{FileId, Span};

    fn convert(source: &str, value: Value, allowance: u64) -> (Value, EvaluationBudget) {
        let alloc = tf_allocator::Allocator::new();
        let (ty, errors) = tf_parser::parse_expression(&alloc, source);
        let ty = ty.unwrap();
        assert!(errors.is_empty());
        let budget = EvaluationBudget::new(tf_limits::Limits::new(allowance).unwrap());
        let cx = InputContext {
            budget: &budget,
            at: FileSpan::new(FileId(0), Span::new(0, 1)),
        };
        (convert_input(value, Some(&ty), None, cx), budget)
    }

    #[test]
    fn refusal_retains_sensitive_evidence_and_uncertain_dependencies() {
        let prov = Prov::EMPTY.referencing(vec![ResourceDependency {
            resource: "test_node.origin".into(),
            key: None,
            certainty: Truth::True,
        }]);
        let input = Value::list(vec![Value::string("1").sensitive().with_prov(prov); 32]);
        let (value, budget) = convert("list(number)", input, 1);
        assert!(matches!(value.origin(), Some(Origin::Limit(_))));
        assert!(value.is_sensitive());
        assert_eq!(budget.used(), 1);
        assert_eq!(value.prov.dependencies().len(), 1);
        assert_eq!(value.prov.dependencies()[0].certainty, Truth::Unknown);
    }

    #[test]
    fn refusal_retains_errors_already_present_in_the_input() {
        let input = Value::list(vec![
            Value::number(1.0),
            Value::error("existing failure").sensitive(),
        ]);
        let (value, budget) = convert("list(number)", input, 1);
        assert!(budget.is_exhausted());
        assert!(tf_eval::eval::contains_error(&value));
        assert!(value.is_sensitive());
    }

    #[test]
    fn nested_errors_survive_exhaustion_after_an_earlier_element() {
        let ty = "list(object({x=optional(number, 7)}))";
        let input = Value::list(vec![
            Value::object([("x".into(), Value::error("existing failure"))].into()),
            Value::object(Map::new()),
        ]);
        let (value, complete) = convert(ty, input.clone(), 1000);
        assert!(tf_eval::eval::contains_error(&value));
        let (value, limited) = convert(ty, input, complete.used() - 1);
        assert!(limited.is_exhausted());
        assert!(tf_eval::eval::contains_error(&value));
    }
}

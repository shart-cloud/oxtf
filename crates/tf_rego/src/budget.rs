//! Adapter work charged before projection, engine admission, and result conversion.
use tf_eval::{Kind, Known, Value};
use tf_linter::RuleBudget;
use tf_semantic::Body;

pub(crate) fn text(budget: &RuleBudget, text: &str) -> Result<(), String> {
    budget.charge((text.len() as u64).div_ceil(64))
}

pub(crate) fn body(budget: &RuleBudget, body: &Body) -> Result<(), String> {
    budget.charge(1)?;
    let mut pending = vec![body];
    while let Some(body) = pending.pop() {
        budget.charge(body.attrs.len() as u64)?;
        budget.charge(body.blocks.len() as u64)?;
        for attr in &body.attrs {
            text(budget, &attr.name)?;
            value(budget, &attr.value)?;
        }
        pending.extend(body.blocks.iter().map(|block| &block.body));
    }
    Ok(())
}

fn value(budget: &RuleBudget, value: &Value) -> Result<(), String> {
    budget.charge(1)?;
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match &value.kind {
            Kind::Known(Known::String(s)) => text(budget, s)?,
            Kind::Known(Known::List(items)) => {
                budget.charge(items.len() as u64)?;
                pending.extend(items.iter());
            }
            Kind::Known(Known::Object(items)) => {
                budget.charge(items.len() as u64)?;
                for key in items.keys() {
                    text(budget, key)?;
                }
                pending.extend(items.values());
            }
            Kind::Known(Known::Json(inner)) => {
                budget.charge(1)?;
                pending.push(inner);
            }
            // Projection omits abstract values without expanding alternatives.
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn result(budget: &RuleBudget, value: &regorus::Value) -> Result<(), String> {
    use regorus::Value::*;
    budget.charge(1)?;
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            String(s) => text(budget, s)?,
            Array(items) => {
                budget.charge(items.len() as u64)?;
                pending.extend(items.iter());
            }
            Set(items) => {
                budget.charge(items.len() as u64)?;
                pending.extend(items.iter());
            }
            Object(items) => {
                budget.charge(items.len() as u64)?;
                budget.charge(items.len() as u64)?;
                pending.extend(items.keys());
                pending.extend(items.values());
            }
            _ => {}
        }
    }
    Ok(())
}

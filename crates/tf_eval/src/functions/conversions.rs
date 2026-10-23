use super::*;

pub(super) fn conversions(name: &str, a: &[Value], budget: &InputBudget) -> R {
    let string = |value: &Value| text::coerce(value, budget);
    match name {
        "tostring" => {
            let v = one_arg(a)?;
            if v.is_null() {
                return Ok(Value::null());
            }
            Ok(Value::string(string(v)?))
        }
        "tonumber" => {
            let v = one_arg(a)?;
            if v.is_null() {
                return Ok(Value::null());
            }
            Ok(num(number(v)?))
        }
        "tobool" => {
            let v = one_arg(a)?;
            if v.is_null() {
                return Ok(Value::null());
            }
            match &v.kind {
                Kind::Known(_) => v
                    .as_bool()
                    .map(Value::bool)
                    .ok_or_else(|| Value::error("tobool: not a bool")),
                _ => Err(v.clone()),
            }
        }
        "sensitive" => Ok(one_arg(a)?.clone().sensitive()),
        "nonsensitive" => {
            let value = one_arg(a)?;
            collections::admit_tree_copy(value, budget)?;
            Ok(value.nonsensitive())
        }
        _ => encoding(name, a, budget),
    }
}

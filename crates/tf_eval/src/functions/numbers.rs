use super::*;

pub(super) fn numbers(name: &str, a: &[Value], budget: &InputBudget) -> R {
    let string = |value: &Value| text::coerce(value, budget);
    match name {
        "max" | "min" => {
            let ns = collections::try_collect(a.iter().map(number), budget)?;
            if ns.is_empty() {
                return Err(Value::error(format!("{name}: no arguments")));
            }
            let r = if name == "max" {
                ns.iter().cloned().fold(f64::MIN, f64::max)
            } else {
                ns.iter().cloned().fold(f64::MAX, f64::min)
            };
            Ok(num(r))
        }
        "abs" => Ok(num(number(one_arg(a)?)?.abs())),
        "ceil" => Ok(num(number(one_arg(a)?)?.ceil())),
        "floor" => Ok(num(number(one_arg(a)?)?.floor())),
        "signum" => {
            let n = number(one_arg(a)?)?;
            Ok(num(if n > 0.0 {
                1.0
            } else if n < 0.0 {
                -1.0
            } else {
                0.0
            }))
        }
        "pow" => {
            arity(a, 2)?;
            Ok(num(number(&a[0])?.powf(number(&a[1])?)))
        }
        "log" => {
            arity(a, 2)?;
            Ok(num(number(&a[0])?.log(number(&a[1])?)))
        }
        "parseint" => {
            arity(a, 2)?;
            let s = string(&a[0])?;
            let base = number(&a[1])?;
            if !(2.0..=36.0).contains(&base) || base.fract() != 0.0 {
                return Err(Value::error(
                    "parseint: base must be a whole number between 2 and 36",
                ));
            }
            i64::from_str_radix(&s, base as u32)
                .map(|n| num(n as f64))
                .map_err(|_| Value::error("parseint: invalid number"))
        }
        _ => strings(name, a, budget),
    }
}

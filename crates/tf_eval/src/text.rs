//! Fallible evaluator text construction. Scratch capacity and copied Arc payload are
//! cumulatively admitted; dropping a temporary cannot refill the scan allowance.
use std::fmt::{self, Write as _};
use std::sync::Arc;

use tf_limits::input::InputBudget;

use crate::{Kind, Known, Value};

pub struct Text<'b> {
    value: String,
    admitted: usize,
    budget: &'b InputBudget,
}

impl<'b> Text<'b> {
    pub fn new(budget: &'b InputBudget) -> Self {
        Self {
            value: String::new(),
            admitted: 0,
            budget,
        }
    }

    pub fn reserve(&mut self, additional: usize) -> Result<(), Value> {
        self.budget.admit_text(0).map_err(limit)?;
        let required = self
            .value
            .len()
            .checked_add(additional)
            .ok_or_else(|| self.refused())?;
        if required > self.admitted {
            let capacity = required.max(self.admitted.saturating_mul(2));
            self.budget
                .admit_text((capacity - self.admitted) as u64)
                .map_err(limit)?;
            self.value
                .try_reserve_exact(capacity - self.value.len())
                .map_err(|_| self.refused())?;
            self.admitted = capacity;
            // The allocator may return extra capacity; it grants no extra admission.
            assert!(self.value.capacity() >= self.admitted);
        }
        Ok(())
    }

    pub fn push_str(&mut self, text: &str) -> Result<(), Value> {
        self.reserve(text.len())?;
        self.value.push_str(text);
        assert!(self.value.len() <= self.admitted);
        Ok(())
    }

    pub fn push(&mut self, ch: char) -> Result<(), Value> {
        self.push_str(ch.encode_utf8(&mut [0; 4]))
    }

    pub fn formatted(&mut self, args: fmt::Arguments<'_>) -> Result<(), Value> {
        self.write_fmt(args).map_err(|_| self.refused())
    }

    pub(crate) fn generated(
        &mut self,
        maximum: usize,
        operation: impl FnOnce(&mut String),
    ) -> Result<(), Value> {
        self.reserve(maximum)?;
        let before = self.value.len();
        let capacity = self.value.capacity();
        operation(&mut self.value);
        assert!(self.value.len() - before <= maximum);
        assert_eq!(self.value.capacity(), capacity);
        Ok(())
    }

    pub fn finish(self) -> Result<Arc<str>, Value> {
        copy(&self.value, self.budget)
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn refused(&self) -> Value {
        limit(self.budget.text_refused())
    }
}

impl fmt::Write for Text<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.push_str(value).map_err(|_| fmt::Error)
    }
}

impl std::io::Write for Text<'_> {
    fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
        // serde_json writes UTF-8 fragments; the writer is not a binary sink.
        let text = std::str::from_utf8(value).expect("JSON serializer writes UTF-8");
        self.push_str(text)
            .map_err(|_| std::io::Error::other(self.budget.text_refused()))?;
        Ok(value.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn limit(error: tf_limits::Exhaustion) -> Value {
    Value::limit(error.to_string())
}

pub fn copy(value: &str, budget: &InputBudget) -> Result<Arc<str>, Value> {
    budget.admit_text(value.len() as u64).map_err(limit)?;
    Ok(Arc::from(value))
}

/// Strings are already admitted and shared. Scalar/JSON conversions build new text.
pub fn coerce(value: &Value, budget: &InputBudget) -> Result<Arc<str>, Value> {
    match &value.kind {
        Kind::Known(Known::String(text)) => Ok(text.clone()),
        Kind::Known(Known::Number(n)) => {
            let mut out = Text::new(budget);
            if n.fract() == 0.0 && n.abs() < 1e17 {
                out.formatted(format_args!("{}", *n as i64))?;
            } else {
                out.formatted(format_args!("{n}"))?;
            }
            out.finish()
        }
        Kind::Known(Known::Bool(b)) => copy(if *b { "true" } else { "false" }, budget),
        Kind::Known(Known::Json(inner)) => json(inner, budget),
        Kind::Known(_) => Err(Value::error(format!(
            "expected string, got {}",
            value.type_name()
        ))),
        _ => Err(crate::eval::non_known_or(value, "")),
    }
}

/// Serialize borrowed values with a bounded explicit traversal stack. Nested Json
/// values are encoded as JSON strings, exactly as in value::to_json.
pub fn json(value: &Value, budget: &InputBudget) -> Result<Arc<str>, Value> {
    json_inner(value, budget).map_err(|stopped| {
        if matches!(stopped.origin(), Some(crate::Origin::Limit(_))) {
            stopped
        } else {
            crate::eval::non_known_or(value, "")
        }
    })
}

fn json_inner(value: &Value, budget: &InputBudget) -> Result<Arc<str>, Value> {
    let mut out = Text::new(budget);
    let mut stack = Vec::with_capacity(tf_limits::EVALUATION_DEPTH_MAX);
    stack.push(Frame::Value(value));
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Value(value) => json_value(value, &mut stack, &mut out, budget)?,
            Frame::List(mut items, first) => match items.next() {
                Some(value) => {
                    if !first {
                        out.push(',')?;
                    }
                    push_pair(&mut stack, Frame::List(items, false), value)?;
                }
                None => out.push(']')?,
            },
            Frame::Object(mut items, first) => match items.next() {
                Some((key, value)) => {
                    if !first {
                        out.push(',')?;
                    }
                    quoted(key, &mut out)?;
                    out.push(':')?;
                    push_pair(&mut stack, Frame::Object(items, false), value)?;
                }
                None => out.push('}')?,
            },
            Frame::Json(mut parent) => {
                quoted(&out.finish()?, &mut parent)?;
                out = parent;
            }
        }
    }
    out.finish()
}

enum Frame<'v, 'b> {
    Value(&'v Value),
    List(std::slice::Iter<'v, Value>, bool),
    Object(std::collections::btree_map::Iter<'v, Arc<str>, Value>, bool),
    Json(Text<'b>),
}

fn push_pair<'v, 'b>(
    stack: &mut Vec<Frame<'v, 'b>>,
    parent: Frame<'v, 'b>,
    value: &'v Value,
) -> Result<(), Value> {
    if stack.len() + 2 > tf_limits::EVALUATION_DEPTH_MAX {
        return Err(Value::limit(
            "JSON text nesting exceeds evaluation depth limit",
        ));
    }
    stack.push(parent);
    stack.push(Frame::Value(value));
    assert!(stack.len() <= tf_limits::EVALUATION_DEPTH_MAX);
    Ok(())
}

fn quoted(value: &str, out: &mut Text<'_>) -> Result<(), Value> {
    serde_json::to_writer(&mut *out, value).map_err(|_| out.refused())
}

fn json_value<'v, 'b>(
    value: &'v Value,
    stack: &mut Vec<Frame<'v, 'b>>,
    out: &mut Text<'b>,
    budget: &'b InputBudget,
) -> Result<(), Value> {
    match &value.kind {
        Kind::Known(Known::Null) => out.push_str("null"),
        Kind::Known(Known::Bool(b)) => out.push_str(if *b { "true" } else { "false" }),
        Kind::Known(Known::Number(n)) => {
            if n.fract() == 0.0 && n.abs() < 9.0e15 {
                out.formatted(format_args!("{}", *n as i64))
            } else if n.is_finite() {
                serde_json::to_writer(&mut *out, n).map_err(|_| out.refused())
            } else {
                Err(Value::error("non-finite JSON number"))
            }
        }
        Kind::Known(Known::String(s)) => quoted(s, out),
        Kind::Known(Known::List(items)) => {
            out.push('[')?;
            // A Value frame was just popped, so this replacement cannot grow the stack.
            assert!(stack.len() < tf_limits::EVALUATION_DEPTH_MAX);
            stack.push(Frame::List(items.iter(), true));
            Ok(())
        }
        Kind::Known(Known::Object(items)) => {
            out.push('{')?;
            assert!(stack.len() < tf_limits::EVALUATION_DEPTH_MAX);
            stack.push(Frame::Object(items.iter(), true));
            Ok(())
        }
        Kind::Known(Known::Json(inner)) => {
            let parent = std::mem::replace(out, Text::new(budget));
            push_pair(stack, Frame::Json(parent), inner)
        }
        _ => Err(crate::eval::non_known_or(
            value,
            "value is not concrete JSON",
        )),
    }
}

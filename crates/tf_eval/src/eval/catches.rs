use super::*;
use tf_limits::input::InputBudget;

impl<'r, 'a> Evaluator<'r, 'a> {
    pub(super) fn eval_try(&self, args: &'a [Expression<'a>], sc: Scope<'_>) -> Value {
        let mut last = Value::error("try: no arguments succeeded");
        let mut successes = Buffer::new(self.budget.storage());
        let mut tainted = false;
        let mut sensitive = false;
        let attempt = (|| {
            for argument in args {
                successes.reserve(1)?;
                let value = self.eval(argument, sc);
                sensitive |= value.is_sensitive();
                if self.budget.is_exhausted() {
                    return Err(value);
                }
                let outcome = try_outcome(&value, self.budget.storage())?;
                if let Some(value) = outcome.value {
                    successes.push(value)?;
                    tainted |= outcome.tainted;
                }
                match outcome.error {
                    None => return Ok(()),
                    Some(error) => last = error,
                }
            }
            successes.push(last)?;
            Ok(())
        })();
        let result = match attempt {
            Ok(()) => self
                .alternatives(successes.finish(), tainted)
                .unwrap_or_else(|v| v),
            Err(value) => failure(value, successes.iter()),
        };
        if sensitive {
            result.sensitive()
        } else {
            result
        }
    }

    pub(super) fn eval_can(&self, args: &'a [Expression<'a>], sc: Scope<'_>) -> Value {
        let Some(a) = args.first() else {
            return Value::error("can: missing argument");
        };
        let v = self.eval(a, sc);
        let result = if contains_error(&v) {
            Value::bool(false)
        } else if v.is_wholly_known() {
            Value::bool(true)
        } else {
            // Unknown results (including analysis limits) do not establish
            // whether evaluation will succeed once their inputs are known.
            v.clone()
        };
        result.inherit_sensitive(&v)
    }
}

/// Successful alternatives of one `try` argument, plus an error if some
/// alternatives fail. Errors inside a container fail the whole argument;
/// the fallback must not be substituted into just the failing element.
struct TryOutcome {
    value: Option<Value>,
    error: Option<Value>,
    tainted: bool,
}

fn try_outcome(v: &Value, budget: &InputBudget) -> Result<TryOutcome, Value> {
    try_outcome_inner(v, budget).map_err(|value| failure(value, [v]))
}

fn try_outcome_inner(v: &Value, budget: &InputBudget) -> Result<TryOutcome, Value> {
    let mut outcome = match &v.kind {
        Kind::OneOf(o) => {
            let mut values = Buffer::with_capacity(o.alternatives.len(), budget)?;
            let mut error = None;
            let mut tainted = o.tainted;
            for alternative in &o.alternatives {
                let result = try_outcome(alternative, budget)?;
                if let Some(value) = result.value {
                    values.push(value)?;
                }
                error = error.or(result.error);
                tainted |= result.tainted;
            }
            let mixed = !values.is_empty() && error.is_some();
            TryOutcome {
                value: if values.is_empty() {
                    None
                } else {
                    Some(collections::one_of(values.finish(), tainted, budget)?)
                },
                error,
                // Uncertainty within successful values is already carried
                // by `value`; only a choice between success and failure
                // controls whether a later fallback can be taken.
                tainted: tainted && mixed,
            }
        }
        Kind::Known(Known::List(items)) => {
            try_container(items.iter(), budget, |values| Ok(Value::list(values)))?
        }
        Kind::Known(Known::Object(items)) => try_container(items.values(), budget, |values| {
            collections::admit::<(Arc<str>, Value)>(items.len(), budget)?;
            Ok(Value::object(items.keys().cloned().zip(values).collect()))
        })?,
        Kind::Known(Known::Json(inner)) => {
            let mut result = try_outcome(inner, budget)?;
            if result.value.is_some() {
                collections::admit::<Value>(1, budget)?;
            }
            result.value = result.value.map(|v| Value::known(Known::Json(Arc::new(v))));
            result
        }
        _ => {
            return Ok(TryOutcome {
                value: (!v.is_error()).then(|| v.clone()),
                error: v.is_error().then(|| v.clone()),
                tainted: false,
            });
        }
    };
    outcome.value = outcome.value.map(|value| value.child_of(v));
    outcome.error = outcome.error.map(|error| error.child_of(v));
    Ok(outcome)
}

fn try_container<'v>(
    items: impl ExactSizeIterator<Item = &'v Value>,
    budget: &InputBudget,
    build: impl FnOnce(Vec<Value>) -> Result<Value, Value>,
) -> Result<TryOutcome, Value> {
    let mut values = Buffer::with_capacity(items.len(), budget)?;
    let mut error = None;
    let mut tainted = false;
    let mut can_succeed = true;
    for item in items {
        let result = try_outcome(item, budget)?;
        match result.value {
            Some(value) => values.push(value)?,
            None => can_succeed = false,
        }
        error = error.or(result.error);
        tainted |= result.tainted;
    }
    Ok(TryOutcome {
        value: if can_succeed {
            Some(build(values.finish())?)
        } else {
            None
        },
        error,
        tainted,
    })
}

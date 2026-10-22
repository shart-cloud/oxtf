//! Default preparation uses one allowance across all declarations and override stages.
use tf_ast::Expression;
use tf_eval::collections::{self, Buffer};
use tf_eval::{EvaluationBudget, Evaluator, NoResolver, Value};
use tf_span::{FileSpan, GetSpan};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DefaultError {
    Invalid,
    Limit,
}

#[derive(Clone, Copy)]
pub(crate) struct DefaultContext<'b> {
    pub budget: &'b EvaluationBudget,
    pub at: FileSpan,
}

impl<'b> DefaultContext<'b> {
    pub fn storage<T>(self, result: Result<T, Value>) -> Result<T, DefaultError> {
        result.map_err(|stopped| {
            self.budget.finish(stopped, self.at);
            DefaultError::Limit
        })
    }

    pub fn admit<T>(self, count: usize) -> Result<(), DefaultError> {
        self.check()?;
        self.storage(collections::admit::<T>(count, self.budget.storage()))
    }

    pub fn buffer<T>(self, count: usize) -> Result<Buffer<'b, T>, DefaultError> {
        self.check()?;
        self.storage(Buffer::with_capacity(count, self.budget.storage()))
    }

    pub fn collect<T>(
        self,
        items: impl ExactSizeIterator<Item = T>,
    ) -> Result<Vec<T>, DefaultError> {
        self.try_collect(items.map(Ok))
    }

    /// Filtered/flattened inference scratch holds only copyable references.
    pub fn scratch<T: Copy>(self, items: impl Iterator<Item = T>) -> Result<Vec<T>, DefaultError> {
        let (lower, upper) = items.size_hint();
        let mut out = self.buffer(upper.unwrap_or(lower))?;
        for item in items {
            self.storage(out.push(item))?;
        }
        Ok(out.finish())
    }

    pub fn try_collect<T>(
        self,
        items: impl ExactSizeIterator<Item = Result<T, DefaultError>>,
    ) -> Result<Vec<T>, DefaultError> {
        let count = items.len();
        let mut out = self.buffer(count)?;
        for item in items {
            self.storage(out.push(item?))?;
        }
        assert_eq!(out.len(), count);
        Ok(out.finish())
    }

    pub fn map<K: Ord, V>(
        self,
        items: impl ExactSizeIterator<Item = Result<(K, V), DefaultError>>,
    ) -> Result<std::collections::BTreeMap<K, V>, DefaultError> {
        let count = items.len();
        self.admit::<(K, V)>(count)?;
        let mut out = std::collections::BTreeMap::new();
        for item in items {
            let (key, value) = item?;
            out.insert(key, value);
        }
        assert!(out.len() <= count);
        Ok(out)
    }

    pub fn boxed<T>(
        self,
        build: impl FnOnce() -> Result<T, DefaultError>,
    ) -> Result<Box<T>, DefaultError> {
        self.admit::<T>(1)?;
        Ok(Box::new(build()?))
    }

    pub fn charge(self, steps: usize) -> Result<(), DefaultError> {
        self.check()?;
        self.budget
            .charge(self.at, steps as u64)
            .map_err(|_| DefaultError::Limit)
    }

    pub fn check(self) -> Result<(), DefaultError> {
        if self.budget.first_limit().is_some() {
            Err(DefaultError::Limit)
        } else {
            Ok(())
        }
    }

    pub fn evaluated(self, value: Value) -> Result<Value, DefaultError> {
        // A real failure already observed inside this expression takes precedence.
        if tf_eval::eval::contains_error(&value) {
            return Err(DefaultError::Invalid);
        }
        self.check()?;
        Ok(value)
    }

    pub fn string(self, value: &Value) -> Result<std::sync::Arc<str>, DefaultError> {
        tf_eval::text::coerce(value, self.budget.storage()).map_err(|stopped| {
            self.budget.finish(stopped, self.at);
            if self.budget.is_exhausted() {
                DefaultError::Limit
            } else {
                DefaultError::Invalid
            }
        })
    }

    pub fn eval_static(self, expression: &Expression<'_>) -> Result<Value, DefaultError> {
        self.check()?;
        let value =
            Evaluator::with_budget(&NoResolver, self.at.file, self.budget).eval_static(expression);
        self.evaluated(value)
    }

    pub fn at_expression(self, expression: &Expression<'_>) -> Self {
        Self {
            at: FileSpan::new(self.at.file, expression.span()),
            ..self
        }
    }
}

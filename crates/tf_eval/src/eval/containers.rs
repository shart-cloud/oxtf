use super::*;
pub(super) use crate::collections::failure;

impl<'r, 'a> Evaluator<'r, 'a> {
    pub(super) fn lift_value(&self, value: &Value, run: &dyn Fn(&Value) -> Value) -> Value {
        let Kind::OneOf(choices) = &value.kind else {
            return run(value).inherit_sensitive(value);
        };
        if choices.alternatives.len() > MAX_ALTERNATIVES {
            return Value::limit_from("too many unary alternatives", [value]);
        }
        self.values(
            choices
                .alternatives
                .iter()
                .map(|child| self.lift_value(&child.child_of(value), run)),
        )
        .and_then(|values| self.alternatives(values.finish(), choices.tainted))
        .unwrap_or_else(|v| failure(v, [value]))
        .inherit_sensitive(value)
    }

    pub(super) fn lift_pair(
        &self,
        left: &Value,
        right: &Value,
        run: &dyn Fn(&Value, &Value) -> Value,
    ) -> Value {
        if left
            .alternative_count()
            .checked_mul(right.alternative_count())
            .is_none_or(|count| count > MAX_ALTERNATIVES)
        {
            return Value::limit_from("too many binary alternatives", [left, right]);
        }
        let attempt = match (&left.kind, &right.kind) {
            (Kind::OneOf(o), _) => self
                .values(
                    o.alternatives
                        .iter()
                        .map(|v| self.lift_pair(&v.child_of(left), right, run)),
                )
                .and_then(|v| self.alternatives(v.finish(), o.tainted)),
            (_, Kind::OneOf(o)) => self
                .values(
                    o.alternatives
                        .iter()
                        .map(|v| self.lift_pair(left, &v.child_of(right), run)),
                )
                .and_then(|v| self.alternatives(v.finish(), o.tainted)),
            _ => Ok(run(left, right)),
        };
        attempt
            .unwrap_or_else(|v| failure(v, [left, right]))
            .inherit_sensitive(left)
            .inherit_sensitive(right)
    }

    /// Admit the destination before evaluating any child expression.
    pub(super) fn values(
        &self,
        items: impl ExactSizeIterator<Item = Value>,
    ) -> Result<Buffer<'_, Value>, Value> {
        let mut out = Buffer::with_capacity(items.len(), self.budget.storage())?;
        for value in items {
            if self.budget.is_exhausted() {
                return Err(failure(value, out.iter()));
            }
            out.push(value)?;
        }
        Ok(out)
    }

    pub(super) fn eval_object(&self, o: &'a tf_ast::Object<'a>, sc: Scope<'_>) -> Value {
        let mut map = Map::new();
        let mut keys = Prov::EMPTY;
        let attempt: Result<(), Value> = (|| {
            for item in &o.items {
                let key = self.object_key(&item.key, sc, &mut keys)?;
                if !map.contains_key(&key) {
                    collections::admit::<(Arc<str>, Value)>(1, self.budget.storage())?;
                }
                let value = self.eval(&item.value, sc);
                map.insert(key, value);
                if self.budget.is_exhausted() {
                    break;
                }
            }
            Ok(())
        })();
        match attempt {
            Ok(()) => Value::object(map).with_prov(keys),
            Err(value) => failure(value.with_prov(keys), map.values()),
        }
    }

    fn object_key(
        &self,
        key: &'a ObjectKey<'a>,
        sc: Scope<'_>,
        prov: &mut Prov,
    ) -> Result<Arc<str>, Value> {
        match key {
            ObjectKey::Identifier(i) => text::copy(i.name.as_str(), self.budget.storage()),
            ObjectKey::Expression(k) => {
                let value = self.eval(k, sc);
                *prov = prov.joined(&value.prov);
                text::coerce(&value, self.budget.storage())
            }
        }
    }

    pub(super) fn static_object(&self, o: &tf_ast::Object<'_>) -> Value {
        let mut map = Map::new();
        let attempt: Result<(), Value> = (|| {
            for item in &o.items {
                let Some(key) = item.key.as_static_str() else {
                    continue;
                };
                let key = text::copy(key, self.budget.storage())?;
                if !map.contains_key(&key) {
                    collections::admit::<(Arc<str>, Value)>(1, self.budget.storage())?;
                }
                map.insert(key, self.eval_static(&item.value));
                if self.budget.is_exhausted() {
                    break;
                }
            }
            Ok(())
        })();
        match attempt {
            Ok(()) => Value::object(map),
            Err(value) => failure(value, map.values()),
        }
    }

    pub(super) fn branch_alternatives(
        &self,
        cond: &Value,
        t: impl FnOnce() -> Value,
        f: impl FnOnce() -> Value,
        tainted: bool,
    ) -> Value {
        let attempt = (|| {
            let mut values = Buffer::with_capacity(2, self.budget.storage())?;
            let first = t();
            if self.budget.is_exhausted() {
                return Err(first);
            }
            values.push(first)?;
            let second = f();
            if self.budget.is_exhausted() {
                return Err(failure(second, values.iter()));
            }
            values.push(second)?;
            self.alternatives(values.finish(), tainted)
        })();
        attempt.unwrap_or_else(|v| failure(v, [cond]))
    }

    pub(super) fn alternatives(&self, values: Vec<Value>, tainted: bool) -> Result<Value, Value> {
        // Retain evidence before the flattening helper consumes its input.
        let count = values
            .iter()
            .try_fold(0usize, |n, v| n.checked_add(v.alternative_count()));
        if let Some(count) = count.filter(|&n| n <= MAX_ALTERNATIVES) {
            collections::admit::<Value>(count, self.budget.storage())
                .map_err(|v| failure(v, &values))?;
        }
        Ok(Value::one_of(values, tainted))
    }
}

impl Scope<'_> {
    pub(super) fn with_iteration<R>(
        &self,
        key_name: Option<&str>,
        value_name: &str,
        key: &Value,
        value: &Value,
        run: impl FnOnce(Scope<'_>) -> R,
    ) -> R {
        match key_name {
            Some(name) => self.with(name, key, |s| s.with(value_name, value, run)),
            None => self.with(value_name, value, run),
        }
    }
}

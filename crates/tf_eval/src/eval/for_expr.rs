use super::*;
use std::collections::BTreeMap;
use tf_limits::input::InputBudget;

struct ForItem {
    key: Option<Arc<str>>,
    value: Value,
    condition: Value,
}

struct ForResult<'b> {
    list: Buffer<'b, Value>,
    object: Map,
    grouped: BTreeMap<Arc<str>, Buffer<'b, Value>>,
}

impl<'b> ForResult<'b> {
    fn new(budget: &'b InputBudget) -> Self {
        Self {
            list: Buffer::new(budget),
            object: Map::new(),
            grouped: BTreeMap::new(),
        }
    }

    fn copy(&self, budget: &'b InputBudget) -> Result<Self, Value> {
        let mut copy = Self::new(budget);
        copy.list = Buffer::with_capacity(self.list.len(), budget)?;
        for value in self.list.iter() {
            copy.list.push(value.clone())?;
        }
        collections::admit::<(Arc<str>, Value)>(self.object.len(), budget)?;
        copy.object = self.object.clone();
        for (key, values) in &self.grouped {
            collections::admit::<(Arc<str>, Buffer<'_, Value>)>(1, budget)?;
            let mut group = Buffer::with_capacity(values.len(), budget)?;
            for value in values.iter() {
                group.push(value.clone())?;
            }
            copy.grouped.insert(key.clone(), group);
        }
        assert_eq!(copy.list.len(), self.list.len());
        assert_eq!(copy.grouped.len(), self.grouped.len());
        Ok(copy)
    }

    fn push(
        &mut self,
        key: Option<Arc<str>>,
        value: Value,
        grouping: bool,
        budget: &'b InputBudget,
    ) -> Result<(), Value> {
        match key {
            None => self.list.push(value),
            Some(key) if grouping => {
                if !self.grouped.contains_key(&key) {
                    collections::insert(
                        &mut self.grouped,
                        key.clone(),
                        Buffer::new(budget),
                        budget,
                    )?;
                }
                self.grouped.get_mut(&key).unwrap().push(value)
            }
            Some(key) => collections::insert(&mut self.object, key, value, budget),
        }
    }

    fn finish(self, f: &ForExpr<'_>, budget: &InputBudget) -> Result<Value, Value> {
        if f.key_expr.is_none() {
            Ok(Value::list(self.list.finish()))
        } else if f.grouping {
            collections::admit::<(Arc<str>, Value)>(self.grouped.len(), budget)?;
            Ok(Value::object(
                self.grouped
                    .into_iter()
                    .map(|(k, v)| (k, Value::list(v.finish())))
                    .collect(),
            ))
        } else {
            Ok(Value::object(self.object))
        }
    }
}

impl<'r, 'a> Evaluator<'r, 'a> {
    pub(super) fn eval_for(&self, f: &'a ForExpr<'a>, sc: Scope<'_>) -> Value {
        let coll = self.eval(&f.collection, sc);
        let attempt = match &coll.kind {
            Kind::OneOf(o) => self
                .values(
                    o.alternatives
                        .iter()
                        .map(|a| self.eval_for_over(f, a.child_of(&coll), sc)),
                )
                .and_then(|values| self.alternatives(values.finish(), o.tainted)),
            Kind::Known(Known::Null) => Err(Value::error("for: iterating over null")),
            _ => Ok(self.eval_for_over(f, coll.clone(), sc)),
        };
        match attempt {
            Ok(value) => value.inherit_sensitive(&coll),
            Err(value) => failure(value, [&coll]),
        }
    }

    fn eval_for_over(&self, f: &'a ForExpr<'a>, coll: Value, sc: Scope<'_>) -> Value {
        let attempt = match &coll.kind {
            Kind::Known(Known::List(items)) => self.eval_for_items(
                f,
                items
                    .iter()
                    .enumerate()
                    .map(|(i, v)| (Value::number(i as f64), v.child_of(&coll))),
                sc,
            ),
            Kind::Known(Known::Object(items)) => self.eval_for_items(
                f,
                items
                    .iter()
                    .map(|(k, v)| (Value::string(k.clone()), v.child_of(&coll))),
                sc,
            ),
            Kind::Known(_) => Err(Value::error("for: collection is not iterable")),
            _ => return coll,
        };
        match attempt {
            Ok(value) => value.inherit_sensitive(&coll),
            Err(value) => failure(value, [&coll]),
        }
    }

    fn eval_for_items(
        &self,
        f: &'a ForExpr<'a>,
        items: impl Iterator<Item = (Value, Value)>,
        sc: Scope<'_>,
    ) -> Result<Value, Value> {
        let budget = self.budget.storage();
        let mut alternatives = Buffer::with_capacity(1, budget)?;
        alternatives.push(ForResult::new(budget))?;
        let mut tainted = false;
        let mut prov = Prov::EMPTY;
        let mut established = None;
        let mut evidence = Prov::EMPTY;
        let attempt = (|| {
            for (key, value) in items {
                let item = sc.with_iteration(
                    f.key_var.as_ref().map(|v| v.name.as_str()),
                    f.value_var.name.as_str(),
                    &key,
                    &value,
                    |scope| self.for_item(f, scope, &mut prov),
                )?;
                let Some(ForItem {
                    key,
                    value,
                    condition,
                }) = item
                else {
                    continue;
                };
                if established.is_none() && contains_error(&value) {
                    established = Some(value.clone());
                }
                evidence = evidence.joined(&value.prov);
                if self.budget.is_exhausted() {
                    return Err(value);
                }
                let count = alternatives.len();
                if condition.as_bool().is_none() {
                    tainted |=
                        crate::truth::uncertainty(&condition) == crate::truth::Truth::Tainted;
                    prov = prov.joined(&condition.prov);
                    fork(&mut alternatives, budget)?;
                }
                for result in &mut alternatives[..count] {
                    result.push(key.clone(), value.clone(), f.grouping, budget)?;
                }
            }
            let values = collections::try_collect(
                alternatives
                    .finish()
                    .into_iter()
                    .map(|result| result.finish(f, budget)),
                budget,
            )?;
            self.alternatives(values, tainted)
        })();
        // Only refusals inherit all observed inputs; successful alternatives keep
        // their own dependency certainty when the lattice combines them.
        attempt
            .map_err(|v| failure(v.with_prov(evidence.joined(&prov)), established.iter()))
            .map(|v| v.with_prov(prov))
    }

    fn for_item(
        &self,
        f: &'a ForExpr<'a>,
        sc: Scope<'_>,
        prov: &mut Prov,
    ) -> Result<Option<ForItem>, Value> {
        let condition = f
            .condition
            .as_ref()
            .map_or_else(|| Value::bool(true), |c| self.eval(c, sc));
        *prov = prov
            .clone()
            .with_sensitive(prov.is_sensitive() || condition.is_sensitive());
        if condition.is_error() || self.budget.is_exhausted() {
            return Err(condition);
        }
        if condition.is_known() && condition.as_bool().is_none() {
            return Err(Value::error("for: condition is not a bool"));
        }
        if condition.as_bool() == Some(false) {
            return Ok(None);
        }
        let value = self.eval(&f.value_expr, sc);
        let key = match &f.key_expr {
            Some(expression) => {
                let key = self.eval(expression, sc);
                *prov = prov
                    .clone()
                    .with_sensitive(prov.is_sensitive() || key.is_sensitive());
                Some(
                    text::coerce(&key, self.budget.storage())
                        .map_err(|v| failure(v, [&value, &key]))?,
                )
            }
            None => None,
        };
        Ok(Some(ForItem {
            key,
            value,
            condition,
        }))
    }
}

fn fork<'b>(
    alternatives: &mut Buffer<'b, ForResult<'b>>,
    budget: &'b InputBudget,
) -> Result<(), Value> {
    let count = alternatives.len();
    if count > MAX_ALTERNATIVES / 2 {
        return Err(Value::limit("for: too many filter alternatives"));
    }
    alternatives.reserve(count)?;
    for index in 0..count {
        let copy = alternatives[index].copy(budget)?;
        alternatives.push(copy)?;
    }
    assert_eq!(alternatives.len(), count * 2);
    Ok(())
}

//! Admission for analyzer-owned containers. Hash maps count logical entries;
//! vectors count reserved capacity. Text and provenance have separate contracts.
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};
use std::sync::Arc;

use tf_eval::collections::{self, Buffer, failure};
use tf_eval::{Map, Value};
use tf_limits::input::InputBudget;

pub(crate) type Build<T> = Result<T, Value>;

pub(crate) fn reserve<T>(out: &mut Vec<T>, count: usize, budget: &InputBudget) -> Build<()> {
    collections::admit::<T>(0, budget)?;
    let required = out
        .len()
        .checked_add(count)
        .ok_or_else(|| collections::refused(budget))?;
    if required > out.capacity() {
        let capacity = required.max(out.capacity().saturating_mul(2));
        collections::admit::<T>(capacity - out.capacity(), budget)?;
        out.try_reserve_exact(capacity - out.len())
            .map_err(|_| collections::refused(budget))?;
        assert!(out.capacity() >= required);
    }
    Ok(())
}

pub(crate) fn hash_slot<K: Eq + Hash, V, S: BuildHasher>(
    out: &mut HashMap<K, V, S>,
    budget: &InputBudget,
) -> Build<()> {
    collections::admit::<(K, V)>(1, budget)?;
    out.try_reserve(1)
        .map_err(|_| collections::refused(budget))?;
    assert!(out.capacity() > out.len());
    Ok(())
}

/// Admit the whole destination before evaluating a child. A stopped child keeps
/// earlier evaluated errors, sensitivity and possible dependencies.
pub(crate) fn values(
    items: impl ExactSizeIterator<Item = Value>,
    budget: &InputBudget,
) -> Build<Vec<Value>> {
    let mut out = Buffer::with_capacity(items.len(), budget)?;
    for value in items {
        if budget.exhaustion().is_some() {
            return Err(failure(value, out.iter()));
        }
        out.push(value)?;
    }
    Ok(out.finish())
}

pub(crate) fn object(
    items: impl ExactSizeIterator<Item = (Arc<str>, Value)>,
    budget: &InputBudget,
) -> Build<Value> {
    collections::admit::<(Arc<str>, Value)>(items.len(), budget)?;
    let mut out = Map::new();
    for (key, value) in items {
        if budget.exhaustion().is_some() {
            return Err(failure(value, out.values()));
        }
        out.insert(key, value);
    }
    Ok(Value::object(out))
}

pub(crate) fn alternatives(
    values: Vec<Value>,
    tainted: bool,
    budget: &InputBudget,
) -> Build<Value> {
    collections::one_of(values, tainted, budget)
}

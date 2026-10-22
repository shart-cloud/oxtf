//! Cumulative collection payload admission. Vector capacity and map entries are
//! charged before growth; shared backing storage is not charged for an Arc clone.
use std::collections::BTreeMap;
use std::mem::size_of;
use std::ops::{Deref, DerefMut};

use tf_limits::input::InputBudget;

use crate::Value;

/// Preserve already-observed failures and evidence when a builder stops.
pub fn failure<'v>(value: Value, inputs: impl IntoIterator<Item = &'v Value>) -> Value {
    let mut prov = value.prov.clone();
    let mut error = crate::eval::contains_error(&value).then(|| value.clone());
    for input in inputs {
        prov = prov.joined(&input.prov);
        if error.is_none() && crate::eval::contains_error(input) {
            error = Some(input.clone());
        }
    }
    if let Some(error) = error {
        return error.with_prov(prov);
    }
    let value = value.with_prov(prov);
    match value.origin() {
        Some(crate::Origin::Limit(message)) => Value::limit_from(message.clone(), [&value]),
        _ => value,
    }
}

pub fn refused(budget: &InputBudget) -> Value {
    Value::limit(budget.collection_refused().to_string())
}

pub fn admit<T>(count: usize, budget: &InputBudget) -> Result<(), Value> {
    let bytes = count
        .checked_mul(size_of::<T>())
        .ok_or_else(|| refused(budget))?;
    budget
        .admit_collection(bytes as u64)
        .map_err(|e| Value::limit(e.to_string()))
}

pub struct Buffer<'b, T> {
    items: Vec<T>,
    admitted: usize,
    budget: &'b InputBudget,
}

impl<'b, T> Buffer<'b, T> {
    pub fn new(budget: &'b InputBudget) -> Self {
        Self {
            items: Vec::new(),
            admitted: 0,
            budget,
        }
    }

    pub fn with_capacity(count: usize, budget: &'b InputBudget) -> Result<Self, Value> {
        let mut buffer = Self::new(budget);
        buffer.reserve(count)?;
        Ok(buffer)
    }

    pub fn reserve(&mut self, additional: usize) -> Result<(), Value> {
        self.budget
            .admit_collection(0)
            .map_err(|e| Value::limit(e.to_string()))?;
        let required = self
            .items
            .len()
            .checked_add(additional)
            .ok_or_else(|| refused(self.budget))?;
        if required > self.admitted {
            let capacity = required.max(self.admitted.saturating_mul(2));
            admit::<T>(capacity - self.admitted, self.budget)?;
            self.items
                .try_reserve_exact(capacity - self.items.len())
                .map_err(|_| refused(self.budget))?;
            self.admitted = capacity;
            assert!(self.items.capacity() >= self.admitted);
        }
        Ok(())
    }

    pub fn push(&mut self, value: T) -> Result<(), Value> {
        self.reserve(1)?;
        self.items.push(value);
        assert!(self.items.len() <= self.admitted);
        Ok(())
    }

    pub fn finish(self) -> Vec<T> {
        self.items
    }

    pub fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }
}

impl<T> Deref for Buffer<'_, T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.items
    }
}

impl<T> DerefMut for Buffer<'_, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.items
    }
}

/// Exact-size iteration admits the full destination before invoking any mapper.
pub fn collect<T>(
    items: impl ExactSizeIterator<Item = T>,
    budget: &InputBudget,
) -> Result<Vec<T>, Value> {
    try_collect(items.map(Ok), budget)
}

pub fn try_collect<T>(
    items: impl ExactSizeIterator<Item = Result<T, Value>>,
    budget: &InputBudget,
) -> Result<Vec<T>, Value> {
    let count = items.len();
    let mut out = Buffer::with_capacity(count, budget)?;
    for item in items {
        out.push(item?)?;
    }
    assert_eq!(out.len(), count);
    Ok(out.finish())
}

/// Charge logical key/value payload. BTreeMap node overhead and unused slots are
/// not byte-accounted; entry count is bounded by the admitted payload.
pub fn insert<K: Ord, V>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    budget: &InputBudget,
) -> Result<(), Value> {
    if !map.contains_key(&key) {
        admit::<(K, V)>(1, budget)?;
    }
    map.insert(key, value);
    Ok(())
}

pub fn one_of(values: Vec<Value>, tainted: bool, budget: &InputBudget) -> Result<Value, Value> {
    let count = values
        .iter()
        .try_fold(0usize, |n, value| n.checked_add(value.alternative_count()))
        .filter(|&n| n <= tf_limits::ALTERNATIVES_MAX);
    if let Some(count) = count {
        admit::<Value>(count, budget).map_err(|stopped| failure(stopped, &values))?;
    }
    Ok(Value::one_of(values, tainted))
}

/// Preflight the existing recursive nonsensitive copier with a bounded traversal.
/// Every occurrence pays for a new backing container, even when inputs share one.
pub fn admit_tree_copy(value: &Value, budget: &InputBudget) -> Result<(), Value> {
    enum Children<'a> {
        List(std::slice::Iter<'a, Value>),
        Object(std::collections::btree_map::Values<'a, std::sync::Arc<str>, Value>),
        Single(std::iter::Once<&'a Value>),
    }
    impl<'a> Iterator for Children<'a> {
        type Item = &'a Value;
        fn next(&mut self) -> Option<Self::Item> {
            match self {
                Self::List(items) => items.next(),
                Self::Object(items) => items.next(),
                Self::Single(item) => item.next(),
            }
        }
    }
    let mut stack = Buffer::new(budget);
    stack.push(Children::Single(std::iter::once(value)))?;
    while let Some(frame) = stack.last_mut() {
        let Some(value) = frame.next() else {
            stack.pop();
            continue;
        };
        let children = match &value.kind {
            crate::Kind::Known(crate::Known::List(items)) => {
                admit::<Value>(items.len(), budget)?;
                Children::List(items.iter())
            }
            crate::Kind::Known(crate::Known::Object(items)) => {
                admit::<(std::sync::Arc<str>, Value)>(items.len(), budget)?;
                Children::Object(items.values())
            }
            crate::Kind::Known(crate::Known::Json(value)) => {
                admit::<Value>(1, budget)?;
                Children::Single(std::iter::once(value))
            }
            crate::Kind::OneOf(choices) => {
                admit::<Value>(choices.alternatives.len(), budget)?;
                Children::List(choices.alternatives.iter())
            }
            _ => continue,
        };
        if stack.len() >= tf_limits::EVALUATION_DEPTH_MAX {
            return Err(Value::limit("nonsensitive: collection nesting limit"));
        }
        stack.push(children)?;
    }
    Ok(())
}

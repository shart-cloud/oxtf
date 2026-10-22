use std::collections::HashSet;
use std::hash::Hash;

use rustc_hash::FxHashMap;
use tf_allocator::AllocResult;
use tf_limits::input::InputBudget;

pub(super) fn map_slot<K: Eq + Hash, V>(
    map: &mut FxHashMap<K, V>,
    key: &K,
    budget: &InputBudget,
) -> AllocResult<()> {
    budget.admit_collection(0)?;
    if !map.contains_key(key) {
        crate::model_budget::hash_slot(map, budget).map_err(|_| budget.collection_refused())?;
    }
    Ok(())
}

pub(super) fn set_insert<K: Eq + Hash>(
    set: &mut HashSet<K>,
    key: K,
    budget: &InputBudget,
) -> AllocResult<bool> {
    budget.admit_collection(0)?;
    if set.contains(&key) {
        return Ok(false);
    }
    budget.admit_collection(size_of::<K>() as u64)?;
    set.try_reserve(1)
        .map_err(|_| budget.collection_refused())?;
    assert!(set.capacity() > set.len());
    let inserted = set.insert(key);
    assert!(inserted);
    Ok(true)
}

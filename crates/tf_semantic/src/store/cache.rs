use std::hash::Hash;
use std::sync::{Mutex, OnceLock};

use elsa::sync::FrozenMap;
use tf_limits::{Exhaustion, input::InputBudget};

/// The miss lock couples admission to insertion. Parsing happens after it is released.
pub(super) struct ParsedCache<K, V> {
    entries: FrozenMap<K, Box<OnceLock<V>>>,
    insertion: Mutex<()>,
}

impl<K: Eq + Hash, V> Default for ParsedCache<K, V> {
    fn default() -> Self {
        Self {
            entries: FrozenMap::new(),
            insertion: Mutex::new(()),
        }
    }
}

impl<K: Eq + Hash, V> ParsedCache<K, V> {
    pub(super) fn entry(&self, key: K, budget: &InputBudget) -> Result<&OnceLock<V>, Exhaustion> {
        if let Some(cell) = self.entries.get(&key) {
            return Ok(cell);
        }
        let _guard = self.insertion.lock().unwrap();
        if let Some(cell) = self.entries.get(&key) {
            return Ok(cell);
        }
        // Count the logical map entry, boxed cell, and its separately boxed arena owner.
        // The arena's backing chunks have their own admission contract.
        let bytes = size_of::<(K, Box<OnceLock<V>>)>()
            .checked_add(size_of::<OnceLock<V>>())
            .and_then(|n| n.checked_add(size_of::<tf_allocator::Allocator>()))
            .ok_or_else(|| budget.collection_refused())?;
        budget.admit_collection(bytes as u64)?;
        Ok(self.entries.insert(key, Box::new(OnceLock::new())))
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

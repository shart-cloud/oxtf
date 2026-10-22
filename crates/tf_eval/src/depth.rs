//! Bound the active evaluation stack, including re-entry through a fresh evaluator.
use std::cell::{Cell, RefCell};
use std::sync::Arc;

use tf_limits::input::InputBudget;

use crate::Value;

/// Keep the existing 90-local provenance regression within budget, with headroom.
/// Crash probes exercise this ceiling on a 2 MiB stack in both build modes.
pub use tf_limits::EVALUATION_DEPTH_MAX;

thread_local! {
    static ACTIVE: Cell<usize> = const { Cell::new(0) };
    /// Collection allowance of the innermost active evaluation, for provenance unions
    /// built inside infallible value constructors.
    static STORAGE: RefCell<Option<Arc<InputBudget>>> = const { RefCell::new(None) };
    static EXHAUSTED: Cell<bool> = const { Cell::new(false) };
}

/// `previous` is set only when entering switched the active allowance.
pub(crate) struct DepthGuard {
    previous: Option<Option<Arc<InputBudget>>>,
}

impl DepthGuard {
    pub(crate) fn enter(storage: &Arc<InputBudget>) -> Result<Self, Value> {
        let active = ACTIVE.get();
        assert!(active <= EVALUATION_DEPTH_MAX);
        if active == 0 {
            EXHAUSTED.set(false);
            crate::meter::reset();
        }
        if active == EVALUATION_DEPTH_MAX || EXHAUSTED.get() {
            EXHAUSTED.set(true);
            return Err(Self::limit());
        }
        ACTIVE.set(active + 1);
        // Nested evaluators usually share the root's allowance: compare without cloning.
        let same = STORAGE.with_borrow(|s| s.as_ref().is_some_and(|s| Arc::ptr_eq(s, storage)));
        let previous = (!same).then(|| STORAGE.replace(Some(Arc::clone(storage))));
        Ok(Self { previous })
    }

    /// A parent operation (length, condition, try/can) cannot erase exhaustion.
    pub(crate) fn finish(&self, value: Value) -> Value {
        assert!(ACTIVE.get() > 0);
        if EXHAUSTED.get() {
            // Preserve an established failure. The shared flag still prevents
            // an enclosing try/can from turning exhaustion into known success.
            if value.is_error() {
                return value;
            }
            Value::limit_from(
                format!("evaluation nesting exceeds limit {EVALUATION_DEPTH_MAX}"),
                [&value],
            )
        } else {
            value
        }
    }

    fn limit() -> Value {
        Value::limit(format!(
            "evaluation nesting exceeds limit {EVALUATION_DEPTH_MAX}"
        ))
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        let active = ACTIVE.get();
        assert!(active > 0);
        ACTIVE.set(active - 1);
        if active == 1 {
            crate::meter::reset();
        }
        if let Some(previous) = self.previous.take() {
            STORAGE.set(previous);
        }
        assert!(ACTIVE.get() > 0 || STORAGE.with_borrow(Option::is_none));
    }
}

/// Provenance lists are built inside infallible constructors, after their inputs
/// were admitted. Refusal is sticky: the evaluator's next charge stops the root and
/// the scan reports `coverage-storage`, so overshoot is at most one list.
/// Outside an active evaluation (analyzer projections) lists copy admitted ones.
/// No evaluation is active on this thread.
pub(crate) fn idle() -> bool {
    ACTIVE.get() == 0
}

pub(crate) fn admit_provenance(bytes: usize) {
    STORAGE.with_borrow(|storage| {
        if let Some(storage) = storage {
            let _refused = storage.admit_collection(bytes as u64);
        }
    });
}

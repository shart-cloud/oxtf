//! Bound the active evaluation stack, including re-entry through a fresh evaluator.
use std::cell::Cell;

use crate::Value;

/// Keep the existing 90-local provenance regression within budget, with headroom.
/// Crash probes exercise this ceiling on a 2 MiB stack in both build modes.
pub use tf_limits::EVALUATION_DEPTH_MAX;

thread_local! {
    static ACTIVE: Cell<usize> = const { Cell::new(0) };
    static EXHAUSTED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) struct DepthGuard;

impl DepthGuard {
    pub(crate) fn enter() -> Result<Self, Value> {
        let active = ACTIVE.get();
        assert!(active <= EVALUATION_DEPTH_MAX);
        if active == 0 {
            EXHAUSTED.set(false);
        }
        if active == EVALUATION_DEPTH_MAX || EXHAUSTED.get() {
            EXHAUSTED.set(true);
            return Err(Self::limit());
        }
        ACTIVE.set(active + 1);
        Ok(Self)
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
    }
}

//! Internal work of value operations that take no budget: equality visits and
//! builtin argument scans. The evaluator charges these ticks to the root's
//! `evaluation_steps` at its next entry or finish. Loops that can grow
//! quadratically stop once uncharged ticks exceed what remains of the allowance;
//! the evaluator's charge then records the typed exhaustion.
use std::cell::Cell;

use crate::{Known, Value};

thread_local! {
    static USED: Cell<u64> = const { Cell::new(0) };
    /// What remained at the evaluator's last charge; unlimited outside evaluation.
    static ALLOWANCE: Cell<u64> = const { Cell::new(u64::MAX) };
}

/// Text is metered per this many bytes, matching one element visit.
const TEXT_BYTES_PER_TICK: usize = 64;

pub(crate) fn tick(n: u64) {
    USED.set(USED.get().saturating_add(n));
}

pub(crate) fn exceeded() -> bool {
    USED.get() > ALLOWANCE.get()
}

/// The evaluator replaces this with the typed exhaustion when it charges.
pub(crate) const LIMIT: &str = "evaluation work exceeds the remaining allowance";

/// Stop a loop whose uncharged work exceeds the remaining allowance.
pub(crate) fn check() -> Result<(), Value> {
    if exceeded() {
        return Err(Value::limit(LIMIT));
    }
    Ok(())
}

/// Uncharged ticks, reset to zero.
pub(crate) fn take() -> u64 {
    USED.replace(0)
}

/// Set after each charge to the allowance that remains.
pub(crate) fn allow(remaining: u64) {
    ALLOWANCE.set(remaining);
}

/// Outside evaluation work is unmetered, and nothing carries into the next root.
pub(crate) fn reset() {
    USED.set(0);
    ALLOWANCE.set(u64::MAX);
}

/// One tick per element, entry, or 64 bytes of text of each builtin argument:
/// a builtin may scan its arguments once, whatever its result size.
pub(crate) fn arguments(args: &[Value]) -> bool {
    let ticks = args.iter().fold(0u64, |ticks, arg| {
        let size = match arg.as_known() {
            Some(Known::List(items)) => items.len(),
            Some(Known::Object(entries)) => entries.len(),
            Some(Known::String(text)) => text.len() / TEXT_BYTES_PER_TICK,
            _ => 0,
        };
        ticks.saturating_add(size as u64)
    });
    tick(ticks);
    !exceeded()
}

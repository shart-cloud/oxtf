//! Root-owned accounting, independent of the abstract value an expression returns.
use std::cell::Cell;
use std::sync::Arc;
use tf_limits::input::InputBudget;

use tf_limits::{Exhaustion, Limits, Resource, WorkBudget};
use tf_span::FileSpan;

use crate::{Origin, Value};

/// A refused operation, located before an enclosing operation can erase its value.
#[derive(Clone, Copy, Debug)]
pub struct EvaluationLimit {
    pub at: FileSpan,
    pub reason: LimitReason,
}

#[derive(Clone, Copy, Debug)]
pub enum LimitReason {
    Work(Exhaustion),
    Storage(Exhaustion),
    /// Existing fixed expansion/depth limits retain their value-level explanation.
    Evaluation,
}

/// A fresh instance starts a root. Borrow it for locals, modules, defaults and templates.
/// Deliberately not Clone: copying counters would reset the root's allowance.
#[derive(Debug)]
pub struct EvaluationBudget {
    work: WorkBudget,
    storage: Arc<InputBudget>,
    first_limit: Cell<Option<EvaluationLimit>>,
}

impl EvaluationBudget {
    pub fn new(limits: Limits) -> Self {
        Self::for_resource(limits, Resource::EvaluationSteps)
    }

    /// Loader evaluators share a distinct allowance with concrete default conversion.
    pub fn for_resource(limits: Limits, resource: Resource) -> Self {
        Self::with_storage(limits, resource, Arc::new(InputBudget::new(limits)))
    }

    pub fn with_storage(limits: Limits, resource: Resource, storage: Arc<InputBudget>) -> Self {
        Self {
            work: WorkBudget::for_resource(limits, resource),
            storage,
            first_limit: Cell::new(None),
        }
    }

    pub fn storage(&self) -> &InputBudget {
        &self.storage
    }

    pub fn used(&self) -> u64 {
        self.work.used()
    }

    /// First work exhaustion, or the first fixed limit if the work allowance is not exhausted.
    pub fn first_limit(&self) -> Option<EvaluationLimit> {
        self.first_limit.get()
    }

    pub fn charge(&self, at: FileSpan, steps: u64) -> Result<(), Value> {
        if let Some(exhaustion) = self.exhaustion() {
            if self.storage.exhaustion().is_some() {
                self.record(at, LimitReason::Storage(exhaustion));
            }
            return Err(Value::limit(exhaustion.to_string()));
        }
        self.work.charge(steps).map_err(|exhaustion| {
            self.record(at, LimitReason::Work(exhaustion));
            Value::limit(exhaustion.to_string())
        })
    }

    /// Replay a cached module's logical cost and exhaustion before exposing its defaults.
    pub fn import(&self, at: FileSpan, steps: u64, limit: Option<EvaluationLimit>) {
        if self.charge(at, steps).is_ok()
            && let Some(limit) = limit
        {
            self.record(limit.at, limit.reason);
        }
    }

    /// A loader reparses a source fragment at offset zero. Locate its recorded
    /// exhaustion at the original declaration before caching the result.
    pub fn locate_limit(&self, at: FileSpan) {
        if let Some(mut limit) = self.first_limit.get() {
            limit.at = at;
            self.first_limit.set(Some(limit));
        }
    }

    /// Further evaluation must stop, but existing errors and coverage evidence remain valid.
    pub fn is_exhausted(&self) -> bool {
        self.exhaustion().is_some()
    }

    fn exhaustion(&self) -> Option<Exhaustion> {
        if let Some(error) = self.storage.exhaustion() {
            return Some(error);
        }
        match self.first_limit.get().map(|limit| limit.reason) {
            Some(LimitReason::Work(exhaustion) | LimitReason::Storage(exhaustion)) => {
                Some(exhaustion)
            }
            _ => self.work.exhaustion(),
        }
    }

    /// Retain exhaustion across an evaluation or semantic conversion boundary.
    /// Established expression errors take precedence over a work limit.
    pub fn finish(&self, value: Value, at: FileSpan) -> Value {
        if let Some(error) = self.storage.exhaustion() {
            self.record(at, LimitReason::Storage(error));
        }
        if matches!(value.origin(), Some(Origin::Limit(_))) {
            self.record(at, LimitReason::Evaluation);
        }
        match self.exhaustion() {
            Some(exhaustion) if !crate::eval::contains_error(&value) => {
                Value::limit_from(exhaustion.to_string(), [&value])
            }
            _ => value,
        }
    }

    fn record(&self, at: FileSpan, reason: LimitReason) {
        let first = self.first_limit.get();
        let work_takes_precedence =
            matches!(reason, LimitReason::Work(_) | LimitReason::Storage(_))
                && first.is_some_and(|limit| matches!(limit.reason, LimitReason::Evaluation));
        if first.is_none() || work_takes_precedence {
            self.first_limit.set(Some(EvaluationLimit { at, reason }));
        }
        assert!(self.first_limit.get().is_some());
    }
}

pub(crate) enum BudgetRef<'b> {
    Owned(EvaluationBudget),
    Shared(&'b EvaluationBudget),
}

impl std::ops::Deref for BudgetRef<'_> {
    type Target = EvaluationBudget;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(budget) => budget,
            Self::Shared(budget) => budget,
        }
    }
}

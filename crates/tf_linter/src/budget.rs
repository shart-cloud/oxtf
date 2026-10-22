//! One monotonic allowance shared by all counted rule work for a root.
use std::any::{Any, TypeId};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::time::Duration;
use tf_limits::{Exhaustion, Limits, Resource, WorkBudget};

use crate::RuleFailure;

pub struct RuleBudget {
    work: WorkBudget,
    caches: RefCell<HashMap<TypeId, Box<dyn Any>>>,
    rego_allowance: Duration,
    rego_used: Cell<Duration>,
    rego_exhaustion: Cell<Option<Exhaustion>>,
}

impl RuleBudget {
    pub fn new(limits: Limits) -> Self {
        Self {
            work: WorkBudget::for_resource(limits, Resource::RuleSteps),
            caches: RefCell::new(HashMap::new()),
            rego_allowance: Duration::from_millis(limits.rego_time_ms()),
            rego_used: Cell::new(Duration::ZERO),
            rego_exhaustion: Cell::new(None),
        }
    }

    /// Backend scratch belongs to this root, including nested scans and early exits.
    /// Take engines out before executing callbacks: no cache borrow may cross re-entry.
    pub fn with_cache<T: Default + 'static, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let mut caches = self.caches.borrow_mut();
        let cache = caches
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::<T>::default());
        f(cache
            .downcast_mut::<T>()
            .expect("cache key matches its stored type"))
    }

    pub fn charge(&self, steps: u64) -> Result<(), RuleFailure> {
        if let Some(limit) = self.exhaustion() {
            return Err(limit.to_string());
        }
        self.work.charge(steps).map_err(|e| e.to_string())
    }

    /// One cumulative allowance; creating/reusing an engine cannot reset it.
    pub fn rego_remaining(&self) -> Result<Duration, RuleFailure> {
        self.charge(0)?;
        let remaining = self.rego_allowance - self.rego_used.get();
        if remaining.is_zero() {
            return Err(self.exhaust_rego_time());
        }
        Ok(remaining)
    }

    pub fn record_rego_elapsed(&self, elapsed: Duration) -> Result<(), RuleFailure> {
        self.charge(0)?;
        let used = self.rego_used.get();
        assert!(used <= self.rego_allowance);
        if elapsed > self.rego_allowance - used {
            self.rego_used.set(self.rego_allowance);
            return Err(self.exhaust_rego_time());
        }
        self.rego_used.set(used + elapsed);
        Ok(())
    }

    pub fn rego_elapsed(&self) -> Duration {
        self.rego_used.get()
    }

    /// Preserve a typed timeout reported by the backend's cooperative timer.
    pub fn exhaust_rego_time(&self) -> RuleFailure {
        let limit = Exhaustion {
            resource: Resource::RegoTimeMs,
            allowance: self
                .rego_allowance
                .as_millis()
                .try_into()
                .expect("configured u64 ms"),
        };
        self.rego_exhaustion.set(Some(limit));
        self.rego_used.set(self.rego_allowance);
        limit.to_string()
    }

    pub fn used(&self) -> u64 {
        self.work.used()
    }

    pub fn exhaustion(&self) -> Option<Exhaustion> {
        self.work.exhaustion().or(self.rego_exhaustion.get())
    }

    /// A hook cannot discard a refused charge and return a successful result.
    pub fn finish<T>(&self, result: Result<T, RuleFailure>) -> Result<T, RuleFailure> {
        match self.exhaustion() {
            Some(exhaustion) => Err(exhaustion.to_string()),
            None => result,
        }
    }
}

impl std::fmt::Debug for RuleBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleBudget")
            .field("work", &self.work)
            .field("cache_types", &self.caches.borrow().len())
            .finish()
    }
}

impl Default for RuleBudget {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

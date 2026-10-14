//! Provenance: where a value came from.
//!
//! A [`Prov`] is a persistent, `Arc`-shared cons list of [`Step`]s, newest
//! step first. Pushing a step is O(1) and shares the tail, so every value can
//! carry its own chain cheaply (one pointer, 8 bytes). Chains are short in
//! practice (one step per variable / local / module boundary / attribute the
//! value flowed through) and are capped at [`MAX_STEPS`].
//!
//! Nested values carry only the steps that apply to *them*. The full chain of
//! an element inside a container is `element.prov.then(&container.prov)`:
//! the element's own history, followed by the container's history after the
//! element was placed into it. The evaluator does this join whenever it
//! projects an element out of a container (`x.attr`, `x[i]`, `for`, `dynamic`
//! iteration), and rules do it when they report a witness.

use std::fmt;
use std::sync::Arc;

use tf_span::FileSpan;

/// Chains longer than this stop growing (newer steps are dropped). Real
/// chains in the corpus are far shorter; the cap only bounds pathological
/// recursion through `for` expressions.
pub const MAX_STEPS: u32 = 48;

/// What kind of hop a [`Step`] records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepKind {
    /// A binding in a `.tfvars` file (`admin_cidr = "0.0.0.0/0"`).
    Tfvars,
    /// The value passed through a `variable` block (bound from tfvars or a
    /// module argument).
    Variable,
    /// A `variable` block's `default`.
    VariableDefault,
    /// An argument of a `module` call, bound to the child's variable.
    ModuleArgument,
    /// A `locals` entry.
    Local,
    /// A child module's `output`.
    Output,
    /// A resource / data / nested-block attribute in configuration.
    Attribute,
    /// A `dynamic` block, `for_each` or `count` iteration.
    Iteration,
    /// A provider default from the defaults overlay (`defaults/*.toml`).
    Default,
    /// Anything else.
    Other,
}

impl StepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StepKind::Tfvars => "tfvars",
            StepKind::Variable => "variable",
            StepKind::VariableDefault => "variable_default",
            StepKind::ModuleArgument => "module_argument",
            StepKind::Local => "local",
            StepKind::Output => "output",
            StepKind::Attribute => "attribute",
            StepKind::Iteration => "iteration",
            StepKind::Default => "default",
            StepKind::Other => "other",
        }
    }
}

/// One hop in a provenance chain: a source location plus a short label.
#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    pub kind: StepKind,
    pub at: FileSpan,
    /// Short human label, e.g. `variable admin_cidr`, `local.ssh_sources`,
    /// `aws_security_group.admin ingress.cidr_blocks`.
    pub label: Arc<str>,
    /// For [`StepKind::Attribute`] steps on a resource or data source: the
    /// owning resource's address (module path included, instance key
    /// excluded). This is explanation metadata, not evidence of identity.
    pub resource: Option<Arc<str>>,
}

impl Step {
    pub fn new(kind: StepKind, at: FileSpan, label: impl Into<Arc<str>>) -> Self {
        Step {
            kind,
            at,
            label: label.into(),
            resource: None,
        }
    }

    pub fn with_resource(mut self, address: Arc<str>) -> Self {
        self.resource = Some(address);
        self
    }

    fn same_place(&self, other: &Step) -> bool {
        self.at == other.at && self.kind == other.kind
    }
}

struct Node {
    step: Step,
    len: u32,
    prev: Option<Arc<Node>>,
}

/// A provenance chain. `Clone` is a refcount bump.
#[derive(Clone, Default)]
pub struct Prov(Option<Arc<Node>>);

impl Prov {
    pub const EMPTY: Prov = Prov(None);

    pub fn single(step: Step) -> Prov {
        Prov::EMPTY.push(step)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |n| n.len as usize)
    }

    /// The newest step (closest to where the value is used).
    pub fn last(&self) -> Option<&Step> {
        self.0.as_ref().map(|n| &n.step)
    }

    /// A new chain with `step` appended as the newest step. A step at the same
    /// place as the current newest one is not repeated.
    #[must_use]
    pub fn push(&self, step: Step) -> Prov {
        if let Some(n) = &self.0
            && (n.step.same_place(&step) || n.len >= MAX_STEPS)
        {
            return self.clone();
        }
        let len = self.len() as u32 + 1;
        Prov(Some(Arc::new(Node {
            step,
            len,
            prev: self.0.clone(),
        })))
    }

    /// Iterate newest step first.
    pub fn iter_newest_first(&self) -> impl Iterator<Item = &Step> {
        let mut cur = self.0.as_deref();
        std::iter::from_fn(move || {
            let n = cur?;
            cur = n.prev.as_deref();
            Some(&n.step)
        })
    }

    /// The steps origin-first (the order a reader follows: tfvars line →
    /// variable → local → attribute).
    pub fn steps(&self) -> Vec<Step> {
        let mut v: Vec<Step> = self.iter_newest_first().cloned().collect();
        v.reverse();
        v
    }

    /// `self` (an inner value's history) followed by `outer` (the history of
    /// the container it was taken from). Steps of `outer` already present in
    /// `self` are skipped.
    #[must_use]
    pub fn then(&self, outer: &Prov) -> Prov {
        if outer.is_empty() {
            return self.clone();
        }
        if self.is_empty() {
            return outer.clone();
        }
        if Arc::ptr_eq(self.0.as_ref().unwrap(), outer.0.as_ref().unwrap()) {
            return self.clone();
        }
        let mut r = self.clone();
        for s in outer.steps() {
            if !r.iter_newest_first().any(|x| x.same_place(&s)) {
                r = r.push(s);
            }
        }
        r
    }

    pub fn any(&self, f: impl FnMut(&Step) -> bool) -> bool {
        self.iter_newest_first().any(f)
    }
}

impl fmt::Debug for Prov {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.steps().iter().map(|s| &*s.label))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_span::{FileId, Span};

    fn st(n: u32, l: &str) -> Step {
        Step::new(
            StepKind::Other,
            FileSpan::new(FileId(0), Span::new(n, n + 1)),
            l,
        )
    }

    #[test]
    fn push_then_order() {
        let a = Prov::single(st(1, "a")).push(st(2, "b"));
        let c = Prov::single(st(3, "c")).push(st(4, "d"));
        let j = a.then(&c);
        let labels: Vec<_> = j.steps().iter().map(|s| s.label.to_string()).collect();
        assert_eq!(labels, ["a", "b", "c", "d"]);
        // dedupe
        let k = j.then(&c);
        assert_eq!(k.len(), 4);
        assert_eq!(std::mem::size_of::<Prov>(), 8);
    }
}

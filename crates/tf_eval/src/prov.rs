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
    /// An attribute a rule required that the resource does not set (and
    /// no default supplies): located at the resource header.
    Absent,
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
            StepKind::Absent => "absent",
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
    /// For [`StepKind::Attribute`] steps: the attribute path within the
    /// resource body (`storage_encrypted`, `ingress.cidr_blocks`).
    pub attribute: Option<Arc<str>>,
}

impl Step {
    pub fn new(kind: StepKind, at: FileSpan, label: impl Into<Arc<str>>) -> Self {
        Step {
            kind,
            at,
            label: label.into(),
            resource: None,
            attribute: None,
        }
    }

    pub fn with_resource(mut self, address: Arc<str>) -> Self {
        self.resource = Some(address);
        self
    }

    pub fn with_attribute(mut self, path: impl Into<Arc<str>>) -> Self {
        self.attribute = Some(path.into());
        self
    }

    fn same_place(&self, other: &Step) -> bool {
        self.at == other.at && self.kind == other.kind
    }
}

#[derive(Clone)]
struct Node {
    step: Option<Step>,
    dependencies: Option<Arc<Vec<ResourceDependency>>>,
    len: u32,
    sensitive: bool,
    prev: Option<Arc<Node>>,
}

/// A provenance chain and a sensitivity mark. The mark survives even when
/// the bounded explanation is empty or truncated.
#[derive(Clone, Default)]
pub struct Prov(Option<Arc<Node>>);

/// A resource traversal evaluated by the resolver. Separate from the bounded
/// explanation chain: dependencies survive transformations and are not identity
/// comparisons between values. An unresolved instance index has uncertain edges.
#[derive(Clone, Debug, PartialEq)]
pub struct ResourceDependency {
    pub resource: Arc<str>,
    pub key: Option<Arc<str>>,
    pub certainty: crate::Truth,
}

impl Prov {
    pub const EMPTY: Prov = Prov(None);

    pub fn is_sensitive(&self) -> bool {
        self.0.as_ref().is_some_and(|n| n.sensitive)
    }

    pub fn with_sensitive(mut self, sensitive: bool) -> Self {
        if self.is_sensitive() != sensitive {
            let n = self.0.get_or_insert_with(|| {
                Arc::new(Node {
                    step: None,
                    dependencies: None,
                    len: 0,
                    sensitive: false,
                    prev: None,
                })
            });
            Arc::make_mut(n).sensitive = sensitive;
        }
        self
    }

    pub fn dependencies(&self) -> &[ResourceDependency] {
        self.0
            .as_ref()
            .and_then(|n| n.dependencies.as_deref())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// A direct traversal names this resource, not all of its dependencies.
    pub fn referencing(self, dependencies: Vec<ResourceDependency>) -> Self {
        Prov(Some(Arc::new(Node {
            step: None,
            len: self.len() as u32,
            dependencies: (!dependencies.is_empty()).then(|| Arc::new(dependencies)),
            sensitive: self.is_sensitive(),
            prev: self.0,
        })))
    }

    pub(crate) fn join_dependencies(&mut self, other: &Prov) {
        if other.is_sensitive() {
            *self = self.clone().with_sensitive(true);
        }
        if other.dependencies().is_empty() {
            return;
        }
        if self.dependencies().is_empty() {
            *self = self.clone().inheriting(other);
            return;
        }
        let mut refs = self.dependencies().to_vec();
        let old_len = refs.len();
        for dependency in other.dependencies() {
            if !refs.contains(dependency) {
                refs.push(dependency.clone());
            }
        }
        if refs.len() != old_len {
            *self = self.clone().referencing(refs);
        }
    }

    /// `self` with the dependency list of `other` (shared, not copied).
    fn inheriting(mut self, other: &Prov) -> Prov {
        let sensitive = self.is_sensitive() || other.is_sensitive();
        self = self.with_sensitive(sensitive);
        match other.0.as_ref().and_then(|n| n.dependencies.clone()) {
            None => self,
            Some(dependencies) => Prov(Some(Arc::new(Node {
                step: None,
                len: self.len() as u32,
                dependencies: Some(dependencies),
                sensitive: self.is_sensitive(),
                prev: self.0,
            }))),
        }
    }

    /// The union of the dependencies of `parts`, as the provenance of a
    /// container built from them. One allocation for the whole union.
    pub(crate) fn union_of<'a>(parts: impl IntoIterator<Item = &'a Prov>) -> Prov {
        let mut refs: Vec<ResourceDependency> = Vec::new();
        let mut first: Option<&'a Prov> = None;
        let mut single = true;
        let mut sensitive = false;
        for part in parts {
            sensitive |= part.is_sensitive();
            let deps = part.dependencies();
            if deps.is_empty() {
                continue;
            }
            match first {
                None => first = Some(part),
                Some(f) if single && f.dependencies() != deps => {
                    single = false;
                    refs.extend_from_slice(f.dependencies());
                }
                _ => {}
            }
            if !single {
                for dependency in deps {
                    if !refs.contains(dependency) {
                        refs.push(dependency.clone());
                    }
                }
            }
        }
        let p = match first {
            None => Prov::EMPTY,
            Some(f) if single => Prov::EMPTY.inheriting(f),
            Some(_) => Prov::EMPTY.referencing(refs),
        };
        p.with_sensitive(sensitive)
    }

    pub fn single(step: Step) -> Prov {
        Prov::EMPTY.push(step)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |n| n.len as usize)
    }

    /// The newest step (closest to where the value is used).
    pub fn last(&self) -> Option<&Step> {
        self.iter_newest_first().next()
    }

    /// A new chain with `step` appended as the newest step. A step at the same
    /// place as the current newest one is not repeated.
    #[must_use]
    pub fn push(&self, step: Step) -> Prov {
        if let Some(n) = &self.0
            && (self.last().is_some_and(|s| s.same_place(&step)) || n.len >= MAX_STEPS)
        {
            return self.clone();
        }
        let len = self.len() as u32 + 1;
        Prov(Some(Arc::new(Node {
            step: Some(step),
            dependencies: self.0.as_ref().and_then(|n| n.dependencies.clone()),
            len,
            sensitive: self.is_sensitive(),
            prev: self.0.clone(),
        })))
    }

    /// Iterate newest step first.
    pub fn iter_newest_first(&self) -> impl Iterator<Item = &Step> {
        let mut cur = self.0.as_deref();
        std::iter::from_fn(move || {
            loop {
                let n = cur?;
                cur = n.prev.as_deref();
                if let Some(step) = &n.step {
                    return Some(step);
                }
            }
        })
    }

    /// The steps origin-first (the order a reader follows: tfvars line →
    /// variable → local → attribute).
    pub fn steps(&self) -> Vec<Step> {
        let mut v: Vec<Step> = self.iter_newest_first().cloned().collect();
        v.reverse();
        if self.is_sensitive() {
            for step in &mut v {
                step.label = format!("{} (sensitive)", step.kind.as_str()).into();
            }
        }
        v
    }

    /// `self` (an inner value's history) followed by `outer` (the history of
    /// the container it was taken from). Steps of `outer` already present in
    /// `self` are skipped. Resource dependencies are the element's own when
    /// it has any, else the container's; see [`Prov::joined`] for a union.
    #[must_use]
    pub fn then(&self, outer: &Prov) -> Prov {
        // An element keeps its own resource dependencies: a container's
        // list is the union over all of its elements, and an element with
        // dependencies of its own is more precise than that union. Only an
        // element that names no resource inherits the container's.
        // A chain with no steps may still carry dependencies, so test the
        // node, not the step count.
        let (Some(inner), Some(container)) = (&self.0, &outer.0) else {
            return (if self.0.is_none() {
                outer.clone()
            } else {
                self.clone()
            })
            .with_sensitive(self.is_sensitive() || outer.is_sensitive());
        };
        if Arc::ptr_eq(inner, container) {
            return self
                .clone()
                .with_sensitive(self.is_sensitive() || outer.is_sensitive());
        }
        let mut r = self
            .clone()
            .with_sensitive(self.is_sensitive() || outer.is_sensitive());
        if r.dependencies().is_empty() {
            r = r.inheriting(outer);
        }
        for s in outer.steps() {
            if !r.iter_newest_first().any(|x| x.same_place(&s)) {
                r = r.push(s);
            }
        }
        r
    }

    /// `self` followed by `other`, with the resource dependencies of both: a
    /// value computed from several parts (function arguments, template
    /// parts, a filter condition) depends on all of them.
    #[must_use]
    pub fn joined(&self, other: &Prov) -> Prov {
        let mut r = self.then(other);
        r.join_dependencies(other);
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

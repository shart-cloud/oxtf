//! The rule trait (oxc-linter shape) and findings.
//!
//! A rule is a small struct implementing [`RuleMeta`] (static metadata,
//! including the resource types it wants) and [`Rule`] (the hooks). The
//! engine stores rules as `Box<dyn DynRule>`; every `T: Rule` is a
//! `DynRule` through a blanket impl, and a rule built at runtime (e.g. from a
//! Python expression compiled to a rule IR) implements `DynRule` directly.

use std::path::PathBuf;
use std::sync::Arc;

use tf_eval::{Kind, Step, Truth, Verdict};
use tf_semantic::{Module, Resource};
use tf_span::FileSpan;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    Network,
    Storage,
    Iam,
    Encryption,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Network => "network",
            Category::Storage => "storage",
            Category::Iam => "iam",
            Category::Encryption => "encryption",
        }
    }
}

/// How bad a rule's finding is (rule metadata, independent of certainty).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        }
    }
}

/// Certainty of a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// Insecure as written (for the configuration with its defaults and
    /// tfvars).
    Definite,
    /// Insecure depending on an unconstrained variable (a root variable with
    /// no default and no tfvars value).
    Conditional,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Definite => "definite",
            Severity::Conditional => "conditional",
        }
    }
}

/// Static rule metadata.
pub trait RuleMeta {
    /// Rule id, e.g. `aws-sg-open-ssh`.
    const NAME: &'static str;
    const CATEGORY: Category;
    const LEVEL: Level;
    const DESCRIPTION: &'static str;
    /// Resource types `run_on_resource` is called for. The engine builds a
    /// type → rules table from these once.
    const RESOURCE_TYPES: &'static [&'static str] = &[];
    /// Whether `run_on_module` should be called (cross-resource rules).
    const RUNS_ON_MODULE: bool = false;
}

/// Rule hooks. Both default to no-ops.
pub trait Rule: RuleMeta + Send + Sync {
    fn run_on_resource(&self, _resource: &Resource, _ctx: &mut RuleContext<'_>) {}
    fn run_on_module(&self, _module: &Module, _ctx: &mut RuleContext<'_>) {}
}

/// Owned metadata, for object-safe dispatch and for listing rules.
#[derive(Clone, Debug)]
pub struct RuleInfo {
    pub name: Arc<str>,
    pub category: Category,
    pub level: Level,
    pub description: Arc<str>,
    pub resource_types: Vec<Arc<str>>,
    pub runs_on_module: bool,
}

/// Object-safe rule interface used by the engine.
pub trait DynRule: Send + Sync {
    fn info(&self) -> RuleInfo;
    fn run_on_resource(&self, resource: &Resource, ctx: &mut RuleContext<'_>);
    fn run_on_module(&self, module: &Module, ctx: &mut RuleContext<'_>);
}

impl<T: Rule> DynRule for T {
    fn info(&self) -> RuleInfo {
        RuleInfo {
            name: T::NAME.into(),
            category: T::CATEGORY,
            level: T::LEVEL,
            description: T::DESCRIPTION.into(),
            resource_types: T::RESOURCE_TYPES.iter().map(|s| Arc::from(*s)).collect(),
            runs_on_module: T::RUNS_ON_MODULE,
        }
    }
    fn run_on_resource(&self, resource: &Resource, ctx: &mut RuleContext<'_>) {
        Rule::run_on_resource(self, resource, ctx)
    }
    fn run_on_module(&self, module: &Module, ctx: &mut RuleContext<'_>) {
        Rule::run_on_module(self, module, ctx)
    }
}

/// A finding.
#[derive(Clone, Debug)]
pub struct Finding {
    pub rule: Arc<str>,
    pub level: Level,
    /// Resource address, module path included (`module.m.aws_s3_bucket.b`).
    pub address: Arc<str>,
    pub resource_type: Arc<str>,
    /// Module instance address (`""` for the root module).
    pub module: Arc<str>,
    pub severity: Severity,
    pub message: String,
    /// Where to point: the attribute that decided the finding, or the
    /// resource header.
    pub primary: FileSpan,
    /// Origin-first provenance chain of the deciding value.
    pub provenance: Vec<Step>,
    /// The root module directory whose analysis produced this finding.
    pub root: PathBuf,
}

/// Per-(rule, module instance) context handed to rule hooks.
pub struct RuleContext<'c> {
    pub(crate) rule: Arc<str>,
    pub(crate) level: Level,
    pub(crate) root: &'c std::path::Path,
    pub module: &'c Module,
    pub(crate) out: &'c mut Vec<Finding>,
}

impl RuleContext<'_> {
    pub fn rule_name(&self) -> &str {
        &self.rule
    }

    /// Report `verdict` for `resource`: `True` → definite, `Tainted` →
    /// conditional, anything else → nothing. A definite finding on a
    /// resource whose existence depends on an unconstrained variable
    /// (`count = var.x ? 1 : 0`) is downgraded to conditional; a resource
    /// whose existence is Unknown (e.g. `count` from a data source) gets
    /// no finding, as with any other Unknown input. `message`
    /// is given the witness value's rendering (if any).
    pub fn report(
        &mut self,
        resource: &Resource,
        verdict: &Verdict,
        message: impl FnOnce(Option<&tf_eval::Value>) -> String,
    ) {
        let mut severity = match verdict.truth {
            Truth::True => Severity::Definite,
            Truth::Tainted => Severity::Conditional,
            _ => return,
        };
        match resource.existence {
            Truth::False | Truth::Unknown => return,
            Truth::Tainted => severity = Severity::Conditional,
            _ => {}
        }
        let provenance = verdict
            .witness
            .as_ref()
            .map(|w| w.prov.steps())
            .unwrap_or_default();
        let primary = provenance
            .iter()
            .rev()
            .find(|s| s.resource.as_deref() == Some(&*resource.base_address))
            .map(|s| s.at)
            .unwrap_or(resource.span);
        let msg = message(verdict.witness.as_ref());
        let msg = match (&severity, verdict.witness.as_ref().map(|w| &w.kind)) {
            (Severity::Conditional, Some(Kind::Tainted(t))) if !t.variable.starts_with('(') => {
                format!(
                    "{msg} (depends on unconstrained variable var.{})",
                    t.variable
                )
            }
            (Severity::Conditional, _)
                if resource.existence == Truth::Tainted && verdict.truth == Truth::True =>
            {
                format!("{msg} (resource exists depending on an unconstrained variable)")
            }
            (Severity::Conditional, _) => format!("{msg} (depends on an unconstrained variable)"),
            _ => msg,
        };
        self.out.push(Finding {
            rule: self.rule.clone(),
            level: self.level,
            address: resource.address.clone(),
            resource_type: resource.ty.clone(),
            module: resource.module.clone(),
            severity,
            message: msg,
            primary,
            provenance,
            root: self.root.to_path_buf(),
        });
    }
}

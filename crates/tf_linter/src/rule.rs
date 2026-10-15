//! The rule traits (oxc-linter shape), findings, and finding construction.
//!
//! A rule is a small struct implementing [`RuleMeta`] (static metadata,
//! including the resource types it wants) and [`Rule`] (verdicts and
//! wording). A rule never builds a finding: it answers "what is the verdict
//! for this resource instance" and "how is that verdict worded", and
//! [`Finding::from_verdict`] turns the answer into a finding, or into
//! nothing. That one function owns the existence gate, the certainty
//! mapping, the primary location and the message suffixes, so every rule
//! backend (native, rule IR, Rego, Python) reaches a finding the same way.
//!
//! The engine stores rules as `Box<dyn DynRule>`; every `T: Rule` is a
//! `DynRule` through a blanket impl, and a rule built at runtime (e.g. from a
//! Python expression compiled to a rule IR) implements `DynRule` directly.

use std::path::{Path, PathBuf};
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
    /// Resource types [`Rule::verdict`] is called for. The engine builds a
    /// type → rules table from these once.
    const RESOURCE_TYPES: &'static [&'static str] = &[];
    /// Whether [`Rule::module_verdicts`] should be called (cross-resource rules).
    const RUNS_ON_MODULE: bool = false;
}

/// What a rule says. Both hooks default to "nothing".
///
/// `verdict` is called for every managed resource instance whose type is
/// in [`RuleMeta::RESOURCE_TYPES`] and whose existence is not `False`.
/// `module_verdicts` is called once per module instance when
/// [`RuleMeta::RUNS_ON_MODULE`] is set; it sees every resource, including
/// data sources and instances whose existence is `False`, and returns a
/// verdict per resource instance the rule is about.
///
/// Rules never decide severity, locations or whether a finding exists;
/// see [`Finding::from_verdict`].
pub trait Rule: RuleMeta + Send + Sync {
    /// Verdict for one resource instance, or `None` when the rule does not
    /// apply to it (a skipped read replica, a missing attribute).
    fn verdict(&self, _resource: &Resource) -> Option<Verdict> {
        None
    }

    /// Cross-resource verdicts, keyed by the resource instance each is about.
    fn module_verdicts<'m>(&self, _module: &'m Module) -> Vec<(&'m Resource, Verdict)> {
        Vec::new()
    }

    /// Wording for a verdict on a resource. Only called for verdicts that
    /// hold; [`Finding::from_verdict`] appends any certainty suffix.
    fn message(&self, resource: &Resource, verdict: &Verdict) -> String;
}

/// A verdict together with its wording, as handed from a rule to the engine.
#[derive(Clone, Debug)]
pub struct Judgement {
    pub verdict: Verdict,
    pub message: String,
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

/// Object-safe rule interface used by the engine. Backends that build
/// rules at runtime implement this directly; `T: Rule` gets it for free.
pub trait DynRule: Send + Sync {
    fn info(&self) -> RuleInfo;
    /// Judgements on one resource instance (usually zero or one).
    fn judge_resource(&self, resource: &Resource) -> Vec<Judgement>;
    /// Judgements of a cross-resource rule over one module instance.
    fn judge_module<'m>(&self, module: &'m Module) -> Vec<(&'m Resource, Judgement)>;
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
    fn judge_resource(&self, resource: &Resource) -> Vec<Judgement> {
        self.verdict(resource)
            .map(|verdict| self.judge(resource, verdict))
            .into_iter()
            .collect()
    }
    fn judge_module<'m>(&self, module: &'m Module) -> Vec<(&'m Resource, Judgement)> {
        self.module_verdicts(module)
            .into_iter()
            .map(|(r, verdict)| (r, self.judge(r, verdict)))
            .collect()
    }
}

/// Word a verdict only when it can become a finding.
trait Judge: Rule {
    fn judge(&self, resource: &Resource, verdict: Verdict) -> Judgement {
        let message = if verdict.holds() {
            self.message(resource, &verdict)
        } else {
            String::new()
        };
        Judgement { verdict, message }
    }
}
impl<T: Rule> Judge for T {}

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

impl Finding {
    /// Build the finding for `verdict` on `resource`, or `None`.
    ///
    /// - `True` → [`Severity::Definite`], `Tainted` → [`Severity::Conditional`],
    ///   `False` / `Unknown` → no finding.
    /// - A resource whose existence is `False` or `Unknown` (e.g. `count`
    ///   from a data source) gets no finding, as with any other Unknown
    ///   input; existence `Tainted` (`count = var.x ? 1 : 0`) downgrades a
    ///   definite finding to conditional.
    /// - The primary location is the newest provenance step of the witness
    ///   that belongs to this resource, else the resource header.
    /// - `message` is the rule's wording; a conditional finding gets a
    ///   suffix naming the unconstrained variable where one is known.
    pub fn from_verdict(
        info: &RuleInfo,
        resource: &Resource,
        verdict: &Verdict,
        message: &str,
        root: &Path,
    ) -> Option<Finding> {
        let mut severity = match verdict.truth {
            Truth::True => Severity::Definite,
            Truth::Tainted => Severity::Conditional,
            _ => return None,
        };
        match resource.existence {
            Truth::False | Truth::Unknown => return None,
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
        let message = match (&severity, verdict.witness.as_ref().map(|w| &w.kind)) {
            (Severity::Conditional, Some(Kind::Tainted(t))) if !t.variable.starts_with('(') => {
                format!(
                    "{message} (depends on unconstrained variable var.{})",
                    t.variable
                )
            }
            (Severity::Conditional, _)
                if resource.existence == Truth::Tainted && verdict.truth == Truth::True =>
            {
                format!("{message} (resource exists depending on an unconstrained variable)")
            }
            (Severity::Conditional, _) => {
                format!("{message} (depends on an unconstrained variable)")
            }
            _ => message.to_string(),
        };
        Some(Finding {
            rule: info.name.clone(),
            level: info.level,
            address: resource.address.clone(),
            resource_type: resource.ty.clone(),
            module: resource.module.clone(),
            severity,
            message,
            primary,
            provenance,
            root: root.to_path_buf(),
        })
    }
}

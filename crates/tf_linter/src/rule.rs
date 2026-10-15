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

use serde::{Deserialize, Serialize};

use tf_eval::{Kind, Step, Truth, Verdict};
use tf_semantic::{Module, Resource};
use tf_span::FileSpan;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Network,
    Storage,
    Iam,
    Encryption,
    /// Rules whose category is not declared (foreign policies).
    Other,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Network => "network",
            Category::Storage => "storage",
            Category::Iam => "iam",
            Category::Encryption => "encryption",
            Category::Other => "other",
        }
    }
}

/// How bad a rule's finding is (rule metadata, independent of certainty).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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

/// Certainty of a finding, ordered from most to least certain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Insecure as written (for the configuration with its defaults and
    /// tfvars).
    Definite,
    /// Insecure depending on an unconstrained variable (a root variable with
    /// no default and no tfvars value).
    Conditional,
    /// A foreign policy fired on the resource's Known values, but an input it
    /// may depend on is only known at apply time (provider-computed). Native
    /// rules never produce this: they return no finding on Unknown. A
    /// downstream tool must treat it as needing a human.
    Indeterminate,
}

impl Severity {
    /// `True` → definite, `Tainted` → conditional, anything else → no finding.
    pub fn from_truth(truth: Truth) -> Option<Severity> {
        match truth {
            Truth::True => Some(Severity::Definite),
            Truth::Tainted => Some(Severity::Conditional),
            Truth::False | Truth::Unknown => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Definite => "definite",
            Severity::Conditional => "conditional",
            Severity::Indeterminate => "indeterminate",
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

    /// A mechanical fix for a verdict that holds, when the rule knows one.
    fn fix_hint(&self, _resource: &Resource, _verdict: &Verdict) -> Option<FixHint> {
        None
    }
}

/// What a rule hands the engine about one resource instance: a certainty,
/// the value that decided it (for provenance), and the wording. Rules built
/// on the lattice get one from a verdict; adapters that classify certainty
/// from their own evidence (foreign policies) build one directly.
#[derive(Clone, Debug)]
pub struct Judgement {
    pub severity: Severity,
    pub witness: Option<tf_eval::Value>,
    pub message: String,
    /// Inputs the rule could not see (foreign policies over a Known-only
    /// projection); empty for rules on the lattice.
    pub hidden: Vec<Hidden>,
    pub fix_hint: Option<FixHint>,
}

impl Judgement {
    /// `None` when the verdict yields no finding (`False` / `Unknown`), so
    /// `message` is only rendered for verdicts that hold.
    pub fn from_verdict(verdict: Verdict, message: impl FnOnce(&Verdict) -> String) -> Option<Self> {
        let severity = Severity::from_truth(verdict.truth)?;
        let message = message(&verdict);
        Some(Judgement {
            severity,
            witness: verdict.witness,
            message,
            hidden: Vec::new(),
            fix_hint: None,
        })
    }
}

/// A configured value a rule did not see, with why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hidden {
    /// Attribute path within the resource body.
    pub path: String,
    /// `Tainted` (unconstrained variable) or `Unknown` (apply-time).
    pub truth: Truth,
}

/// What a mechanical fix would do, for a patch tool. Judgement about
/// *whether* to apply it stays with the caller.
#[derive(Clone, Debug, PartialEq)]
pub struct FixHint {
    /// The resource instance to edit (not always the finding's: the S3 rule
    /// points at the public-access block).
    pub resource: tf_semantic::Address,
    /// Attribute path to set.
    pub attribute: String,
    pub action: FixAction,
    /// The literal to write.
    pub value: serde_json::Value,
    /// Where the attribute is written today, or `None` to insert into the
    /// resource block.
    pub site: Option<FileSpan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixAction {
    /// Set (or add) a top-level attribute to a literal.
    Set,
}

impl FixAction {
    pub fn as_str(self) -> &'static str {
        match self {
            FixAction::Set => "set",
        }
    }
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
    /// Judgements on one resource instance (usually zero or one); only
    /// judgements that can become findings are returned.
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
            .and_then(|v| self.judge(resource, v))
            .into_iter()
            .collect()
    }
    fn judge_module<'m>(&self, module: &'m Module) -> Vec<(&'m Resource, Judgement)> {
        self.module_verdicts(module)
            .into_iter()
            .filter_map(|(r, v)| self.judge(r, v).map(|j| (r, j)))
            .collect()
    }
}

trait Judge: Rule {
    fn judge(&self, r: &Resource, v: Verdict) -> Option<Judgement> {
        let fix_hint = Severity::from_truth(v.truth).and_then(|_| self.fix_hint(r, &v));
        Judgement::from_verdict(v, |v| self.message(r, v)).map(|j| Judgement { fix_hint, ..j })
    }
}
impl<T: Rule> Judge for T {}

/// A finding.
#[derive(Clone, Debug)]
pub struct Finding {
    pub rule: Arc<str>,
    pub category: Category,
    pub description: Arc<str>,
    pub level: Level,
    /// The resource instance's identity.
    pub resource: tf_semantic::Address,
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
    /// Attribute path of the deciding value within this resource, when the
    /// provenance names one.
    pub attribute: Option<Arc<str>>,
    /// The deciding top-level attribute as written (`None` when absent).
    pub configured: Option<tf_eval::Value>,
    /// The same after the defaults overlay.
    pub effective: Option<tf_eval::Value>,
    pub hidden: Vec<Hidden>,
    pub fix_hint: Option<FixHint>,
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
        let severity = Severity::from_truth(verdict.truth)?;
        Self::with_severity(info, resource, severity, verdict.witness.as_ref(), message, root)
    }

    /// Build a finding whose certainty the caller has already decided
    /// (adapters for foreign policies classify from their own evidence).
    /// Applies the same existence gate, downgrade, primary location and
    /// suffixes as [`Finding::from_verdict`]; `witness` supplies provenance.
    pub fn with_severity(
        info: &RuleInfo,
        resource: &Resource,
        severity: Severity,
        witness: Option<&tf_eval::Value>,
        message: &str,
        root: &Path,
    ) -> Option<Finding> {
        Self::build(info, resource, severity, witness, message, root, Vec::new(), None)
    }

    /// [`Finding::with_severity`] plus the hidden inputs and fix hint a
    /// judgement carries. The engine's entry point.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        info: &RuleInfo,
        resource: &Resource,
        severity: Severity,
        witness: Option<&tf_eval::Value>,
        message: &str,
        root: &Path,
        hidden: Vec<Hidden>,
        fix_hint: Option<FixHint>,
    ) -> Option<Finding> {
        let mut downgraded = false;
        let severity = match resource.existence {
            Truth::False | Truth::Unknown => return None,
            Truth::Tainted => {
                downgraded = severity == Severity::Definite;
                severity.max(Severity::Conditional)
            }
            Truth::True => severity,
        };
        let provenance = witness.map(|w| w.prov.steps()).unwrap_or_default();
        let deciding = provenance
            .iter()
            .rev()
            .find(|s| s.resource.as_deref() == Some(&*resource.base_address));
        let primary = deciding.map(|s| s.at).unwrap_or(resource.span);
        let attribute = deciding.and_then(|s| s.attribute.clone());
        let top = attribute
            .as_deref()
            .map(|p| p.split(['.', '[']).next().unwrap_or(p).to_string());
        let configured = top.as_deref().and_then(|t| resource.value(t));
        let effective = top.as_deref().and_then(|t| resource.value_or_default(t));
        let message = match (severity, witness.map(|w| &w.kind)) {
            (Severity::Conditional, Some(Kind::Tainted(t))) if !t.variable.starts_with('(') => {
                format!(
                    "{message} (depends on unconstrained variable var.{})",
                    t.variable
                )
            }
            (Severity::Conditional, _) if downgraded => {
                format!("{message} (resource exists depending on an unconstrained variable)")
            }
            (Severity::Conditional, _) => {
                format!("{message} (depends on an unconstrained variable)")
            }
            _ => message.to_string(),
        };
        Some(Finding {
            rule: info.name.clone(),
            category: info.category,
            description: info.description.clone(),
            level: info.level,
            resource: resource.id.clone(),
            address: resource.address.clone(),
            resource_type: resource.ty.clone(),
            module: resource.module.clone(),
            severity,
            message,
            primary,
            provenance,
            root: root.to_path_buf(),
            attribute,
            configured,
            effective,
            hidden,
            fix_hint,
        })
    }
}

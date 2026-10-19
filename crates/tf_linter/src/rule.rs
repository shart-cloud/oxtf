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
use tf_semantic::source::SourceFile;
use tf_semantic::{Analysis, Module, Resource};
use tf_span::{FileSpan, Span};

/// One `.tf` file of one module instance, parsed, for rules that judge
/// whole configuration files (Conftest policies).
pub struct ConfigFile<'a> {
    pub module: &'a Module,
    pub source: Arc<SourceFile>,
    pub ast: &'a tf_ast::File<'a>,
    /// Unique per [`crate::Linter::run_with`] call: the files of one root
    /// share it, so a rule may cache per-root work under it.
    pub run: u64,
}

/// What a whole-file judgement is about.
#[derive(Clone, Copy)]
pub enum Subject<'a> {
    Resource(&'a Resource),
    /// A configuration file of a module instance, for a result no single
    /// resource accounts for (module, provider or variable blocks, joins).
    File {
        module: &'a Module,
        file: tf_span::FileId,
    },
}

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
    /// A Checkov or Rego policy's category name: `NETWORKING`/`network`,
    /// `ENCRYPTION`, `IAM` and `STORAGE` map to ours (case-insensitively),
    /// everything else (`GENERAL_SECURITY`, `LOGGING`, ...) to `other`.
    pub fn from_foreign(name: &str) -> Category {
        match name.to_ascii_lowercase().as_str() {
            "networking" | "network" => Category::Network,
            "encryption" => Category::Encryption,
            "iam" => Category::Iam,
            "storage" => Category::Storage,
            _ => Category::Other,
        }
    }

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
pub enum Certainty {
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

impl Certainty {
    /// `True` → definite, `Tainted` → conditional, anything else → no finding.
    pub fn from_truth(truth: Truth) -> Option<Certainty> {
        match truth {
            Truth::True => Some(Certainty::Definite),
            Truth::Tainted => Some(Certainty::Conditional),
            Truth::False | Truth::Unknown => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Certainty::Definite => "definite",
            Certainty::Conditional => "conditional",
            Certainty::Indeterminate => "indeterminate",
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
    /// IDs of bundled rules this rule replaces: proven to flag the same
    /// resources, so a catalog holding both keeps only this one. It is
    /// selected by, and `checkov:skip`-suppressed by, any of them too.
    const ALIASES: &'static [&'static str] = &[];
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
/// Rules never decide certainty, locations or whether a finding exists;
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
    pub certainty: Certainty,
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
    pub fn from_verdict(
        verdict: Verdict,
        message: impl FnOnce(&Verdict) -> String,
    ) -> Option<Self> {
        let certainty = Certainty::from_truth(verdict.truth)?;
        let message = message(&verdict);
        Some(Judgement {
            certainty,
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

impl FixHint {
    /// Set top-level `attribute` of `r` to `value`: in place when it is
    /// written, else inserted into the resource block.
    pub fn set(r: &Resource, attribute: &str, value: serde_json::Value) -> FixHint {
        FixHint {
            resource: r.id.clone(),
            attribute: attribute.to_string(),
            action: FixAction::Set,
            value,
            site: r.attr(attribute).map(|a| a.span),
        }
    }
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
    /// The rule ID.
    pub name: Arc<str>,
    pub category: Category,
    pub level: Level,
    /// The rule's name for humans (a policy's title).
    pub description: Arc<str>,
    pub resource_types: Vec<Arc<str>>,
    pub runs_on_module: bool,
    /// A page explaining the rule and its fix, when the rule names one.
    pub guideline: Option<Arc<str>>,
    pub source: RuleSource,
    /// Other IDs of this rule ([`RuleMeta::ALIASES`]).
    pub aliases: Vec<Arc<str>>,
}

/// Where a rule comes from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSource {
    pub engine: Engine,
    /// The rule's file, for rules loaded from one.
    pub file: Option<PathBuf>,
    /// 1-based line of the rule (or its metadata) in `file`.
    pub line: Option<u32>,
}

/// The front-end a rule came through.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    /// A seed rule compiled into oxtf.
    #[default]
    Builtin,
    /// Rule IR JSON (e.g. from the tfscan expression API).
    Ir,
    /// A Checkov YAML/JSON policy.
    Checkov,
    /// A Rego entry rule (OPA mode).
    Rego,
    /// A Rego rule found by Conftest's conventions.
    Conftest,
    /// A Python callback rule.
    Python,
}

impl Engine {
    pub fn as_str(self) -> &'static str {
        match self {
            Engine::Builtin => "builtin",
            Engine::Ir => "ir",
            Engine::Checkov => "checkov",
            Engine::Rego => "rego",
            Engine::Conftest => "conftest",
            Engine::Python => "python",
        }
    }
}

/// Why a rule could not judge. The engine records it as a
/// [`crate::record::RuleError`] on the scan; it is never a pass.
pub type RuleFailure = String;

/// Object-safe rule interface used by the engine. Backends that build
/// rules at runtime implement this directly; `T: Rule` gets it for free.
///
/// A hook that fails (a policy runtime error, a callback that raised)
/// returns `Err`; the engine keeps scanning and reports the failure on
/// the result, so a reader never mistakes it for "no finding".
pub trait DynRule: Send + Sync {
    fn info(&self) -> RuleInfo;
    /// Rules that need connections across module boundaries run once per root.
    fn needs_graph(&self) -> bool {
        false
    }
    fn judge_graph<'a>(
        &self,
        _graph: &tf_semantic::graph::ResourceGraph<'a>,
    ) -> Result<Vec<(&'a Resource, Judgement)>, RuleFailure> {
        Ok(Vec::new())
    }
    /// Rules that judge whole configuration files run once per root.
    fn needs_files(&self) -> bool {
        false
    }
    /// Judgements over the root's analysis and every parsed file of every
    /// module instance (empty for a plan scan, which has no source files).
    fn judge_files<'a>(
        &self,
        _analysis: &'a Analysis,
        _files: &[ConfigFile<'a>],
    ) -> Result<Vec<(Subject<'a>, Judgement)>, RuleFailure> {
        Ok(Vec::new())
    }
    /// Judgements on one resource instance (usually zero or one); only
    /// judgements that can become findings are returned.
    fn judge_resource(&self, resource: &Resource) -> Result<Vec<Judgement>, RuleFailure>;
    /// Judgements of a cross-resource rule over one module instance.
    fn judge_module<'m>(
        &self,
        module: &'m Module,
    ) -> Result<Vec<(&'m Resource, Judgement)>, RuleFailure>;
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
            guideline: None,
            source: RuleSource::default(),
            aliases: T::ALIASES.iter().map(|s| Arc::from(*s)).collect(),
        }
    }
    fn judge_resource(&self, resource: &Resource) -> Result<Vec<Judgement>, RuleFailure> {
        Ok(self
            .verdict(resource)
            .and_then(|v| self.judge(resource, v))
            .into_iter()
            .collect())
    }
    fn judge_module<'m>(
        &self,
        module: &'m Module,
    ) -> Result<Vec<(&'m Resource, Judgement)>, RuleFailure> {
        Ok(self
            .module_verdicts(module)
            .into_iter()
            .filter_map(|(r, v)| self.judge(r, v).map(|j| (r, j)))
            .collect())
    }
}

trait Judge: Rule {
    fn judge(&self, r: &Resource, v: Verdict) -> Option<Judgement> {
        let fix_hint = Certainty::from_truth(v.truth).and_then(|_| self.fix_hint(r, &v));
        Judgement::from_verdict(v, |v| self.message(r, v)).map(|j| Judgement { fix_hint, ..j })
    }
}
impl<T: Rule> Judge for T {}

/// What a finding is about: a resource instance, or (for a whole-file
/// policy result that no single resource accounts for) a configuration
/// file of a module instance.
#[derive(Clone, Debug, PartialEq)]
pub enum FindingSubject {
    Resource(tf_semantic::Address),
    File { path: PathBuf },
}

impl FindingSubject {
    pub fn resource(&self) -> Option<&tf_semantic::Address> {
        match self {
            FindingSubject::Resource(a) => Some(a),
            FindingSubject::File { .. } => None,
        }
    }
}

/// A finding.
#[derive(Clone, Debug)]
pub struct Finding {
    pub rule: Arc<str>,
    pub category: Category,
    pub description: Arc<str>,
    pub level: Level,
    pub guideline: Option<Arc<str>>,
    pub source: RuleSource,
    /// The rule's other IDs ([`RuleInfo::aliases`]).
    pub aliases: Vec<Arc<str>>,
    /// What the finding is about.
    pub subject: FindingSubject,
    /// Resource address, module path included (`module.m.aws_s3_bucket.b`);
    /// for a file subject, the file's path.
    pub address: Arc<str>,
    /// `None` for a file subject.
    pub resource_type: Option<Arc<str>>,
    /// Module instance address (`""` for the root module).
    pub module: Arc<str>,
    pub certainty: Certainty,
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
    /// - `True` → [`Certainty::Definite`], `Tainted` → [`Certainty::Conditional`],
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
        let certainty = Certainty::from_truth(verdict.truth)?;
        Self::with_severity(
            info,
            resource,
            certainty,
            verdict.witness.as_ref(),
            message,
            root,
        )
    }

    /// Build a finding whose certainty the caller has already decided
    /// (adapters for foreign policies classify from their own evidence).
    /// Applies the same existence gate, downgrade, primary location and
    /// suffixes as [`Finding::from_verdict`]; `witness` supplies provenance.
    pub fn with_severity(
        info: &RuleInfo,
        resource: &Resource,
        certainty: Certainty,
        witness: Option<&tf_eval::Value>,
        message: &str,
        root: &Path,
    ) -> Option<Finding> {
        Self::build(
            info,
            resource,
            Judgement {
                certainty,
                witness: witness.cloned(),
                message: message.to_string(),
                hidden: Vec::new(),
                fix_hint: None,
            },
            root,
        )
    }

    /// The finding for a judgement on a resource, or `None`. The engine's
    /// entry point: this is where the existence gate, the downgrade, the
    /// primary location and the certainty suffix are decided.
    pub fn build(
        info: &RuleInfo,
        resource: &Resource,
        judgement: Judgement,
        root: &Path,
    ) -> Option<Finding> {
        let Judgement {
            certainty,
            witness,
            message,
            hidden,
            fix_hint,
        } = judgement;
        let mut downgraded = false;
        let certainty = match resource.existence {
            Truth::False | Truth::Unknown => return None,
            Truth::Tainted => {
                downgraded = certainty == Certainty::Definite;
                certainty.max(Certainty::Conditional)
            }
            Truth::True => certainty,
        };
        let provenance = witness.as_ref().map(|w| w.prov.steps()).unwrap_or_default();
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
        let message = certainty_suffix(message, certainty, witness.as_ref(), downgraded);
        Some(Finding {
            rule: info.name.clone(),
            category: info.category,
            description: info.description.clone(),
            level: info.level,
            guideline: info.guideline.clone(),
            source: info.source.clone(),
            aliases: info.aliases.clone(),
            subject: FindingSubject::Resource(resource.id.clone()),
            address: resource.address.clone(),
            resource_type: Some(resource.ty.clone()),
            module: resource.module.clone(),
            certainty,
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

    /// A finding on a configuration file of `module` (a whole-file policy
    /// result no single resource accounts for). The primary location is the
    /// witness's newest provenance step in that file, else the file's start.
    pub fn for_file(
        info: &RuleInfo,
        module: &Module,
        file: &SourceFile,
        judgement: Judgement,
        root: &Path,
    ) -> Finding {
        let Judgement {
            certainty,
            witness,
            message,
            hidden,
            ..
        } = judgement;
        let provenance = witness.as_ref().map(|w| w.prov.steps()).unwrap_or_default();
        let primary = provenance
            .iter()
            .rev()
            .find(|s| s.at.file == file.id)
            .map(|s| s.at)
            .unwrap_or(FileSpan {
                file: file.id,
                span: Span::new(0, 0),
            });
        let message = certainty_suffix(message, certainty, witness.as_ref(), false);
        Finding {
            rule: info.name.clone(),
            category: info.category,
            description: info.description.clone(),
            level: info.level,
            guideline: info.guideline.clone(),
            source: info.source.clone(),
            aliases: info.aliases.clone(),
            subject: FindingSubject::File {
                path: file.path.clone(),
            },
            address: file.path.display().to_string().into(),
            resource_type: None,
            module: module.address.clone(),
            certainty,
            message,
            primary,
            provenance,
            root: root.to_path_buf(),
            attribute: None,
            configured: None,
            effective: None,
            hidden,
            fix_hint: None,
        }
    }
}

/// The rule's wording, with a suffix naming what a conditional finding
/// depends on: the unconstrained variable where the witness names one,
/// the resource's own existence when that is what was downgraded.
fn certainty_suffix(
    message: String,
    certainty: Certainty,
    witness: Option<&tf_eval::Value>,
    downgraded: bool,
) -> String {
    match (certainty, witness.map(|w| &w.kind)) {
        (Certainty::Conditional, Some(Kind::Tainted(t))) if !t.variable.starts_with('(') => {
            format!(
                "{message} (depends on unconstrained variable var.{})",
                t.variable
            )
        }
        (Certainty::Conditional, _) if downgraded => {
            format!("{message} (resource exists depending on an unconstrained variable)")
        }
        (Certainty::Conditional, _) => {
            format!("{message} (depends on an unconstrained variable)")
        }
        _ => message,
    }
}

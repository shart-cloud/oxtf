//! The scan request: the one front door every adapter (CLI, Python,
//! tests) goes through.
//!
//! A [`ScanRequest`] says *what to scan* ([`ScanInput`]: directories or a
//! plan), *with which rules* ([`Catalog`]: seed rules, rule-IR files and
//! documents, runtime rules, Rego policies), *narrowed to which ids*
//! (`selection`, applied to the whole catalog), and how (var files,
//! threads). [`scan`] resolves the catalog, validates the selection,
//! discovers roots, runs the engine and returns a [`ScanOutput`]: the
//! `ScanResult` with resolved files, plus the analysed model of every
//! root. Everything that can go wrong before rules run is a
//! [`ScanError`]; a rule that fails *while* running is a rule error on the
//! result, never an `Err`.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use tf_linter::rule::DynRule;
use tf_linter::{Linter, RuleSelectionError, ScanOptions, ScanRecord, ScanResult, discover_roots};
use tf_plan::{PlanError, PlanOptions};
use tf_rego::{Policies, PolicyError};
use tf_semantic::source::normalize;
use tf_semantic::{Analysis, FileTable};

pub use tf_rego::Shape;

/// What to scan.
#[derive(Clone, Debug)]
pub enum ScanInput {
    /// Root module directories. With `recursive`, every directory under
    /// each path that contains `.tf` files is a root module.
    Dirs {
        paths: Vec<PathBuf>,
        recursive: bool,
    },
    /// `terraform show -json` output, mapped back to source in `source`
    /// (default: the plan's directory when it has `.tf` files).
    Plan {
        plan: PathBuf,
        source: Option<PathBuf>,
    },
}

/// Where rules come from. Sources are resolved in field order and a later
/// rule **shadows** an earlier one of the same name, so a native-tier Rego
/// policy named `aws-rds-unencrypted` replaces the seed rule.
#[derive(Default)]
pub struct Catalog {
    /// The seed rules (`tf_linter::rules::all`).
    pub builtin: bool,
    /// Rule-IR JSON files (`--rule-file`).
    pub rule_files: Vec<PathBuf>,
    /// Rule-IR JSON documents already in memory (the Python expression API).
    pub rule_json: Vec<String>,
    /// Rules built at runtime by the adapter (Python callbacks).
    pub runtime: Vec<Box<dyn DynRule>>,
    /// Rego policies, native tier and foreign.
    pub policies: Policies,
}

impl Catalog {
    /// The seed rules and nothing else.
    pub fn seed() -> Catalog {
        Catalog {
            builtin: true,
            ..Catalog::default()
        }
    }

    /// The rules this catalog yields, in order, shadowed by name.
    pub fn resolve(self) -> Result<Vec<Box<dyn DynRule>>, ScanError> {
        let mut rules: Vec<Box<dyn DynRule>> = Vec::new();
        let mut add = |batch: Vec<Box<dyn DynRule>>| {
            for rule in batch {
                let name = rule.info().name;
                rules.retain(|r| r.info().name != name);
                rules.push(rule);
            }
        };
        if self.builtin {
            add(tf_linter::rules::all());
        }
        for path in &self.rule_files {
            let specs = tf_rule_ir::load_rules_file(path).map_err(ScanError::Rules)?;
            add(compile_specs(specs)?);
        }
        for json in &self.rule_json {
            let specs = tf_rule_ir::parse_rules(json).map_err(ScanError::Rules)?;
            add(compile_specs(specs)?);
        }
        add(self.runtime);
        if !self.policies.is_empty() {
            add(tf_rego::catalog(&self.policies)?);
        }
        Ok(rules)
    }
}

fn compile_specs(specs: Vec<tf_rule_ir::RuleSpec>) -> Result<Vec<Box<dyn DynRule>>, ScanError> {
    specs
        .into_iter()
        .map(|s| {
            tf_rule_ir::compile(s)
                .map(|r| Box::new(r) as Box<dyn DynRule>)
                .map_err(ScanError::Rules)
        })
        .collect()
}

pub struct ScanRequest {
    pub input: ScanInput,
    pub catalog: Catalog,
    /// Only run these rule ids, from the whole resolved catalog. Unknown
    /// ids are an error; an empty selection runs nothing.
    pub selection: Option<Vec<String>>,
    /// Extra `-var-file`s for the root module(s) (directory input only).
    pub var_files: Vec<PathBuf>,
    /// Worker threads; `None` = number of CPUs.
    pub threads: Option<usize>,
    /// In-memory files that shadow the disk for this scan: their text is
    /// read instead of the file's, and they are listed in their directory
    /// whether or not it exists. Paths are matched lexically, so write them
    /// the way the input paths are written. This is how an unsaved buffer,
    /// stdin, or a proposed patch is scanned without touching the checkout.
    pub overlay: Vec<(PathBuf, Arc<str>)>,
    /// Return the analysed models in `ScanOutput::analyses`. Off, each
    /// root's model is dropped once its rules have run (the CLI wants
    /// findings only); `analyses` is then empty.
    pub keep_models: bool,
}

impl ScanRequest {
    /// Seed rules over `paths`, every other knob at its default.
    pub fn dirs(paths: Vec<PathBuf>, recursive: bool) -> ScanRequest {
        ScanRequest {
            input: ScanInput::Dirs { paths, recursive },
            catalog: Catalog::seed(),
            selection: None,
            var_files: Vec::new(),
            threads: None,
            overlay: Vec::new(),
            keep_models: true,
        }
    }

    /// Seed rules over a plan.
    pub fn plan(plan: PathBuf, source: Option<PathBuf>) -> ScanRequest {
        ScanRequest {
            input: ScanInput::Plan { plan, source },
            catalog: Catalog::seed(),
            selection: None,
            var_files: Vec::new(),
            threads: None,
            overlay: Vec::new(),
            keep_models: true,
        }
    }
}

pub struct ScanOutput {
    pub result: ScanResult,
    /// The analysed model of every root (one entry for a plan); empty
    /// when the request's `keep_models` was off.
    pub analyses: Vec<Analysis>,
}

impl ScanOutput {
    /// The resolved, versioned record (`docs/FINDING_SCHEMA.md`).
    pub fn record(&self) -> ScanRecord {
        ScanRecord::from_result(&self.result)
    }
}

/// Everything that stops a scan before rules run.
#[derive(Debug)]
pub enum ScanError {
    /// A path that is not a directory, or a `var_files` with plan input.
    Input(String),
    /// A rule file or document that does not load or compile.
    Rules(String),
    Selection(RuleSelectionError),
    Policy(PolicyError),
    Plan(PlanError),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Input(m) | ScanError::Rules(m) => f.write_str(m),
            ScanError::Selection(e) => e.fmt(f),
            ScanError::Policy(e) => e.fmt(f),
            ScanError::Plan(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<RuleSelectionError> for ScanError {
    fn from(e: RuleSelectionError) -> Self {
        ScanError::Selection(e)
    }
}
impl From<PolicyError> for ScanError {
    fn from(e: PolicyError) -> Self {
        ScanError::Policy(e)
    }
}
impl From<PlanError> for ScanError {
    fn from(e: PlanError) -> Self {
        ScanError::Plan(e)
    }
}

/// Run one request. The catalog is resolved and the selection validated
/// before any input is read, so a bad rule id never costs a parse.
pub fn scan(req: ScanRequest) -> Result<ScanOutput, ScanError> {
    let rules = req.catalog.resolve()?;
    let linter = match &req.selection {
        Some(ids) => Linter::filtered(rules, ids)?,
        None => Linter::new(rules),
    };
    match req.input {
        ScanInput::Dirs { paths, recursive } => {
            // Only for root discovery; the scan builds its own table from
            // the same overlay so `FileId`s stay scan-local.
            let files = FileTable::with_overlay(req.overlay.iter().cloned());
            let mut roots = Vec::new();
            for p in &paths {
                if !files.is_dir(p) {
                    return Err(ScanError::Input(format!(
                        "{} is not a directory",
                        p.display()
                    )));
                }
                // Normalised so a root is never analysed twice under two
                // spellings when the overlay adds directories below.
                roots.extend(discover_roots(p, recursive).iter().map(|r| normalize(r)));
                if recursive {
                    // Directories that exist only in the overlay.
                    for f in files.overlay_under(p) {
                        if f.extension().is_some_and(|x| x == "tf")
                            && let Some(dir) = f.parent().map(normalize)
                            && !roots.contains(&dir)
                        {
                            roots.push(dir);
                        }
                    }
                }
            }
            let opts = ScanOptions {
                recursive,
                var_files: req.var_files,
                threads: req.threads,
                overlay: req.overlay,
                keep_models: req.keep_models,
            };
            let (result, analyses) = tf_linter::scan_with(&linter, &roots, &opts);
            Ok(ScanOutput { result, analyses })
        }
        ScanInput::Plan { plan, source } => {
            if !req.var_files.is_empty() {
                return Err(ScanError::Input(
                    "var files apply to directory input, not a plan".into(),
                ));
            }
            let files = Arc::new(FileTable::with_overlay(req.overlay));
            let (result, analysis) =
                tf_plan::scan_plan_with_model(&linter, &plan, &PlanOptions { source }, files)?;
            Ok(ScanOutput {
                result,
                analyses: vec![analysis],
            })
        }
    }
}

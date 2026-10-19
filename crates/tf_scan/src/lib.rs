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

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use tf_linter::rule::DynRule;
use tf_linter::{Linter, RuleSelectionError, ScanOptions, ScanRecord, ScanResult, discover_roots};
use tf_plan::{PlanError, PlanOptions};
use tf_rego::{Policies, PolicyError};
use tf_semantic::source::normalize;
use tf_semantic::{Analysis, DiagSeverity, Diagnostic, FileTable};

pub use tf_rego::Shape;
pub use tf_rego::foreign::{TestOutcome, TestResult};

/// Run the `test_*` rules of the catalog's Rego (its rule files and
/// policy paths) as `conftest verify` does.
pub fn verify_policies(catalog: &Catalog) -> Result<Vec<TestOutcome>, ScanError> {
    let policies = &catalog.policies;
    let mut paths = policies.foreign.clone();
    let mut exclude = policies.exclude.clone();
    for path in &catalog.rule_files {
        let loaded = tf_rule_ir::load_rules_file(path).map_err(ScanError::Rules)?;
        if !loaded.rego.is_empty() {
            paths.push(path.clone());
            exclude.extend(loaded.claimed);
        }
    }
    if paths.is_empty() {
        return Err(ScanError::Policy(PolicyError(
            "no Rego policies to test".into(),
        )));
    }
    tf_rego::foreign::verify(&tf_rego::foreign::Options {
        paths: &paths,
        data: &policies.data,
        exclude: &exclude,
        entries: &[],
        namespaces: &policies.namespaces,
        all_namespaces: true,
        shape: Shape::Hcl,
        rego_v0: policies.rego_v0,
    })
    .map_err(|e| ScanError::Policy(PolicyError(e)))
}

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
/// rule **shadows** an earlier one of the same name, so a rule-IR or Rego
/// rule named `aws-rds-unencrypted` replaces the seed rule, and a Checkov
/// policy loaded from a file replaces the bundled one with its ID.
#[derive(Default)]
pub struct Catalog {
    /// The bundled Checkov catalog (`tf_rule_ir::bundled`): Checkov's
    /// Terraform value checks and graph policies, translated at a pinned
    /// version and compiled into the binary.
    pub bundled: bool,
    /// The seed rules (`tf_linter::rules::all`).
    pub builtin: bool,
    /// Rule-IR JSON files (`--rule-file`).
    pub rule_files: Vec<PathBuf>,
    /// Rule-IR JSON documents already in memory (the Python expression API).
    pub rule_json: Vec<String>,
    /// Rules built at runtime by the adapter (Python callbacks).
    pub runtime: Vec<Box<dyn DynRule>>,
    /// Rego policies.
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

    /// What a scan runs when not told otherwise: the bundled Checkov
    /// catalog and the seed rules.
    pub fn standard() -> Catalog {
        Catalog {
            bundled: true,
            builtin: true,
            ..Catalog::default()
        }
    }

    /// The rules this catalog yields, in order, shadowed by name, and a
    /// warning for each rule-directory file that was skipped.
    pub fn resolve(mut self) -> Result<Resolved, ScanError> {
        let mut warnings = Vec::new();
        // A shadowed rule leaves a hole, so each rule keeps the position of
        // its source; holes are dropped at the end. A rule's aliases shadow
        // as its name does: a seed rule replaces the bundled rule it
        // aliases.
        let mut rules: Vec<Option<Box<dyn DynRule>>> = Vec::new();
        let mut by_name: HashMap<Arc<str>, usize> = HashMap::new();
        let mut add = |batch: Vec<Box<dyn DynRule>>| {
            for rule in batch {
                let info = rule.info();
                // A rule that repeats a name among its own aliases shadows
                // nothing: the repeated name maps to the rule being added.
                for name in std::iter::once(info.name).chain(info.aliases) {
                    if let Some(old) = by_name.insert(name, rules.len())
                        && old != rules.len()
                    {
                        rules[old] = None;
                    }
                }
                rules.push(Some(rule));
            }
        };
        if self.bundled {
            add(tf_rule_ir::bundled::rules().map_err(ScanError::Rules)?);
        }
        if self.builtin {
            add(tf_linter::rules::all());
        }
        for path in &self.rule_files {
            let loaded = tf_rule_ir::load_rules_file(path).map_err(ScanError::Rules)?;
            // Rego goes to the policy bundle: the file, or the directory
            // (whose rule files are not data for OPA mode).
            if !loaded.rego.is_empty() {
                self.policies.foreign.push(path.clone());
                self.policies.exclude.extend(loaded.claimed.iter().cloned());
            }
            warnings.extend(
                loaded
                    .skipped
                    .into_iter()
                    .map(|s| format!("skipped rule file {}:\n{}", s.path.display(), s.reason)),
            );
            add(compile_specs(loaded.rules)?);
        }
        for json in &self.rule_json {
            let specs = tf_rule_ir::parse_rules(json).map_err(ScanError::Rules)?;
            add(compile_specs(specs)?);
        }
        add(self.runtime);
        if !self.policies.is_empty() {
            add(tf_rego::catalog(&self.policies)?);
        }
        Ok(Resolved {
            rules: rules.into_iter().flatten().collect(),
            warnings,
        })
    }
}

/// A resolved catalog.
pub struct Resolved {
    pub rules: Vec<Box<dyn DynRule>>,
    /// Rule files skipped while loading a rule directory, one entry per
    /// file. A scan reports each as a `rule-skipped` warning diagnostic.
    pub warnings: Vec<String>,
}

impl Resolved {
    fn diagnostics(&self) -> impl Iterator<Item = Diagnostic> + '_ {
        self.warnings.iter().map(|message| Diagnostic {
            severity: DiagSeverity::Warning,
            code: "rule-skipped",
            message: message.clone(),
            at: None,
        })
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
pub fn scan(mut req: ScanRequest) -> Result<ScanOutput, ScanError> {
    // Conftest-mode policies see what Conftest would be given: a `.tf`
    // file (HCL shape) when scanning directories, the plan for a plan.
    let policies = &mut req.catalog.policies;
    if policies.shape.is_none() && policies.entries.is_empty() {
        policies.shape = Some(match req.input {
            ScanInput::Dirs { .. } => Shape::Hcl,
            ScanInput::Plan { .. } => Shape::Plan,
        });
    }
    let resolved = req.catalog.resolve()?;
    let skipped: Vec<Diagnostic> = resolved.diagnostics().collect();
    let linter = match &req.selection {
        Some(ids) => Linter::filtered(resolved.rules, ids)?,
        None => Linter::new(resolved.rules),
    };
    // Skipped rule files come first: they qualify every finding below them.
    let output = |mut result: ScanResult, analyses| {
        // Point each skipped file's warning at its first located problem.
        let located = skipped.iter().cloned().map(|mut d| {
            d.at = d.message.lines().find_map(|l| {
                let (file, line, col) = tf_linter::render::message_location(l)?;
                tf_linter::render::locate(&result.files, &file, line, col)
            });
            d
        });
        let located: Vec<Diagnostic> = located.collect();
        result.diagnostics.splice(0..0, located);
        Ok(ScanOutput { result, analyses })
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
            output(result, analyses)
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
            output(result, vec![analysis])
        }
    }
}

/// One file's text after applying a fix hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixEdit {
    pub file: PathBuf,
    pub text: String,
}

/// Apply a finding's fix hint to the source of `output` (scanned with
/// `keep_models`): the attribute is rewritten at its `site`, or inserted
/// into the resource block when it is not written. The value is written as
/// an HCL literal. Nothing is written to disk; scan the edit through
/// `ScanRequest::overlay` to check it.
pub fn apply_fix(output: &ScanOutput, hint: &tf_linter::FixHint) -> Result<FixEdit, String> {
    let resource = output
        .analyses
        .iter()
        .flat_map(|a| &a.modules)
        .flat_map(|m| &m.resources)
        .find(|r| r.id == hint.resource)
        .ok_or_else(|| {
            format!(
                "{} is not in the scan (scan with keep_models)",
                hint.resource
            )
        })?;
    let line = format!("{} = {}", hint.attribute, hcl_literal(&hint.value));
    let (file, text) = match hint.site {
        Some(at) => {
            let sf = output.result.files.get(at.file);
            let mut text = sf.text.to_string();
            text.replace_range(at.span.start as usize..at.span.end as usize, &line);
            (sf.path.clone(), text)
        }
        None => {
            let body = resource.body.span;
            let sf = output.result.files.get(body.file);
            let mut text = sf.text.to_string();
            // A block body's span ends at its closing brace.
            let close = body.span.end as usize;
            if text.as_bytes().get(close) != Some(&b'}') {
                return Err(format!(
                    "{}: resource block has no closing brace",
                    hint.resource
                ));
            }
            let line_start = text[..close].rfind('\n').map_or(0, |i| i + 1);
            if text[line_start..close].trim().is_empty() {
                text.insert_str(line_start, &format!("  {line}\n"));
            } else {
                text.insert_str(close, &format!("\n  {line}\n"));
            }
            (sf.path.clone(), text)
        }
    };
    Ok(FixEdit { file, text })
}

/// A JSON value as an HCL literal.
fn hcl_literal(v: &serde_json::Value) -> String {
    use serde_json::Value as J;
    match v {
        J::String(s) => serde_json::to_string(s)
            .expect("a string serializes")
            .replace("${", "$${")
            .replace("%{", "%%{"),
        J::Array(items) => format!(
            "[{}]",
            items.iter().map(hcl_literal).collect::<Vec<_>>().join(", ")
        ),
        J::Object(m) => format!(
            "{{ {} }}",
            m.iter()
                .map(|(k, v)| format!(
                    "{} = {}",
                    serde_json::to_string(k).expect("a key"),
                    hcl_literal(v)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => other.to_string(),
    }
}

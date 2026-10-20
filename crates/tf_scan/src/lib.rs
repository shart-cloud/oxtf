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

use tf_linter::Profile;
use tf_linter::rule::DynRule;
use tf_linter::{Linter, RuleSelectionError, ScanOptions, ScanRecord, ScanResult};
use tf_plan::{PlanError, PlanOptions};
use tf_rego::{Policies, PolicyError};
use tf_semantic::source::normalize;
use tf_semantic::{Analysis, DiagSeverity, Diagnostic, FileTable};

pub use tf_fetch::{FetchLimits, FetchReport, FetchRequest, FetchedModule, fetch};
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
    /// Which profiles of the shipped rules (bundled and seed) run; `None`
    /// is the default, `security`. Unreviewed bundled rules run with
    /// `security`. Rules from files, documents, callbacks and policies
    /// always run: the caller chose them. A scan with an explicit
    /// selection ignores this and selects from every shipped rule.
    pub profiles: Option<Vec<Profile>>,
}

/// Whether a shipped rule of `profile` runs under `selected` (`None`: the
/// default).
pub fn profile_runs(profile: Profile, selected: Option<&[Profile]>) -> bool {
    let selected = selected.unwrap_or(&[Profile::Security]);
    selected.contains(&profile)
        || (profile == Profile::Unreviewed && selected.contains(&Profile::Security))
}

/// Every profile, for `--profile all`.
pub const ALL_PROFILES: &[Profile] = &[
    Profile::Security,
    Profile::Audit,
    Profile::Hygiene,
    Profile::Unreviewed,
];

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

    /// A copy of this catalog, unless it holds runtime rules (Python
    /// callbacks), which cannot be copied.
    pub fn try_clone(&self) -> Option<Catalog> {
        self.runtime.is_empty().then(|| Catalog {
            bundled: self.bundled,
            builtin: self.builtin,
            rule_files: self.rule_files.clone(),
            rule_json: self.rule_json.clone(),
            runtime: Vec::new(),
            policies: self.policies.clone(),
            profiles: self.profiles.clone(),
        })
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
        // Shipped rules outside the selected profiles are not in the
        // catalog at all, so they shadow nothing.
        let profiles = self.profiles.clone();
        let shipped = |rules: Vec<Box<dyn DynRule>>| -> Vec<Box<dyn DynRule>> {
            rules
                .into_iter()
                .filter(|r| profile_runs(r.info().profile, profiles.as_deref()))
                .collect()
        };
        if self.bundled {
            add(shipped(
                tf_rule_ir::bundled::rules().map_err(ScanError::Rules)?,
            ));
        }
        if self.builtin {
            add(shipped(tf_linter::rules::all()));
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
    /// Installed Terraform data directory, relative to each source root
    /// unless absolute. Defaults to `.terraform`; scanning never fetches.
    pub data_dir: Option<PathBuf>,
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
    /// A copy of this request, unless its catalog holds runtime rules.
    pub fn try_clone(&self) -> Option<ScanRequest> {
        Some(ScanRequest {
            input: self.input.clone(),
            catalog: self.catalog.try_clone()?,
            selection: self.selection.clone(),
            var_files: self.var_files.clone(),
            data_dir: self.data_dir.clone(),
            threads: self.threads,
            overlay: self.overlay.clone(),
            keep_models: self.keep_models,
        })
    }

    /// Seed rules over `paths`, every other knob at its default.
    pub fn dirs(paths: Vec<PathBuf>, recursive: bool) -> ScanRequest {
        ScanRequest {
            input: ScanInput::Dirs { paths, recursive },
            catalog: Catalog::seed(),
            selection: None,
            var_files: Vec::new(),
            data_dir: None,
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
            data_dir: None,
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
    // A selection names its rules: every shipped rule is a candidate.
    if req.selection.is_some() {
        req.catalog.profiles = Some(ALL_PROFILES.to_vec());
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
                if !recursive || p.is_dir() {
                    roots.extend(
                        tf_linter::scan::discover_roots_checked(p, recursive)
                            .map_err(|e| ScanError::Input(format!("{}: {e}", p.display())))?
                            .iter()
                            .map(|r| normalize(r)),
                    );
                }
                if recursive {
                    // Directories that exist only in the overlay.
                    for f in files.overlay_under(p) {
                        if tf_semantic::module::is_config(f)
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
                data_dir: req.data_dir,
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
            let (result, analysis) = tf_plan::scan_plan_with_model(
                &linter,
                &plan,
                &PlanOptions {
                    source,
                    data_dir: req.data_dir,
                },
                files,
            )?;
            output(result, vec![analysis])
        }
    }
}

/// What [`fix`] did: the edit for a finding's fix hint, and whether the
/// scan of the edited source still has the finding.
#[derive(Clone, Debug)]
pub struct FixOutcome {
    pub fingerprint: String,
    /// The rule of the finding.
    pub rule: String,
    pub hint: tf_linter::FixHint,
    /// Where the literal was written.
    pub site: FixSite,
    /// The file's text before the edit.
    pub original: String,
    pub edit: FixEdit,
    /// A display diff with sensitive source ranges masked. `original` and
    /// `edit.text` remain raw so callers can apply the edit without data loss.
    pub diff: String,
    /// Both scans completed and the rule no longer fails on the declaration
    /// with the edit as an overlay (on no attribute, from no root).
    pub verified: bool,
    /// Analysis failures or coverage gaps in either scan. Empty does not
    /// imply verified: the finding may still be present.
    pub verification_errors: Vec<String>,
}

/// Why [`fix`] produced no edit.
#[derive(Debug)]
pub enum FixError {
    Scan(ScanError),
    /// No finding has the fingerprint.
    NotFound(String),
    /// The finding has no fix hint: no mechanical edit is known.
    NoHint {
        fingerprint: String,
        rule: String,
    },
    /// The hint could not be applied to the source.
    Apply(String),
    /// The request's catalog holds runtime rules, so it cannot be re-run
    /// to verify the edit.
    NotRepeatable,
}

impl fmt::Display for FixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixError::Scan(e) => e.fmt(f),
            FixError::NotFound(fp) => write!(f, "no finding has fingerprint {fp}"),
            FixError::NoHint { fingerprint, rule } => write!(
                f,
                "finding {fingerprint} ({rule}) has no fix hint: no mechanical edit is known"
            ),
            FixError::Apply(m) => f.write_str(m),
            FixError::NotRepeatable => {
                f.write_str("a request with runtime rules cannot be re-run to verify a fix")
            }
        }
    }
}

impl std::error::Error for FixError {}

/// Fix the finding with `fingerprint`: scan `request`, apply the finding's
/// fix hint to the source in memory ([`apply_fix_at`]), and scan again
/// with the edit as an overlay to check the rule no longer fails on the
/// declaration. Nothing is written to disk; the caller decides what to do
/// with a verified (or unverified) edit.
///
/// With `site` `None`, a value written as `var.x` is first fixed at the
/// variable's default (keeping the module's interface), and at the
/// attribute when that does not verify (a caller passes its own value).
pub fn fix(
    request: ScanRequest,
    fingerprint: &str,
    site: Option<FixSite>,
) -> Result<FixOutcome, FixError> {
    let verify = request.try_clone().ok_or(FixError::NotRepeatable)?;
    let mut request = request;
    request.keep_models = true;
    let output = scan(request).map_err(FixError::Scan)?;
    let r = &output.result;
    let mut repos = tf_linter::record::RepoRoots::new();
    let group = tf_linter::record::group(&r.files, &r.findings)
        .into_iter()
        .find(|g| {
            tf_linter::record::finding_fingerprint(
                &r.files,
                &r.findings[g.representative],
                &mut repos,
            ) == fingerprint
        })
        .ok_or_else(|| FixError::NotFound(fingerprint.to_string()))?;
    let representative = &r.findings[group.representative];
    let rule = representative.rule.to_string();
    let subject = tf_linter::record::finding_subject_key(&r.files, representative, &mut repos);
    // The representative's hint, else any occurrence's.
    let hinted = std::iter::once(group.representative)
        .chain(group.members.iter().copied())
        .map(|i| &r.findings[i])
        .find(|f| f.fix_hint.is_some())
        .ok_or_else(|| FixError::NoHint {
            fingerprint: fingerprint.to_string(),
            rule: rule.clone(),
        })?;
    let hint = hinted.fix_hint.clone().expect("found by its hint");
    let sites = match site {
        Some(s) => vec![s],
        None if hint.default_site(&r.files).is_some() => {
            vec![FixSite::Default, FixSite::Attribute]
        }
        None => vec![FixSite::Attribute],
    };
    let mut first = None;
    for site in sites {
        let edit = apply_fix_at(&output, &hinted.root, &hint, site).map_err(FixError::Apply)?;
        let original = r
            .files
            .load(&edit.file)
            .map(|sf| sf.text.to_string())
            .map_err(|e| FixError::Apply(format!("{}: {e}", edit.file.display())))?;
        let mut verify = verify.try_clone().ok_or(FixError::NotRepeatable)?;
        verify.keep_models = false;
        verify
            .overlay
            .retain(|(p, _)| normalize(p) != normalize(&edit.file));
        verify
            .overlay
            .push((edit.file.clone(), Arc::from(edit.text.as_str())));
        let after = scan(verify).map_err(FixError::Scan)?;
        let before_file = r
            .files
            .load(&edit.file)
            .map_err(|e| FixError::Apply(e.to_string()))?;
        let after_file = after
            .result
            .files
            .load(&edit.file)
            .map_err(|e| FixError::Apply(e.to_string()))?;
        let diff = unified_diff(
            &edit.file,
            &r.files.display_text(before_file.id),
            &after.result.files.display_text(after_file.id),
        );
        let mut repos = tf_linter::record::RepoRoots::new();
        let verification_errors: Vec<String> = r
            .completion_issues()
            .into_iter()
            .map(|e| format!("before edit: {e}"))
            .chain(
                after
                    .result
                    .completion_issues()
                    .into_iter()
                    .map(|e| format!("after edit: {e}")),
            )
            .collect();
        let verified = verification_errors.is_empty()
            && !after.result.findings.iter().any(|f| {
                f.rule == representative.rule
                    && tf_linter::record::finding_subject_key(&after.result.files, f, &mut repos)
                        == subject
            });
        let outcome = FixOutcome {
            fingerprint: fingerprint.to_string(),
            rule: rule.clone(),
            hint: hint.clone(),
            site,
            original,
            edit,
            diff,
            verified,
            verification_errors,
        };
        if verified {
            return Ok(outcome);
        }
        first.get_or_insert(outcome);
    }
    Ok(first.expect("at least one site is tried"))
}

/// A unified diff of one file's edit (one hunk around the changed lines,
/// three lines of context), for showing a [`FixOutcome`].
pub fn unified_diff(path: &std::path::Path, before: &str, after: &str) -> String {
    let a: Vec<&str> = before.split_inclusive('\n').collect();
    let b: Vec<&str> = after.split_inclusive('\n').collect();
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    if prefix == a.len() && prefix == b.len() {
        return String::new();
    }
    const CONTEXT: usize = 3;
    let start = prefix.saturating_sub(CONTEXT);
    let a_end = (a.len() - suffix + CONTEXT).min(a.len());
    let b_end = (b.len() - suffix + CONTEXT).min(b.len());
    let line = |s: &str| {
        if s.ends_with('\n') {
            s.to_string()
        } else {
            format!("{s}\n\\ No newline at end of file\n")
        }
    };
    let path = path.display();
    let mut out = format!(
        "--- a/{path}\n+++ b/{path}\n@@ -{},{} +{},{} @@\n",
        start + 1,
        a_end - start,
        start + 1,
        b_end - start
    );
    for l in &a[start..prefix] {
        out.push(' ');
        out.push_str(&line(l));
    }
    for l in &a[prefix..a.len() - suffix] {
        out.push('-');
        out.push_str(&line(l));
    }
    for l in &b[prefix..b.len() - suffix] {
        out.push('+');
        out.push_str(&line(l));
    }
    for l in &a[a.len() - suffix..a_end] {
        out.push(' ');
        out.push_str(&line(l));
    }
    out
}

/// One file's text after applying a fix hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixEdit {
    pub file: PathBuf,
    pub text: String,
}

/// Where a fix writes its literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixSite {
    /// The attribute in the resource block (inserted when not written).
    Attribute,
    /// The default of the variable the attribute is written as
    /// ([`tf_linter::FixHint::default_site`]).
    Default,
}

impl FixSite {
    pub fn as_str(self) -> &'static str {
        match self {
            FixSite::Attribute => "attribute",
            FixSite::Default => "default",
        }
    }
}

/// Apply a finding's fix hint to the source of `output` (scanned with
/// `keep_models`) at the attribute: rewritten in place when it is written,
/// else inserted into the resource block, creating the blocks on its path.
/// See [`apply_fix_at`].
pub fn apply_fix(output: &ScanOutput, finding: &tf_linter::Finding) -> Result<FixEdit, String> {
    let hint = finding
        .fix_hint
        .as_ref()
        .ok_or_else(|| format!("{} on {}: no fix hint", finding.rule, finding.address))?;
    apply_fix_at(output, &finding.root, hint, FixSite::Attribute)
}

/// Apply a fix hint of a finding from root module `root` at `site` (the
/// hint's resource address is looked up in that root: two roots may each
/// declare `aws_instance.this`). A written value is replaced, keeping the
/// text up to and including its `=` (so alignment survives); an inserted
/// attribute is aligned with the attributes above it the way `terraform
/// fmt` aligns them. The value is written as an HCL literal. Nothing is
/// written to disk; scan the edit through `ScanRequest::overlay` to check
/// it.
pub fn apply_fix_at(
    output: &ScanOutput,
    root: &std::path::Path,
    hint: &tf_linter::FixHint,
    site: FixSite,
) -> Result<FixEdit, String> {
    let files = &output.result.files;
    let value = hcl_literal(&hint.value);
    let at = match site {
        FixSite::Attribute => hint.site,
        FixSite::Default => Some(hint.default_site(files).ok_or_else(|| {
            format!(
                "{} {}: not written as a variable with a default",
                hint.resource, hint.attribute
            )
        })?),
    };
    if let Some(at) = at {
        let sf = files.get(at.file);
        if files.is_protected(&sf.path) {
            return Err("automatic edits to installed module files are disabled".into());
        }
        if sf.path.extension().is_some_and(|e| e == "json") {
            return Err("JSON source edits require a format-aware fix".into());
        }
        let mut text = sf.text.to_string();
        let (start, end) = (at.span.start as usize, at.span.end as usize);
        let eq = text[start..end]
            .find('=')
            .ok_or_else(|| format!("{}: no `=` in the attribute", hint.attribute))?;
        let mut from = start + eq + 1;
        while matches!(text.as_bytes().get(from), Some(b' ' | b'\t')) {
            from += 1;
        }
        text.replace_range(from..end, &value);
        return Ok(FixEdit {
            file: sf.path.clone(),
            text,
        });
    }
    let resource = output
        .analyses
        .iter()
        .filter(|a| normalize(&a.root_dir) == normalize(root))
        .flat_map(|a| &a.modules)
        .flat_map(|m| &m.resources)
        .find(|r| r.id == hint.resource)
        .ok_or_else(|| {
            format!(
                "{} is not in the scan (scan with keep_models)",
                hint.resource
            )
        })?;
    // Descend the blocks on the path that are written; the rest is created.
    let path: Vec<&str> = hint.attribute.split('.').collect();
    let (&key, blocks) = path.split_last().expect("split yields one item");
    let mut body = &resource.body;
    let mut missing = blocks;
    while let Some((&name, rest)) = missing.split_first() {
        let mut written = body.blocks_of(name);
        match (written.next(), written.next()) {
            (Some(one), None) if !one.dynamic => body = &one.body,
            (None, _) => break,
            _ => {
                return Err(format!(
                    "{}: more than one `{name}` block, or a dynamic one",
                    hint.resource
                ));
            }
        }
        missing = rest;
    }
    let sf = files.get(body.span.file);
    if files.is_protected(&sf.path) {
        return Err("automatic edits to installed module files are disabled".into());
    }
    if sf.path.extension().is_some_and(|e| e == "json") {
        return Err("JSON source edits require a format-aware fix".into());
    }
    let mut text = sf.text.to_string();
    let span = body.span.span;
    insert_into_body(
        &mut text,
        (span.start as usize, span.end as usize),
        missing,
        key,
        &value,
    )
    .ok_or_else(|| format!("{}: cannot find the block's braces", hint.resource))?;
    Ok(FixEdit {
        file: sf.path.clone(),
        text,
    })
}

/// Insert `key = value`, wrapped in new nested `blocks`, at the end of the
/// block body `(open, close)` (from after its `{` to its `}`) of `text`.
fn insert_into_body(
    text: &mut String,
    (open, close): (usize, usize),
    blocks: &[&str],
    key: &str,
    value: &str,
) -> Option<()> {
    if open == 0 || text.as_bytes().get(open - 1) != Some(&b'{') {
        return None;
    }
    if text.as_bytes().get(close) != Some(&b'}') {
        return None;
    }
    let indent_of = |text: &str, at: usize| -> String {
        let line = text[..at].rfind('\n').map_or(0, |i| i + 1);
        text[line..]
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect()
    };
    // A one-line block (`{}` or `{ a = 1 }`) is opened up first: HCL wants
    // the opening brace to end its line in a multi-line block.
    let close = if text[open..close].contains('\n') {
        close
    } else {
        let outer = indent_of(text, open);
        let inner = text[open..close].trim().to_string();
        let mut expanded = String::from("\n");
        if !inner.is_empty() {
            expanded.push_str(&format!("{outer}  {inner}\n"));
        }
        expanded.push_str(&outer);
        text.replace_range(open..close, &expanded);
        open + expanded.len()
    };
    let line_start = text[..close].rfind('\n').map_or(0, |i| i + 1);
    let mut close = close;
    if !text[line_start..close].trim().is_empty() {
        // Content before the closing brace on its line: break the line.
        let outer = indent_of(text, open);
        text.insert_str(close, &format!("\n{outer}"));
        close += 1 + outer.len();
    }
    let line_start = text[..close].rfind('\n').map_or(0, |i| i + 1);
    let base = format!("{}  ", &text[line_start..close]);
    let mut lines = String::new();
    for (depth, name) in blocks.iter().enumerate() {
        lines.push_str(&format!("{base}{}{name} {{\n", "  ".repeat(depth)));
    }
    let mut line_start = line_start;
    if blocks.is_empty() {
        let (line, at) = align(text, line_start, &base, key, value)?;
        lines.push_str(&line);
        line_start = at;
    } else {
        let deepest = format!("{base}{}", "  ".repeat(blocks.len()));
        lines.push_str(&format!("{deepest}{key} = {value}\n"));
    }
    for depth in (0..blocks.len()).rev() {
        lines.push_str(&format!("{base}{}}}\n", "  ".repeat(depth)));
    }
    text.insert_str(line_start, &lines);
    Some(())
}

/// `key = value` as a line at `indent`, aligned with the run of one-line
/// attributes ending just above `at` the way `terraform fmt` aligns them.
/// Only when `key` is the longest are the run's lines re-padded in `text`;
/// the line goes at the returned offset (`at`, moved by the re-padding).
fn align(
    text: &mut String,
    at: usize,
    indent: &str,
    key: &str,
    value: &str,
) -> Option<(String, usize)> {
    // The run: one-line `name = value` lines at `indent`, directly above.
    let mut run: Vec<(usize, usize)> = Vec::new(); // (line start, line end)
    let mut end = at;
    while end > 0 {
        let start = text[..end - 1].rfind('\n').map_or(0, |i| i + 1);
        let line = &text[start..end - 1];
        if attribute_line(line, indent).is_none() {
            break;
        }
        run.push((start, end - 1));
        end = start;
    }
    let longest = run
        .iter()
        .filter_map(|&(s, e)| attribute_line(&text[s..e], indent).map(|(k, _)| k.len()))
        .max()
        .unwrap_or(0);
    let width = longest.max(key.len());
    let mut at = at;
    // Lines already aligned to the longest name keep their text.
    let repad: &[(usize, usize)] = if key.len() > longest { &run } else { &[] };
    for &(s, e) in repad {
        let (k, rest) = attribute_line(&text[s..e], indent)?;
        let line = format!("{indent}{k:width$} = {rest}");
        at = at + line.len() - (e - s);
        text.replace_range(s..e, &line);
    }
    Some((format!("{indent}{key:width$} = {value}\n"), at))
}

/// `name = value` on one line at exactly `indent`: the name and the
/// value. A value opening a multi-line expression is not one line.
fn attribute_line<'t>(line: &'t str, indent: &str) -> Option<(&'t str, &'t str)> {
    let rest = line.strip_prefix(indent)?;
    if rest.starts_with([' ', '\t']) {
        return None;
    }
    let (name, value) = rest.split_once('=')?;
    let name = name.trim_end();
    let value = value.trim();
    let ident = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    let opens = value.ends_with(['{', '[', '(']) || value.starts_with("<<") || value.is_empty();
    (ident && !value.starts_with('=') && !opens).then_some((name, value))
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

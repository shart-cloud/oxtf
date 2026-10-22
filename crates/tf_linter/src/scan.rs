//! Library entry points: discover module roots, analyse each in parallel,
//! run the rules.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tf_semantic::{
    Analysis, AnalyzeOptions, DiagSeverity, Diagnostic, FileTable, ModuleStore,
    analyze_module_shared,
};

use crate::engine::Linter;
use crate::record::RuleError;
use crate::rule::{Certainty, Finding};

/// At most 64 workers of 4 MiB each: 256 MiB of reserved stack.
pub use tf_limits::WORKERS_MAX;
/// Guarded recursion at every depth ceiling needs at most 274 KiB in release and
/// 635 KiB in debug (docs/LIMITS.md); `tests/stack.rs` in tf_scan enforces the fit.
const WORKER_STACK_BYTES: usize = 4 << 20;

#[derive(Debug)]
pub enum ScanError {
    Workers(usize),
    Discovery(std::io::Error),
    ThreadPool(rayon::ThreadPoolBuildError),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Workers(n) => write!(f, "worker count {n} must be between 1 and {WORKERS_MAX}"),
            Self::Discovery(e) => write!(f, "cannot discover module roots: {e}"),
            Self::ThreadPool(e) => write!(f, "cannot create scan thread pool: {e}"),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workers(_) => None,
            Self::Discovery(e) => Some(e),
            Self::ThreadPool(e) => Some(e),
        }
    }
}

pub fn validate_threads(threads: Option<usize>) -> Result<(), ScanError> {
    if let Some(n) = threads {
        if !(1..=WORKERS_MAX).contains(&n) {
            return Err(ScanError::Workers(n));
        }
        assert!(n > 0);
        assert!(n <= WORKERS_MAX);
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub limits: tf_limits::Limits,
    /// Treat every directory under the path that contains `.tf` files as a
    /// root module (hidden directories and `.terraform` are skipped).
    /// Otherwise the path itself is the root module.
    pub recursive: bool,
    /// Extra `-var-file`s for the root module(s).
    pub var_files: Vec<PathBuf>,
    pub data_dir: Option<PathBuf>,
    /// Worker threads (1..=WORKERS_MAX); `None` uses CPUs, capped by roots and WORKERS_MAX.
    pub threads: Option<usize>,
    /// In-memory files that shadow the disk (`FileTable::with_overlay`):
    /// unsaved editor buffers, stdin, a proposed patch.
    pub overlay: Vec<(PathBuf, Arc<str>)>,
    /// Return the analysed model of every root in `scan_with`'s second
    /// value. Callers that only want findings (the CLI) set this off and
    /// each root's model is dropped as soon as its rules have run, which
    /// bounds memory by the largest root instead of the whole corpus.
    pub keep_models: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            limits: tf_limits::Limits::default(),
            recursive: false,
            var_files: Vec::new(),
            data_dir: None,
            threads: None,
            overlay: Vec::new(),
            keep_models: true,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScanStats {
    pub roots: usize,
    pub module_instances: usize,
    /// Distinct source files loaded (`.tf` + `.tfvars`).
    pub files: usize,
    pub resources: usize,
    pub findings: usize,
    pub definite: usize,
    pub conditional: usize,
    pub indeterminate: usize,
    pub findings_by_rule: BTreeMap<String, usize>,
    pub elapsed: Duration,
}

impl ScanStats {
    /// The one fold from findings to counts. Callers fill in `roots`,
    /// `module_instances`, `resources`, `files` and `elapsed`.
    pub fn from_findings(findings: &[Finding]) -> ScanStats {
        let mut stats = ScanStats {
            findings: findings.len(),
            ..ScanStats::default()
        };
        for f in findings {
            *stats
                .findings_by_rule
                .entry(f.rule.to_string())
                .or_default() += 1;
            match f.certainty {
                Certainty::Definite => stats.definite += 1,
                Certainty::Conditional => stats.conditional += 1,
                Certainty::Indeterminate => stats.indeterminate += 1,
            }
        }
        stats
    }
}

pub struct ScanResult {
    pub findings: Vec<Finding>,
    /// Parse errors, strict-bool warnings, missing local modules, ...
    pub diagnostics: Vec<Diagnostic>,
    pub stats: ScanStats,
    /// Rules that failed to run; never silent (see `record::RuleError`).
    pub rule_errors: Vec<RuleError>,
    /// Resolves the `FileId`s in findings, provenance and diagnostics.
    pub files: Arc<FileTable>,
    /// Findings of Checkov-sourced rules that a `checkov:skip` line
    /// suppressed ([`crate::suppress`]).
    pub suppressed: Vec<crate::suppress::Suppressed>,
    /// Each scanned root's own completion, in scan order. Scan-wide terminal
    /// diagnostics (storage, results) apply to every root and appear only in
    /// [`ScanResult::status`].
    pub roots: Vec<RootOutcome>,
}

/// One root module and whether its analysis and rules completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootOutcome {
    pub dir: PathBuf,
    pub status: ScanStatus,
    /// Some remote module call had no installed package to read.
    pub needs_install: bool,
}

/// Whether analysis completed, independently of whether it found violations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    #[default]
    Complete,
    /// A source, module or rule was skipped, or an analysis limit was reached.
    Incomplete,
    /// An input could not be analysed or a rule failed to execute.
    Failed,
}

impl ScanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
        }
    }
}

/// Diagnostics that prevent interpreting silence as a completed check.
pub fn limits_analysis(d: &Diagnostic) -> bool {
    d.severity == DiagSeverity::Error
        || d.code.starts_with("coverage-")
        || matches!(
            d.code,
            "rule-skipped"
                | "module-cycle"
                | "module-depth"
                | "module-missing"
                | "plan-errored"
                | "plan-format"
        )
}

/// A remote module call whose package is not installed under the data directory.
pub const NOT_INSTALLED: &str = "coverage-module-not-installed";

/// Failure wins over incomplete; shared by the scan and each root.
pub fn status_of(diagnostics: &[Diagnostic], rule_errors: &[RuleError]) -> ScanStatus {
    if !rule_errors.is_empty()
        || diagnostics
            .iter()
            .any(|d| d.severity == DiagSeverity::Error)
    {
        ScanStatus::Failed
    } else if diagnostics.iter().any(limits_analysis) {
        ScanStatus::Incomplete
    } else {
        ScanStatus::Complete
    }
}

impl ScanResult {
    pub fn status(&self) -> ScanStatus {
        status_of(&self.diagnostics, &self.rule_errors)
    }

    /// Reasons a scan cannot establish that a proposed fix was checked.
    pub fn completion_issues(&self) -> Vec<String> {
        self.diagnostics
            .iter()
            .filter(|d| limits_analysis(d))
            .map(|d| format!("{}: {}", d.code, d.message))
            .chain(self.rule_errors.iter().map(|e| match &e.resource {
                Some(r) => format!("{} on {r}: {}", e.rule, e.message),
                None => format!("{}: {}", e.rule, e.message),
            }))
            .collect()
    }
}

/// Directories to treat as root modules.
pub fn discover_roots(path: &Path, recursive: bool) -> Vec<PathBuf> {
    discover_roots_checked(path, recursive).unwrap_or_default()
}

/// Root discovery that does not hide directory read failures.
pub fn discover_roots_checked(path: &Path, recursive: bool) -> std::io::Result<Vec<PathBuf>> {
    discover_roots_with_budget(path, recursive, &tf_limits::input::InputBudget::default())
}

pub fn discover_roots_with_budget(
    path: &Path,
    recursive: bool,
    budget: &tf_limits::input::InputBudget,
) -> std::io::Result<Vec<PathBuf>> {
    if !recursive {
        budget.root()?;
        return Ok(vec![path.to_path_buf()]);
    }
    let mut roots = Vec::new();
    let mut pending = vec![path.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = budget.entries(&dir)?;
        if entries.iter().any(|(p, t)| {
            tf_semantic::module::is_config(p) && (t.is_file() || (t.is_symlink() && p.is_file()))
        }) {
            budget.root()?;
            roots.push(dir);
        }
        // Reverse the stack insertion to retain lexical depth-first order. Never follow links.
        for (path, kind) in entries.into_iter().rev() {
            let hidden = path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'));
            if kind.is_dir() && !hidden {
                pending.push(path);
            }
        }
        assert!(pending.len() as u64 <= budget.limits().directory_entries());
    }
    Ok(roots)
}

/// Scan `path` with the seed rules. A convenience for tests and examples;
/// scans with a catalog, selection or plan input go through `tf_scan`.
pub fn scan_dir(path: &Path, opts: &ScanOptions) -> Result<ScanResult, ScanError> {
    validate_threads(opts.threads)?;
    let files = Arc::new(FileTable::with_overlay_and_limits(
        opts.overlay.iter().cloned(),
        opts.limits,
    ));
    let roots = match discover_roots_with_budget(path, opts.recursive, files.input_budget()) {
        Ok(roots) => roots,
        Err(e) if tf_limits::input::exhaustion(&e).is_some() => Vec::new(),
        Err(e) => return Err(ScanError::Discovery(e)),
    };
    scan_with_files(&Linter::with_seed_rules(), &roots, opts, files).map(|(result, _)| result)
}

/// Scan explicit root module directories with a given linter: the one
/// parallel loop over roots, shared by every front door.
pub fn scan_with(
    linter: &Linter,
    roots: &[PathBuf],
    opts: &ScanOptions,
) -> Result<(ScanResult, Vec<Analysis>), ScanError> {
    let files = Arc::new(FileTable::with_overlay_and_limits(
        opts.overlay.iter().cloned(),
        opts.limits,
    ));
    scan_with_files(linter, roots, opts, files)
}

/// Reuse the snapshot and admission counters established during discovery/catalog loading.
#[expect(clippy::too_many_lines)]
pub fn scan_with_files(
    linter: &Linter,
    roots: &[PathBuf],
    opts: &ScanOptions,
    files: Arc<FileTable>,
) -> Result<(ScanResult, Vec<Analysis>), ScanError> {
    validate_threads(opts.threads)?;
    if files
        .input_budget()
        .ensure_roots(roots.len() as u64)
        .is_err()
    {
        return Ok((limited_scan(files), Vec::new()));
    }
    // Discovery can include overlay-only directories or a custom data
    // directory without a leading dot. Installed packages are reached through
    // their calls, never added as independent roots by a recursive scan.
    let caches: std::collections::HashSet<_> = roots
        .iter()
        .map(|root| {
            let path =
                tf_semantic::installed::data_dir(root, opts.data_dir.as_deref()).join("modules");
            tf_semantic::source::normalize(&std::path::absolute(&path).unwrap_or(path))
        })
        .collect();
    let filtered: Vec<_> = roots
        .iter()
        .filter(|candidate| {
            !opts.recursive
                || (!candidate
                    .components()
                    .any(|c| c.as_os_str() == ".terraform")
                    && !std::path::absolute(candidate).ok().is_some_and(|p| {
                        tf_semantic::source::normalize(&p)
                            .ancestors()
                            .any(|a| caches.contains(a))
                    }))
        })
        .cloned()
        .collect();
    let roots = filtered.as_slice();
    let start = Instant::now();
    // Parsed modules shared by every root: a recursive scan reaches most
    // module directories from several roots.
    let store = ModuleStore::new();
    let aopts = AnalyzeOptions {
        limits: opts.limits,
        var_files: opts.var_files.clone(),
        data_dir: opts.data_dir.clone(),
        whole_files: linter.needs_files(),
        ..AnalyzeOptions::default()
    };
    // What survives a root once its rules have run.
    struct RootResult {
        module_instances: usize,
        resources: usize,
        diagnostics: Vec<Diagnostic>,
        out: crate::engine::RunOutput,
        analysis: Option<Analysis>,
    }
    let work = || -> Vec<RootResult> {
        roots
            .par_iter()
            .map(|r| {
                let a = analyze_module_shared(r, &aopts, &files, &store);
                let mut out = linter.run_with(
                    &a,
                    Some(crate::engine::Sources {
                        limits: opts.limits,
                        store: &store,
                        files: &files,
                    }),
                );
                let (findings, suppressed) = crate::suppress::checkov_skips(
                    std::mem::take(&mut out.findings),
                    &a,
                    &files,
                    Some((&store, opts.limits)),
                );
                out.findings = findings;
                out.suppressed = suppressed;
                RootResult {
                    module_instances: a.modules.len(),
                    resources: a.stats.resources,
                    diagnostics: if opts.keep_models {
                        Vec::new()
                    } else {
                        a.diagnostics.clone()
                    },
                    out,
                    analysis: opts.keep_models.then_some(a),
                }
            })
            .collect()
    };
    // No more workers than roots: a one-root scan (an editor buffer, a patch)
    // must not spawn a thread per CPU to use one of them.
    let threads = opts
        .threads
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .min(WORKERS_MAX)
        })
        .min(roots.len().max(1));
    let results = run_in_pool(roots.len(), threads, work, |threads| {
        rayon::ThreadPoolBuilder::new()
            .stack_size(WORKER_STACK_BYTES)
            .num_threads(threads)
            .build()
    })?;
    let mut findings = Vec::new();
    let mut rule_errors = Vec::new();
    let mut suppressed = Vec::new();
    let mut diagnostics = Vec::new();
    if roots.is_empty() {
        diagnostics.push(Diagnostic {
            severity: DiagSeverity::Warning,
            code: "coverage-no-input",
            message: "no Terraform module roots found".into(),
            at: None,
        });
    }
    let mut analyses = Vec::new();
    let mut module_instances = 0;
    let mut resources = 0;
    let mut outcomes = Vec::with_capacity(roots.len());
    assert_eq!(results.len(), roots.len());
    for (dir, r) in roots.iter().zip(results) {
        module_instances += r.module_instances;
        resources += r.resources;
        let own = r
            .analysis
            .as_ref()
            .map_or(&r.diagnostics[..], |a| &a.diagnostics[..]);
        outcomes.push(RootOutcome {
            dir: dir.clone(),
            status: status_of(own, &r.out.rule_errors),
            needs_install: own.iter().any(|d| d.code == NOT_INSTALLED),
        });
        findings.extend(r.out.findings);
        rule_errors.extend(r.out.rule_errors);
        suppressed.extend(r.out.suppressed);
        match r.analysis {
            Some(a) => {
                diagnostics.extend(a.diagnostics.iter().cloned());
                analyses.push(a);
            }
            None => diagnostics.extend(r.diagnostics),
        }
    }
    diagnostics.retain(|d| d.code != "coverage-storage");
    diagnostics.extend(files.limit_diagnostic());
    diagnostics.extend(files.results_diagnostic());
    let stats = ScanStats {
        roots: roots.len(),
        module_instances,
        resources,
        files: files.len(),
        elapsed: start.elapsed(),
        ..ScanStats::from_findings(&findings)
    };
    Ok((
        ScanResult {
            findings,
            diagnostics,
            stats,
            rule_errors,
            files,
            suppressed,
            roots: outcomes,
        },
        analyses,
    ))
}

/// A terminal admission refusal is evidence, even when no root or plan could be loaded.
pub fn limited_scan(files: Arc<FileTable>) -> ScanResult {
    let diagnostic = files.limit_diagnostic().expect("typed input exhaustion");
    ScanResult {
        findings: Vec::new(),
        diagnostics: vec![diagnostic],
        stats: ScanStats::default(),
        rule_errors: Vec::new(),
        files,
        suppressed: Vec::new(),
        roots: Vec::new(),
    }
}

fn run_in_pool<T: Send>(
    roots: usize,
    threads: usize,
    work: impl FnOnce() -> Vec<T> + Send,
    build: impl FnOnce(usize) -> Result<rayon::ThreadPool, rayon::ThreadPoolBuildError>,
) -> Result<Vec<T>, ScanError> {
    assert!(threads > 0);
    assert!(threads <= WORKERS_MAX);
    if roots == 0 {
        return Ok(Vec::new());
    }
    assert!(threads <= roots);
    let pool = build(threads).map_err(ScanError::ThreadPool)?;
    Ok(pool.install(work))
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    #[test]
    fn operating_failure_returns_an_error_without_running_work() {
        let result = run_in_pool::<()>(
            1,
            1,
            || panic!("work must not run"),
            |threads| {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .spawn_handler(|_| Err(std::io::Error::other("injected spawn failure")))
                    .build()
            },
        );
        assert!(matches!(result, Err(ScanError::ThreadPool(_))));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected spawn failure")
        );
    }

    #[test]
    fn no_roots_never_builds_a_pool() {
        let result = run_in_pool::<()>(0, 1, || panic!("no work"), |_| panic!("no pool"));
        assert!(result.unwrap().is_empty());
    }
}

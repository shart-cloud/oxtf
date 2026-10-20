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

#[derive(Clone, Debug)]
pub struct ScanOptions {
    /// Treat every directory under the path that contains `.tf` files as a
    /// root module (hidden directories and `.terraform` are skipped).
    /// Otherwise the path itself is the root module.
    pub recursive: bool,
    /// Extra `-var-file`s for the root module(s).
    pub var_files: Vec<PathBuf>,
    pub data_dir: Option<PathBuf>,
    /// Worker threads (rayon); `None` = number of CPUs.
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

impl ScanResult {
    pub fn status(&self) -> ScanStatus {
        if !self.rule_errors.is_empty()
            || self
                .diagnostics
                .iter()
                .any(|d| d.severity == DiagSeverity::Error)
        {
            ScanStatus::Failed
        } else if self.diagnostics.iter().any(limits_analysis) {
            ScanStatus::Incomplete
        } else {
            ScanStatus::Complete
        }
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
    if !recursive {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut out = Vec::new();
    walk(path, &mut out)?;
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let rd = std::fs::read_dir(dir)?;
    // The entry type comes with the listing; a stat per entry would triple
    // the syscalls of a recursive scan. A symlink is never followed into
    // (one pointing at an ancestor would recurse until the path length
    // limit) but one pointing at a `.tf` file still makes a root.
    let mut entries: Vec<(PathBuf, std::fs::FileType)> = rd
        .map(|e| {
            let e = e?;
            Ok((e.path(), e.file_type()?))
        })
        .collect::<std::io::Result<_>>()?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    if entries.iter().any(|(p, t)| {
        tf_semantic::module::is_config(p) && (t.is_file() || (t.is_symlink() && p.is_file()))
    }) {
        out.push(dir.to_path_buf());
    }
    for (p, t) in entries {
        let hidden = p
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'));
        if t.is_dir() && !hidden {
            walk(&p, out)?;
        }
    }
    Ok(())
}

/// Scan `path` with the seed rules. A convenience for tests and examples;
/// scans with a catalog, selection or plan input go through `tf_scan`.
pub fn scan_dir(path: &Path, opts: &ScanOptions) -> ScanResult {
    scan_with(
        &Linter::with_seed_rules(),
        &discover_roots(path, opts.recursive),
        opts,
    )
    .0
}

/// Scan explicit root module directories with a given linter: the one
/// parallel loop over roots, shared by every front door.
pub fn scan_with(
    linter: &Linter,
    roots: &[PathBuf],
    opts: &ScanOptions,
) -> (ScanResult, Vec<Analysis>) {
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
    let files = Arc::new(FileTable::with_overlay(opts.overlay.iter().cloned()));
    // Parsed modules shared by every root: a recursive scan reaches most
    // module directories from several roots.
    let store = ModuleStore::new();
    let aopts = AnalyzeOptions {
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
                        store: &store,
                        files: &files,
                    }),
                );
                let (findings, suppressed) = crate::suppress::checkov_skips(
                    std::mem::take(&mut out.findings),
                    &a,
                    &files,
                    Some(&store),
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
    // Deep reference chains recurse; give workers generous stacks. No more
    // workers than roots: a one-root scan (an editor buffer, a patch) must
    // not spawn a thread per CPU to use one of them.
    let threads = opts.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(roots.len().max(1))
    });
    let pool = rayon::ThreadPoolBuilder::new()
        .stack_size(64 << 20)
        .num_threads(threads)
        .build()
        .expect("thread pool");
    let results = pool.install(work);
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
    for r in results {
        module_instances += r.module_instances;
        resources += r.resources;
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
    let stats = ScanStats {
        roots: roots.len(),
        module_instances,
        resources,
        files: files.len(),
        elapsed: start.elapsed(),
        ..ScanStats::from_findings(&findings)
    };
    (
        ScanResult {
            findings,
            diagnostics,
            stats,
            rule_errors,
            files,
            suppressed,
        },
        analyses,
    )
}

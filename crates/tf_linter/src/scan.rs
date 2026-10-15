//! Library entry points: discover module roots, analyse each in parallel,
//! run the rules.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use tf_semantic::{Analysis, AnalyzeOptions, Diagnostic, FileTable, analyze_module};

use crate::engine::Linter;
use crate::record::RuleError;
use crate::rule::{Finding, Severity};

#[derive(Clone, Debug, Default)]
pub struct ScanOptions {
    /// Treat every directory under the path that contains `.tf` files as a
    /// root module (hidden directories and `.terraform` are skipped).
    /// Otherwise the path itself is the root module.
    pub recursive: bool,
    /// Extra `-var-file`s for the root module(s).
    pub var_files: Vec<PathBuf>,
    /// Worker threads (rayon); `None` = number of CPUs.
    pub threads: Option<usize>,
    /// In-memory files that shadow the disk (`FileTable::with_overlay`):
    /// unsaved editor buffers, stdin, a proposed patch.
    pub overlay: Vec<(PathBuf, Arc<str>)>,
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
            match f.severity {
                Severity::Definite => stats.definite += 1,
                Severity::Conditional => stats.conditional += 1,
                Severity::Indeterminate => stats.indeterminate += 1,
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
}

/// Directories to treat as root modules.
pub fn discover_roots(path: &Path, recursive: bool) -> Vec<PathBuf> {
    if !recursive {
        return vec![path.to_path_buf()];
    }
    let mut out = Vec::new();
    walk(path, &mut out);
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    if entries
        .iter()
        .any(|p| p.is_file() && p.extension().is_some_and(|x| x == "tf"))
    {
        out.push(dir.to_path_buf());
    }
    for p in entries {
        let hidden = p
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'));
        // Don't follow directory symlinks: one pointing at an ancestor
        // would recurse until the path length limit.
        let is_link = p
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink());
        if p.is_dir() && !hidden && !is_link {
            walk(&p, out);
        }
    }
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
    let start = Instant::now();
    let files = Arc::new(FileTable::with_overlay(opts.overlay.iter().cloned()));
    let aopts = AnalyzeOptions {
        var_files: opts.var_files.clone(),
        ..AnalyzeOptions::default()
    };
    let work = || -> Vec<(Analysis, crate::engine::RunOutput)> {
        roots
            .par_iter()
            .map(|r| {
                let a = analyze_module(r, &aopts, &files);
                let out = linter.run(&a);
                (a, out)
            })
            .collect()
    };
    // Deep reference chains recurse; give workers generous stacks.
    let pool = rayon::ThreadPoolBuilder::new()
        .stack_size(64 << 20)
        .num_threads(opts.threads.unwrap_or(0))
        .build()
        .expect("thread pool");
    let results = pool.install(work);
    let mut findings = Vec::new();
    let mut rule_errors = Vec::new();
    let mut diagnostics = Vec::new();
    let mut analyses = Vec::new();
    let mut module_instances = 0;
    let mut resources = 0;
    for (a, out) in results {
        module_instances += a.modules.len();
        resources += a.stats.resources;
        diagnostics.extend(a.diagnostics.iter().cloned());
        findings.extend(out.findings);
        rule_errors.extend(out.rule_errors);
        analyses.push(a);
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
        },
        analyses,
    )
}

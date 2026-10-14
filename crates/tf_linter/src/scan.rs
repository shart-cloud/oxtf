//! Library entry points: discover module roots, analyse each in parallel,
//! run the rules.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use tf_semantic::{Analysis, AnalyzeOptions, Diagnostic, FileTable, analyze_module};

use crate::engine::Linter;
use crate::rule::{Finding, Severity};

#[derive(Clone, Debug, Default)]
pub struct ScanOptions {
    /// Treat every directory under the path that contains `.tf` files as a
    /// root module (hidden directories and `.terraform` are skipped).
    /// Otherwise the path itself is the root module.
    pub recursive: bool,
    /// Extra `-var-file`s for the root module(s).
    pub var_files: Vec<PathBuf>,
    /// Only run these rule ids (all seed rules when `None`).
    pub rules: Option<Vec<String>>,
    /// Worker threads (rayon); `None` = number of CPUs.
    pub threads: Option<usize>,
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
    pub findings_by_rule: BTreeMap<String, usize>,
    pub elapsed: Duration,
}

pub struct ScanResult {
    pub findings: Vec<Finding>,
    /// Parse errors, strict-bool warnings, missing local modules, ...
    pub diagnostics: Vec<Diagnostic>,
    pub stats: ScanStats,
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
        if p.is_dir() && !hidden {
            walk(&p, out);
        }
    }
}

/// Scan `path` and return findings only.
pub fn scan_dir(path: &Path, opts: &ScanOptions) -> ScanResult {
    scan_dir_with_model(path, opts).0
}

/// Scan `path` and also return the analysed model of every root module
/// (resources with evaluated attributes, variables, outputs, symbols).
pub fn scan_dir_with_model(path: &Path, opts: &ScanOptions) -> (ScanResult, Vec<Analysis>) {
    let rules = crate::rules::all();
    let linter = match &opts.rules {
        Some(ids) => Linter::filtered(rules, ids),
        None => Linter::new(rules),
    };
    scan_with(&linter, &discover_roots(path, opts.recursive), opts)
}

/// Scan explicit root module directories with a given linter (custom or
/// runtime-built rules).
pub fn scan_with(
    linter: &Linter,
    roots: &[PathBuf],
    opts: &ScanOptions,
) -> (ScanResult, Vec<Analysis>) {
    let start = Instant::now();
    let files = Arc::new(FileTable::new());
    let aopts = AnalyzeOptions {
        var_files: opts.var_files.clone(),
        ..AnalyzeOptions::default()
    };
    let work = || -> Vec<(Analysis, Vec<Finding>)> {
        roots
            .par_iter()
            .map(|r| {
                let a = analyze_module(r, &aopts, &files);
                let f = linter.run(&a);
                (a, f)
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
    let mut diagnostics = Vec::new();
    let mut analyses = Vec::new();
    let mut stats = ScanStats {
        roots: roots.len(),
        ..ScanStats::default()
    };
    for (a, f) in results {
        stats.module_instances += a.modules.len();
        stats.resources += a.stats.resources;
        diagnostics.extend(a.diagnostics.iter().cloned());
        findings.extend(f);
        analyses.push(a);
    }
    for f in &findings {
        *stats
            .findings_by_rule
            .entry(f.rule.to_string())
            .or_default() += 1;
        match f.severity {
            Severity::Definite => stats.definite += 1,
            Severity::Conditional => stats.conditional += 1,
        }
    }
    stats.findings = findings.len();
    stats.files = files.len();
    stats.elapsed = start.elapsed();
    (
        ScanResult {
            findings,
            diagnostics,
            stats,
            files,
        },
        analyses,
    )
}

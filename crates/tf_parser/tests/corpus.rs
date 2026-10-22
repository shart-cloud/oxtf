//! Corpus tests: every `.tf` / `.tfvars` under `corpus/repos` must parse
//! without errors, and its structure must match `hcl-edit` (trivia excluded).
//!
//! Run with `--nocapture` to see the report. Skipped if the corpus is absent.

mod common;

use tf_parser::dump::{Options, dump_file};

#[test]
fn corpus_differential_vs_hcl_edit() {
    let files = common::corpus_files();
    if files.is_empty() {
        eprintln!("corpus not found; skipping");
        return;
    }
    let opts = Options {
        spans: false,
        normalize: true,
        dedupe_object_keys: true,
    };
    let mut parser_failed = Vec::new();
    let mut hcl_failed = Vec::new();
    let mut diverged = Vec::new();
    let mut same = 0usize;
    let mut source_bytes = 0usize;
    let mut compared_bytes = 0usize;
    for path in &files {
        let src = std::fs::read_to_string(path).unwrap();
        source_bytes += src.len();
        let alloc = tf_allocator::Allocator::new();
        let ret = tf_parser::parse(&alloc, &src);
        // Require clean parsing even for files the reference parser rejects.
        if !ret.errors.is_empty() {
            parser_failed.push((path.clone(), ret.errors.clone()));
        }
        let mine = dump_file(&ret.file, opts);
        match hcl_edit::parser::parse_body(&src) {
            Err(e) => hcl_failed.push((path.clone(), e.to_string())),
            Ok(body) => {
                let theirs = common::hcl_body(&body);
                compared_bytes += mine.len();
                if mine == theirs {
                    same += 1;
                } else {
                    let (a, b) = first_diff(&mine, &theirs);
                    diverged.push((path.clone(), a, b));
                }
            }
        }
    }
    println!(
        "corpus: {} files, {} bytes, {} with errors",
        files.len(),
        source_bytes,
        parser_failed.len()
    );
    for (p, errs) in parser_failed.iter().take(20) {
        println!("  {}: {}", p.display(), errs[0]);
    }
    println!(
        "differential: {} files, {} identical, {} diverged, {} rejected by hcl-edit",
        files.len(),
        same,
        diverged.len(),
        hcl_failed.len()
    );
    println!("differential: {compared_bytes} bytes of normalised S-expressions compared");
    assert!(
        compared_bytes > 1_000_000,
        "normaliser output suspiciously small"
    );
    for (p, a, b) in diverged.iter().take(30) {
        println!(
            "  DIVERGED {}\n    tf_parser: {}\n    hcl-edit:  {}",
            p.display(),
            a,
            b
        );
    }
    for (p, e) in hcl_failed.iter().take(10) {
        println!(
            "  HCL-EDIT ERROR {}: {}",
            p.display(),
            e.lines().next().unwrap_or("")
        );
    }
    assert!(
        parser_failed.is_empty(),
        "{} corpus files had parse errors",
        parser_failed.len()
    );
    assert!(
        diverged.is_empty(),
        "{} files diverged from hcl-edit",
        diverged.len()
    );
}

/// First differing line of two dumps.
fn first_diff(a: &str, b: &str) -> (String, String) {
    for (x, y) in a.lines().zip(b.lines()) {
        if x != y {
            return (x.trim().to_string(), y.trim().to_string());
        }
    }
    (
        format!("<{} lines>", a.lines().count()),
        format!("<{} lines>", b.lines().count()),
    )
}

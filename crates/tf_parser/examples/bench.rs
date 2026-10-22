//! Throughput benchmark: tf_parser vs hcl-edit on the whole corpus.
//!
//! `cargo run --release -p tf_parser --example bench -- [ITERATIONS]`
//!
//! All files are read into memory first; only parsing is timed. Single
//! threaded. tf_parser reuses one arena, reset after every file (oxc style);
//! hcl-edit builds and drops an owned tree per file.

use std::path::{Path, PathBuf};
use std::time::Instant;

fn corpus_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                walk(&p, out);
            } else if ft.is_file() {
                let n = p.file_name().unwrap().to_string_lossy();
                if n.ends_with(".tf") || n.ends_with(".tfvars") || n.ends_with(".hcl") {
                    out.push(p);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/repos"),
        &mut out,
    );
    out.sort();
    out
}

fn main() {
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let sources: Vec<String> = corpus_files()
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect();
    let total_bytes: usize = sources.iter().map(String::len).sum();
    let mb = total_bytes as f64 / 1e6;
    println!(
        "corpus: {} files, {} bytes ({:.2} MB), {} iterations",
        sources.len(),
        total_bytes,
        mb,
        iters
    );

    // Arena footprint: parse everything into one arena without resetting.
    {
        let alloc = tf_allocator::Allocator::new();
        let mut errors = 0;
        let mut comments = 0;
        for s in &sources {
            let ret = tf_parser::parse(&alloc, s);
            errors += ret.errors.len();
            comments += ret.comments.len();
            std::mem::forget(ret.file);
        }
        let used = alloc.used_bytes();
        println!(
            "arena: {} bytes used ({} bytes in chunks) for {} source bytes = {:.2} used arena bytes per source byte ({} errors, {} comments)",
            used,
            alloc.allocated_bytes(),
            total_bytes,
            used as f64 / total_bytes as f64,
            errors,
            comments
        );
    }

    let mut alloc = tf_allocator::Allocator::new();
    // Warm up both.
    for s in &sources {
        let ret = tf_parser::parse(&alloc, s);
        std::hint::black_box(&ret.file);
        drop(ret);
        alloc.reset();
        std::hint::black_box(hcl_edit::parser::parse_body(s).ok());
    }

    let mut mine = Vec::new();
    let mut theirs = Vec::new();
    for _ in 0..iters {
        let mut alloc = tf_allocator::Allocator::new();
        let t = Instant::now();
        for s in &sources {
            let ret = tf_parser::parse(&alloc, s);
            assert!(alloc.budget().exhaustion().is_none());
            std::hint::black_box(&ret.file);
            drop(ret);
            alloc.reset();
        }
        mine.push(t.elapsed().as_secs_f64());

        let t = Instant::now();
        for s in &sources {
            let body = hcl_edit::parser::parse_body(s);
            std::hint::black_box(&body);
        }
        theirs.push(t.elapsed().as_secs_f64());
    }
    let report = |name: &str, v: &mut Vec<f64>| {
        v.sort_by(f64::total_cmp);
        let median = v[v.len() / 2];
        let min = v[0];
        let total: f64 = v.iter().sum();
        println!(
            "{name:10} total {total:.3}s over {iters} passes | per pass: median {:.1} ms, min {:.1} ms | median {:.1} MB/s, best {:.1} MB/s",
            median * 1e3,
            min * 1e3,
            mb / median,
            mb / min
        );
        median
    };
    let a = report("tf_parser", &mut mine);
    let b = report("hcl-edit", &mut theirs);
    println!("speedup (median): {:.2}x", b / a);
}

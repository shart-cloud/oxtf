//! Compile-only check of a Rego tree with the regorus configuration oxtf
//! uses, for comparison with `opa check` (bench/rego/opa_compare.py).
//!
//! `cargo run --release -p tf_rego --example rego_check -- [--v0] DIR...`
//! prints `{"files": N, "errors": [{"file", "message"}]}`: per-file parse
//! errors, then one entry for a bundle-level compile error.

use std::path::{Path, PathBuf};

fn walk(p: &Path, out: &mut Vec<PathBuf>) {
    if p.is_dir() {
        let mut children: Vec<_> = std::fs::read_dir(p)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        children.sort();
        for c in children {
            walk(&c, out);
        }
    } else if p.extension().is_some_and(|e| e == "rego") {
        out.push(p.to_path_buf());
    }
}

fn main() {
    let mut v0 = false;
    let mut files = Vec::new();
    for arg in std::env::args().skip(1) {
        if arg == "--v0" {
            v0 = true;
        } else {
            walk(Path::new(&arg), &mut files);
        }
    }
    let mut engine = tf_rego::foreign::new_engine(v0);
    let mut errors = Vec::new();
    for f in &files {
        let source = std::fs::read_to_string(f).unwrap();
        if let Err(e) = engine.add_policy(f.display().to_string(), source) {
            errors.push(
                serde_json::json!({"file": f.display().to_string(), "message": e.to_string()}),
            );
        }
    }
    if let Err(e) = engine.eval_query("true".to_string(), false) {
        errors.push(serde_json::json!({"file": null, "message": e.to_string()}));
    }
    println!(
        "{}",
        serde_json::json!({"files": files.len(), "errors": errors})
    );
}

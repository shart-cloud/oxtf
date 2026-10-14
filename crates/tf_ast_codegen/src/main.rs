//! `cargo run -p tf_ast_codegen [-- --check]`
//!
//! Regenerates `crates/tf_ast/src/generated/*.rs` from `crates/tf_ast/src/ast.rs`.
//! With `--check`, exits non-zero if the committed files are stale.
//! `--input FILE --out-dir DIR` generates from another AST file (used for the
//! scaled compile-time experiment in docs/findings/W1.md).

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let check = args.iter().any(|a| a == "--check");
    let opt = |name: &str| args.iter().position(|a| a == name).map(|i| PathBuf::from(&args[i + 1]));
    let ast_crate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tf_ast");
    let input = opt("--input").unwrap_or_else(|| ast_crate.join("src/ast.rs"));
    let out_dir = opt("--out-dir").unwrap_or_else(|| ast_crate.join("src/generated"));
    let src = std::fs::read_to_string(&input).expect("read ast.rs");
    std::fs::create_dir_all(&out_dir).unwrap();
    let mut stale = false;
    for (name, content) in tf_ast_codegen::generate_files(&src) {
        let path = out_dir.join(&name);
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current != content {
            stale = true;
            if !check {
                std::fs::write(&path, content).unwrap();
                println!("wrote {}", path.display());
            } else {
                eprintln!("stale: {}", path.display());
            }
        }
    }
    if check && stale {
        std::process::exit(1);
    }
}

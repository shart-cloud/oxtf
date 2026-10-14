//! `cargo run -p tf_ast_codegen [-- --check]`
//!
//! Regenerates `crates/tf_ast/src/generated/*.rs` from `crates/tf_ast/src/ast.rs`.
//! With `--check`, exits non-zero if the committed files are stale.

use std::path::PathBuf;

fn main() {
    let check = std::env::args().any(|a| a == "--check");
    let ast_crate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tf_ast");
    let src = std::fs::read_to_string(ast_crate.join("src/ast.rs")).expect("read ast.rs");
    let out_dir = ast_crate.join("src/generated");
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

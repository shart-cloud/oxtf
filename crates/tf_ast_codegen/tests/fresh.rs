//! The committed `tf_ast/src/generated/*.rs` must match the generator output
//! (CI check, like oxc's `just ast`). Fix with `cargo run -p tf_ast_codegen`.
use std::path::PathBuf;

#[test]
fn generated_files_are_fresh() {
    let ast_crate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tf_ast");
    let src = std::fs::read_to_string(ast_crate.join("src/ast.rs")).unwrap();
    for (name, content) in tf_ast_codegen::generate_files(&src) {
        let committed = std::fs::read_to_string(ast_crate.join("src/generated").join(&name)).unwrap();
        assert!(committed == content, "{name} is stale; run `cargo run -p tf_ast_codegen`");
    }
}

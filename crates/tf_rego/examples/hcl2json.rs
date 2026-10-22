//! hcl2json's rendering of `.tf` files, for comparison with
//! `conftest parse` (bench/rego/conftest_compare.py).
//!
//! `cargo run --release -p tf_rego --example hcl2json -- FILE...` prints one
//! JSON line per file: `{"file", "doc"}`, or `{"file", "error"}` when the
//! file does not parse or convert.

fn main() {
    for path in std::env::args().skip(1) {
        let text = std::fs::read_to_string(&path).unwrap();
        let alloc = tf_allocator::Allocator::new();
        let parsed = tf_parser::parse(&alloc, &text);
        let line = if !parsed.errors.is_empty() {
            serde_json::json!({"file": path, "error": "parse error"})
        } else {
            let file = alloc.alloc(parsed.file).unwrap();
            match tf_rego::hcl2json::raw(file, &text) {
                Ok(doc) => serde_json::json!({"file": path, "doc": doc}),
                Err(e) => serde_json::json!({"file": path, "error": e}),
            }
        };
        println!("{line}");
    }
}

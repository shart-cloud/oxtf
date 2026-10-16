//! `tf_rego::hcl2json::raw` against Conftest v0.71.0's `conftest parse`.
//! The corpus-wide comparison is `bench/rego/hcl2json_compare.py`.

use std::path::Path;

#[test]
fn raw_rendering_matches_conftest_parse() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rego/hcl2json");
    let text = std::fs::read_to_string(dir.join("tricky.tf")).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("tricky.conftest.json")).unwrap())
            .unwrap();
    let alloc = tf_allocator::Allocator::new();
    let parsed = tf_parser::parse(&alloc, &text);
    assert!(parsed.errors.is_empty());
    let file = alloc.alloc(parsed.file);
    assert_eq!(tf_rego::hcl2json::raw(file, &text).unwrap(), expected);
}

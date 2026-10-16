//! The front-end's re-implementations of PyYAML and the JSONPath compiler,
//! against fixtures produced by the pinned Python originals
//! (`bench/checkov/frontend_fixtures.py`).

use serde_json::Value as Json;
use tf_rule_ir::checkov_policy::compile_jsonpath;
use tf_rule_ir::pyyaml;

fn fixtures() -> Json {
    serde_json::from_str(include_str!("fixtures/checkov_frontend.json")).unwrap()
}

#[test]
fn yaml_matches_pyyaml_safe_load() {
    // PyYAML constructs these, but they are rejected rather than reproduced.
    let stricter = ["a: !!omap [{x: 1}]\n"];
    let mut wrong = Vec::new();
    for case in fixtures()["yaml"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let ours = pyyaml::load(text);
        match (case.get("value"), &ours) {
            (Some(expected), Ok(doc)) if &doc.value == expected => {}
            (None, Err(_)) => {}
            (Some(_), Err(_)) if stricter.contains(&text) => {}
            _ => wrong.push(format!(
                "{text:?}: PyYAML {case}, ours {:?}",
                ours.map(|d| d.value)
            )),
        }
    }
    assert!(
        wrong.is_empty(),
        "{} differences:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn jsonpath_matches_importer() {
    let mut wrong = Vec::new();
    let mut stricter = Vec::new();
    for case in fixtures()["jsonpath"].as_array().unwrap() {
        let attribute = case["attribute"].as_str().unwrap();
        let ours = compile_jsonpath(attribute).map(Json::Array);
        match (&case["path"], ours) {
            (Json::Null, None) => {}
            (expected, Some(ours)) if *expected == ours => {}
            (expected, None) => stricter.push(format!("{attribute:?} (importer: {expected})")),
            (expected, Some(ours)) => {
                wrong.push(format!("{attribute:?}: importer {expected}, ours {ours}"))
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "accepted differently:\n{}",
        wrong.join("\n")
    );
    // Spellings the importer accepted that the native grammar rejects, with
    // a diagnostic, rather than reproduce bc_jsonpath_ng's full grammar.
    assert_eq!(
        stricter,
        [
            r#""a[:]" (importer: ["a",{"kind":"each"}])"#,
            r#""a.[*]" (importer: ["a",{"kind":"each"}])"#,
            r#""a['b'][*]" (importer: ["a","b",{"kind":"each"}])"#,
            r#""a.'b'[*]" (importer: ["a","b",{"kind":"each"}])"#,
            r#""a[?(@.k == @v)]" (importer: ["a",{"kind":"filter","predicates":[{"operator":"equals","path":["k"],"value":"@v"}]}])"#,
        ]
    );
}

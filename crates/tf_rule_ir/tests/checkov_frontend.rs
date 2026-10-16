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

#[test]
fn regex_classes_match_python_over_all_code_points() {
    use tf_rule_ir::pyre::{Mode, compile};
    let fixtures = fixtures();
    // Code points unassigned in the Unicode version of the reference Python:
    // the `regex` crate's newer tables may classify them.
    let unassigned: Vec<(u32, u32)> = fixtures["unassigned"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r[0].as_u64().unwrap() as u32, r[1].as_u64().unwrap() as u32))
        .collect();
    let newer = |c: u32| unassigned.iter().any(|(a, b)| (*a..=*b).contains(&c));
    let mut wrong = Vec::new();
    for (class, ranges) in fixtures["regex_classes"].as_object().unwrap() {
        let rx = compile(class, Mode::Match).unwrap();
        let ranges: Vec<(u32, u32)> = ranges
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r[0].as_u64().unwrap() as u32, r[1].as_u64().unwrap() as u32))
            .collect();
        let mut diffs = Vec::new();
        for c in (0..=0x10FFFFu32).filter_map(char::from_u32) {
            let python = ranges.iter().any(|(a, b)| (*a..=*b).contains(&(c as u32)));
            if rx.is_match(&c.to_string()) != python && !newer(c as u32) {
                diffs.push(format!("U+{:04X}", c as u32));
            }
        }
        if !diffs.is_empty() {
            wrong.push(format!(
                "{class}: {} code points differ, e.g. {:?}",
                diffs.len(),
                &diffs[..diffs.len().min(12)]
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn regex_matches_python() {
    use tf_rule_ir::pyre::{Mode, compile};
    let mut wrong = Vec::new();
    let mut stricter = Vec::new();
    for case in fixtures()["regex"].as_array().unwrap() {
        let pattern = case["pattern"].as_str().unwrap();
        if case.get("error").is_some() {
            if compile(pattern, Mode::Match).is_ok() {
                wrong.push(format!("{pattern:?}: Python rejects it, ours compiles"));
            }
            continue;
        }
        for mode in [Mode::Match, Mode::Search] {
            let Ok(rx) = compile(pattern, mode) else {
                if mode == Mode::Match {
                    stricter.push(pattern.to_string());
                }
                continue;
            };
            let key = if mode == Mode::Match {
                "match"
            } else {
                "search"
            };
            for (input, expected) in case[key].as_object().unwrap() {
                if rx.is_match(input) != expected.as_bool().unwrap() {
                    wrong.push(format!("{key} {pattern:?} on {input:?}: Python {expected}"));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} differences:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    // Valid in Python, rejected here (each with a reason) rather than
    // approximated.
    assert_eq!(
        stricter,
        [
            "(?i)straße",
            "a$b",
            r"\bword",
            "(?=a)",
            r"(a)\1",
            "a*+",
            "(?s).",
            "(?m)^a",
            "(?x)a b",
            r"(?a)\w",
            "^(?!x)",
            "(?i)é",
        ]
    );
}

#[test]
fn python_builtins_match() {
    use tf_rule_ir::py;
    let fixtures = fixtures();
    let mut wrong = Vec::new();
    for case in fixtures["ip"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let ours = py::network_str(text).map(|n| match n {
            py::Network::V4 { first, last } => (4, first as u128, last as u128),
            py::Network::V6 { first, last } => (6, first, last),
        });
        let python = case["network"].as_object().map(|n| {
            (
                n["version"].as_u64().unwrap(),
                n["first"].as_str().unwrap().parse::<u128>().unwrap(),
                n["last"].as_str().unwrap().parse::<u128>().unwrap(),
            )
        });
        // Scoped IPv6 addresses are rejected rather than compared by scope.
        if ours != python && !text.contains('%') {
            wrong.push(format!(
                "ip_network({text:?}): Python {python:?}, ours {ours:?}"
            ));
        }
    }
    for case in fixtures["str"].as_array().unwrap() {
        let ours = py::str(&case["value"]);
        let python = case["str"].as_str().unwrap();
        // Non-ASCII strings inside containers are left unresolved by design.
        let excused = ours.is_none() && !python.is_ascii();
        if ours.as_deref() != Some(python) && !excused {
            wrong.push(format!(
                "str({}): Python {python:?}, ours {ours:?}",
                case["value"]
            ));
        }
    }
    for case in fixtures["int"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let ours = py::int_str(text).map(|n| n.to_string());
        let python = case["int"].as_str().map(str::to_string);
        // Non-ASCII digits are valid for Python but rejected here; huge
        // values saturate.
        let saturated = python.as_deref().is_some_and(|p| p.len() > 38);
        let excused = saturated || (ours.is_none() && !text.is_ascii());
        if ours != python && !excused {
            wrong.push(format!("int({text:?}): Python {python:?}, ours {ours:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

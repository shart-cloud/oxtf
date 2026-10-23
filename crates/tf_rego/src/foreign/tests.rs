use super::*;

fn dir(files: &[(&str, &str)]) -> tempdir::Dir {
    tempdir::Dir::new(files)
}

fn test_policy(dir: &tempdir::Dir, sources: Arc<tf_semantic::FileTable>) -> ForeignPolicy {
    let bundle = Bundle::load_with_sources(
        &Options {
            paths: &[dir.path().to_path_buf()],
            data: &[],
            namespaces: &[],
            all_namespaces: false,
            exclude: &[],
            entries: &[],
            shape: Shape::Plan,
            rego_v0: false,
        },
        sources,
    )
    .unwrap();
    ForeignPolicy {
        info: tf_linter::rules::all()[0].info(),
        types: None,
        input: Input::Document,
        bundle: Arc::new(bundle),
        entry: DEFAULT_ENTRY.into(),
        shape: Shape::Plan,
        exception: None,
        trace: None,
    }
}

#[test]
fn internal_rego_work_is_interrupted_and_cannot_reset_the_root_timer() {
    let dir = dir(&[(
        "main.rego",
        r#"package main
import rego.v1
deny contains "bad" if {
    some x in numbers.range(1, 2000)
    some y in numbers.range(1, 2000)
    x + y == 999999
}"#,
    )]);
    let policy = test_policy(&dir, Arc::new(tf_semantic::FileTable::new()));
    let budget =
        tf_linter::RuleBudget::new(tf_limits::Limits::default().with_rego_time_ms(1).unwrap());
    let run = PolicyRun {
        policy: &policy,
        budget: &budget,
    };
    assert!(run.run(json!({})).unwrap_err().contains("rego_time_ms"));
    assert_eq!(
        budget.exhaustion().unwrap().resource,
        tf_limits::Resource::RegoTimeMs
    );
    assert!(run.run(json!({})).is_err());
    assert!(budget.finish(Ok(())).is_err());
}

#[test]
fn policy_cache_lives_only_as_long_as_its_root_budget() {
    let dir = dir(&[(
        "main.rego",
        "package main\nimport rego.v1\ndeny contains \"bad\" if true",
    )]);
    let sources = Arc::new(tf_semantic::FileTable::new());
    let weak = Arc::downgrade(&sources);
    let policy = test_policy(&dir, sources);
    let budget = tf_linter::RuleBudget::default();
    let found = PolicyRun {
        policy: &policy,
        budget: &budget,
    }
    .run(json!({}))
    .unwrap();
    assert_eq!(found[0].msg, "bad");
    let cost = budget.used();
    assert!(cost > 1);
    for allowance in [cost - 1, cost, cost + 1] {
        let limits = tf_semantic::AnalyzeOptions::default()
            .limits
            .with_rule_steps(allowance)
            .unwrap();
        let root = tf_linter::RuleBudget::new(limits);
        let result = PolicyRun {
            policy: &policy,
            budget: &root,
        }
        .run(json!({}));
        assert_eq!(result.is_ok(), allowance >= cost);
        assert_eq!(root.exhaustion().is_some(), allowance < cost);
    }
    drop(policy);
    assert!(
        weak.upgrade().is_some(),
        "the working engine owns its input extensions"
    );
    drop(budget);
    assert!(
        weak.upgrade().is_none(),
        "no engine survives its root on a persistent thread"
    );
}

mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct Dir(pub PathBuf);

    impl Dir {
        pub fn new(files: &[(&str, &str)]) -> Dir {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static N: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "tf_rego_foreign_{}_{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            for (name, text) in files {
                let path = root.join(name);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text).unwrap();
            }
            Dir(root)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn load(d: &tempdir::Dir, entries: &[&str]) -> Result<Vec<RuleInfo>, String> {
    let paths = [d.path().to_path_buf()];
    let entries: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
    rules(&Options {
        paths: &paths,
        data: &[],
        namespaces: &[],
        all_namespaces: false,
        exclude: &[],
        entries: &entries,
        shape: Shape::Plan,
        rego_v0: false,
    })
    .map(|rs| rs.iter().map(|r| r.info()).collect())
}

#[test]
fn packages_merge_across_files_and_data_is_placed_by_directory() {
    let d = dir(&[
        (
            "a.rego",
            "package main\nimport rego.v1\ndeny contains data.lib.cfg.msg if true\n",
        ),
        (
            "b.rego",
            "package main\nimport rego.v1\ndeny contains \"b\" if true\n",
        ),
        ("lib/cfg.json", "{\"cfg\": {\"msg\": \"from data\"}}"),
    ]);
    let infos = load(&d, &[]).unwrap();
    assert_eq!(infos.len(), 1);
    // Defined in two files: the fallback ID is the rule path.
    assert_eq!(&*infos[0].name, "rego:main.deny");
    let paths = [d.path().to_path_buf()];
    // OPA mode (an entry is named): data next to the policies loads, as
    // with `opa eval -d`.
    let opa = Bundle::load(&Options {
        paths: &paths,
        data: &[],
        namespaces: &[],
        all_namespaces: false,
        exclude: &[],
        entries: &[DEFAULT_ENTRY.into()],
        shape: Shape::Plan,
        rego_v0: false,
    })
    .unwrap();
    let msgs = |bundle: &Bundle| {
        let v = violations(&eval(&bundle.engine, json!({}), DEFAULT_ENTRY).unwrap()).unwrap();
        let mut msgs: Vec<_> = v.into_iter().map(|v| v.msg).collect();
        msgs.sort();
        msgs
    };
    assert_eq!(msgs(&opa), ["b", "from data"]);
    // Conftest mode: policy paths load `.rego` only; data comes from
    // `data` paths.
    let conftest = |data: &[PathBuf]| {
        Bundle::load(&Options {
            paths: &paths,
            data,
            namespaces: &[],
            all_namespaces: false,
            exclude: &[],
            entries: &[],
            shape: Shape::Plan,
            rego_v0: false,
        })
        .unwrap()
    };
    assert_eq!(msgs(&conftest(&[])), ["b"]);
    // Data sits at its directory's path below the data root, so the
    // root is the parent of `lib`; `.rego` files there are not data.
    assert_eq!(
        msgs(&conftest(&[d.path().to_path_buf()])),
        ["b", "from data"]
    );
}

#[test]
#[expect(clippy::too_many_lines)]
fn conftest_rules_namespaces_and_exceptions() {
    let d = dir(&[
        (
            "main.rego",
            "package main\nimport rego.v1\ndeny contains \"d\" if true\nviolation_tags contains {\"msg\": \"v\"} if true\nwarn_old contains \"w\" if true\ndenyx contains \"not a rule\" if true\ndeny_ contains \"not a rule\" if true\nexception contains [\"old\"] if input.skip_old\n",
        ),
        (
            "other.rego",
            "package other.ns\nimport rego.v1\ndeny_x contains \"o\" if true\n",
        ),
    ]);
    let paths = [d.path().to_path_buf()];
    let load = |namespaces: &[String], all: bool| {
        rules(&Options {
            paths: &paths,
            data: &[],
            namespaces,
            all_namespaces: all,
            exclude: &[],
            entries: &[],
            shape: Shape::Plan,
            rego_v0: false,
        })
    };
    let names = |rs: Vec<Box<dyn DynRule>>| -> Vec<(String, Level)> {
        rs.iter()
            .map(|r| (r.info().name.to_string(), r.info().level))
            .collect()
    };
    assert_eq!(
        names(load(&[], false).unwrap()),
        [
            ("rego:main.deny".to_string(), Level::Medium),
            ("rego:main.violation_tags".to_string(), Level::Medium),
            ("rego:main.warn_old".to_string(), Level::Low),
        ]
    );
    assert_eq!(
        names(load(&["other.ns".into()], false).unwrap()),
        [("rego:other".to_string(), Level::Medium)]
    );
    assert_eq!(names(load(&[], true).unwrap()).len(), 4);
    assert!(
        load(&["nope".into()], false)
            .err()
            .unwrap()
            .contains("package nope")
    );
    assert_eq!(conftest_kind("deny_a_B1"), Some(RuleKind::Failure));
    assert_eq!(conftest_kind("deny__a"), None);
    assert_eq!(conftest_kind("warning"), None);
    assert_eq!(exception_name("violation_tags"), "tags");
    assert_eq!(exception_name("deny"), "");
    // The exception set suppresses `warn_old` on inputs that ask for it.
    let bundle = Bundle::load(&Options {
        paths: &paths,
        data: &[],
        namespaces: &[],
        all_namespaces: false,
        exclude: &[],
        entries: &[],
        shape: Shape::Plan,
        rego_v0: false,
    })
    .unwrap();
    let e = Exception {
        rule: "data.main.exception".into(),
        name: "old".into(),
    };
    let v = |j: Json| regorus::Value::from(j);
    let excepted = |input: Json| {
        exception_names(&eval_value(&bundle.engine, v(input), &e.rule).unwrap(), &e).unwrap()
    };
    assert!(excepted(json!({"skip_old": true})));
    assert!(!excepted(json!({})));
}

#[test]
fn load_errors_are_loud() {
    let missing = dir(&[(
        "a.rego",
        "package other\nimport rego.v1\ndeny contains 1 if true\n",
    )]);
    assert!(
        load(&missing, &[])
            .unwrap_err()
            .contains("no policy declares package main")
    );
    assert!(
        load(&missing, &[DEFAULT_ENTRY])
            .unwrap_err()
            .contains("not defined")
    );
    let conflict = dir(&[
        (
            "a.rego",
            "package main\nimport rego.v1\ndeny contains 1 if true\n",
        ),
        ("x.json", "{\"k\": 1}"),
        ("y.json", "{\"k\": 2}"),
    ]);
    assert!(
        load(&conflict, &[DEFAULT_ENTRY])
            .unwrap_err()
            .contains("merge error")
    );
    assert!(
        load(&conflict, &[]).is_ok(),
        "Conftest mode ignores data next to policies"
    );
    let v0 = dir(&[("a.rego", "package main\ndeny[msg] { msg := \"x\" }\n")]);
    assert!(load(&v0, &[]).is_err(), "v0 syntax is an error in v1 mode");
    let paths = [v0.path().to_path_buf()];
    assert!(
        rules(&Options {
            paths: &paths,
            data: &[],
            namespaces: &[],
            all_namespaces: false,
            exclude: &[],
            entries: &[],
            shape: Shape::Plan,
            rego_v0: true
        })
        .is_ok()
    );
    let bad_severity = dir(&[(
        "a.rego",
        "# METADATA\n# custom:\n#   severity: urgent\npackage main\nimport rego.v1\ndeny contains 1 if true\n",
    )]);
    assert!(load(&bad_severity, &[]).unwrap_err().contains("a.rego:1"));
    let dup = dir(&[
        (
            "a.rego",
            "# METADATA\n# custom:\n#   id: X\npackage a\nimport rego.v1\ndeny contains 1 if true\n",
        ),
        (
            "b.rego",
            "# METADATA\n# custom:\n#   id: X\npackage b\nimport rego.v1\ndeny contains 1 if true\n",
        ),
    ]);
    assert!(
        load(&dup, &["data.a.deny", "data.b.deny"])
            .unwrap_err()
            .contains("rule ID X")
    );
}

#[test]
fn metadata_comes_from_the_nearest_annotation() {
    let d = dir(&[
        (
            "s3.rego",
            "# METADATA\n# title: Package title\n# custom:\n#   id: PKG-1\n#   severity: low\n#   oxtf:\n#     resource_types: [aws_s3_bucket]\npackage demo.s3\n\nimport rego.v1\n\n# METADATA\n# title: Rule title\n# custom:\n#  id: RULE-1\n\ndeny contains \"x\" if {\n  # METADATA\n  # title: not an annotation\n  true\n}\n\nwarn contains \"w\" if true\n",
        ),
        (
            "legacy.rego",
            "package legacy\nimport rego.v1\n__rego_metadata__ := {\"id\": \"AVD-1\", \"title\": \"Legacy\", \"severity\": \"CRITICAL\"}\ndeny contains 1 if false\n",
        ),
    ]);
    let infos = load(
        &d,
        &["data.demo.s3.deny", "data.demo.s3.warn", "data.legacy.deny"],
    )
    .unwrap();
    let summary: Vec<_> = infos
        .iter()
        .map(|i| {
            (
                i.name.to_string(),
                i.level,
                i.description.to_string(),
                i.resource_types.clone(),
            )
        })
        .collect();
    let s3 = vec![Arc::<str>::from("aws_s3_bucket")];
    assert_eq!(
        summary,
        vec![
            ("RULE-1".into(), Level::Low, "Rule title".into(), s3.clone()),
            ("PKG-1".into(), Level::Low, "Package title".into(), s3),
            (
                "AVD-1".into(),
                Level::Critical,
                "Legacy".into(),
                vec![Arc::<str>::from(ANY_TYPE)]
            ),
        ]
    );
}

#[test]
fn structured_violations() {
    let v = regorus::Value::from_json_str(
            r#"["a", {"msg": "b", "x": 1}, 3, "", {"msg": "c", "address": "aws_s3_bucket.b", "path": "versioning[0].enabled", "fix": {"attribute": "acl", "value": "private"}}, {"msg": "d", "path": ["tags", "env"]}]"#,
        )
        .unwrap();
    // As Conftest reads results: non-string, non-object values and empty
    // messages are not violations.
    let got = violations(&v).unwrap();
    let msgs: Vec<_> = got.iter().map(|v| v.msg.as_str()).collect();
    assert_eq!(msgs, ["a", "b", "c", "d"]);
    let got = &got[1..];
    assert_eq!(got[1].fix, Some(("acl".into(), json!("private"))));
    assert_eq!(got[1].address.as_deref(), Some("aws_s3_bucket.b"));
    assert_eq!(
        got[1].path,
        Some(vec![
            Segment::Key("versioning".into()),
            Segment::Index(0),
            Segment::Key("enabled".into())
        ])
    );
    assert_eq!(
        got[2].path,
        Some(vec![
            Segment::Key("tags".into()),
            Segment::Key("env".into())
        ])
    );
    assert!(violations(&regorus::Value::Undefined).unwrap().is_empty());
    assert!(violations(&regorus::Value::from_json_str("\"x\"").unwrap()).is_err());
    for bad in [
        r#"[{"msg": "x", "address": 1}]"#,
        r#"[{"message": "no msg"}]"#,
        r#"[{"msg": "x", "fix": {"attribute": "a.b", "value": 1}}]"#,
    ] {
        assert!(
            violations(&regorus::Value::from_json_str(bad).unwrap()).is_err(),
            "{bad}"
        );
    }
    assert_eq!(
        parse_path("a[0][1].b"),
        Some(vec![
            Segment::Key("a".into()),
            Segment::Index(0),
            Segment::Index(1),
            Segment::Key("b".into())
        ])
    );
    assert_eq!(parse_path("a..b"), None);
    assert_eq!(parse_path("a[x]"), None);
}

/// Evaluates one policy file with `data.main.deny` as the entry.
fn eval_one(src: &str, input: Json, rego_v0: bool) -> Result<Vec<String>, String> {
    let d = dir(&[("p.rego", src)]);
    let paths = [d.path().to_path_buf()];
    let bundle = Bundle::load(&Options {
        paths: &paths,
        data: &[],
        namespaces: &[],
        all_namespaces: false,
        exclude: &[],
        entries: &[],
        shape: Shape::Plan,
        rego_v0,
    })?;
    let mut msgs: Vec<String> = violations(&eval(&bundle.engine, input, DEFAULT_ENTRY)?)?
        .into_iter()
        .map(|v| v.msg)
        .collect();
    msgs.sort();
    Ok(msgs)
}

/// regorus 0.12.0 differed from OPA 1.17.0 on these (loudly). The
/// regorus fork (FIRST_CLASS_RULES_PLAN.md, F3) fixes them; each
/// expected value is OPA's answer.
#[test]
fn former_regorus_divergences_match_opa() {
    // `some x in null` is undefined, not an error.
    let got = eval_one(
        "package main\nimport rego.v1\ndeny contains x if { some x in input.xs }\n",
        json!({"xs": null}),
        false,
    );
    assert_eq!(got, Ok(vec![]));
    // `%q` of a string is Go-quoted.
    let got = eval_one(
        "package main\nimport rego.v1\ndeny contains sprintf(\"%q\", [input.x]) if true\n",
        json!({"x": "a\"b"}),
        false,
    );
    assert_eq!(got, Ok(vec![r#""a\"b""#.to_string()]));
    // An import after rules applies to the whole module.
    let got = eval_one(
        "package main\nimport rego.v1\ndeny contains l.v if true\nimport input as l\n",
        json!({"v": "late"}),
        false,
    );
    assert_eq!(got, Ok(vec!["late".to_string()]));
    // A comprehension variable may be named like its function.
    let got = eval_one(
        "package main\nimport rego.v1\nf(xs) := [f | some f in xs]\ndeny contains \"hit\" if f([1]) == [1]\n",
        json!({}),
        false,
    );
    assert_eq!(got, Ok(vec!["hit".to_string()]));
    // A v0 rule with several bodies is several rules with one head.
    let got = eval_one(
        "package main\ndeny[x] { x := \"a\" } { x := \"b\" }\n",
        json!({}),
        true,
    );
    assert_eq!(got, Ok(vec!["a".to_string(), "b".to_string()]));
}

/// The fork still differs from OPA here, loudly: OPA formats `%q` of
/// any value, regorus only strings. When an upgrade fixes it, this
/// fails and the plan's gap list needs updating.
#[test]
fn known_regorus_divergences_fail_loudly() {
    let err = eval_one(
        "package main\nimport rego.v1\ndeny contains sprintf(\"%q\", [input.x]) if true\n",
        json!({"x": 1}),
        false,
    )
    .unwrap_err();
    assert!(err.contains("format verb q"), "{err}");
}

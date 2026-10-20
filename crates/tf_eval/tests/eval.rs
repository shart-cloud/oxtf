use tf_allocator::Allocator;
use tf_eval::{Evaluator, NoResolver, Scope, Value};
use tf_span::FileId;

fn ev(src: &str) -> Value {
    ev_with(src, &[])
}

fn ev_with(src: &str, bindings: &[(&str, Value)]) -> Value {
    let alloc = Allocator::new();
    let text = alloc.alloc_str(&format!("x = {src}\n"));
    let ret = tf_parser::parse(&alloc, text);
    assert!(ret.errors.is_empty(), "{:?}", ret.errors);
    let file = alloc.alloc(ret.file);
    let attr = file.body.attributes().next().unwrap();
    let r = NoResolver;
    Scope::EMPTY.with_all(bindings, |sc| {
        Evaluator::new(&r, FileId(0)).eval(&attr.value, sc)
    })
}

fn s(src: &str) -> String {
    ev(src).to_string()
}

#[test]
fn literals_and_ops() {
    assert_eq!(s("1 + 2 * 3"), "7");
    assert_eq!(s("\"a${1 + 1}b\""), "\"a2b\"");
    assert_eq!(s("true && !false"), "true");
    assert_eq!(s("[1, \"x\", null]"), "[1, \"x\", null]");
    assert_eq!(s("{ b = 1, a = \"z\" }"), "{a = \"z\", b = 1}");
    assert_eq!(s("1 == 1 ? \"y\" : \"n\""), "\"y\"");
    assert_eq!(s("[for x in [1,2,3] : x * 2 if x > 1]"), "[4, 6]");
    assert_eq!(
        s("{for k, v in {a = 1, b = 2} : v => k}"),
        "{1 = \"a\", 2 = \"b\"}"
    );
    assert_eq!(
        s("{for x in [\"a\", \"b\", \"a\"] : x => 1...}"),
        "{a = [1, 1], b = [1]}"
    );
    assert_eq!(s("[{a = 1}, {a = 2}][*].a"), "[1, 2]");
    assert_eq!(s("{a = [1, 2]}.a[1]"), "2");
}

#[test]
fn templates_strip_markers() {
    assert_eq!(s("\"a   ${~ \"b\" ~}   c\""), "\"abc\"");
    assert_eq!(
        s("<<EOT\n%{ for x in [1,2] ~}\n  ${x}\n%{~ endfor }\nEOT\n"),
        "\"12\\n\""
    );
    assert_eq!(s("\"%{ if true }yes%{ else }no%{ endif }\""), "\"yes\"");
    assert_eq!(s("\"${\"single\"}\""), "\"single\"");
}

#[test]
fn heredoc_and_json() {
    let v = ev("<<-EOF\n  {\"a\": [1]}\n  EOF\n");
    assert_eq!(v.to_string(), "\"{\\\"a\\\": [1]}\\n\"");
    assert_eq!(
        s("jsondecode(\"{\\\"a\\\": [1, true]}\")"),
        "{a = [1, true]}"
    );
    assert_eq!(
        ev("jsonencode({b = 1, a = [\"x\"]})")
            .to_str()
            .unwrap()
            .as_ref(),
        "{\"a\":[\"x\"],\"b\":1}"
    );
}

#[test]
fn functions() {
    assert_eq!(s("concat([1], [2, 3])"), "[1, 2, 3]");
    assert_eq!(s("merge({a = 1}, {b = 2}, {a = 3})"), "{a = 3, b = 2}");
    assert_eq!(s("lookup({a = 1}, \"b\", 5)"), "5");
    assert_eq!(s("format(\"%s:%d\", \"p\", 22)"), "\"p:22\"");
    assert_eq!(s("toset([\"b\", \"a\", \"b\"])"), "[\"a\", \"b\"]");
    assert_eq!(s("cidrsubnet(\"10.0.0.0/16\", 8, 1)"), "\"10.0.1.0/24\"");
    assert_eq!(s("length(flatten([[1], [2, [3]]]))"), "3");
    assert_eq!(s("coalesce(null, \"\", \"x\")"), "\"x\"");
    assert_eq!(s("try({}.missing, \"fallback\")"), "\"fallback\"");
    assert_eq!(s("can({}.missing)"), "false");
    assert_eq!(s("element([\"a\", \"b\"], 3)"), "\"b\"");
    assert_eq!(s("keys({b = 1, a = 2})"), "[\"a\", \"b\"]");
    assert_eq!(s("contains([\"a\"], \"a\")"), "true");
    assert_eq!(s("join(\",\", split(\"-\", upper(\"a-b\")))"), "\"A,B\"");
    assert_eq!(s("replace(lower(\"ABC\"), \"b\", \"x\")"), "\"axc\"");
    assert!(s("sha256(\"x\")").contains("unsupported function sha256"));
}

#[test]
fn sensitivity_survives_computation_without_changing_values() {
    for expression in [
        "upper(sensitive(\"secret\"))",
        "jsondecode(jsonencode({ x = sensitive(\"secret\") })).x",
        "sensitive(true) ? \"secret\" : \"public\"",
        "[for x in sensitive([\"secret\"]) : upper(x)][0]",
        "keys({ (sensitive(\"secret\")) = 1 })[0]",
        "length([for x in [1] : x if sensitive(false)])",
        "sensitive(4) * 2",
        "!sensitive(false)",
        "sensitive(false) && true",
        "can(sensitive(\"secret\"))",
        "length(sensitive([])[*])",
        "length(sensitive(null)[*])",
        "try(tonumber(sensitive(\"secret\")), \"fallback\")",
        "(flag ? \"secret\" : sensitive(\"secret\"))",
    ] {
        let v = ev_with(expression, &[("flag", Value::tainted("flag"))]);
        assert!(v.is_sensitive(), "{expression}: {v:?}");
        assert_eq!(v.to_string(), "(sensitive)", "{expression}");
    }
    let secret = ev("upper(sensitive(\"secret\"))");
    assert_eq!(secret.as_str(), Some("SECRET"));
    let clear = ev("nonsensitive({ x = sensitive(\"secret\") }).x");
    assert!(!clear.is_sensitive());
    assert_eq!(clear.as_str(), Some("secret"));
}

// Regressions from the final code review.

#[test]
fn attr_splat_carries_only_attribute_accesses() {
    // `.*` applies only the following `.attr`s per element; `[0]` indexes the result.
    assert_eq!(s("[{a = [1, 2]}, {a = [3, 4]}].*.a[0]"), "[1, 2]");
    // `[*]` carries every following operator.
    assert_eq!(s("[{a = [1, 2]}, {a = [3, 4]}][*].a[0]"), "[1, 3]");
}

#[test]
fn parseint_rejects_bad_base_without_panicking() {
    assert!(ev("parseint(\"10\", 1)").is_error());
    assert!(ev("parseint(\"10\", 0)").is_error());
    assert!(ev("parseint(\"10\", 37)").is_error());
    assert_eq!(s("parseint(\"ff\", 16)"), "255");
}

#[test]
fn split_empty_string_is_one_empty_element() {
    assert_eq!(s("split(\",\", \"\")"), "[\"\"]");
    assert_eq!(s("length(split(\",\", \"\"))"), "1");
}

#[test]
fn cidr_functions_follow_terraform() {
    // Allocation starts at the network address, not the host address.
    assert_eq!(s("cidrsubnets(\"10.1.2.3/16\", 8)"), "[\"10.1.0.0/24\"]");
    // Running out of space inside the prefix is an error, not a subnet outside it.
    assert!(ev("cidrsubnets(\"10.0.0.0/24\", 1, 1, 1)").is_error());
    assert_eq!(
        s("cidrsubnets(\"10.0.0.0/24\", 1, 1)"),
        "[\"10.0.0.0/25\", \"10.0.0.128/25\"]"
    );
    // A huge negative host number is out of range, not an overflow panic.
    assert!(ev("cidrhost(\"10.0.0.0/8\", -1e40)").is_error());
    assert_eq!(s("cidrhost(\"10.0.0.0/8\", -1)"), "\"10.255.255.255\"");
}

#[test]
fn uncertain_filters_preserve_collection_membership() {
    for (condition, tainted) in [
        (Value::tainted("enabled"), true),
        (Value::other("computed"), false),
    ] {
        for expression in [
            "length([for x in [1] : x if enabled])",
            "length({for x in [1] : tostring(x) => x if enabled})",
            "length(lookup({for x in [1] : \"group\" => x... if enabled}, \"group\", []))",
        ] {
            let v = ev_with(expression, &[("enabled", condition.clone())]);
            let tf_eval::Kind::OneOf(o) = &v.kind else {
                panic!("{expression}: expected lengths 0 and 1, got {v}");
            };
            assert_eq!(o.tainted, tainted, "{expression}");
            let mut lengths: Vec<_> = o
                .alternatives
                .iter()
                .map(|a| a.as_number().unwrap() as i64)
                .collect();
            lengths.sort();
            assert_eq!(lengths, [0, 1], "{expression}");
        }
    }
    // Null is an element, not an absent element.
    assert_eq!(s("length([for x in [1] : null if true])"), "1");
    assert_eq!(s("length([for x in [1] : null if false])"), "0");
    // A known member remains present in every alternative.
    assert_eq!(
        ev_with(
            "contains([for x in [1, 2] : x if x == 1 || enabled], 1)",
            &[("enabled", Value::tainted("enabled"))]
        )
        .as_bool(),
        Some(true)
    );
}

#[test]
fn uncertain_filter_expansion_is_bounded_without_claiming_a_known_length() {
    for condition in [Value::tainted("enabled"), Value::other("computed")] {
        let v = ev_with(
            "length([for x in range(100) : x if enabled])",
            &[("enabled", condition.clone())],
        );
        assert!(!v.is_known(), "{v}");
        assert_eq!(v.is_tainted(), condition.is_tainted(), "{v}");
    }
}

#[test]
fn try_uses_the_fallback_only_for_failing_alternatives() {
    for (condition, tainted) in [
        (Value::tainted("enabled"), true),
        (Value::other("computed"), false),
    ] {
        for expression in [
            "try((enabled ? { encrypted = true } : {}).encrypted, false)",
            "try([ (enabled ? { encrypted = true } : {}).encrypted ], [false])[0]",
            "try({ encrypted = (enabled ? { encrypted = true } : {}).encrypted }, {encrypted = false}).encrypted",
            "jsondecode(try(jsonencode({ encrypted = (enabled ? { encrypted = true } : {}).encrypted }), jsonencode({encrypted = false}))).encrypted",
            "try((enabled ? { encrypted = true } : {}).encrypted, {}.missing, false)",
        ] {
            let v = ev_with(expression, &[("enabled", condition.clone())]);
            let tf_eval::Kind::OneOf(o) = &v.kind else {
                panic!("{expression}: expected true and false, got {v}");
            };
            assert_eq!(o.tainted, tainted, "{expression}");
            let mut values: Vec<_> = o
                .alternatives
                .iter()
                .map(|a| a.as_bool().unwrap())
                .collect();
            values.sort();
            assert_eq!(values, [false, true], "{expression}");
        }
    }
    assert!(ev("try({}.a, {}.b)").is_error());
    assert!(ev_with("try(input, false)", &[("input", Value::other("computed"))]).is_unknown());
    // A certain error in a sibling invalidates the entire argument.
    assert_eq!(
        ev_with(
            "try([(enabled ? {x = true} : {}).x, {}.missing], false)",
            &[("enabled", Value::tainted("enabled"))]
        )
        .as_bool(),
        Some(false)
    );

    // Unrelated taint in a successful field must not make a provider-driven
    // failure/fallback choice conditional on a user-controlled variable.
    let v = ev_with(
        "try({unrelated = enabled ? true : false, encrypted = (computed ? {x = true} : {}).x}, {unrelated = true, encrypted = false}).encrypted",
        &[
            ("enabled", Value::tainted("enabled")),
            ("computed", Value::other("computed")),
        ],
    );
    let tf_eval::Kind::OneOf(o) = &v.kind else {
        panic!("{v}")
    };
    assert!(!o.tainted, "{v}");
}

#[test]
fn try_evaluates_a_needed_fallback_once_and_skips_unneeded_ones() {
    struct Fallback(std::cell::Cell<usize>);
    impl<'a> tf_eval::Resolver<'a> for Fallback {
        fn resolve(
            &self,
            _: &Evaluator<'_, 'a>,
            _: Scope<'_>,
            root: &'a str,
            _: tf_span::Span,
            _: &'a [tf_ast::TraversalOperator<'a>],
        ) -> (Value, usize) {
            assert_eq!(root, "fallback");
            self.0.set(self.0.get() + 1);
            (Value::bool(false), 0)
        }
    }
    for (expression, calls) in [
        ("try(true, fallback)", 0),
        ("try((enabled ? {x = true} : {}).x, fallback, fallback)", 1),
    ] {
        let alloc = Allocator::new();
        let text = alloc.alloc_str(&format!("x = {expression}\n"));
        let ret = tf_parser::parse(&alloc, text);
        assert!(ret.errors.is_empty());
        let file = alloc.alloc(ret.file);
        let attr = file.body.attributes().next().unwrap();
        let r = Fallback(std::cell::Cell::new(0));
        Scope::EMPTY.with("enabled", &Value::tainted("enabled"), |sc| {
            Evaluator::new(&r, FileId(0)).eval(&attr.value, sc)
        });
        assert_eq!(r.0.get(), calls, "{expression}");
    }
}

#[test]
fn regex_functions_preserve_capture_shapes_and_replacement_semantics() {
    assert_eq!(
        s(r#"replace("policy-name!", "/[^0-9A-Za-z]*/", "")"#),
        "\"policyname\""
    );
    assert_eq!(
        s(r#"replace("a1 b2", "/([a-z])([0-9])/", "$2-$1")"#),
        "\"1-a 2-b\""
    );
    assert_eq!(
        s(r#"regex("projects/([^/]+)/", "projects/example/global/networks/n")"#),
        "[\"example\"]"
    );
    assert_eq!(
        s(r#"regex("(?P<key>[a-z]+)=(?P<value>[0-9]+)", "x=12")"#),
        "{key = \"x\", value = \"12\"}"
    );
    assert_eq!(s(r#"regex("[a-z]+", "123abc")"#), "\"abc\"");
    assert_eq!(s(r#"can(regex("(?P<n>a)(b)", "ab"))"#), "false");
    assert_eq!(s(r#"can(regex("x", "abc"))"#), "false");
    assert_eq!(s(r#"can(regex("\\d", "٣"))"#), "false");
    assert_eq!(s(r#"regex("\\Q(a)\\E", "(a)")"#), "\"(a)\"");
    assert!(ev(r#"regex("(.)", sensitive("secret"))"#).is_sensitive());
}

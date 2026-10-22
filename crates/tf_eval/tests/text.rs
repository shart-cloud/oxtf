use std::sync::Arc;

use tf_allocator::Allocator;
use tf_eval::{EvaluationBudget, Evaluator, NoResolver, Origin, Scope, Value, functions, text};
use tf_limits::{Limits, Resource, input::InputBudget};
use tf_span::FileId;

fn evaluate(source: &str, budget: &EvaluationBudget) -> Value {
    let alloc = Allocator::new();
    let (expr, errors) = tf_parser::parse_expression(&alloc, source);
    assert!(errors.is_empty(), "{errors:?}");
    Evaluator::with_budget(&NoResolver, FileId(0), budget).eval(&expr.unwrap(), Scope::EMPTY)
}

#[test]
fn exact_boundaries_cover_literals_templates_and_text_functions() {
    for source in [
        r#""abc""#,
        r#"{ "key" = "value" }"#,
        r#""hello ${"世界"}!""#,
        r#""%{ for x in [1, 2, 3] }${x}%{ endfor }""#,
        r#"replace("aaa", "a", "bbbb")"#,
        r#"replace("aaa", "", "-界-")"#,
        r#"replace("aa", "/(a)/", "$1$1")"#,
        r#"join("-", ["a", "b", "c"])"#,
        r#"format("%q %.8f %v", "hello", 3, {x = [1, 2]})"#,
        r#"formatlist("%s%s", ["a", "b"], "long")"#,
        r#"lower("ΟΣ İẞ")"#,
        r#"upper("ßi")"#,
        r#"title("ß i")"#,
        r#"base64encode("hello 世界")"#,
        r#"base64decode("aGVsbG8=")"#,
        r#"urlencode("世界 ?")"#,
        r#"split("", "世界")"#,
        r#"substr("世界abc", -3, 2)"#,
        r#"regex("(?P<name>[a-z]+)", "abc")"#,
        r#"indent(3, "a\nb\n")"#,
        r#"jsondecode("{\"key\": [\"value\", 1]}")"#,
        r#""${jsonencode({ x = jsonencode([1, "hello"]) })}""#,
    ] {
        let baseline = EvaluationBudget::new(Limits::default());
        let expected = evaluate(source, &baseline);
        assert!(
            !tf_eval::eval::contains_error(&expected),
            "{source}: {expected:?}"
        );
        assert!(baseline.first_limit().is_none(), "{source}: {expected:?}");
        let cost = baseline.storage().stats().text_bytes;
        assert!(cost > 0);
        for allowance in [cost - 1, cost, cost + 1] {
            let budget =
                EvaluationBudget::new(Limits::default().with_text_bytes(allowance).unwrap());
            let actual = evaluate(source, &budget);
            if allowance < cost {
                assert!(
                    matches!(actual.origin(), Some(Origin::Limit(_))),
                    "{source}: {actual:?}"
                );
                assert_eq!(
                    budget.storage().exhaustion().unwrap().resource,
                    Resource::TextBytes
                );
            } else {
                assert_eq!(
                    tf_eval::value::to_json(&actual),
                    tf_eval::value::to_json(&expected),
                    "{source}"
                );
                assert!(budget.first_limit().is_none());
            }
            assert!(budget.storage().stats().text_bytes <= allowance);
        }
    }
}

#[test]
fn text_refusal_is_shared_sticky_and_cannot_be_caught_or_discarded() {
    for source in [
        r#"try(replace("aa", "a", "verylong"), "fallback")"#,
        r#"can(replace("aa", "a", "verylong"))"#,
        r#"length([replace("aa", "a", "verylong")])"#,
        r#"format("%.184467440737095516160f", 1)"#,
        r#"jsonencode(jsonencode(jsonencode("abcdefghijk"))) == "x""#,
    ] {
        let budget = EvaluationBudget::new(Limits::default().with_text_bytes(32).unwrap());
        let value = evaluate(source, &budget);
        assert!(
            matches!(value.origin(), Some(Origin::Limit(_))),
            "{source}: {value:?}"
        );
        assert!(matches!(
            evaluate("1", &budget).origin(),
            Some(Origin::Limit(_))
        ));
    }
    let storage = Arc::new(InputBudget::new(
        Limits::default().with_text_bytes(5).unwrap(),
    ));
    for (source, limited) in [(r#""abc""#, false), (r#""abc""#, true)] {
        let budget = EvaluationBudget::with_storage(
            Limits::default(),
            Resource::EvaluationSteps,
            storage.clone(),
        );
        let value = evaluate(source, &budget);
        assert_eq!(matches!(value.origin(), Some(Origin::Limit(_))), limited);
    }
}

#[test]
fn refusal_retains_sensitivity_dependencies_and_prior_errors() {
    use tf_eval::prov::{Prov, ResourceDependency};
    let input = Value::string("aa")
        .sensitive()
        .with_prov(Prov::EMPTY.referencing(vec![ResourceDependency {
            resource: "test_node.origin".into(),
            key: None,
            certainty: tf_eval::Truth::True,
        }]));
    let budget = InputBudget::new(Limits::default().with_text_bytes(2).unwrap());
    let value = functions::call_budgeted(
        "replace",
        vec![input, Value::string("a"), Value::string("long")],
        &budget,
    );
    assert!(matches!(value.origin(), Some(Origin::Limit(_))));
    assert!(value.is_sensitive());
    assert_eq!(value.prov.dependencies().len(), 1);
    assert_eq!(
        value.prov.dependencies()[0].certainty,
        tf_eval::Truth::Unknown
    );
    let budget = EvaluationBudget::new(Limits::default().with_text_bytes(4).unwrap());
    let value = evaluate(r#"[missing, "too long"]"#, &budget);
    assert!(tf_eval::eval::contains_error(&value));
    assert!(budget.is_exhausted());
}

#[test]
fn borrowed_json_serialization_preserves_existing_encodings() {
    for value in [
        Value::number(-0.0),
        Value::number(1e16),
        Value::number(1.25),
        Value::string("\"\n世界"),
        Value::json(Value::list(vec![Value::bool(true), Value::null()])),
    ] {
        let expected = tf_eval::value::to_json(&value).unwrap().to_string();
        assert_eq!(
            &*text::json(&value, &InputBudget::default()).unwrap(),
            expected
        );
    }
    assert_eq!(
        functions::call("lower", vec![Value::string("ΟΣ")])
            .as_str()
            .unwrap(),
        "ος"
    );
}

#[test]
fn concurrent_text_builders_cannot_overbook_and_drop_does_not_refund() {
    let budget = InputBudget::new(Limits::default().with_text_bytes(4).unwrap());
    let accepted = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| text::copy("four", &budget).is_ok()))
            .collect();
        threads
            .into_iter()
            .map(|t| t.join().unwrap() as usize)
            .sum::<usize>()
    });
    assert_eq!(accepted, 1);
    assert_eq!(budget.stats().text_bytes, 4);
    assert!(text::copy("", &budget).is_err());
}

#[test]
fn nested_json_text_stops_on_a_bounded_stack() {
    let mut value = Value::number(0.0);
    for _ in 0..256 {
        value = Value::list(vec![value]);
    }
    let stopped = text::json(&value, &InputBudget::default()).unwrap_err();
    assert!(matches!(stopped.origin(), Some(Origin::Limit(_))));
}

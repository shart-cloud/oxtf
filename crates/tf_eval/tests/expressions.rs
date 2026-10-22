use std::cell::Cell;
use std::mem::size_of;
use std::sync::Arc;

use tf_allocator::Allocator;
use tf_ast::TraversalOperator;
use tf_eval::{EvaluationBudget, Evaluator, Kind, NoResolver, Origin, Resolver, Scope, Value};
use tf_limits::{Limits, Resource};
use tf_span::{FileId, Span};

fn budget(bytes: u64) -> EvaluationBudget {
    EvaluationBudget::new(Limits::default().with_collection_bytes(bytes).unwrap())
}

fn evaluate(source: &str, budget: &EvaluationBudget, bindings: &[(&str, Value)]) -> Value {
    let arena = Allocator::new();
    let (expression, errors) = tf_parser::parse_expression(&arena, source);
    assert!(errors.is_empty(), "{source}: {errors:?}");
    let expression = expression.unwrap();
    Scope::EMPTY.with_all(bindings, |scope| {
        Evaluator::with_budget(&NoResolver, FileId(0), budget).eval(&expression, scope)
    })
}

fn limited(value: &Value, budget: &EvaluationBudget) {
    assert!(
        matches!(value.origin(), Some(Origin::Limit(_))),
        "{value:?}"
    );
    assert_eq!(
        budget.storage().exhaustion().unwrap().resource,
        Resource::CollectionBytes
    );
    assert!(budget.first_limit().is_some());
}

#[test]
fn expression_builders_obey_exact_boundaries() {
    let bindings = [
        ("flag", Value::tainted("flag")),
        (
            "choice",
            Value::one_of(vec![Value::number(1.0), Value::number(2.0)], false),
        ),
        (
            "items",
            Value::one_of(
                vec![
                    Value::list(vec![Value::number(1.0)]),
                    Value::list(vec![Value::number(2.0)]),
                ],
                false,
            ),
        ),
    ];
    for source in [
        "[1, 2, [3]]",
        "{a = 1, b = [2]}",
        "{a = 1, a = 2}",
        "[for x in [1, 2] : [x, x]]",
        "[for k, v in {a = 1} : [k, v]]",
        "{for x in [1, 2] : x => x}",
        "{for x in [1, 2, 1] : x => x...}",
        "[for x in [1, 2] : x if flag]",
        "{for x in [1, 2] : x => x... if flag}",
        "[for x in items : x]",
        "[for x in [] : x]",
        "[{a = 1}, {a = 2}][*].a",
        "[{a = [1]}].*.a[0]",
        "1[*]",
        "items[*]",
        "max(1, 2)",
        "max(0, [1, 2, 3]...)",
        "flag ? [1] : [2]",
        "-choice",
        "choice + choice",
        "items[choice - 1]",
        "(flag ? {a=1} : {a=2}).a",
        "try([1, 2], [])",
        "try({a = 1}, {})",
        "try(jsonencode([1]), null)",
        "try(flag ? {a = 1} : {a = {}.missing}, {a = 2})",
        r#""a${choice}b""#,
        r#""%{ for k, v in {a = 1, b = 2} }${k}${v}%{ endfor }""#,
        r#""%{ for x in [1,2] }${x}%{ endfor }""#,
    ] {
        let baseline = budget(Limits::default().collection_bytes());
        let expected = evaluate(source, &baseline, &bindings);
        assert!(baseline.first_limit().is_none(), "{source}: {expected:?}");
        let cost = baseline.storage().stats().collection_bytes;
        assert!(cost > 1, "{source}");
        for allowance in [cost - 1, cost, cost + 1] {
            let budget = budget(allowance);
            let actual = evaluate(source, &budget, &bindings);
            if allowance < cost {
                // Some try alternatives have an established error when refusal occurs.
                assert!(
                    matches!(actual.origin(), Some(Origin::Limit(_)))
                        || tf_eval::eval::contains_error(&actual),
                    "{source}: {actual:?}"
                );
                assert!(budget.storage().exhaustion().is_some(), "{source}");
            } else {
                assert_eq!(format!("{actual:?}"), format!("{expected:?}"), "{source}");
                assert!(budget.first_limit().is_none(), "{source}");
            }
            assert!(budget.storage().stats().collection_bytes <= allowance);
        }
    }
}

#[derive(Default)]
struct Probe {
    references: Cell<usize>,
    calls: Cell<usize>,
}

impl<'a> Resolver<'a> for Probe {
    fn resolve(
        &self,
        _: &Evaluator<'_, 'a>,
        _: Scope<'_>,
        _: &'a str,
        _: Span,
        _: &'a [TraversalOperator<'a>],
    ) -> (Value, usize) {
        self.references.set(self.references.get() + 1);
        (Value::number(1.0), 0)
    }
    fn call(&self, _: &str, _: Vec<Value>, _: &EvaluationBudget) -> Value {
        self.calls.set(self.calls.get() + 1);
        Value::null()
    }
}

#[test]
fn admission_precedes_child_evaluation_and_function_dispatch() {
    for source in [
        "[probe, probe]",
        "{a = probe}",
        "custom(probe, probe)",
        "items[*][probe]",
        "custom(items...)",
        "[for x in items : probe]",
        "flag ? probe : probe",
    ] {
        let arena = Allocator::new();
        let (expression, errors) = tf_parser::parse_expression(&arena, source);
        assert!(errors.is_empty());
        let expression = expression.unwrap();
        let probe = Probe::default();
        let budget = budget(32);
        let bindings = [
            ("items", Value::list(vec![Value::null(); 1000])),
            ("flag", Value::tainted("flag")),
        ];
        let value = Scope::EMPTY.with_all(&bindings, |scope| {
            Evaluator::with_budget(&probe, FileId(0), &budget).eval(&expression, scope)
        });
        limited(&value, &budget);
        assert_eq!(probe.references.get(), 0, "{source}");
        assert_eq!(probe.calls.get(), 0, "{source}");
    }
}

#[test]
fn literal_costs_and_static_defaults_share_the_budget() {
    for (source, cost) in [
        ("[1, 2]", 2 * size_of::<Value>()),
        ("{a=1, a=2}", size_of::<(Arc<str>, Value)>()),
    ] {
        let arena = Allocator::new();
        let (expression, errors) = tf_parser::parse_expression(&arena, source);
        assert!(errors.is_empty());
        let expression = expression.unwrap();
        for allowance in [cost - 1, cost, cost + 1] {
            let budget = budget(allowance as u64);
            let evaluator = Evaluator::with_budget(&NoResolver, FileId(0), &budget);
            let value = evaluator.eval_static(&expression);
            if allowance < cost {
                limited(&value, &budget);
            } else {
                assert!(value.is_known());
                assert_eq!(budget.storage().stats().collection_bytes, cost as u64);
                limited(&evaluator.eval(&expression, Scope::EMPTY), &budget);
            }
        }
    }
}

#[test]
fn every_comprehension_copy_boundary_keeps_marks_and_dependency_uncertainty() {
    use tf_eval::prov::{Prov, ResourceDependency};
    let input = Value::list(vec![Value::number(1.0), Value::number(2.0)])
        .sensitive()
        .with_prov(Prov::EMPTY.referencing(vec![ResourceDependency {
            resource: "test_node.origin".into(),
            key: None,
            certainty: tf_eval::Truth::True,
        }]));
    let bindings = [("items", input), ("flag", Value::tainted("flag"))];
    for source in [
        "items[*]",
        "custom(items...)",
        "try(items, [])",
        "[for x in items : x if flag]",
        "{for x in items : x => x... if flag}",
        r#""%{ for x in items }${x}%{ endfor }""#,
    ] {
        let baseline = EvaluationBudget::new(Limits::default());
        evaluate(source, &baseline, &bindings);
        let cost = baseline.storage().stats().collection_bytes;
        for allowance in 1..cost {
            // The first argument slot can fail before the input is observed.
            if source.starts_with("custom") && allowance < size_of::<Value>() as u64 {
                continue;
            }
            if source.starts_with("try") && allowance < size_of::<Value>() as u64 {
                continue;
            }
            let budget = budget(allowance);
            let value = evaluate(source, &budget, &bindings);
            limited(&value, &budget);
            assert!(value.is_sensitive(), "{source}, {allowance}");
            assert_eq!(value.prov.dependencies().len(), 1, "{source}, {allowance}");
            assert_eq!(
                value.prov.dependencies()[0].certainty,
                tf_eval::Truth::Unknown,
                "{source}, {allowance}"
            );
        }
    }
}

#[test]
fn catches_discarded_values_and_later_evaluators_cannot_clear_refusal() {
    for source in [
        "try([1,2], [])",
        "can([1,2])",
        "length([1,2])",
        "[for x in [1,2] : [x,x]]",
        "[1,2][*]",
    ] {
        let budget = budget(32);
        limited(&evaluate(source, &budget, &[]), &budget);
        limited(&evaluate("1", &budget, &[]), &budget);
    }
    for source in [
        "{a=missing,b=[1,2]}",
        "[missing, [1,2]]",
        "custom(missing,[1,2])",
    ] {
        let budget = budget(100);
        let value = evaluate(source, &budget, &[]);
        assert!(tf_eval::eval::contains_error(&value), "{source}: {value:?}");
        assert!(budget.first_limit().is_some());
    }
}

#[test]
fn empty_alternatives_and_short_circuits_preserve_behavior() {
    let bindings = [
        ("empty", Value::one_of(vec![], false)),
        ("flag", Value::bool(true)),
    ];
    for source in [
        "empty[*]",
        "[for x in empty : x]",
        "empty + 1",
        "-empty",
        "empty.a",
    ] {
        let value = evaluate(source, &budget(1), &bindings);
        assert!(
            matches!(&value.kind, Kind::OneOf(o) if o.alternatives.is_empty()),
            "{source}"
        );
    }
    assert_eq!(
        evaluate("flag ? 1 : [1,2]", &budget(1), &bindings).as_number(),
        Some(1.0)
    );
}

#[test]
fn builder_errors_retain_their_original_explanation() {
    for (source, message) in [
        ("[for x in 1 : x]", "for: collection is not iterable"),
        (
            r#""%{ if 1 }yes%{ endif }""#,
            "template if: condition is not a bool",
        ),
    ] {
        let budget = EvaluationBudget::new(Limits::default());
        let value = evaluate(source, &budget, &[]);
        assert!(
            matches!(value.origin(), Some(Origin::Error(error)) if &**error == message),
            "{source}: {value:?}"
        );
        assert!(budget.first_limit().is_none());
    }
    let budget = budget(60);
    let value = evaluate("{a = missing, b = [1,2]}", &budget, &[]);
    assert!(matches!(value.origin(), Some(Origin::Error(message))
        if &**message == "reference to \"missing\" not allowed here"));
    assert!(budget.first_limit().is_some());
}

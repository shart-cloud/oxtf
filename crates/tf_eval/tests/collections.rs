use std::cell::Cell;
use std::sync::Arc;

use tf_allocator::Allocator;
use tf_eval::{
    EvaluationBudget, Evaluator, NoResolver, Origin, Scope, Value, collections, functions,
};
use tf_limits::{Limits, Resource, input::InputBudget};
use tf_span::FileId;

fn evaluate(source: &str, budget: &EvaluationBudget) -> Value {
    let alloc = Allocator::new();
    let (expr, errors) = tf_parser::parse_expression(&alloc, source);
    assert!(errors.is_empty(), "{errors:?}");
    Evaluator::with_budget(&NoResolver, FileId(0), budget).eval(&expr.unwrap(), Scope::EMPTY)
}

#[test]
fn builtin_boundaries_cover_collections_and_scratch() {
    for source in [
        "concat([1, 2], [3])",
        "merge({a = 1}, {a = 2, b = 3})",
        "keys({a = 1, b = 2})",
        "values({a = 1, b = 2})",
        "flatten([[1, [2]], [3]])",
        "distinct([1, 2, 1])",
        "toset([3, 2, 1, 2])",
        r#"compact(["a", "", null, "b"])"#,
        "reverse([1, 2, 3])",
        "slice([1, 2, 3], 1, 3)",
        r#"sort(["c", "a", "b"])"#,
        "range(3)",
        r#"zipmap(["a", "b"], [1, 2])"#,
        "chunklist([1, 2, 3], 2)",
        "chunklist([1, 2], 0)",
        "setunion([1, 2], [2, 3])",
        "setintersection([1, 2], [2, 3])",
        "setsubtract([1, 2], [2, 3])",
        "setproduct([1, 2], [3, 4])",
        "matchkeys([1, 2, 3], [1, 2, 3], [2, 3])",
        r#"transpose({a = ["x", "y"], b = ["x"]})"#,
        r#"split("", "世界")"#,
        r#"formatlist("%s", ["a", "b"])"#,
        "nonsensitive(sensitive({a = [1, 2]}))",
        r#"jsondecode("{\"a\": [1, 2]}")"#,
        r#"cidrsubnets("10.0.0.0/16", 8, 8)"#,
        r#"regex("(a)(b)", "ab")"#,
        r#"regex("(?P<a>a)(?P<b>b)", "ab")"#,
        "max(1, 2, 3)",
    ] {
        let baseline = EvaluationBudget::new(Limits::default());
        let expected = evaluate(source, &baseline);
        assert!(expected.is_known(), "{source}: {expected:?}");
        assert!(baseline.first_limit().is_none(), "{source}");
        let cost = baseline.storage().stats().collection_bytes;
        assert!(cost > 1, "{source}");
        for allowance in [cost - 1, cost, cost + 1] {
            let budget =
                EvaluationBudget::new(Limits::default().with_collection_bytes(allowance).unwrap());
            let actual = evaluate(source, &budget);
            if allowance < cost {
                assert!(
                    matches!(actual.origin(), Some(Origin::Limit(_))),
                    "{source}: {actual:?}"
                );
                assert_eq!(
                    budget.storage().exhaustion().unwrap().resource,
                    Resource::CollectionBytes
                );
            } else {
                assert_eq!(
                    tf_eval::value::to_json(&actual),
                    tf_eval::value::to_json(&expected),
                    "{source}"
                );
                assert!(budget.first_limit().is_none());
            }
            assert!(budget.storage().stats().collection_bytes <= allowance);
        }
    }
}

#[test]
fn refusal_is_sticky_across_evaluators_catches_and_discarded_values() {
    for source in ["try(range(3), [])", "can(range(3))", "length([range(3)])"] {
        let storage = Arc::new(InputBudget::new(
            Limits::default().with_collection_bytes(32).unwrap(),
        ));
        for source in [source, "1"] {
            let budget = EvaluationBudget::with_storage(
                Limits::default(),
                Resource::EvaluationSteps,
                storage.clone(),
            );
            assert!(
                matches!(evaluate(source, &budget).origin(), Some(Origin::Limit(_))),
                "{source}"
            );
        }
    }
}

#[test]
fn exact_size_construction_refuses_before_visiting_elements() {
    let budget = InputBudget::new(Limits::default().with_collection_bytes(31).unwrap());
    let visits = Cell::new(0);
    let values = collections::collect(
        (0..1000).map(|_| {
            visits.set(visits.get() + 1);
            Value::null()
        }),
        &budget,
    );
    assert!(values.is_err());
    assert_eq!(visits.get(), 0);
    assert_eq!(budget.stats().collection_bytes, 0);
    assert!(collections::admit::<Value>(usize::MAX, &InputBudget::default()).is_err());
}

#[test]
fn alternatives_share_admission_and_keep_order_and_marks() {
    let alternatives =
        || Value::one_of(vec![Value::number(1.0), Value::number(2.0)], true).sensitive();
    let budget = InputBudget::default();
    let seen = std::cell::RefCell::new(Vec::new());
    let result = functions::call_with_budget(
        "custom",
        vec![alternatives(), alternatives()],
        &budget,
        &|_, args| {
            let pair = (args[0].as_number().unwrap(), args[1].as_number().unwrap());
            seen.borrow_mut().push(pair);
            Value::number(10.0 * pair.0 + pair.1)
        },
    );
    assert_eq!(
        *seen.borrow(),
        [(1.0, 1.0), (1.0, 2.0), (2.0, 1.0), (2.0, 2.0)]
    );
    assert!(result.is_sensitive());
    assert!(matches!(&result.kind, tf_eval::Kind::OneOf(o) if o.tainted));
    let budget = InputBudget::new(Limits::default().with_collection_bytes(1).unwrap());
    let calls = Cell::new(0);
    let refused = functions::call_with_budget("custom", vec![alternatives()], &budget, &|_, _| {
        calls.set(calls.get() + 1);
        Value::null()
    });
    assert!(matches!(refused.origin(), Some(Origin::Limit(_))));
    assert!(refused.is_sensitive());
    assert_eq!(calls.get(), 0);
    let empty = functions::call("reverse", vec![Value::one_of(vec![], true)]);
    assert!(
        matches!(&empty.kind, tf_eval::Kind::OneOf(o) if o.alternatives.is_empty() && !o.tainted)
    );
}

#[test]
fn refusal_preserves_uncertain_dependencies_and_existing_errors() {
    use tf_eval::prov::{Prov, ResourceDependency};
    let input =
        Value::list(vec![Value::number(1.0)])
            .sensitive()
            .with_prov(Prov::EMPTY.referencing(vec![ResourceDependency {
                resource: "test_node.origin".into(),
                key: None,
                certainty: tf_eval::Truth::True,
            }]));
    let budget = InputBudget::new(Limits::default().with_collection_bytes(1).unwrap());
    let result = functions::call_budgeted("reverse", vec![input], &budget);
    assert!(matches!(result.origin(), Some(Origin::Limit(_))));
    assert!(result.is_sensitive());
    assert_eq!(result.prov.dependencies().len(), 1);
    assert_eq!(
        result.prov.dependencies()[0].certainty,
        tf_eval::Truth::Unknown
    );
    let budget = InputBudget::new(Limits::default().with_collection_bytes(1).unwrap());
    let result = functions::call_with_budget("custom", vec![], &budget, &|_, _| {
        let _ = budget.admit_collection(2);
        Value::error("established failure")
    });
    assert!(result.is_error());
    assert!(budget.exhaustion().is_some());
}

#[test]
fn a_later_alternative_cannot_erase_an_established_error() {
    let choices = Value::one_of(vec![Value::number(1.0), Value::number(2.0)], false);
    let budget = InputBudget::new(Limits::default().with_collection_bytes(1_000).unwrap());
    let result = functions::call_with_budget("custom", vec![choices], &budget, &|_, args| {
        if args[0].as_number() == Some(1.0) {
            Value::error("first alternative failed")
        } else {
            let _ = budget.admit_collection(1_001);
            Value::null()
        }
    });
    assert!(result.is_error());
    assert!(budget.exhaustion().is_some());
}

#[test]
fn collection_walks_bound_depth_before_recursive_copying() {
    for depth in [127, 129] {
        let mut value = Value::number(1.0).sensitive();
        for _ in 0..depth {
            value = Value::list(vec![value]);
        }
        for name in ["flatten", "nonsensitive"] {
            let result = functions::call(name, vec![value.clone()]);
            if depth == 127 {
                assert!(result.is_known(), "{name}");
            } else {
                assert!(matches!(result.origin(), Some(Origin::Limit(_))), "{name}");
                assert!(result.is_sensitive());
            }
        }
    }
}

#[test]
fn map_replacement_and_shared_backing_do_not_charge_new_slots() {
    let input = Value::object([(Arc::from("a"), Value::number(1.0))].into());
    let budget = InputBudget::default();
    let result = functions::call_budgeted("merge", vec![input.clone(), input.clone()], &budget);
    assert!(result.is_known());
    assert_eq!(
        budget.stats().collection_bytes,
        std::mem::size_of::<(Arc<str>, Value)>() as u64
    );
    let before = budget.stats();
    let shared = functions::call_budgeted("tomap", vec![input.clone()], &budget);
    assert_eq!(before, budget.stats());
    let (
        tf_eval::Kind::Known(tf_eval::Known::Object(a)),
        tf_eval::Kind::Known(tf_eval::Known::Object(b)),
    ) = (input.kind, shared.kind)
    else {
        panic!("expected objects");
    };
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn concurrent_collection_reservations_cannot_overbook() {
    let budget = InputBudget::new(Limits::default().with_collection_bytes(32).unwrap());
    let admitted = std::thread::scope(|scope| {
        let attempts: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| budget.admit_collection(16)))
            .collect();
        attempts
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(Result::is_ok)
            .count()
    });
    assert_eq!(admitted, 2);
    assert_eq!(budget.stats().collection_bytes, 32);
    assert_eq!(
        budget.exhaustion().unwrap().resource,
        Resource::CollectionBytes
    );
}

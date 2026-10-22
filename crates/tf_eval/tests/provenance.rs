use std::time::{Duration, Instant};

use tf_allocator::Allocator;
use tf_eval::prov::{Prov, ResourceDependency};
use tf_eval::{EvaluationBudget, Evaluator, NoResolver, Origin, Scope, Truth, Value};
use tf_limits::{Limits, Resource};
use tf_span::FileId;

fn dependencies(range: std::ops::Range<usize>) -> Vec<ResourceDependency> {
    range
        .map(|i| ResourceDependency {
            resource: "test_node.n".into(),
            key: Some(i.to_string().into()),
            certainty: Truth::True,
        })
        .collect()
}

fn referencing(range: std::ops::Range<usize>) -> Value {
    Value::string("x").with_prov(Prov::EMPTY.referencing(dependencies(range)))
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

#[test]
fn unions_keep_first_seen_order_on_both_deduplication_paths() {
    for (left, right) in [(0..3, 2..5), (0..400, 200..600)] {
        let expected = dependencies(left.start..right.end);
        let joined = referencing(left.clone())
            .prov
            .joined(&referencing(right.clone()).prov);
        assert_eq!(joined.dependencies(), expected.as_slice());
        let list = Value::list(vec![referencing(left), referencing(right)]);
        assert_eq!(list.prov.dependencies(), expected.as_slice());
    }
}

#[test]
fn large_unions_are_linear_not_quadratic() {
    // Quadratic deduplication needs ~10^9 comparisons here; linear takes milliseconds.
    let left = referencing(0..30_000);
    let right = referencing(15_000..45_000);
    let start = Instant::now();
    let joined = left.prov.joined(&right.prov);
    assert_eq!(joined.dependencies().len(), 45_000);
    let alternatives = Value::one_of(vec![left, right], false);
    assert_eq!(alternatives.prov.dependencies().len(), 45_000);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    let shared = &alternatives.prov.dependencies()[20_000];
    assert_eq!(shared.certainty, Truth::True);
    let only_left = &alternatives.prov.dependencies()[0];
    assert_eq!(only_left.certainty, Truth::Unknown);
}

#[test]
fn evaluated_unions_charge_the_root_collection_allowance() {
    let bindings = [
        ("a", referencing(0..1_000)),
        ("b", referencing(1_000..2_000)),
    ];
    let baseline = EvaluationBudget::new(Limits::default());
    let value = evaluate("[a, b]", &baseline, &bindings);
    assert_eq!(value.prov.dependencies().len(), 2_000);
    let cost = baseline.storage().stats().collection_bytes;
    let union = 2_000 * size_of::<ResourceDependency>() as u64;
    assert!(cost >= union, "{cost} < {union}");
    let budget = EvaluationBudget::new(Limits::default().with_collection_bytes(cost - 1).unwrap());
    let value = evaluate("[a, b, [a, b]]", &budget, &bindings);
    assert_eq!(
        budget.storage().exhaustion().unwrap().resource,
        Resource::CollectionBytes
    );
    assert!(
        matches!(value.origin(), Some(Origin::Limit(_))),
        "{value:?}"
    );
    assert!(budget.first_limit().is_some());
}

#[test]
fn unions_outside_evaluation_are_not_charged_to_a_stale_root() {
    let budget = EvaluationBudget::new(Limits::default());
    evaluate("[1]", &budget, &[]);
    let before = budget.storage().stats().collection_bytes;
    let _ = referencing(0..10).prov.joined(&referencing(10..20).prov);
    assert_eq!(budget.storage().stats().collection_bytes, before);
}

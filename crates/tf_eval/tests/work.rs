//! Builtin internals and deep equality charge the root's evaluation allowance.
use tf_allocator::Allocator;
use tf_eval::budget::LimitReason;
use tf_eval::{EvaluationBudget, Evaluator, NoResolver, Origin, Scope, Value};
use tf_limits::{Limits, Resource};
use tf_span::FileId;

fn numbers(n: usize) -> Value {
    Value::list((0..n).map(|i| Value::number(i as f64)).collect())
}

fn evaluate(source: &str, budget: &EvaluationBudget, xs: &Value) -> Value {
    let arena = Allocator::new();
    let (expression, errors) = tf_parser::parse_expression(&arena, source);
    assert!(errors.is_empty(), "{source}: {errors:?}");
    let expression = expression.unwrap();
    Scope::EMPTY.with_all(&[("xs", xs.clone())], |scope| {
        Evaluator::with_budget(&NoResolver, FileId(0), budget).eval(&expression, scope)
    })
}

fn steps(source: &str, xs: &Value) -> u64 {
    let budget = EvaluationBudget::new(Limits::default());
    let value = evaluate(source, &budget, xs);
    assert!(value.is_known(), "{source}: {value:?}");
    budget.used()
}

fn exhausted(value: &Value, budget: &EvaluationBudget) {
    assert!(
        matches!(value.origin(), Some(Origin::Limit(_))),
        "{value:?}"
    );
    let limit = budget.first_limit().unwrap();
    assert!(
        matches!(limit.reason, LimitReason::Work(e) if e.resource == Resource::EvaluationSteps),
        "{limit:?}"
    );
}

#[test]
fn scans_inside_loops_are_charged_per_element() {
    let source = "length([for x in xs : x if contains(xs, x)])";
    let small = steps(source, &numbers(100));
    let large = steps(source, &numbers(400));
    // Quadratic work: four times the input costs about sixteen times the steps.
    assert!(large > 12 * small, "{small} -> {large}");
    assert!(large >= 400 * 400 / 2, "{large}");
}

#[test]
fn quadratic_builtins_stop_inside_one_call_at_the_allowance() {
    let xs = numbers(20_000);
    for source in [
        "distinct(xs)",
        "setunion(xs, [for x in xs : x + 20000])",
        "matchkeys(xs, xs, xs)",
        "length([for x in xs : index(xs, x)])",
        "length([for x in xs : x if xs == xs])",
    ] {
        let budget = EvaluationBudget::new(Limits::new(100_000).unwrap());
        let start = std::time::Instant::now();
        exhausted(&evaluate(source, &budget, &xs), &budget);
        // Unmetered, each of these performs 10^8 or more comparisons.
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "{source}"
        );
    }
}

#[test]
fn index_lookups_are_not_charged_by_collection_size() {
    let map = "{for x in xs : tostring(x) => x}";
    let lookup = format!("length([for x in xs : lookup({map}, \"1\", 0)])");
    let cost = steps("length([for x in xs : element(xs, x)])", &numbers(300));
    assert!(cost < 300 * 300 / 4, "{cost}");
    let cost = steps(&lookup, &numbers(30));
    assert!(cost < 30 * 30 * 30, "{cost}");
}

#[test]
fn unmetered_work_outside_evaluation_does_not_reach_the_next_root() {
    let xs = numbers(1_000);
    let baseline = steps("length(xs)", &xs);
    for _ in 0..100 {
        assert_eq!(xs.known_eq(&xs), Some(true));
    }
    assert_eq!(steps("length(xs)", &xs), baseline);
}

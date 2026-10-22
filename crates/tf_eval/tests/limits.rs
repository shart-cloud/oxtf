//! Limits apply before work, and exhaustion remains distinct from an expression error.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use tf_allocator::Allocator;
use tf_eval::eval::{MAX_ALTERNATIVES, lift2};
use tf_eval::functions::call;
use tf_eval::prov::ResourceDependency;
use tf_eval::{Evaluator, Kind, NoResolver, Origin, Prov, Scope, Truth, Value};
use tf_span::FileId;

thread_local! {
    static ALLOCATED: Cell<Option<usize>> = const { Cell::new(None) };
}

struct CountAllocations;

// SAFETY: every allocation and deallocation is forwarded unchanged to System.
unsafe impl GlobalAlloc for CountAllocations {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATED.try_with(|count| {
            count.set(count.get().map(|bytes| bytes.saturating_add(layout.size())));
        });
        // SAFETY: the caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the pointer and its original layout are forwarded to its allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountAllocations = CountAllocations;

fn assert_limit(value: &Value) {
    assert!(
        matches!(value.origin(), Some(Origin::Limit(_))),
        "{value:?}"
    );
    assert!(!value.is_error());
}

fn numbers(count: usize) -> Value {
    Value::list((0..count).map(|i| Value::number(i as f64)).collect())
}

fn alternatives(count: usize, scale: usize) -> Value {
    Value::one_of(
        (0..count)
            .map(|i| Value::number((i * scale) as f64))
            .collect(),
        false,
    )
}

fn evaluate(source: &str, bindings: &[(&str, Value)]) -> Value {
    let arena = Allocator::new();
    let (expression, errors) = tf_parser::parse_expression(&arena, source);
    let expression = expression.unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    Scope::EMPTY.with_all(bindings, |scope| {
        Evaluator::new(&NoResolver, FileId(0)).eval(&expression, scope)
    })
}

#[test]
fn product_rejects_before_allocating_rows() {
    let input = numbers(1024);
    let args = vec![input.clone(), input];
    // Count only this call on this thread, excluding input construction and test reporting.
    ALLOCATED.with(|count| count.set(Some(0)));
    let result = call("setproduct", args);
    let allocated = ALLOCATED.with(|count| count.replace(None).unwrap());
    assert_limit(&result);
    assert!(
        allocated < 64 * 1024,
        "rejection allocated {allocated} bytes"
    );
}

#[test]
fn collection_refusal_precedes_large_builtin_copies_and_json_parsing() {
    for (name, input) in [
        ("reverse", numbers(100_000)),
        (
            "jsondecode",
            Value::string(format!("[{}0]", "0,".repeat(100_000))),
        ),
    ] {
        let budget = tf_limits::input::InputBudget::new(
            tf_limits::Limits::default()
                .with_collection_bytes(1)
                .unwrap(),
        );
        let args = vec![input];
        ALLOCATED.with(|count| count.set(Some(0)));
        let result = tf_eval::functions::call_budgeted(name, args, &budget);
        let allocated = ALLOCATED.with(|count| count.replace(None).unwrap());
        assert_limit(&result);
        assert!(
            allocated < 64 * 1024,
            "{name} allocated {allocated} bytes before refusal"
        );
    }
}

#[test]
fn expression_refusal_precedes_large_container_copies() {
    let input = numbers(100_000);
    for source in [
        "items[*]",
        "max(items...)",
        "[for x in items : x]",
        "try(items, [])",
    ] {
        let arena = Allocator::new();
        let (expression, errors) = tf_parser::parse_expression(&arena, source);
        assert!(errors.is_empty());
        let expression = expression.unwrap();
        let budget = tf_eval::EvaluationBudget::new(
            tf_limits::Limits::default()
                .with_collection_bytes(32)
                .unwrap(),
        );
        let evaluator = Evaluator::with_budget(&NoResolver, FileId(0), &budget);
        ALLOCATED.with(|count| count.set(Some(0)));
        let result = Scope::EMPTY.with("items", &input, |scope| evaluator.eval(&expression, scope));
        let allocated = ALLOCATED.with(|count| count.replace(None).unwrap());
        assert_limit(&result);
        assert!(
            allocated < 64 * 1024,
            "{source} allocated {allocated} bytes before refusal"
        );
    }
}

#[test]
fn product_preserves_boundaries_empty_inputs_and_element_marks() {
    for rows in [4095, 4096] {
        let result = call("setproduct", vec![numbers(rows), numbers(1)]);
        assert_eq!(result.as_list().unwrap().len(), rows);
    }
    assert_limit(&call("setproduct", vec![numbers(4097), numbers(1)]));
    let result = call("setproduct", vec![numbers(1024), numbers(1024), numbers(0)]);
    assert_eq!(result.as_list().unwrap().len(), 0);

    let result = call(
        "setproduct",
        vec![
            Value::list(vec![Value::string("secret").sensitive()]),
            numbers(2),
        ],
    );
    let rows = result.as_list().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows[0].as_list().unwrap()[0].is_sensitive());
    assert_eq!(rows[1].as_list().unwrap()[1].as_number(), Some(1.0));
}

#[test]
fn product_bounds_tuple_width_and_total_elements() {
    let singleton = numbers(1);
    assert_limit(&call("setproduct", vec![singleton.clone(); 65_537]));
    let mut args = vec![numbers(4096)];
    args.extend(vec![singleton; 16]);
    assert_limit(&call("setproduct", args));
}

#[test]
fn indent_rejects_invalid_widths_and_bounds_output_bytes() {
    for width in [-1.0, 1.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(call("indent", vec![Value::number(width), Value::string("a\nb")]).is_error());
    }
    assert_limit(&call(
        "indent",
        vec![Value::number(1e100), Value::string("a\nb")],
    ));
    for bytes in [1_048_575, 1_048_576] {
        let result = call(
            "indent",
            vec![Value::number((bytes - 1) as f64), Value::string("\n")],
        );
        assert_eq!(result.as_str().unwrap().len(), bytes);
    }
    assert_limit(&call(
        "indent",
        vec![Value::number(524_288.0), Value::string("\n\n")],
    ));
    assert_limit(&call(
        "indent",
        vec![Value::number(0.0), Value::string("x".repeat(1_048_577))],
    ));
    assert_eq!(
        evaluate("indent(2, \"é\\nb\\n\")", &[]).as_str(),
        Some("é\n  b\n  ")
    );
    assert_eq!(evaluate("indent(0, \"a\\nb\")", &[]).as_str(), Some("a\nb"));
}

#[test]
fn binary_alternatives_reject_before_invoking_the_operation() {
    let count = Cell::new(0);
    let operation = |a: &Value, b: &Value| {
        count.set(count.get() + 1);
        Value::number(a.as_number().unwrap() + b.as_number().unwrap())
    };
    let result = lift2(&alternatives(4, 1), &alternatives(4, 4), &operation);
    let Kind::OneOf(values) = result.kind else {
        panic!("expected alternatives")
    };
    assert_eq!(values.alternatives.len(), MAX_ALTERNATIVES);
    assert_eq!(count.replace(0), MAX_ALTERNATIVES);

    let result = lift2(&alternatives(16, 1), &alternatives(16, 16), &operation);
    assert_limit(&result);
    assert_eq!(count.get(), 0);
}

#[test]
fn alternative_construction_bounds_flattening_before_deduplication() {
    assert_limit(&alternatives(17, 1));
    assert_limit(&Value::one_of(vec![Value::bool(true); 17], false));
    assert_limit(&Value::one_of(
        vec![alternatives(16, 1), Value::number(16.0)],
        true,
    ));
    assert_eq!(
        Value::one_of(vec![Value::bool(true); 16], false).as_bool(),
        Some(true)
    );
}

#[test]
fn limits_preserve_sensitivity_and_possible_resource_dependencies() {
    let secret = alternatives(16, 1)
        .sensitive()
        .with_prov(Prov::EMPTY.referencing(vec![ResourceDependency {
            resource: "aws_vpc.secret".into(),
            key: None,
            certainty: Truth::True,
        }]));
    let other = alternatives(16, 16);
    let operation = |_: &Value, _: &Value| panic!("the budget must stop evaluation");
    let result = lift2(&secret, &other, &operation);
    assert_limit(&result);
    assert!(result.is_sensitive());
    let dependency = &result.prov.dependencies()[0];
    assert_eq!(dependency.resource.as_ref(), "aws_vpc.secret");
    assert_eq!(dependency.certainty, Truth::Unknown);

    for expression in ["format(\"%s%s\", a, b)", "\"${a}${b}\""] {
        let result = evaluate(expression, &[("a", other.clone()), ("b", secret.clone())]);
        assert_limit(&result);
        assert!(result.is_sensitive(), "{expression}");
        assert!(!result.prov.dependencies().is_empty(), "{expression}");
    }
}

#[test]
fn exhaustion_is_not_a_catchable_error_or_a_known_condition() {
    for expression in [
        "try(indent(1e100, \"a\\nb\"), \"fallback\")",
        "can(indent(1e100, \"a\\nb\"))",
        "(a + b) == 0 ? true : true",
        "length([for x in range(5) : x if enabled])",
    ] {
        let result = evaluate(
            expression,
            &[
                ("a", alternatives(16, 1)),
                ("b", alternatives(16, 16)),
                ("enabled", Value::tainted("enabled")),
            ],
        );
        assert_limit(&result);
    }
}

use super::*;
use crate::input_conversion::{InputContext, convert_input};
use tf_eval::{EvaluationBudget, Origin, Prov, Truth, prov::ResourceDependency};
use tf_limits::{Limits, Resource};
use tf_span::{FileId, FileSpan, Span};

fn budget(bytes: u64) -> EvaluationBudget {
    EvaluationBudget::new(Limits::default().with_collection_bytes(bytes).unwrap())
}

fn context(budget: &EvaluationBudget) -> DefaultContext<'_> {
    DefaultContext {
        budget,
        at: FileSpan::new(FileId(0), Span::new(0, 1)),
    }
}

fn input_context(budget: &EvaluationBudget) -> InputContext<'_> {
    let cx = context(budget);
    InputContext { budget, at: cx.at }
}

fn evidence(value: Value) -> Value {
    value
        .sensitive()
        .with_prov(Prov::EMPTY.referencing(vec![ResourceDependency {
            resource: "test_node.origin".into(),
            key: None,
            certainty: Truth::True,
        }]))
}

fn assert_refusal(value: &Value, budget: &EvaluationBudget, allowance: u64) {
    assert!(
        matches!(value.origin(), Some(Origin::Limit(_))),
        "{value:?}"
    );
    assert_eq!(
        budget.storage().exhaustion().unwrap().resource,
        Resource::CollectionBytes
    );
    assert!(budget.storage().stats().collection_bytes <= allowance);
    assert!(matches!(
        budget.first_limit().unwrap().reason,
        tf_eval::budget::LimitReason::Storage(_)
    ));
}

#[test]
fn runtime_conversion_reserves_exact_payload_before_children() {
    let list = Value::list(vec![Value::string("1"), Value::string("2")]);
    let object = Value::object(
        [
            ("x".into(), Value::string("1")),
            ("y".into(), Value::string("2")),
        ]
        .into(),
    );
    let cases = [
        ("list(number)", list.clone(), 2 * size_of::<Value>()),
        ("set(number)", list.clone(), 2 * size_of::<Value>()),
        ("tuple([number, number])", list, 2 * size_of::<Value>()),
        (
            "map(number)",
            object.clone(),
            2 * size_of::<(std::sync::Arc<str>, Value)>(),
        ),
        (
            "object({x=number, y=number})",
            object,
            2 * size_of::<(std::sync::Arc<str>, Value)>(),
        ),
    ];
    for (source, input, cost) in cases {
        let arena = tf_allocator::Allocator::new();
        let (ty, errors) = tf_parser::parse_expression(&arena, source);
        assert!(errors.is_empty());
        let input = evidence(input);
        for allowance in [cost - 1, cost, cost + 1] {
            let budget = budget(allowance as u64);
            let result = convert_input(input.clone(), ty.as_ref(), None, input_context(&budget));
            assert!(result.is_sensitive());
            assert_eq!(result.prov.dependencies().len(), 1);
            if allowance < cost {
                assert_refusal(&result, &budget, allowance as u64);
                assert_eq!(budget.used(), 3, "children ran before admission: {source}");
                assert_eq!(result.prov.dependencies()[0].certainty, Truth::Unknown);
            } else {
                assert!(result.is_wholly_known());
                assert_eq!(budget.storage().stats().collection_bytes, cost as u64);
                assert_eq!(result.prov.dependencies()[0].certainty, Truth::True);
            }
        }
    }
}

#[test]
fn every_optional_default_application_boundary_retains_input_evidence() {
    let arena = tf_allocator::Allocator::new();
    let (ty, errors) = tf_parser::parse_expression(
        &arena,
        concat!(
            "object({x=optional(list(number), [1, 2]), ",
            "y=optional(object({z=optional(number, 7)}), {})})"
        ),
    );
    assert!(errors.is_empty());
    let ty = ty.unwrap();
    let preparation = budget(100_000);
    let defaults = TypeDefaults::from_type(&ty, context(&preparation)).unwrap();
    let input = evidence(Value::object([("x".into(), Value::null())].into()));
    let full = budget(100_000);
    let result = convert_input(
        input.clone(),
        Some(&ty),
        Some(&defaults),
        input_context(&full),
    );
    assert_eq!(
        tf_eval::value::to_json(&result),
        Some(serde_json::json!({"x":[1,2], "y":{"z":7}}))
    );
    let cost = full.storage().stats().collection_bytes;
    for allowance in 1..=cost {
        let budget = budget(allowance);
        let result = convert_input(
            input.clone(),
            Some(&ty),
            Some(&defaults),
            input_context(&budget),
        );
        assert!(result.is_sensitive());
        assert_eq!(result.prov.dependencies().len(), 1);
        if allowance < cost {
            assert_refusal(&result, &budget, allowance);
            assert_eq!(result.prov.dependencies()[0].certainty, Truth::Unknown);
        } else {
            assert!(result.is_wholly_known());
        }
    }
}

#[test]
fn runtime_storage_refusal_preserves_errors_before_and_during_conversion() {
    let arena = tf_allocator::Allocator::new();
    let (ty, errors) = tf_parser::parse_expression(
        &arena,
        "object({x=number, y=optional(list(number), [1, 2])})",
    );
    assert!(errors.is_empty());
    let ty = ty.unwrap();
    for allowance in [1, 2 * size_of::<(std::sync::Arc<str>, Value)>() as u64] {
        let budget = budget(allowance);
        let input = Value::object([("x".into(), Value::error("prior failure").sensitive())].into());
        let result = convert_input(input, Some(&ty), None, input_context(&budget));
        assert!(tf_eval::eval::contains_error(&result));
        assert!(result.is_sensitive());
        assert!(budget.is_exhausted());
    }
}

fn prepare(
    value: Value,
    ty: &Expression<'_>,
    cx: DefaultContext<'_>,
) -> Result<Value, DefaultError> {
    TypeDefaults::from_type(ty, cx)?;
    let default = DefaultValue::literal(value, cx)?;
    let copied = default.clone_with_context(cx)?;
    copied.ty.check_conversion(ty, cx)?;
    let converted = conversion::convert(&copied.value, ty, true, cx)?;
    let common = CommonType::infer_typed(&[&converted], Some(ty), &[Some(&copied.ty)], cx)?;
    common.convert(&converted, cx)
}

#[test]
fn every_default_preparation_boundary_is_typed_storage_exhaustion() {
    let cases = [
        (
            "tuple([list(number), map(string)])",
            serde_json::json!(null),
        ),
        ("object({x=optional(set(string))})", serde_json::json!(null)),
        ("list(any)", serde_json::json!([{"a":"x"},{"b":"y"}])),
        (
            "list(any)",
            serde_json::json!([{"a":true,"b":"text"},{"a":1,"b":"text"}]),
        ),
        ("list(any)", serde_json::json!([1, "2", 3])),
        ("set(string)", serde_json::json!(["z", "a", "z", "b", "a"])),
        ("map(list(number))", serde_json::json!({"x":[1,2],"y":[]})),
        (
            "tuple([list(number), object({x=optional(number,7)})])",
            serde_json::json!([[], {}]),
        ),
        (
            "object({x=optional(set(string),[\"b\",\"a\",\"b\"])})",
            serde_json::json!({}),
        ),
    ];
    for (source, input) in cases {
        let arena = tf_allocator::Allocator::new();
        let (ty, errors) = tf_parser::parse_expression(&arena, source);
        assert!(errors.is_empty());
        let ty = ty.unwrap();
        let input = tf_eval::value::from_json(&input, &Prov::EMPTY);
        let full = budget(100_000);
        let expected = prepare(input.clone(), &ty, context(&full)).unwrap();
        let cost = full.storage().stats().collection_bytes;
        assert!(cost > 1);
        for allowance in 1..=cost {
            let budget = budget(allowance);
            let result = prepare(input.clone(), &ty, context(&budget));
            if allowance < cost {
                assert!(
                    matches!(result, Err(DefaultError::Limit)),
                    "{source}, {allowance}: {result:?}"
                );
                assert_eq!(
                    budget.storage().exhaustion().unwrap().resource,
                    Resource::CollectionBytes
                );
                assert!(budget.storage().stats().collection_bytes <= allowance);
                assert!(matches!(
                    budget.first_limit().unwrap().reason,
                    tf_eval::budget::LimitReason::Storage(_)
                ));
            } else {
                assert_eq!(
                    tf_eval::value::to_json(&result.unwrap()),
                    tf_eval::value::to_json(&expected)
                );
            }
        }
    }
}

#[test]
fn rejection_does_not_allocate_large_runtime_or_type_copies() {
    let arena = tf_allocator::Allocator::new();
    let (ty, errors) = tf_parser::parse_expression(&arena, "list(number)");
    assert!(errors.is_empty());
    let input = Value::list(vec![Value::number(1.0); 100_000]);
    let concrete = CommonType::Tuple(vec![CommonType::Number; 100_000]);
    for operation in 0..3 {
        let budget = budget(32);
        let (refused, bytes) = crate::test_allocations::measure(|| match operation {
            0 => convert_input(input.clone(), ty.as_ref(), None, input_context(&budget))
                .is_wholly_known(),
            1 => DefaultValue::literal(input.clone(), context(&budget)).is_ok(),
            _ => concrete.clone_with_context(context(&budget)).is_ok(),
        });
        assert!(!refused);
        assert!(
            bytes < 64 * 1024,
            "operation {operation} allocated {bytes} bytes"
        );
        assert_eq!(
            budget.storage().exhaustion().unwrap().resource,
            Resource::CollectionBytes
        );
    }
}

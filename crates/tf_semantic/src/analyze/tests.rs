use super::*;
use tf_eval::prov::ResourceDependency;
use tf_limits::input::InputBudget;
use tf_limits::{Limits, Resource};

fn budget(bytes: u64) -> InputBudget {
    InputBudget::new(Limits::default().with_collection_bytes(bytes).unwrap())
}

fn dependency() -> ResourceDependency {
    ResourceDependency {
        resource: "test_node.source".into(),
        key: None,
        certainty: Truth::True,
    }
}

#[test]
fn reference_copies_retain_evidence_at_every_storage_boundary() {
    let input = Value::object(
        [(
            "nested".into(),
            Value::json(Value::list(vec![Value::one_of(
                vec![Value::number(1.0), Value::number(2.0)],
                false,
            )])),
        )]
        .into(),
    )
    .sensitive();
    let full = budget(100_000);
    let expected = reference_value(input.clone(), &[dependency()], &full);
    let cost = full.stats().collection_bytes;
    for allowance in 1..=cost + 1 {
        let budget = budget(allowance);
        let value = reference_value(input.clone(), &[dependency()], &budget);
        assert!(value.is_sensitive());
        assert_eq!(value.prov.dependencies().len(), 1);
        if allowance < cost {
            assert!(matches!(value.origin(), Some(Origin::Limit(_))));
            assert_eq!(
                budget.exhaustion().unwrap().resource,
                Resource::CollectionBytes
            );
            assert_eq!(value.prov.dependencies()[0].certainty, Truth::Unknown);
        } else {
            assert_eq!(format!("{:?}", value.kind), format!("{:?}", expected.kind));
            assert!(budget.exhaustion().is_none());
        }
        assert!(budget.stats().collection_bytes <= allowance);
    }
    let input = Value::list(vec![Value::error("earlier error").sensitive()]);
    let value = reference_value(input, &[dependency()], &budget(1));
    assert!(tf_eval::eval::contains_error(&value));
    assert!(value.is_sensitive());
}

#[test]
fn projection_destinations_refuse_before_mapping_and_keep_prior_errors() {
    for map in [false, true] {
        let calls = Cell::new(0);
        let budget = budget(1);
        let values = (0..100_000).map(|_| {
            calls.set(calls.get() + 1);
            Value::number(1.0)
        });
        let result = if map {
            storage::object(values.map(|v| (Arc::from("key"), v)), &budget)
        } else {
            storage::values(values, &budget).map(Value::list)
        };
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
    }
    let budget = budget(1024);
    let input = Value::error("earlier error").sensitive();
    let result = storage::values(
        (0..2).map(|i| {
            if i == 0 {
                input.clone()
            } else {
                collections::refused(&budget)
            }
        }),
        &budget,
    )
    .unwrap_err();
    assert!(tf_eval::eval::contains_error(&result));
    assert!(result.is_sensitive());
}

#[test]
fn memo_entries_charge_once_and_refuse_before_compute() {
    let files = FileTable::new();
    let store = ModuleStore::new();
    let options = AnalyzeOptions::default();
    let analyzer = Analyzer::new(
        &store,
        &files,
        &options,
        None,
        Path::new("/nonexistent/memo"),
    );
    let map = RefCell::new(HashMap::<String, Slot>::default());
    let value = analyzer.memo(
        &map,
        "key",
        || "key".into(),
        || "key".into(),
        || Value::number(3.0),
    );
    assert_eq!(value.as_number(), Some(3.0));
    let used = files.input_budget().stats().collection_bytes;
    analyzer.memo(
        &map,
        "key",
        || panic!("warm key allocation"),
        || "key".into(),
        || panic!("warm compute"),
    );
    assert_eq!(files.input_budget().stats().collection_bytes, used);
    collections::refused(files.input_budget());
    let result = analyzer.memo(
        &map,
        "other",
        || panic!("refused key allocation"),
        || "other".into(),
        || panic!("refused compute"),
    );
    assert!(matches!(result.origin(), Some(Origin::Limit(_))));
    assert_eq!(map.borrow().len(), 1);
}

#[test]
fn large_references_and_expansion_inputs_are_rejected_without_large_copies() {
    let input = Value::list(vec![Value::number(1.0); 100_000]);
    let files = FileTable::new();
    let store = ModuleStore::new();
    let options = AnalyzeOptions::default();
    let analyzer = Analyzer::new(
        &store,
        &files,
        &options,
        None,
        Path::new("/nonexistent/expand"),
    );
    let (length, bytes) =
        crate::test_allocations::measure(|| collection_items(&input).unwrap().len());
    assert_eq!(length, 100_000);
    assert_eq!(bytes, 0);
    let (value, bytes) = crate::test_allocations::measure(|| {
        reference_value(input.clone(), &[dependency()], &budget(32))
    });
    assert!(matches!(value.origin(), Some(Origin::Limit(_))));
    assert!(bytes < 64 * 1024, "reference allocated {bytes} bytes");
    let (binds, bytes) = crate::test_allocations::measure(|| {
        analyzer.each_binds(&input, FileSpan::default()).unwrap()
    });
    assert_eq!(binds.len(), 1);
    assert!(binds[0].key.is_none());
    assert!(bytes < 64 * 1024, "expansion allocated {bytes} bytes");
}

#[test]
fn empty_count_alternatives_still_have_no_instances() {
    let files = FileTable::new();
    let store = ModuleStore::new();
    let options = AnalyzeOptions::default();
    let analyzer = Analyzer::new(
        &store,
        &files,
        &options,
        None,
        Path::new("/nonexistent/empty"),
    );
    let value = Value::new(Kind::OneOf(Arc::new(tf_eval::value::OneOf {
        alternatives: Vec::new(),
        tainted: false,
    })));
    assert!(
        analyzer
            .count_binds(&value, FileSpan::default())
            .unwrap()
            .is_empty()
    );
}

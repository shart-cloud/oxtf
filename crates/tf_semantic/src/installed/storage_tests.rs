use super::*;
use tf_limits::{Limits, Resource, input::InputBudget};

#[test]
fn manifest_records_admit_before_decoding_and_charge_each_record_once() {
    let text = r#"{"Modules":[{"Key":"","Dir":"."},{"Key":"child","Dir":"child"}]}"#;
    let entry_bytes = size_of::<(String, Record)>() as u64;
    for allowance in 1..=2 * entry_bytes + 1 {
        let budget = InputBudget::new(Limits::default().with_collection_bytes(allowance).unwrap());
        let result = decode::records(text, &budget);
        if allowance < 2 * entry_bytes {
            assert!(matches!(result, Err(ResolveError::Storage(error))
                if error.resource == Resource::CollectionBytes));
        } else {
            let records = result.unwrap();
            assert_eq!(records.len(), 2);
            assert_eq!(records["child"].dir, Path::new("child"));
            assert_eq!(budget.stats().collection_bytes, 2 * entry_bytes);
        }
        assert!(budget.stats().collection_bytes <= allowance);
    }
}

#[test]
fn refused_manifest_record_does_not_decode_large_fields_or_remaining_records() {
    let long = "x".repeat(1_000_000);
    let text = format!(r#"{{"Modules":[{{"Key":"{long}","Dir":"."}}]}}"#);
    let budget = InputBudget::new(Limits::default().with_collection_bytes(1).unwrap());
    let (result, bytes) = crate::test_allocations::measure(|| decode::records(&text, &budget));
    assert!(matches!(result, Err(ResolveError::Storage(_))));
    assert!(
        bytes < 4096,
        "allocated {bytes} bytes before refusing a record"
    );
    assert_eq!(budget.stats().collection_bytes, 0);
    let text = format!(r#"{{"Modules":[{{"Key":"a","Dir":"."}},{{"Key":"{long}","Dir":"."}}]}}"#);
    let entry_bytes = size_of::<(String, Record)>() as u64;
    let budget = InputBudget::new(
        Limits::default()
            .with_collection_bytes(entry_bytes)
            .unwrap(),
    );
    let (result, bytes) = crate::test_allocations::measure(|| decode::records(&text, &budget));
    assert!(matches!(result, Err(ResolveError::Storage(_))));
    assert!(
        bytes < 4096,
        "allocated {bytes} bytes before refusing the second record"
    );
    assert_eq!(budget.stats().collection_bytes, entry_bytes);
}

#[test]
fn manifest_validation_still_rejects_duplicates_missing_fields_and_trailing_input() {
    for text in [
        r#"{"Modules":[{"Key":"a","Dir":"."},{"Key":"a","Dir":"other"}]}"#,
        r#"{"Modules":[],"Modules":[]}"#,
        r#"{}"#,
        r#"{"Modules":[{"Key":"a"}]}"#,
        r#"{"Modules":[{"Dir":"."}]}"#,
        r#"{"Modules":[]} false"#,
    ] {
        let budget = InputBudget::new(Limits::default());
        assert!(matches!(
            decode::records(text, &budget),
            Err(ResolveError::Invalid(_))
        ));
        assert!(budget.exhaustion().is_none());
    }
    let budget = InputBudget::new(Limits::default());
    let text = r#"{"Ignored":{"nested":[1,2]},"Modules":[]}"#;
    assert!(decode::records(text, &budget).unwrap().is_empty());
    assert_eq!(budget.stats().collection_bytes, 0);
}

#[test]
fn manifest_success_and_storage_failure_are_cached_without_recharging() {
    for allowance in [1, 100_000] {
        let root = Path::new("/nonexistent/oxtf-installed-metadata");
        let files = FileTable::with_overlay_and_limits(
            [(
                root.join(".terraform/modules/modules.json"),
                std::sync::Arc::from(r#"{"Modules":[{"Key":"a","Dir":"a"}]}"#),
            )],
            Limits::default().with_collection_bytes(allowance).unwrap(),
        );
        let installed = InstalledModules::new(root, None, &files);
        let first = installed.records();
        let consumed = files.input_budget().stats();
        let second = installed.records();
        match (first, second) {
            (Ok(a), Ok(b)) => assert!(std::ptr::eq(a, b)),
            (Err(ResolveError::Storage(a)), Err(ResolveError::Storage(b))) => assert_eq!(a, b),
            _ => panic!("manifest cache changed its outcome"),
        }
        assert_eq!(files.input_budget().stats(), consumed);
    }
}

use tf_linter::Linter;

#[test]
fn selection_validates_all_ids_and_preserves_empty_selection() {
    let ids = vec![
        "aws-rds-unencrypted".into(),
        "typo".into(),
        "another-typo".into(),
        "typo".into(),
    ];
    let err = Linter::filtered(tf_linter::rules::all(), &ids)
        .err()
        .unwrap();
    assert_eq!(err.unknown_ids, ["typo", "another-typo"]);
    let empty = Linter::filtered(tf_linter::rules::all(), &[]).unwrap();
    assert!(empty.rules().is_empty());
    let selected = Linter::filtered(
        tf_linter::rules::all(),
        &["aws-rds-unencrypted".into(), "aws-rds-unencrypted".into()],
    )
    .unwrap();
    assert_eq!(selected.rules().len(), 1);
}

use tf_eval::{Origin, Value};
use tf_semantic::references::{ReferenceMatch, match_resource_reference};
use tf_semantic::{AnalyzeOptions, FileTable, InstanceKey, Resource, analyze_module};

#[test]
fn ambiguous_references_do_not_claim_exact_instance_identity() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rules/aws-s3-public-access-block/pass_full_block");
    let files = FileTable::new();
    let analysis = analyze_module(&root, &AnalyzeOptions::default(), &files);
    let found = analysis.modules[0]
        .resources_of("aws_s3_bucket")
        .next()
        .unwrap();
    let bucket = Resource::new(
        found.id.clone().with_key(Some(InstanceKey::Key("a".into()))),
        found.span,
        found.body.clone(),
        found.existence,
        None,
        None,
        found.provider,
    );
    assert_eq!(&*bucket.address, "aws_s3_bucket.data[\"a\"]");
    let computed = |key: Option<&str>| {
        Value::unknown(Origin::Computed {
            resource: bucket.base_address.clone(),
            key: key.map(Into::into),
            attr: "id".into(),
        })
    };
    let matches =
        |value: &Value| match_resource_reference(value, &bucket, "bucket", &["id", "bucket"]);
    assert_eq!(matches(&computed(Some("a"))), ReferenceMatch::Yes);
    assert_eq!(matches(&computed(Some("b"))), ReferenceMatch::No);
    assert_eq!(matches(&computed(None)), ReferenceMatch::Maybe);
    assert_eq!(matches(&Value::tainted("name")), ReferenceMatch::Maybe);
    assert_eq!(
        matches(&Value::other("remote module output")),
        ReferenceMatch::Maybe
    );
    assert_eq!(
        matches(&Value::one_of(
            vec![computed(Some("a")), computed(Some("b"))],
            true
        )),
        ReferenceMatch::Maybe
    );
    assert_eq!(
        matches(&Value::one_of(
            vec![Value::string("other"), Value::string("another")],
            true
        )),
        ReferenceMatch::No
    );
    assert_eq!(matches(&Value::null()), ReferenceMatch::No);
}

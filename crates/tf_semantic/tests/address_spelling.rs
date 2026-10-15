//! Resource instance addresses are spelled by `Address`, with instance keys
//! quoted the way Terraform quotes them, on the HCL front end.

use tf_semantic::{AnalyzeOptions, FileTable, InstanceKey, analyze_module};

#[test]
fn escaped_for_each_keys_are_spelled_like_terraform() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rules/aws-s3-public-access-block/pass_escaped_instance_key");
    let analysis = analyze_module(&root, &AnalyzeOptions::default(), &FileTable::new());
    let mut addresses: Vec<String> = analysis.modules[0]
        .resources
        .iter()
        .map(|r| r.address.to_string())
        .collect();
    addresses.sort();
    assert_eq!(
        addresses,
        [
            "aws_s3_bucket.b[\"plain\"]",
            "aws_s3_bucket.b[\"quote\\\"back\\\\slash\"]",
            "aws_s3_bucket_public_access_block.p[\"plain\"]",
            "aws_s3_bucket_public_access_block.p[\"quote\\\"back\\\\slash\"]",
        ]
    );
    let escaped = analysis.modules[0]
        .resources
        .iter()
        .find(|r| r.key.as_deref() == Some("quote\"back\\slash"))
        .unwrap();
    assert_eq!(escaped.id.key, Some(InstanceKey::Key("quote\"back\\slash".into())));
    assert_eq!(&*escaped.base_address, "aws_s3_bucket.b");
    assert_eq!(escaped.id.base_string(), "aws_s3_bucket.b");
    // The string form round-trips through the parser, so the plan front end
    // (which parses Terraform's own spelling) lands on the same identity.
    assert_eq!(tf_semantic::Address::parse(&escaped.address).unwrap(), escaped.id);
}

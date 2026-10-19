//! Bundled Checkov rules see attribute values as Checkov's parser leaves
//! them (`clean_parser_types`).
use std::path::Path;
use std::sync::Arc;

use tf_scan::{Catalog, ScanRequest, scan};

/// Checkov's parser reads the strings "true" and "false" as booleans,
/// also through variables and locals, so the bundled rule passes these as
/// Checkov does (and as `gcp-storage-uniform-access` always did).
#[test]
fn bundled_rules_read_string_booleans_as_checkov_does() {
    for (text, flagged) in [
        (r#"uniform_bucket_level_access = "true""#, false),
        (r#"uniform_bucket_level_access = local.u"#, false),
        (r#"uniform_bucket_level_access = "false""#, true),
        (r#"uniform_bucket_level_access = "True""#, true),
    ] {
        let tf = format!(
            "locals {{\n  u = \"true\"\n}}\nresource \"google_storage_bucket\" \"b\" {{\n  name = \"x\"\n  location = \"US\"\n  {text}\n}}\n"
        );
        let dir = Path::new("/oxtf-test/parser-types");
        let mut req = ScanRequest::dirs(vec![dir.into()], false);
        req.catalog = Catalog {
            bundled: true,
            ..Catalog::default()
        };
        req.selection = Some(vec!["CKV_GCP_29".into()]);
        req.overlay = vec![(dir.join("main.tf"), Arc::from(tf.as_str()))];
        let out = scan(req).unwrap();
        assert_eq!(!out.result.findings.is_empty(), flagged, "{text}");
    }
}

//! The bundled catalog costs a scan only the rules of the resource types
//! it meets: each is compiled the first time it judges.
//!
//! One test in its own binary, since the compile count is per process.
use std::path::Path;
use std::sync::Arc;

use tf_scan::{Catalog, ScanRequest, scan};

const DB: &str = r#"resource "aws_db_instance" "db" {
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = false
}
"#;

#[test]
fn a_scan_compiles_only_the_bundled_rules_it_uses() {
    let all = Catalog::standard().resolve().unwrap().rules;
    assert_eq!(tf_rule_ir::bundled::compiled_count(), 0, "listing compiles");
    let used = all
        .iter()
        .map(|r| r.info())
        .filter(|i| i.source.engine == tf_linter::Engine::Checkov)
        .filter(|i| i.resource_types.iter().any(|t| &**t == "aws_db_instance"))
        .count();
    assert!(used > 0 && used < all.len() / 10, "{used} of {}", all.len());

    let dir = Path::new("/oxtf-test/bundled-lazy");
    let mut req = ScanRequest::dirs(vec![dir.into()], false);
    req.overlay = vec![(dir.join("main.tf"), Arc::from(DB))];
    let out = scan(req).unwrap();
    assert!(
        out.result.rule_errors.is_empty(),
        "{:?}",
        out.result.rule_errors
    );
    assert!(out.result.findings.iter().any(|f| &*f.rule == "CKV_AWS_16"));
    assert_eq!(tf_rule_ir::bundled::compiled_count(), used);
}

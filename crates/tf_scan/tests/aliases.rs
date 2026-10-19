//! A seed rule proven equivalent to a bundled Checkov rule replaces it and
//! answers to its ID: one finding per issue, selected and `checkov:skip`-
//! suppressed by either ID.
use std::path::Path;
use std::sync::Arc;

use tf_scan::{Catalog, ScanOutput, ScanRequest, scan};

const SEED: &str = "gcp-storage-uniform-access";
const CHECKOV: &str = "CKV_GCP_29";

fn run(catalog: Catalog, select: Option<&str>, text: &str) -> ScanOutput {
    let dir = Path::new("/oxtf-test/aliases");
    let mut req = ScanRequest::dirs(vec![dir.into()], false);
    req.catalog = catalog;
    req.selection = select.map(|s| vec![s.to_string()]);
    req.overlay = vec![(dir.join("main.tf"), Arc::from(text))];
    scan(req).unwrap()
}

fn ids(out: &ScanOutput) -> Vec<&str> {
    out.result
        .findings
        .iter()
        .map(|f| &*f.rule)
        .filter(|r| [SEED, CHECKOV].contains(r))
        .collect()
}

fn bundled_only() -> Catalog {
    Catalog {
        bundled: true,
        ..Catalog::default()
    }
}

const UNIFORM_ABSENT: &str = r#"resource "google_storage_bucket" "b" {
  name     = "x"
  location = "US"
}
"#;

#[test]
fn the_seed_rule_replaces_the_bundled_rule_it_aliases() {
    let resolved = Catalog::standard().resolve().unwrap();
    let names: Vec<_> = resolved.rules.iter().map(|r| r.info().name).collect();
    assert!(names.iter().any(|n| &**n == SEED));
    assert!(!names.iter().any(|n| &**n == CHECKOV));

    assert_eq!(ids(&run(Catalog::standard(), None, UNIFORM_ABSENT)), [SEED]);
    // Either ID selects it.
    assert_eq!(
        ids(&run(Catalog::standard(), Some(CHECKOV), UNIFORM_ABSENT)),
        [SEED]
    );
    // Without the seed rules, the bundled rule runs under its own ID.
    assert_eq!(ids(&run(bundled_only(), None, UNIFORM_ABSENT)), [CHECKOV]);
}

#[test]
fn a_checkov_skip_of_the_alias_suppresses_the_seed_rule() {
    let text = r#"resource "google_storage_bucket" "b" {
  # checkov:skip=CKV_GCP_29: legacy ACLs needed
  name     = "x"
  location = "US"
}
"#;
    let out = run(Catalog::standard(), None, text);
    assert!(ids(&out).is_empty());
    let suppressed: Vec<_> = out.result.suppressed.iter().map(|s| &*s.rule).collect();
    assert_eq!(suppressed, [SEED]);
}

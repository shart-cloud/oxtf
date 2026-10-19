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

/// A rule whose aliases repeat its own name (and one another).
struct SelfAliased(Box<dyn tf_linter::DynRule>);

impl tf_linter::DynRule for SelfAliased {
    fn info(&self) -> tf_linter::RuleInfo {
        let mut info = self.0.info();
        info.aliases.push(info.name.clone());
        info.aliases.push(Arc::from("twice"));
        info.aliases.push(Arc::from("twice"));
        info
    }
    fn judge_resource(
        &self,
        resource: &tf_semantic::Resource,
    ) -> Result<Vec<tf_linter::Judgement>, tf_linter::RuleFailure> {
        self.0.judge_resource(resource)
    }
    fn judge_module<'m>(
        &self,
        module: &'m tf_semantic::Module,
    ) -> Result<Vec<(&'m tf_semantic::Resource, tf_linter::Judgement)>, tf_linter::RuleFailure>
    {
        self.0.judge_module(module)
    }
}

#[test]
fn a_rule_repeating_its_own_name_among_its_aliases_shadows_nothing() {
    let seed = tf_linter::rules::all()
        .into_iter()
        .find(|r| &*r.info().name == SEED)
        .unwrap();
    let catalog = Catalog {
        runtime: vec![Box::new(SelfAliased(seed))],
        ..Catalog::default()
    };
    let resolved = catalog.resolve().unwrap();
    let names: Vec<_> = resolved.rules.iter().map(|r| r.info().name).collect();
    assert_eq!(names.len(), 1);
    assert_eq!(&*names[0], SEED);
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

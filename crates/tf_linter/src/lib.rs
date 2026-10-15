//! oxtf rule engine, seed rules and scan entry points.
//!
//! ```no_run
//! use tf_linter::{scan_dir, ScanOptions};
//! let r = scan_dir("fixtures/rules/aws-sg-open-ssh/fail_tfvars_through_local".as_ref(), &ScanOptions::default()).unwrap();
//! for f in &r.findings {
//!     println!("{}", tf_linter::render::render_finding(&r.files, f, false));
//! }
//! ```
//!
//! - [`rule`]: the `Rule` / `RuleMeta` traits (oxc-linter shape), the
//!   object-safe [`DynRule`], [`Finding`] and [`Finding::from_verdict`].
//! - [`engine::Linter`]: dispatch table (resource type → rules) and module
//!   rules, run per module instance.
//! - [`scan`]: root discovery and the parallel (rayon) scan;
//!   [`scan_dir`] / [`scan_dir_with_model`] / [`scan_with`].
//! - [`record`]: the resolved, versioned finding record every output is a
//!   projection of (`docs/FINDING_SCHEMA.md`).
//! - [`render`]: miette text rendering with provenance, JSON.
//! - [`rules`]: the five seed rules.

pub mod engine;
pub mod record;
pub mod render;
pub mod rule;
pub mod rules;
pub mod scan;

pub use engine::{Linter, RuleSelectionError, select_rules};
pub use record::{FindingRecord, RuleError, ScanRecord};
pub use rule::{
    Category, DynRule, Finding, FixAction, FixHint, Hidden, Judgement, Level, Rule, RuleInfo,
    RuleMeta, Severity,
};
pub use scan::{
    ScanOptions, ScanResult, ScanStats, discover_roots, scan_dir, scan_dir_with_model, scan_with,
};

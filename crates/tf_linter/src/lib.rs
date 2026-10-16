//! oxtf rule engine, seed rules and scan entry points.
//!
//! ```no_run
//! use tf_linter::{scan_dir, ScanOptions};
//! let r = scan_dir("fixtures/rules/aws-sg-open-ssh/fail_tfvars_through_local".as_ref(), &ScanOptions::default());
//! for f in &r.findings {
//!     println!("{}", tf_linter::render::render_finding(&r.files, f, false));
//! }
//! ```
//!
//! - [`rule`]: the `Rule` / `RuleMeta` traits (oxc-linter shape), the
//!   object-safe [`DynRule`], [`Finding`] and [`Finding::from_verdict`].
//! - [`engine::Linter`]: dispatch table (resource type → rules) and module
//!   rules, run per module instance.
//! - [`scan`]: root discovery and the parallel (rayon) scan over roots
//!   ([`scan_with`], [`scan_dir`]). Catalogs, selection, plan input and
//!   foreign policies are orchestrated one level up, in `tf_scan`.
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
pub mod suppress;

pub use engine::{ANY_TYPE, Linter, RuleSelectionError, RunOutput, Sources, select_rules};
pub use record::{FindingRecord, RuleError, ScanRecord};
pub use rule::{
    Category, ConfigFile, DynRule, Engine, Finding, FindingSubject, FixAction, FixHint, Hidden,
    Judgement, Level, Rule, RuleFailure, RuleInfo, RuleMeta, RuleSource, Severity, Subject,
};
pub use scan::{ScanOptions, ScanResult, ScanStats, discover_roots, scan_dir, scan_with};

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
//!   object-safe [`DynRule`], [`Finding`] and [`RuleContext`].
//! - [`engine::Linter`]: dispatch table (resource type → rules) and module
//!   rules, run per module instance.
//! - [`scan`]: root discovery and the parallel (rayon) scan;
//!   [`scan_dir`] / [`scan_dir_with_model`] / [`scan_with`].
//! - [`render`]: miette text rendering with provenance, JSON.
//! - [`rules`]: the five seed rules.

pub mod engine;
pub mod render;
pub mod rule;
pub mod rules;
pub mod scan;

pub use engine::Linter;
pub use rule::{
    Category, DynRule, Finding, Level, Rule, RuleContext, RuleInfo, RuleMeta, Severity,
};
pub use scan::{
    ScanOptions, ScanResult, ScanStats, discover_roots, scan_dir, scan_dir_with_model, scan_with,
};

//! Abstract evaluation of HCL expressions for Terraform analysis.
//!
//! - [`value`]: the lattice (`Known` / `Unknown{origin}` / `Tainted` /
//!   `OneOf`), with per-value provenance.
//! - [`prov`]: provenance chains (`Arc`-shared cons lists of file spans with
//!   labels).
//! - [`eval`]: the expression evaluator, generic over a [`eval::Resolver`]
//!   that the semantic layer (`tf_semantic`) implements for module symbols.
//! - [`functions`]: Terraform built-ins.
//! - [`truth`]: four-valued predicate results for rules.
//!
//! This crate is split from `tf_semantic` so that values, functions and the
//! evaluator can be tested (and reused, e.g. by a plan-JSON front end that
//! produces `Known` values directly) without module loading or schemas.

pub mod budget;
pub use budget::EvaluationBudget;
pub mod collections;
mod depth;
pub mod eval;
pub mod functions;
pub mod prov;
pub mod text;
pub mod truth;
pub mod value;

pub use eval::{Evaluator, NoResolver, Resolver, Scope};
pub use prov::{Prov, Step, StepKind};
pub use truth::{Truth, Verdict};
pub use value::{Kind, Known, Map, OneOf, Origin, Taint, Value};

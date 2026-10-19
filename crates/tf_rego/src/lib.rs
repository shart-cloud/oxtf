//! Rego policies on regorus, over one principle: **Rego never sees an
//! abstract value**, so it can never mishandle one. Certainty is always
//! decided on the Rust side.
//!
//! Foreign policies (`policy` files people already have, written for
//! Conftest, OPA or KICS) run unchanged: each resource instance is
//! projected into the input shape the policy expects, Known values only
//! ([`projection`]). A violation is Definite when nothing was hidden from
//! the policy, Conditional when a hidden value traces to an unconstrained
//! variable, Indeterminate when hidden values are provider-computed.
//!
//! Policy errors never become passes: a policy that fails to compile
//! refuses the scan up front ([`catalog`] returns `Err`), and a runtime
//! failure on a resource is returned from the rule hook, so the engine
//! records it as a rule error on the scan.

pub mod foreign;
pub mod hcl2json;
pub mod projection;

use std::fmt;
use std::path::PathBuf;

use tf_linter::rule::DynRule;

pub use projection::Shape;

/// Which policies a scan runs.
#[derive(Clone, Debug, Default)]
pub struct Policies {
    /// Policy files and directories, loaded as one bundle and run
    /// unchanged ([`foreign`]).
    pub foreign: Vec<PathBuf>,
    pub shape: Option<Shape>,
    /// Entry rules the policies' violations are read from, one oxtf rule
    /// each ([`foreign::DEFAULT_ENTRY`] when empty).
    pub entries: Vec<String>,
    /// Parse policies as Rego v0 (`opa eval --v0-compatible`).
    pub rego_v0: bool,
    /// Data documents (Conftest's `--data`).
    pub data: Vec<PathBuf>,
    /// Conftest namespaces (`main` when empty), unless `entries` are named.
    pub namespaces: Vec<String>,
    /// Every namespace (`--all-namespaces`).
    pub all_namespaces: bool,
    /// Files under `foreign` that are not part of the bundle (rule files of
    /// other formats found in the same directory).
    pub exclude: Vec<PathBuf>,
}

impl Policies {
    pub fn is_empty(&self) -> bool {
        self.foreign.is_empty()
    }
}

/// A policy that could not be loaded or compiled, or whose declared
/// interface is wrong. Refuses the scan before it starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PolicyError {}

impl From<String> for PolicyError {
    fn from(s: String) -> Self {
        PolicyError(s)
    }
}

/// The rules the policies contribute: one rule per entry rule. Every
/// policy is compiled and its interface checked here.
pub fn catalog(policies: &Policies) -> Result<Vec<Box<dyn DynRule>>, PolicyError> {
    if policies.foreign.is_empty() {
        return Ok(Vec::new());
    }
    Ok(foreign::rules(&foreign::Options {
        paths: &policies.foreign,
        data: &policies.data,
        entries: &policies.entries,
        namespaces: &policies.namespaces,
        all_namespaces: policies.all_namespaces,
        exclude: &policies.exclude,
        shape: policies.shape.unwrap_or(Shape::Plan),
        rego_v0: policies.rego_v0,
    })?)
}

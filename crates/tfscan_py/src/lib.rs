//! `tfscan._tfscan`: PyO3 bindings for the oxtf engine.
//!
//! Ownership model (see `docs/findings/W6.md`, Q7):
//!
//! - **Scan results / the analysed model.** `tf_semantic::Analysis` is an
//!   owned, `Send + Sync` model (the arena AST is dropped after analysis).
//!   A scan's findings, file table and analyses live in one [`ScanData`]
//!   behind an `Arc`; Python objects ([`Finding`], [`Resource`]) hold the
//!   `Arc` plus indices. No borrow crosses into Python.
//! - **Values.** [`Value`] holds a `tf_eval::Value` (itself `Arc`-shared
//!   and immutable; cloning is a refcount bump) plus the scan's file table
//!   for provenance locations.
//! - **The raw arena AST** (`tfscan.parse`) is the `self_cell` + `Arc` +
//!   node-index prototype in [`ast`].
//!
//! Parse, analyse and scan run with the GIL released (`Python::detach`,
//! PyO3 0.29's name for the former `allow_threads`).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use pyo3::exceptions::{PyKeyError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use tf_eval::{Kind, Known, Truth};
use tf_linter::{Category, DynRule, Judgement, Level, Linter, RuleFailure, RuleInfo};
use tf_scan::{Catalog, ScanInput, ScanRequest};
use tf_semantic::{Analysis, FileTable, Mode, Module};
use tf_span::FileSpan;

mod arrow;
mod ast;

mod commands;
mod findings;
mod resources;
mod results;
mod rules;
mod scanning;
mod values;
use commands::*;
pub use findings::*;
pub use resources::*;
pub use results::*;
pub use rules::*;
use scanning::*;
pub use values::*;

// ---------------------------------------------------------------------------
// Shared scan data
// ---------------------------------------------------------------------------

pub(crate) struct ScanData {
    pub result: tf_linter::ScanResult,
    pub analyses: Vec<Analysis>,
    /// (analysis, module, resource) of every resource / data instance.
    pub resources: Vec<(u32, u32, u32)>,
}

impl ScanData {
    fn new(result: tf_linter::ScanResult, analyses: Vec<Analysis>) -> Self {
        let mut resources = Vec::new();
        for (a, an) in analyses.iter().enumerate() {
            for (m, md) in an.modules.iter().enumerate() {
                for r in 0..md.resources.len() {
                    resources.push((a as u32, m as u32, r as u32));
                }
            }
        }
        ScanData {
            result,
            analyses,
            resources,
        }
    }
    pub fn resource(&self, (a, m, r): (u32, u32, u32)) -> &tf_semantic::Resource {
        &self.analyses[a as usize].modules[m as usize].resources[r as usize]
    }
    pub fn files(&self) -> &FileTable {
        &self.result.files
    }
}

/// `(path, line, column)` of a file span.
pub(crate) fn loc(files: &FileTable, at: FileSpan) -> (String, u32, u32) {
    let f = files.get(at.file);
    let (l, c) = f.line_col(at.span.start);
    (f.path.display().to_string(), l, c)
}

pub(crate) fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::Managed => "managed",
        Mode::Data => "data",
    }
}

pub(crate) fn truth_str(t: Truth) -> &'static str {
    match t {
        Truth::True => "true",
        Truth::False => "false",
        Truth::Tainted => "tainted",
        Truth::Unknown => "unknown",
    }
}

/// JSON with the lattice made explicit: Known parts as plain JSON,
/// `{"$unknown": origin}`, `{"$tainted": "var.x"}`,
/// `{"$one_of": [...], "tainted": bool}`; a `jsonencode` result whose
/// argument is not wholly known is `{"$jsonencode": ...}`.
pub(crate) fn abstract_json(v: &tf_eval::Value) -> serde_json::Value {
    use serde_json::{Value as J, json};
    if v.is_sensitive() {
        return json!({"$sensitive": true});
    }
    match &v.kind {
        Kind::Known(k) => match k {
            Known::Null => J::Null,
            Known::Bool(b) => J::Bool(*b),
            Known::Number(_) => tf_eval::value::to_json(v).unwrap_or(J::Null),
            Known::String(s) => J::String(s.to_string()),
            Known::List(l) => J::Array(l.iter().map(abstract_json).collect()),
            Known::Object(m) => J::Object(
                m.iter()
                    .map(|(k, x)| (k.to_string(), abstract_json(x)))
                    .collect(),
            ),
            Known::Json(inner) => match v.to_str() {
                Some(s) => J::String(s.to_string()),
                None => json!({ "$jsonencode": abstract_json(inner) }),
            },
        },
        Kind::Unknown(o) => json!({ "$unknown": o.to_string() }),
        Kind::Tainted(t) => json!({ "$tainted": format!("var.{}", t.variable) }),
        Kind::OneOf(o) => json!({
            "$one_of": o.alternatives.iter().map(abstract_json).collect::<Vec<_>>(),
            "tainted": o.tainted,
        }),
    }
}

/// A resource's configuration (attributes and nested blocks) as abstract JSON.
pub(crate) fn body_json(b: &tf_semantic::Body) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for a in &b.attrs {
        m.insert(a.name.to_string(), abstract_json(&a.value));
    }
    for bl in &b.blocks {
        let e = m
            .entry(bl.ty.to_string())
            .or_insert_with(|| serde_json::Value::Array(vec![]));
        if let serde_json::Value::Array(v) = e {
            v.push(body_json(&bl.body));
        }
    }
    serde_json::Value::Object(m)
}

#[pymodule]
fn _tfscan(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("CHECKOV_VERSION", tf_scan::CHECKOV_VERSION)?;
    m.add_class::<ScanResult>()?;
    m.add_class::<Finding>()?;
    m.add_class::<Resource>()?;
    m.add_class::<Value>()?;
    m.add_class::<CompiledRule>()?;
    m.add_class::<arrow::ArrowStream>()?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(fetch, m)?)?;
    m.add_function(wrap_pyfunction!(fix_finding, m)?)?;
    m.add_function(wrap_pyfunction!(compile_rules, m)?)?;
    m.add_function(wrap_pyfunction!(builtin_rules, m)?)?;
    m.add_function(wrap_pyfunction!(rules_info, m)?)?;
    m.add_function(wrap_pyfunction!(test_policies, m)?)?;
    m.add("IR_VERSION", tf_rule_ir::IR_VERSION)?;
    m.add("PYO3_VERSION", "0.29.3")?;
    ast::register(m)?;
    Ok(())
}

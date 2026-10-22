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

// ---------------------------------------------------------------------------
// Value
// ---------------------------------------------------------------------------

/// An abstract value (`known`, `unknown`, `tainted`, `one_of`) with
/// provenance.
#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct Value {
    v: tf_eval::Value,
    files: Option<Arc<ScanData>>,
}

impl Value {
    fn wrap(&self, v: tf_eval::Value) -> Value {
        Value {
            v,
            files: self.files.clone(),
        }
    }
}

fn number_to_py(py: Python<'_>, n: f64) -> PyResult<Py<PyAny>> {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        Ok((n as i64).into_pyobject(py)?.into_any().unbind())
    } else {
        Ok(n.into_pyobject(py)?.into_any().unbind())
    }
}

/// Convert to Python: Known scalars/lists/objects to Python objects, any
/// abstract part to a `Value` handle.
fn to_py(py: Python<'_>, v: &tf_eval::Value, files: &Option<Arc<ScanData>>) -> PyResult<Py<PyAny>> {
    Ok(match &v.kind {
        Kind::Known(k) => match k {
            Known::Null => py.None(),
            Known::Bool(b) => b.into_pyobject(py)?.to_owned().into_any().unbind(),
            Known::Number(n) => number_to_py(py, *n)?,
            Known::String(s) => s.as_ref().into_pyobject(py)?.into_any().unbind(),
            Known::Json(_) => match v.to_str() {
                Some(s) => s.as_ref().into_pyobject(py)?.into_any().unbind(),
                None => Py::new(
                    py,
                    Value {
                        v: v.clone(),
                        files: files.clone(),
                    },
                )?
                .into_any(),
            },
            Known::List(l) => {
                let out = PyList::empty(py);
                for x in l.iter() {
                    out.append(to_py(py, &x.child_of(v), files)?)?;
                }
                out.into_any().unbind()
            }
            Known::Object(m) => {
                let out = PyDict::new(py);
                for (k, x) in m.iter() {
                    out.set_item(k.as_ref(), to_py(py, &x.child_of(v), files)?)?;
                }
                out.into_any().unbind()
            }
        },
        _ => Py::new(
            py,
            Value {
                v: v.clone(),
                files: files.clone(),
            },
        )?
        .into_any(),
    })
}

fn steps_to_py<'py>(
    py: Python<'py>,
    steps: &[tf_eval::Step],
    files: Option<&FileTable>,
) -> PyResult<Bound<'py, PyList>> {
    let out = PyList::empty(py);
    for s in steps {
        let d = PyDict::new(py);
        d.set_item("kind", s.kind.as_str())?;
        d.set_item("label", s.label.as_ref())?;
        if let Some(files) = files {
            let (f, l, c) = loc(files, s.at);
            d.set_item("file", f)?;
            d.set_item("line", l)?;
            d.set_item("column", c)?;
        }
        d.set_item("resource", s.resource.as_deref())?;
        d.set_item("attribute", s.attribute.as_deref())?;
        out.append(d)?;
    }
    Ok(out)
}

/// Plain JSON to Python objects (dicts, lists, str, int/float, bool, None).
fn json_to_py(py: Python<'_>, j: &serde_json::Value) -> PyResult<Py<PyAny>> {
    use serde_json::Value as J;
    Ok(match j {
        J::Null => py.None(),
        J::Bool(b) => b.into_pyobject(py)?.to_owned().into_any().unbind(),
        J::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => i.into_pyobject(py)?.into_any().unbind(),
            (None, Some(f)) => f.into_pyobject(py)?.into_any().unbind(),
            _ => py.None(),
        },
        J::String(s) => s.into_pyobject(py)?.into_any().unbind(),
        J::Array(items) => {
            let out = PyList::empty(py);
            for x in items {
                out.append(json_to_py(py, x)?)?;
            }
            out.into_any().unbind()
        }
        J::Object(m) => {
            let out = PyDict::new(py);
            for (k, v) in m {
                out.set_item(k, json_to_py(py, v)?)?;
            }
            out.into_any().unbind()
        }
    })
}

#[pymethods]
impl Value {
    /// `"known"`, `"unknown"`, `"tainted"` or `"one_of"`.
    #[getter]
    fn kind(&self) -> &'static str {
        match &self.v.kind {
            Kind::Known(_) => "known",
            Kind::Unknown(_) => "unknown",
            Kind::Tainted(_) => "tainted",
            Kind::OneOf(_) => "one_of",
        }
    }
    #[getter]
    fn is_known(&self) -> bool {
        self.v.is_known()
    }
    #[getter]
    fn is_wholly_known(&self) -> bool {
        self.v.is_wholly_known()
    }
    #[getter]
    fn is_null(&self) -> bool {
        self.v.is_null()
    }
    /// Type of a Known value (`null`, `bool`, `number`, `string`, `list`,
    /// `object`), else the kind.
    #[getter]
    fn type_name(&self) -> &'static str {
        self.v.type_name()
    }
    /// The unconstrained variable a Tainted value depends on.
    #[getter]
    fn variable(&self) -> Option<String> {
        match &self.v.kind {
            Kind::Tainted(t) => Some(t.variable.to_string()),
            _ => None,
        }
    }
    /// Why an Unknown value is unknown.
    #[getter]
    fn origin(&self) -> Option<String> {
        self.v.origin().map(|o| {
            if self.v.is_sensitive() {
                "(sensitive)".into()
            } else {
                o.to_string()
            }
        })
    }
    /// Whether presentation/export should redact this value.
    #[getter]
    fn sensitive(&self) -> bool {
        self.v.is_sensitive()
    }
    /// Alternatives of a OneOf (provenance joined), else `[]`.
    #[getter]
    fn alternatives(&self) -> Vec<Value> {
        match &self.v.kind {
            Kind::OneOf(o) => o
                .alternatives
                .iter()
                .map(|a| self.wrap(a.child_of(&self.v)))
                .collect(),
            _ => vec![],
        }
    }
    /// For a OneOf: does the ambiguity come from an unconstrained variable?
    #[getter]
    fn tainted(&self) -> bool {
        match &self.v.kind {
            Kind::OneOf(o) => o.tainted,
            Kind::Tainted(_) => true,
            _ => false,
        }
    }
    /// Elements of a Known list as Values (provenance joined), else `None`.
    fn items(&self) -> Option<Vec<Value>> {
        self.v
            .as_list()
            .map(|l| l.iter().map(|x| self.wrap(x.child_of(&self.v))).collect())
    }
    /// Field of an object (missing → null), lifted over OneOf; Unknown /
    /// Tainted receivers return themselves.
    fn get(&self, name: &str) -> Value {
        self.wrap(self.v.field_or_null(name))
    }
    /// A Known `null`.
    #[staticmethod]
    fn null() -> Value {
        Value {
            v: tf_eval::Value::null(),
            files: None,
        }
    }
    /// Terraform string conversion of a Known primitive (else `None`).
    fn to_str(&self) -> Option<String> {
        self.v.to_str().map(|s| s.to_string())
    }
    fn as_number(&self) -> Option<f64> {
        self.v.as_number()
    }
    fn as_bool(&self) -> Option<bool> {
        self.v.as_bool()
    }
    /// Python conversion; abstract parts stay `Value` handles.
    fn py(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        to_py(py, &self.v, &self.files)
    }
    /// JSON with the lattice explicit (`{"$unknown": ...}` etc.).
    fn to_json(&self) -> String {
        abstract_json(&self.v).to_string()
    }
    /// Origin-first provenance steps.
    #[getter]
    fn provenance<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        steps_to_py(
            py,
            &self.v.prov.steps(),
            self.files.as_deref().map(|d| d.files()),
        )
    }
    fn __repr__(&self) -> String {
        format!("Value({})", self.v)
    }
    fn __str__(&self) -> String {
        self.v.to_string()
    }
}

// ---------------------------------------------------------------------------
// Resource
// ---------------------------------------------------------------------------

enum ResSrc {
    /// From a finished scan: shared data plus indices.
    Scan(Arc<ScanData>, (u32, u32, u32)),
    /// Inside a callback rule: a copy of the resource (the analysis is
    /// borrowed by the engine during the scan, so it cannot be shared).
    Owned(Arc<tf_semantic::Resource>),
}

/// A resource or data-source instance of the analysed model.
#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct Resource {
    src: ResSrc,
}

impl Resource {
    fn res(&self) -> &tf_semantic::Resource {
        match &self.src {
            ResSrc::Scan(d, i) => d.resource(*i),
            ResSrc::Owned(r) => r,
        }
    }
    fn data(&self) -> Option<Arc<ScanData>> {
        match &self.src {
            ResSrc::Scan(d, _) => Some(d.clone()),
            ResSrc::Owned(_) => None,
        }
    }
    fn value(&self, v: tf_eval::Value) -> Value {
        Value {
            v,
            files: self.data(),
        }
    }
}

#[pymethods]
impl Resource {
    #[getter]
    fn address(&self) -> &str {
        &self.res().address
    }
    #[getter]
    fn base_address(&self) -> &str {
        &self.res().base_address
    }
    #[getter]
    fn r#type(&self) -> &str {
        &self.res().ty
    }
    #[getter]
    fn name(&self) -> &str {
        &self.res().name
    }
    #[getter]
    fn module(&self) -> &str {
        &self.res().module
    }
    #[getter]
    fn key(&self) -> Option<&str> {
        self.res().key.as_deref()
    }
    #[getter]
    fn mode(&self) -> &'static str {
        mode_str(self.res().mode)
    }
    /// `"true"`, `"tainted"` (count/for_each on an unconstrained variable)
    /// or `"unknown"`.
    #[getter]
    fn existence(&self) -> &'static str {
        truth_str(self.res().existence)
    }
    #[getter]
    fn root(&self) -> Option<String> {
        match &self.src {
            ResSrc::Scan(d, (a, _, _)) => {
                Some(d.analyses[*a as usize].root_dir.display().to_string())
            }
            ResSrc::Owned(_) => None,
        }
    }
    #[getter]
    fn file(&self) -> Option<String> {
        self.data().map(|d| loc(d.files(), self.res().span).0)
    }
    #[getter]
    fn line(&self) -> Option<u32> {
        self.data().map(|d| loc(d.files(), self.res().span).1)
    }
    /// Names of the top-level attributes set in configuration.
    fn keys(&self) -> Vec<String> {
        self.res()
            .body
            .attrs
            .iter()
            .map(|a| a.name.to_string())
            .collect()
    }
    /// Attribute value (`KeyError` if not set).
    fn __getitem__(&self, name: &str) -> PyResult<Value> {
        self.res()
            .value(name)
            .map(|v| self.value(v))
            .ok_or_else(|| PyKeyError::new_err(name.to_string()))
    }
    fn __contains__(&self, name: &str) -> bool {
        self.res().attr(name).is_some()
    }
    /// Attribute value, or `None` if not set.
    fn get(&self, name: &str) -> Option<Value> {
        self.res().value(name).map(|v| self.value(v))
    }
    /// Attribute value, or the provider default from the defaults overlay.
    fn get_or_default(&self, name: &str) -> Option<Value> {
        self.res().value_or_default(name).map(|v| self.value(v))
    }
    /// All attributes and nested blocks as abstract JSON.
    fn to_json(&self) -> String {
        body_json(&self.res().body).to_string()
    }
    /// Configured values in Checkov's dict-of-lists shape, retaining unknowns.
    fn checkov_configuration(&self) -> Value {
        self.value(tf_rule_ir::checkov::configuration(&self.res().body))
    }
    fn __repr__(&self) -> String {
        format!("Resource({})", self.res().address)
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct Finding {
    data: Arc<ScanData>,
    i: usize,
}

impl Finding {
    fn f(&self) -> &tf_linter::Finding {
        &self.data.result.findings[self.i]
    }
    fn record(&self) -> serde_json::Value {
        tf_linter::render::finding_json(self.data.files(), self.f())
    }
    fn record_field(&self, py: Python<'_>, field: &str) -> PyResult<Py<PyAny>> {
        json_to_py(py, &self.record()[field])
    }
}

#[pymethods]
impl Finding {
    #[getter]
    fn rule(&self) -> &str {
        &self.f().rule
    }
    #[getter]
    fn level(&self) -> &'static str {
        self.f().level.as_str()
    }
    /// `"definite"`, `"conditional"` or `"indeterminate"` (foreign policies only).
    #[getter]
    fn certainty(&self) -> &'static str {
        self.f().certainty.as_str()
    }
    #[getter]
    fn address(&self) -> &str {
        &self.f().address
    }
    #[getter]
    fn resource_type(&self) -> Option<&str> {
        self.f().resource_type.as_deref()
    }
    #[getter]
    fn module(&self) -> &str {
        &self.f().module
    }
    #[getter]
    fn message(&self) -> &str {
        &self.f().message
    }
    #[getter]
    fn root(&self) -> String {
        self.f().root.display().to_string()
    }
    /// Stable identity across scans (rule, repository-relative file, local
    /// address, attribute path); shared by every occurrence of a finding.
    #[getter]
    fn fingerprint(&self) -> String {
        tf_linter::record::finding_fingerprint(
            self.data.files(),
            self.f(),
            &mut tf_linter::record::RepoRoots::new(),
        )
    }
    #[getter]
    fn category(&self) -> &'static str {
        self.f().category.as_str()
    }
    #[getter]
    fn description(&self) -> &str {
        &self.f().description
    }
    /// Attribute path of the deciding value within the resource, if any.
    #[getter]
    fn attribute(&self) -> Option<&str> {
        self.f().attribute.as_deref()
    }
    /// The deciding top-level attribute as written: `{"kind", "value", "display"}`, or None.
    #[getter]
    fn configured(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "configured")
    }
    /// The same after the defaults overlay.
    #[getter]
    fn effective(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "effective")
    }
    /// A mechanical fix (`resource`, `attribute`, `action`, `value`, `site`), or None.
    #[getter]
    fn fix_hint(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "fix_hint")
    }
    /// Inputs a foreign policy could not see: `[{"path", "kind"}]`.
    #[getter]
    fn hidden(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "hidden")
    }
    /// The resource instance's identity, structured; None for a finding on
    /// a file.
    #[getter]
    fn resource(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "resource")
    }
    /// What the finding is about: `{"kind": "resource", "address"}` or
    /// `{"kind": "file", "file", "module"}`.
    #[getter]
    fn subject(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "subject")
    }
    /// The whole finding record (`docs/FINDING_SCHEMA.md`) as a dict.
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_to_py(py, &self.record())
    }
    #[getter]
    fn file(&self) -> String {
        loc(self.data.files(), self.f().primary).0
    }
    #[getter]
    fn line(&self) -> u32 {
        loc(self.data.files(), self.f().primary).1
    }
    #[getter]
    fn column(&self) -> u32 {
        loc(self.data.files(), self.f().primary).2
    }
    /// Origin-first provenance chain: dicts with kind, label, file, line,
    /// column, resource.
    #[getter]
    fn provenance<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        steps_to_py(py, &self.f().provenance, Some(self.data.files()))
    }
    /// miette rendering (with the provenance chain).
    #[pyo3(signature = (color = false))]
    fn render(&self, color: bool) -> String {
        tf_linter::render::render_finding(self.data.files(), self.f(), color)
    }
    fn to_json(&self) -> String {
        tf_linter::render::finding_json(self.data.files(), self.f()).to_string()
    }
    fn __repr__(&self) -> String {
        let f = self.f();
        format!(
            "Finding({} {} {} {:?})",
            f.rule,
            f.certainty.as_str(),
            f.address,
            f.message
        )
    }
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct ScanResult {
    data: Arc<ScanData>,
}

#[pymethods]
impl ScanResult {
    #[getter]
    fn status(&self) -> &'static str {
        self.data.result.status().as_str()
    }
    #[getter]
    fn findings(&self) -> Vec<Finding> {
        (0..self.data.result.findings.len())
            .map(|i| Finding {
                data: self.data.clone(),
                i,
            })
            .collect()
    }
    /// Every resource and data-source instance of every analysed module.
    #[getter]
    fn resources(&self) -> Vec<Resource> {
        self.data
            .resources
            .iter()
            .map(|&i| Resource {
                src: ResSrc::Scan(self.data.clone(), i),
            })
            .collect()
    }
    #[getter]
    fn resource_count(&self) -> usize {
        self.data.resources.len()
    }
    #[getter]
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = &self.data.result.stats;
        let d = PyDict::new(py);
        d.set_item("roots", s.roots)?;
        d.set_item("module_instances", s.module_instances)?;
        d.set_item("files", s.files)?;
        d.set_item("resources", s.resources)?;
        d.set_item("findings", s.findings)?;
        d.set_item("definite", s.definite)?;
        d.set_item("conditional", s.conditional)?;
        d.set_item("indeterminate", s.indeterminate)?;
        d.set_item("elapsed_s", s.elapsed.as_secs_f64())?;
        d.set_item(
            "findings_by_rule",
            s.findings_by_rule.clone().into_pyobject(py)?,
        )?;
        Ok(d)
    }
    /// Rules that failed on some resource: dicts with `rule`, `resource`
    /// (or None) and `message`. Never silent; see `docs/FINDING_SCHEMA.md`.
    #[getter]
    fn rule_errors<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        for e in &self.data.result.rule_errors {
            let d = PyDict::new(py);
            d.set_item("rule", &e.rule)?;
            d.set_item("resource", e.resource.as_deref())?;
            d.set_item("message", &e.message)?;
            out.append(d)?;
        }
        Ok(out)
    }
    /// Findings a `checkov:skip` line suppressed: dicts with `rule`,
    /// `resource`, `comment`, `file` and `line`.
    #[getter]
    fn suppressed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        for x in &self.data.result.suppressed {
            let (file, line, _) = loc(self.data.files(), x.at);
            let d = PyDict::new(py);
            d.set_item("rule", x.rule.as_ref())?;
            d.set_item("resource", x.address.as_ref())?;
            d.set_item("comment", &x.comment)?;
            d.set_item("file", file)?;
            d.set_item("line", line)?;
            out.append(d)?;
        }
        Ok(out)
    }
    /// Each scanned root's own completion: `path` and `status`.
    #[getter]
    fn roots<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        for root in &self.data.result.roots {
            let d = PyDict::new(py);
            d.set_item("path", root.dir.display().to_string())?;
            d.set_item("status", root.status.as_str())?;
            out.append(d)?;
        }
        Ok(out)
    }
    #[getter]
    fn diagnostics<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        for x in &self.data.result.diagnostics {
            let d = PyDict::new(py);
            d.set_item("severity", format!("{:?}", x.severity).to_lowercase())?;
            d.set_item("code", x.code)?;
            d.set_item("message", &x.message)?;
            if let Some(at) = x.at {
                let (f, l, c) = loc(self.data.files(), at);
                d.set_item("file", f)?;
                d.set_item("line", l)?;
                d.set_item("column", c)?;
                d.set_item("start", at.span.start)?;
                d.set_item("end", at.span.end)?;
            }
            out.append(d)?;
        }
        Ok(out)
    }
    /// Same JSON as `oxtf scan --format json`.
    fn to_json(&self) -> String {
        tf_linter::render::result_json(&self.data.result).to_string()
    }
    /// Findings as an Arrow C stream (`__arrow_c_stream__` capsule holder);
    /// `tfscan.ScanResult.findings_arrow()` turns it into a `pyarrow.Table`.
    fn _findings_stream(&self, py: Python<'_>) -> PyResult<arrow::ArrowStream> {
        let d = self.data.clone();
        let batch = py
            .detach(move || arrow::findings_batch(&d))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(arrow::ArrowStream::new(batch))
    }
    fn _resources_stream(&self, py: Python<'_>) -> PyResult<arrow::ArrowStream> {
        let d = self.data.clone();
        let batch = py
            .detach(move || arrow::resources_batch(&d))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(arrow::ArrowStream::new(batch))
    }
    fn __repr__(&self) -> String {
        let s = &self.data.result.stats;
        format!(
            "ScanResult(findings={}, roots={}, resources={}, files={})",
            s.findings, s.roots, s.resources, s.files
        )
    }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// A rule compiled from the JSON rule IR (validated in Rust).
#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct CompiledRule {
    json: String,
    name: String,
}

#[pymethods]
impl CompiledRule {
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }
    /// The IR re-serialized by Rust (`serde_json`), for round-trip checks.
    fn to_json(&self) -> String {
        self.json.clone()
    }
}

/// Parse + validate rule IR JSON (one rule, a list, or `{"rules": [...]}`).
#[pyfunction]
fn compile_rules(json: &str) -> PyResult<Vec<CompiledRule>> {
    let specs = tf_rule_ir::parse_rules(json).map_err(PyValueError::new_err)?;
    specs
        .into_iter()
        .map(|s| {
            let json = serde_json::to_string(&s).expect("serialize");
            let name = s.name.clone();
            tf_rule_ir::compile(s).map_err(PyValueError::new_err)?;
            Ok(CompiledRule { json, name })
        })
        .collect()
}

/// A Python callback rule: called (with the GIL) for each resource that
/// passes the Rust-side type filter.
struct CallbackRule {
    info: RuleInfo,
    func: Py<PyAny>,
    error: Arc<Mutex<Option<PyErr>>>,
    calls: Arc<std::sync::atomic::AtomicU64>,
    record_errors: bool,
}

struct Report {
    message: String,
    witness: Option<tf_eval::Value>,
    conditional: bool,
    indeterminate: bool,
    hidden: Vec<tf_linter::Hidden>,
}

fn parse_reports(ret: &Bound<'_, PyAny>, out: &mut Vec<Report>) -> PyResult<()> {
    if ret.is_none() {
        return Ok(());
    }
    if let Ok(b) = ret.extract::<bool>() {
        if b {
            out.push(Report {
                message: String::new(),
                witness: None,
                conditional: false,
                indeterminate: false,
                hidden: Vec::new(),
            });
        }
        return Ok(());
    }
    if let Ok(s) = ret.extract::<String>() {
        if !s.is_empty() {
            out.push(Report {
                message: s,
                witness: None,
                conditional: false,
                indeterminate: false,
                hidden: Vec::new(),
            });
        }
        return Ok(());
    }
    if let Ok(l) = ret.cast::<PyList>() {
        for x in l.iter() {
            parse_reports(&x, out)?;
        }
        return Ok(());
    }
    // tfscan.Report(message, witness=None, conditional=False)
    let message: String = ret.getattr("message")?.extract()?;
    let conditional: bool = ret.getattr("conditional")?.extract()?;
    let indeterminate: bool = ret
        .getattr("indeterminate")
        .map(|v| v.extract())
        .unwrap_or(Ok(false))?;
    let mut hidden = Vec::new();
    if let Ok(items) = ret.getattr("hidden") {
        for (path, kind) in items.extract::<Vec<(String, String)>>()? {
            let truth = match kind.as_str() {
                "tainted" => tf_eval::Truth::Tainted,
                "unknown" => tf_eval::Truth::Unknown,
                _ => {
                    return Err(PyValueError::new_err(
                        "hidden kind must be tainted or unknown",
                    ));
                }
            };
            hidden.push(tf_linter::Hidden { path, truth });
        }
    }
    let w = ret.getattr("witness")?;
    let witness = if w.is_none() {
        None
    } else {
        Some(w.cast::<Value>()?.get().v.clone())
    };
    out.push(Report {
        message,
        witness,
        conditional,
        indeterminate,
        hidden,
    });
    Ok(())
}

impl DynRule for CallbackRule {
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn judge_resource(&self, r: &tf_semantic::Resource) -> Result<Vec<Judgement>, RuleFailure> {
        if self.error.lock().unwrap().is_some() {
            return Err("skipped after an earlier exception".into());
        }
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let res = Arc::new(r.clone());
        let reports = Python::attach(|py| -> PyResult<Vec<Report>> {
            let obj = Py::new(
                py,
                Resource {
                    src: ResSrc::Owned(res),
                },
            )?;
            let ret = self.func.call1(py, (obj,))?;
            let mut out = Vec::new();
            parse_reports(ret.bind(py), &mut out)?;
            Ok(out)
        });
        match reports {
            Ok(reports) => Ok(reports
                .into_iter()
                .map(|rep| Judgement {
                    certainty: if rep.indeterminate {
                        tf_linter::Certainty::Indeterminate
                    } else if rep.conditional {
                        tf_linter::Certainty::Conditional
                    } else {
                        tf_linter::Certainty::Definite
                    },
                    witness: rep.witness,
                    message: rep.message,
                    hidden: rep.hidden,
                    fix_hint: None,
                })
                .collect()),
            Err(e) => {
                // By default re-raise once the pool drains. Foreign adapters
                // may instead retain the error in the scan result and continue.
                let message = e.to_string();
                if !self.record_errors {
                    let mut g = self.error.lock().unwrap();
                    if g.is_none() {
                        *g = Some(e);
                    }
                }
                Err(message)
            }
        }
    }
    fn judge_module<'m>(
        &self,
        _m: &'m Module,
    ) -> Result<Vec<(&'m tf_semantic::Resource, Judgement)>, RuleFailure> {
        Ok(Vec::new())
    }
}

fn level_of(s: &str) -> PyResult<Level> {
    Ok(match s {
        "low" => Level::Low,
        "medium" => Level::Medium,
        "high" => Level::High,
        "critical" => Level::Critical,
        _ => return Err(PyValueError::new_err(format!("unknown level {s:?}"))),
    })
}

fn category_of(s: &str) -> PyResult<Category> {
    Ok(match s {
        "network" => Category::Network,
        "storage" => Category::Storage,
        "iam" => Category::Iam,
        "encryption" => Category::Encryption,
        "other" => Category::Other,
        _ => return Err(PyValueError::new_err(format!("unknown category {s:?}"))),
    })
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

type CallbackError = Arc<Mutex<Option<PyErr>>>;
type CallCount = Arc<std::sync::atomic::AtomicU64>;

/// The catalog a Python call describes: seed rules (or not), rule-IR
/// documents, callback rules and Rego policies.
struct PyCatalog {
    catalog: Catalog,
    error: CallbackError,
    calls: CallCount,
}

/// Rule files and policy options, as `oxtf --rule-file` and its policy
/// flags take them.
#[derive(Default)]
struct PolicyArgs {
    /// Any format, detected per file (`--rule-file`, `--policy`).
    rule_files: Vec<PathBuf>,
    data: Vec<PathBuf>,
    namespaces: Vec<String>,
    all_namespaces: bool,
    entries: Vec<String>,
    shape: Option<String>,
    rego_v0: bool,
}

impl PolicyArgs {
    fn catalog(self, builtin: bool, bundled: bool, ir_rules: Vec<String>) -> PyResult<Catalog> {
        let shape = self
            .shape
            .as_deref()
            .map(|s| s.parse::<tf_scan::Shape>().map_err(PyValueError::new_err))
            .transpose()?;
        Ok(Catalog {
            // `builtin=False` means nothing shipped, as `oxtf --no-builtin`.
            bundled: builtin && bundled,
            builtin,
            rule_files: self.rule_files,
            rule_json: ir_rules,
            runtime: Vec::new(),
            profiles: None,
            policies: tf_rego::Policies {
                shape,
                entries: self.entries,
                rego_v0: self.rego_v0,
                data: self.data,
                namespaces: self.namespaces,
                all_namespaces: self.all_namespaces,
                ..Default::default()
            },
        })
    }
}

fn build_catalog(
    builtin: bool,
    bundled: bool,
    ir_rules: Vec<String>,
    callbacks: Vec<Bound<'_, PyAny>>,
    policy: PolicyArgs,
) -> PyResult<PyCatalog> {
    let mut catalog = policy.catalog(builtin, bundled, ir_rules)?;
    let error = Arc::new(Mutex::new(None));
    let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
    for cb in &callbacks {
        let types: Vec<String> = cb.getattr("resource_types")?.extract()?;
        catalog.runtime.push(Box::new(CallbackRule {
            info: RuleInfo {
                name: Arc::from(cb.getattr("name")?.extract::<String>()?.as_str()),
                category: category_of(&cb.getattr("category")?.extract::<String>()?)?,
                level: level_of(&cb.getattr("level")?.extract::<String>()?)?,
                description: Arc::from(cb.getattr("description")?.extract::<String>()?.as_str()),
                resource_types: types.iter().map(|t| Arc::from(t.as_str())).collect(),
                runs_on_module: false,
                guideline: None,
                rationale: None,
                remediation: None,
                source: tf_linter::RuleSource {
                    engine: tf_linter::Engine::Python,
                    file: None,
                    line: None,
                },
                aliases: Vec::new(),
                profile: tf_linter::Profile::Security,
            },
            func: cb.getattr("func")?.unbind(),
            error: error.clone(),
            calls: calls.clone(),
            record_errors: cb
                .getattr("record_errors")
                .map(|v| v.extract())
                .unwrap_or(Ok(false))?,
        }));
    }
    Ok(PyCatalog {
        catalog,
        error,
        calls,
    })
}

fn scan_error(e: tf_scan::ScanError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Run one scan request. `paths` are root module directories, or `plan`
/// is a `terraform show -json` file (with `source` as its module
/// directory). `builtin`: run the shipped rules; `bundled`: with them, the
/// bundled Checkov catalog (`tf_rule_ir::bundled`), not only the seed
/// rules. `select`: rule ids from the
/// whole catalog, or `None` for all. `ir_rules`: rule IR JSON documents.
/// `callbacks`: `tfscan.CallbackRule` objects (attributes `name`,
/// `resource_types`, `level`, `category`, `description`, `func`).
/// `rule_files`: rule files and directories of any format (rule IR,
/// Checkov policies, Rego), as `oxtf --rule-file`; `policies` is an alias.
/// `data`, `namespaces`, `all_namespaces`, `policy_entries` (OPA mode),
/// `policy_shape` and `rego_v0` are the policy flags; `policy_entry` adds
/// one entry. `overlay`: `(path, text)` pairs that shadow the disk for this
/// scan.
#[pyfunction]
#[pyo3(signature = (paths=vec![], recursive=false, plan=None, source=None, var_files=vec![], builtin=true, select=None, ir_rules=vec![], callbacks=vec![], policies=vec![], policy_shape=None, policy_entry=None, overlay=vec![], threads=None, _release_gil=true, rule_files=vec![], data=vec![], namespaces=vec![], all_namespaces=false, policy_entries=vec![], rego_v0=false, bundled=true, profiles=None, data_dir=None, limits=None, fetch=false))]
#[allow(clippy::too_many_arguments)]
fn scan(
    py: Python<'_>,
    paths: Vec<PathBuf>,
    recursive: bool,
    plan: Option<PathBuf>,
    source: Option<PathBuf>,
    var_files: Vec<PathBuf>,
    builtin: bool,
    select: Option<Vec<String>>,
    ir_rules: Vec<String>,
    callbacks: Vec<Bound<'_, PyAny>>,
    policies: Vec<PathBuf>,
    policy_shape: Option<&str>,
    policy_entry: Option<String>,
    overlay: Vec<(PathBuf, String)>,
    threads: Option<usize>,
    _release_gil: bool,
    rule_files: Vec<PathBuf>,
    data: Vec<PathBuf>,
    namespaces: Vec<String>,
    all_namespaces: bool,
    policy_entries: Vec<String>,
    rego_v0: bool,
    bundled: bool,
    profiles: Option<Vec<String>>,
    data_dir: Option<PathBuf>,
    limits: Option<Bound<'_, PyDict>>,
    fetch: bool,
) -> PyResult<(ScanResult, u64)> {
    if !_release_gil && !callbacks.is_empty() {
        // Workers would block on the GIL held by this thread.
        return Err(PyValueError::new_err(
            "_release_gil=False (test control) cannot run callback rules",
        ));
    }
    let (request, error, calls) = scan_request(ScanArgs {
        paths,
        recursive,
        plan,
        source,
        var_files,
        data_dir,
        limits: parse_limits(limits.as_ref())?,
        builtin,
        select,
        ir_rules,
        callbacks,
        policies,
        policy_shape,
        policy_entry,
        overlay,
        threads,
        rule_files,
        data,
        namespaces,
        all_namespaces,
        policy_entries,
        rego_v0,
        bundled,
        profiles,
    })?;
    let run = if fetch {
        tf_scan::scan_fetching
    } else {
        tf_scan::scan
    };
    let work = move || run(request).map(|o| ScanData::new(o.result, o.analyses));
    let data = if _release_gil {
        py.detach(work)
    } else {
        work()
    };
    if let Some(e) = error.lock().unwrap().take() {
        return Err(e);
    }
    Ok((
        ScanResult {
            data: Arc::new(data.map_err(scan_error)?),
        },
        calls.load(std::sync::atomic::Ordering::Relaxed),
    ))
}

/// The arguments of [`scan`] and [`fix_finding`], which build the same
/// request.
struct ScanArgs<'py, 's> {
    limits: tf_scan::Limits,
    paths: Vec<PathBuf>,
    recursive: bool,
    plan: Option<PathBuf>,
    source: Option<PathBuf>,
    var_files: Vec<PathBuf>,
    data_dir: Option<PathBuf>,
    builtin: bool,
    select: Option<Vec<String>>,
    ir_rules: Vec<String>,
    callbacks: Vec<Bound<'py, PyAny>>,
    policies: Vec<PathBuf>,
    policy_shape: Option<&'s str>,
    policy_entry: Option<String>,
    overlay: Vec<(PathBuf, String)>,
    threads: Option<usize>,
    rule_files: Vec<PathBuf>,
    data: Vec<PathBuf>,
    namespaces: Vec<String>,
    all_namespaces: bool,
    policy_entries: Vec<String>,
    rego_v0: bool,
    bundled: bool,
    profiles: Option<Vec<String>>,
}

fn parse_limits(limits: Option<&Bound<'_, PyDict>>) -> PyResult<tf_scan::Limits> {
    let Some(limits) = limits else {
        return Ok(tf_scan::Limits::default());
    };
    let mut parsed = tf_scan::Limits::default();
    for (key, value) in limits.iter() {
        let key: String = key
            .extract()
            .map_err(|_| PyValueError::new_err("invalid limits key"))?;
        if value.is_instance_of::<pyo3::types::PyBool>() {
            return Err(PyValueError::new_err(format!(
                "{key} must be a positive integer"
            )));
        }
        let value: u64 = value.extract().map_err(|_| {
            PyValueError::new_err(format!("{key} must be a positive integer fitting u64"))
        })?;
        parsed = match key.as_str() {
            "evaluation_steps" => parsed.with_evaluation_steps(value),
            "loader_steps" => parsed.with_loader_steps(value),
            "rule_steps" => parsed.with_rule_steps(value),
            "rego_time_ms" => parsed.with_rego_time_ms(value),
            "input_bytes" => parsed.with_input_bytes(value),
            "source_bytes" => parsed.with_source_bytes(value),
            "file_entries" => parsed.with_file_entries(value),
            "directory_entries" => parsed.with_directory_entries(value),
            "roots" => parsed.with_roots(value),
            "arena_bytes" => parsed.with_arena_bytes(value),
            "ast_nodes" => parsed.with_ast_nodes(value),
            "text_bytes" => parsed.with_text_bytes(value),
            "collection_bytes" => parsed.with_collection_bytes(value),
            "results" => parsed.with_results(value),
            _ => {
                return Err(PyValueError::new_err(format!(
                    "unknown limits field {key:?}"
                )));
            }
        }
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    }
    Ok(parsed)
}

fn scan_request(a: ScanArgs<'_, '_>) -> PyResult<(ScanRequest, CallbackError, CallCount)> {
    let PyCatalog {
        catalog,
        error,
        calls,
    } = build_catalog(
        a.builtin,
        a.bundled,
        a.ir_rules,
        a.callbacks,
        PolicyArgs {
            rule_files: a.rule_files.into_iter().chain(a.policies).collect(),
            data: a.data,
            namespaces: a.namespaces,
            all_namespaces: a.all_namespaces,
            entries: a.policy_entries.into_iter().chain(a.policy_entry).collect(),
            shape: a.policy_shape.map(str::to_string),
            rego_v0: a.rego_v0,
        },
    )?;
    let mut catalog = catalog;
    if let Some(names) = a.profiles {
        let mut profiles = Vec::new();
        for name in &names {
            match name.as_str() {
                "all" => profiles.extend_from_slice(tf_scan::ALL_PROFILES),
                "security" | "audit" | "hygiene" => {
                    profiles.push(tf_linter::Profile::parse(name).expect("a profile name"))
                }
                other => {
                    return Err(PyValueError::new_err(format!(
                        "unknown profile {other:?} (security, audit, hygiene, all)"
                    )));
                }
            }
        }
        catalog.profiles = Some(profiles);
    }
    let input = match a.plan {
        Some(plan) => {
            if !a.paths.is_empty() || a.recursive {
                return Err(PyValueError::new_err(
                    "a plan scan takes no paths and is not recursive",
                ));
            }
            ScanInput::Plan {
                plan,
                source: a.source,
            }
        }
        None => ScanInput::Dirs {
            paths: a.paths,
            recursive: a.recursive,
        },
    };
    let request = ScanRequest {
        limits: a.limits,
        input,
        catalog,
        selection: a.select,
        var_files: a.var_files,
        data_dir: a.data_dir,
        threads: a.threads,
        overlay: a
            .overlay
            .into_iter()
            .map(|(p, t)| (p, Arc::from(t)))
            .collect(),
        keep_models: true,
    };
    Ok((request, error, calls))
}

/// Fix the finding with `fingerprint` in the scan the other arguments
/// describe (as [`scan`]'s, without callback rules): its fix hint applied
/// in memory and the source rescanned with the edit as an overlay
/// (`tf_scan::fix`). Returns a dict: `fingerprint`, `rule`, `file`,
/// `resource`, `attribute`, `action`, `value`, `site` (`attribute` or
/// `default`: where the literal went; `at` picks one, else a variable's
/// default is tried first), `original` and `text` (the file before and
/// after), `diff` (unified), `finding_delta`, `target_resolved`,
/// `no_new_findings`, and `verified` (both checks passed with complete scans).
/// Nothing is written. Raises `ValueError` when no
/// finding has the fingerprint, it has no fix hint, or the scan fails.
#[pyfunction]
#[pyo3(signature = (fingerprint, paths=vec![], recursive=false, plan=None, source=None, var_files=vec![], builtin=true, select=None, ir_rules=vec![], policies=vec![], policy_shape=None, policy_entry=None, overlay=vec![], threads=None, rule_files=vec![], data=vec![], namespaces=vec![], all_namespaces=false, policy_entries=vec![], rego_v0=false, bundled=true, profiles=None, at=None, data_dir=None, limits=None))]
#[allow(clippy::too_many_arguments)]
fn fix_finding<'py>(
    py: Python<'py>,
    fingerprint: String,
    paths: Vec<PathBuf>,
    recursive: bool,
    plan: Option<PathBuf>,
    source: Option<PathBuf>,
    var_files: Vec<PathBuf>,
    builtin: bool,
    select: Option<Vec<String>>,
    ir_rules: Vec<String>,
    policies: Vec<PathBuf>,
    policy_shape: Option<&str>,
    policy_entry: Option<String>,
    overlay: Vec<(PathBuf, String)>,
    threads: Option<usize>,
    rule_files: Vec<PathBuf>,
    data: Vec<PathBuf>,
    namespaces: Vec<String>,
    all_namespaces: bool,
    policy_entries: Vec<String>,
    rego_v0: bool,
    bundled: bool,
    profiles: Option<Vec<String>>,
    at: Option<&str>,
    data_dir: Option<PathBuf>,
    limits: Option<Bound<'_, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let site = match at {
        None => None,
        Some("attribute") => Some(tf_scan::FixSite::Attribute),
        Some("default") => Some(tf_scan::FixSite::Default),
        Some(other) => {
            return Err(PyValueError::new_err(format!(
                "at must be \"attribute\" or \"default\", not {other:?}"
            )));
        }
    };
    let (request, _, _) = scan_request(ScanArgs {
        paths,
        recursive,
        plan,
        source,
        var_files,
        data_dir,
        limits: parse_limits(limits.as_ref())?,
        builtin,
        select,
        ir_rules,
        callbacks: Vec::new(),
        policies,
        policy_shape,
        policy_entry,
        overlay,
        threads,
        rule_files,
        data,
        namespaces,
        all_namespaces,
        policy_entries,
        rego_v0,
        bundled,
        profiles,
    })?;
    let o = py
        .detach(move || tf_scan::fix(request, &fingerprint, site))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let d = PyDict::new(py);
    d.set_item("fingerprint", &o.fingerprint)?;
    d.set_item("rule", &o.rule)?;
    d.set_item("file", o.edit.file.display().to_string())?;
    d.set_item("resource", o.hint.resource.to_string())?;
    d.set_item("attribute", &o.hint.attribute)?;
    d.set_item("action", o.hint.action.as_str())?;
    d.set_item("value", json_to_py(py, &o.hint.value)?)?;
    d.set_item("site", o.site.as_str())?;
    d.set_item("diff", &o.diff)?;
    d.set_item("original", &o.original)?;
    d.set_item("text", &o.edit.text)?;
    d.set_item("target_resolved", o.target_resolved)?;
    d.set_item("no_new_findings", o.no_new_findings)?;
    d.set_item(
        "finding_delta",
        json_to_py(py, &serde_json::json!(o.finding_delta))?,
    )?;
    d.set_item("verified", o.verified)?;
    d.set_item("verification_errors", &o.verification_errors)?;
    Ok(d)
}

/// One rule's metadata as a dict: `name`, `level`, `category`,
/// `description`, `resource_types`, `runs_on_module`, `guideline`, `rationale`,
/// `remediation`, `source`
/// (`engine`, `file`, `line`).
fn rule_dict<'py>(py: Python<'py>, r: &RuleInfo) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("name", r.name.as_ref())?;
    d.set_item("level", r.level.as_str())?;
    d.set_item("category", r.category.as_str())?;
    d.set_item("description", r.description.as_ref())?;
    d.set_item(
        "resource_types",
        r.resource_types
            .iter()
            .map(|t| t.as_ref())
            .collect::<Vec<_>>(),
    )?;
    d.set_item("runs_on_module", r.runs_on_module)?;
    d.set_item("guideline", r.guideline.as_deref())?;
    d.set_item("rationale", r.rationale.as_deref())?;
    d.set_item("remediation", r.remediation.as_deref())?;
    let src = PyDict::new(py);
    src.set_item("engine", r.source.engine.as_str())?;
    src.set_item(
        "file",
        r.source.file.as_ref().map(|f| f.display().to_string()),
    )?;
    src.set_item("line", r.source.line)?;
    d.set_item("source", src)?;
    d.set_item(
        "aliases",
        r.aliases.iter().map(|a| a.as_ref()).collect::<Vec<_>>(),
    )?;
    d.set_item("profile", r.profile.as_str())?;
    Ok(d)
}

/// The catalog `oxtf rules` lists: the shipped rules (unless `builtin` is
/// false: the seed rules, and the bundled Checkov catalog unless `bundled`
/// is false) and the
/// rules in `rule_files` (any format), with the policy options. Returns
/// (rules, warnings for skipped files).
#[pyfunction]
#[pyo3(signature = (rule_files=vec![], builtin=true, data=vec![], namespaces=vec![], all_namespaces=false, policy_entries=vec![], policy_shape=None, rego_v0=false, bundled=true))]
#[allow(clippy::too_many_arguments)]
fn rules_info<'py>(
    py: Python<'py>,
    rule_files: Vec<PathBuf>,
    builtin: bool,
    data: Vec<PathBuf>,
    namespaces: Vec<String>,
    all_namespaces: bool,
    policy_entries: Vec<String>,
    policy_shape: Option<String>,
    rego_v0: bool,
    bundled: bool,
) -> PyResult<(Bound<'py, PyList>, Vec<String>)> {
    let catalog = PolicyArgs {
        rule_files,
        data,
        namespaces,
        all_namespaces,
        entries: policy_entries,
        shape: policy_shape,
        rego_v0,
    }
    .catalog(builtin, bundled, Vec::new())?;
    let mut catalog = catalog;
    // The listing shows every profile.
    catalog.profiles = Some(tf_scan::ALL_PROFILES.to_vec());
    let resolved = catalog.resolve().map_err(scan_error)?;
    let out = PyList::empty(py);
    for r in Linter::new(resolved.rules).rules() {
        out.append(rule_dict(py, r)?)?;
    }
    Ok((out, resolved.warnings))
}

/// `(rule, file, result, error)`.
type TestRow = (String, String, String, Option<String>);

/// Run the `test_*` rules of the Rego in `rule_files`, as `oxtf rules
/// test` (Conftest's `verify`). Returns `(rule, file, result, error)` with
/// result `pass`, `fail`, `skip` or `error`.
#[pyfunction]
#[pyo3(signature = (rule_files, data=vec![], namespaces=vec![], rego_v0=false))]
fn test_policies(
    rule_files: Vec<PathBuf>,
    data: Vec<PathBuf>,
    namespaces: Vec<String>,
    rego_v0: bool,
) -> PyResult<Vec<TestRow>> {
    let catalog = PolicyArgs {
        rule_files,
        data,
        namespaces,
        rego_v0,
        ..PolicyArgs::default()
    }
    .catalog(false, false, Vec::new())?;
    let outcomes = tf_scan::verify_policies(&catalog).map_err(scan_error)?;
    Ok(outcomes
        .into_iter()
        .map(|o| {
            let (result, error) = match o.result {
                tf_scan::TestResult::Pass => ("pass", None),
                tf_scan::TestResult::Fail => ("fail", None),
                tf_scan::TestResult::Skip => ("skip", None),
                tf_scan::TestResult::Error(e) => ("error", Some(e)),
            };
            (
                o.rule,
                o.file.display().to_string(),
                result.to_string(),
                error,
            )
        })
        .collect())
}

/// Names and metadata of the built-in rules.
#[pyfunction]
fn builtin_rules<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
    let out = PyList::empty(py);
    for r in Linter::with_seed_rules().rules() {
        let d = PyDict::new(py);
        d.set_item("name", r.name.as_ref())?;
        d.set_item("level", r.level.as_str())?;
        d.set_item("category", r.category.as_str())?;
        d.set_item("description", r.description.as_ref())?;
        d.set_item(
            "resource_types",
            r.resource_types
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>(),
        )?;
        d.set_item("runs_on_module", r.runs_on_module)?;
        out.append(d)?;
    }
    Ok(out)
}

/// Resolve and cache dependencies explicitly; scan remains offline.
#[pyfunction]
#[pyo3(signature = (root, data_dir=None, refresh=false, registry_origins=None))]
fn fetch(
    py: Python<'_>,
    root: PathBuf,
    data_dir: Option<PathBuf>,
    refresh: bool,
    registry_origins: Option<std::collections::BTreeMap<String, String>>,
) -> PyResult<String> {
    let mut request = tf_scan::FetchRequest::new(root);
    request.data_dir = data_dir;
    request.refresh = refresh;
    request.registry_origins = registry_origins.unwrap_or_default();
    let result = py
        .detach(move || tf_scan::fetch(request))
        .map_err(pyo3::exceptions::PyValueError::new_err)?;
    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pymodule]
fn _tfscan(m: &Bound<'_, PyModule>) -> PyResult<()> {
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

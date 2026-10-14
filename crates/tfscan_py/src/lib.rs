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
use tf_eval::{Kind, Known, Truth, Verdict};
use tf_linter::{Category, DynRule, Level, Linter, RuleContext, RuleInfo, ScanOptions};
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
        out.append(d)?;
    }
    Ok(out)
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
        self.v.origin().map(|o| o.to_string())
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
        self.wrap(tf_rule_ir::field(&self.v, name))
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
    /// `"definite"` or `"conditional"`.
    #[getter]
    fn severity(&self) -> &'static str {
        self.f().severity.as_str()
    }
    #[getter]
    fn address(&self) -> &str {
        &self.f().address
    }
    #[getter]
    fn resource_type(&self) -> &str {
        &self.f().resource_type
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
            f.severity.as_str(),
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
        d.set_item("elapsed_s", s.elapsed.as_secs_f64())?;
        d.set_item(
            "findings_by_rule",
            s.findings_by_rule.clone().into_pyobject(py)?,
        )?;
        Ok(d)
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
}

struct Report {
    message: String,
    witness: Option<tf_eval::Value>,
    conditional: bool,
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
    });
    Ok(())
}

impl DynRule for CallbackRule {
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn run_on_resource(&self, r: &tf_semantic::Resource, ctx: &mut RuleContext<'_>) {
        if self.error.lock().unwrap().is_some() {
            return;
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
            Ok(reports) => {
                for rep in reports {
                    let v = Verdict::new(
                        if rep.conditional {
                            Truth::Tainted
                        } else {
                            Truth::True
                        },
                        rep.witness,
                    );
                    let msg = rep.message;
                    ctx.report(r, &v, |_| msg);
                }
            }
            Err(e) => {
                let mut g = self.error.lock().unwrap();
                if g.is_none() {
                    *g = Some(e);
                }
            }
        }
    }
    fn run_on_module(&self, _m: &Module, _ctx: &mut RuleContext<'_>) {}
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
        _ => return Err(PyValueError::new_err(format!("unknown category {s:?}"))),
    })
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/// Scan module directories. `builtin`: `None` = all built-in rules, a list
/// = only those ids. `ir_rules`: rule IR JSON documents. `callbacks`:
/// `tfscan.CallbackRule` objects (attributes `name`, `resource_types`,
/// `level`, `category`, `description`, `func`).
#[pyfunction]
#[pyo3(signature = (paths, recursive=false, var_files=vec![], builtin=None, ir_rules=vec![], callbacks=vec![], threads=None, _release_gil=true))]
#[allow(clippy::too_many_arguments)]
fn scan(
    py: Python<'_>,
    paths: Vec<PathBuf>,
    recursive: bool,
    var_files: Vec<PathBuf>,
    builtin: Option<Vec<String>>,
    ir_rules: Vec<String>,
    callbacks: Vec<Bound<'_, PyAny>>,
    threads: Option<usize>,
    _release_gil: bool,
) -> PyResult<(ScanResult, u64)> {
    if !_release_gil && !callbacks.is_empty() {
        // Workers would block on the GIL held by this thread.
        return Err(PyValueError::new_err(
            "_release_gil=False (test control) cannot run callback rules",
        ));
    }
    let mut rules: Vec<Box<dyn DynRule>> = match &builtin {
        None => tf_linter::rules::all(),
        Some(ids) => tf_linter::rules::all()
            .into_iter()
            .filter(|r| ids.iter().any(|i| *i == *r.info().name))
            .collect(),
    };
    for j in &ir_rules {
        for r in tf_rule_ir::compile_json(j).map_err(PyValueError::new_err)? {
            rules.push(Box::new(r));
        }
    }
    let error = Arc::new(Mutex::new(None));
    let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
    for cb in &callbacks {
        let types: Vec<String> = cb.getattr("resource_types")?.extract()?;
        rules.push(Box::new(CallbackRule {
            info: RuleInfo {
                name: Arc::from(cb.getattr("name")?.extract::<String>()?.as_str()),
                category: category_of(&cb.getattr("category")?.extract::<String>()?)?,
                level: level_of(&cb.getattr("level")?.extract::<String>()?)?,
                description: Arc::from(cb.getattr("description")?.extract::<String>()?.as_str()),
                resource_types: types.iter().map(|t| Arc::from(t.as_str())).collect(),
                runs_on_module: false,
            },
            func: cb.getattr("func")?.unbind(),
            error: error.clone(),
            calls: calls.clone(),
        }));
    }
    for p in &paths {
        if !p.is_dir() {
            return Err(PyValueError::new_err(format!(
                "{} is not a directory",
                p.display()
            )));
        }
    }
    let opts = ScanOptions {
        recursive,
        var_files,
        rules: None,
        threads,
    };
    let work = move || {
        let linter = Linter::new(rules);
        let roots: Vec<PathBuf> = paths
            .iter()
            .flat_map(|p| tf_linter::discover_roots(p, recursive))
            .collect();
        let (r, analyses) = tf_linter::scan_with(&linter, &roots, &opts);
        ScanData::new(r, analyses)
    };
    let data = if _release_gil { py.detach(work) } else { work() };
    if let Some(e) = error.lock().unwrap().take() {
        return Err(e);
    }
    Ok((
        ScanResult {
            data: Arc::new(data),
        },
        calls.load(std::sync::atomic::Ordering::Relaxed),
    ))
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

#[pymodule]
fn _tfscan(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ScanResult>()?;
    m.add_class::<Finding>()?;
    m.add_class::<Resource>()?;
    m.add_class::<Value>()?;
    m.add_class::<CompiledRule>()?;
    m.add_class::<arrow::ArrowStream>()?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(compile_rules, m)?)?;
    m.add_function(wrap_pyfunction!(builtin_rules, m)?)?;
    m.add("IR_VERSION", tf_rule_ir::IR_VERSION)?;
    m.add("PYO3_VERSION", "0.29.3")?;
    ast::register(m)?;
    Ok(())
}

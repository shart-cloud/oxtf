use super::*;

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct Finding {
    pub(super) data: Arc<ScanData>,
    pub(super) i: usize,
}

impl Finding {
    pub(super) fn f(&self) -> &tf_linter::Finding {
        &self.data.result.findings[self.i]
    }
    pub(super) fn record(&self) -> serde_json::Value {
        tf_linter::render::finding_json(self.data.files(), self.f())
    }
    pub(super) fn record_field(&self, py: Python<'_>, field: &str) -> PyResult<Py<PyAny>> {
        json_to_py(py, &self.record()[field])
    }
}

#[pymethods]
impl Finding {
    #[getter]
    pub(super) fn rule(&self) -> &str {
        &self.f().rule
    }
    #[getter]
    pub(super) fn level(&self) -> &'static str {
        self.f().level.as_str()
    }
    /// `"definite"`, `"conditional"` or `"indeterminate"` (foreign policies only).
    #[getter]
    pub(super) fn certainty(&self) -> &'static str {
        self.f().certainty.as_str()
    }
    #[getter]
    pub(super) fn address(&self) -> &str {
        &self.f().address
    }
    #[getter]
    pub(super) fn resource_type(&self) -> Option<&str> {
        self.f().resource_type.as_deref()
    }
    #[getter]
    pub(super) fn module(&self) -> &str {
        &self.f().module
    }
    #[getter]
    pub(super) fn message(&self) -> &str {
        &self.f().message
    }
    #[getter]
    pub(super) fn root(&self) -> String {
        self.f().root.display().to_string()
    }
    /// Stable identity across scans (rule, repository-relative file, local
    /// address, attribute path); shared by every occurrence of a finding.
    #[getter]
    pub(super) fn fingerprint(&self) -> String {
        tf_linter::record::finding_fingerprint(
            self.data.files(),
            self.f(),
            &mut tf_linter::record::RepoRoots::new(),
        )
    }
    #[getter]
    pub(super) fn category(&self) -> &'static str {
        self.f().category.as_str()
    }
    #[getter]
    pub(super) fn description(&self) -> &str {
        &self.f().description
    }
    /// Attribute path of the deciding value within the resource, if any.
    #[getter]
    pub(super) fn attribute(&self) -> Option<&str> {
        self.f().attribute.as_deref()
    }
    /// The deciding top-level attribute as written: `{"kind", "value", "display"}`, or None.
    #[getter]
    pub(super) fn configured(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "configured")
    }
    /// The same after the defaults overlay.
    #[getter]
    pub(super) fn effective(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "effective")
    }
    /// A mechanical fix (`resource`, `attribute`, `action`, `value`, `site`), or None.
    #[getter]
    pub(super) fn fix_hint(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "fix_hint")
    }
    /// Inputs a foreign policy could not see: `[{"path", "kind"}]`.
    #[getter]
    pub(super) fn hidden(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "hidden")
    }
    /// The resource instance's identity, structured; None for a finding on
    /// a file.
    #[getter]
    pub(super) fn resource(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "resource")
    }
    /// What the finding is about: `{"kind": "resource", "address"}` or
    /// `{"kind": "file", "file", "module"}`.
    #[getter]
    pub(super) fn subject(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.record_field(py, "subject")
    }
    /// The whole finding record (`docs/FINDING_SCHEMA.md`) as a dict.
    pub(super) fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_to_py(py, &self.record())
    }
    #[getter]
    pub(super) fn file(&self) -> String {
        loc(self.data.files(), self.f().primary).0
    }
    #[getter]
    pub(super) fn line(&self) -> u32 {
        loc(self.data.files(), self.f().primary).1
    }
    #[getter]
    pub(super) fn column(&self) -> u32 {
        loc(self.data.files(), self.f().primary).2
    }
    /// Origin-first provenance chain: dicts with kind, label, file, line,
    /// column, resource.
    #[getter]
    pub(super) fn provenance<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        steps_to_py(py, &self.f().provenance, Some(self.data.files()))
    }
    /// miette rendering (with the provenance chain).
    #[pyo3(signature = (color = false))]
    pub(super) fn render(&self, color: bool) -> String {
        tf_linter::render::render_finding(self.data.files(), self.f(), color)
    }
    pub(super) fn to_json(&self) -> String {
        tf_linter::render::finding_json(self.data.files(), self.f()).to_string()
    }
    pub(super) fn __repr__(&self) -> String {
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

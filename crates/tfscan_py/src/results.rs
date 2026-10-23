use super::*;

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct ScanResult {
    pub(super) data: Arc<ScanData>,
}

#[pymethods]
impl ScanResult {
    #[getter]
    pub(super) fn status(&self) -> &'static str {
        self.data.result.status().as_str()
    }
    #[getter]
    pub(super) fn findings(&self) -> Vec<Finding> {
        (0..self.data.result.findings.len())
            .map(|i| Finding {
                data: self.data.clone(),
                i,
            })
            .collect()
    }
    /// Every resource and data-source instance of every analysed module.
    #[getter]
    pub(super) fn resources(&self) -> Vec<Resource> {
        self.data
            .resources
            .iter()
            .map(|&i| Resource {
                src: ResSrc::Scan(self.data.clone(), i),
            })
            .collect()
    }
    #[getter]
    pub(super) fn resource_count(&self) -> usize {
        self.data.resources.len()
    }
    #[getter]
    pub(super) fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
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
    pub(super) fn rule_errors<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
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
    pub(super) fn suppressed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
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
    pub(super) fn roots<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
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
    pub(super) fn diagnostics<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
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
    pub(super) fn to_json(&self) -> String {
        tf_linter::render::result_json(&self.data.result).to_string()
    }
    /// Findings as an Arrow C stream (`__arrow_c_stream__` capsule holder);
    /// `tfscan.ScanResult.findings_arrow()` turns it into a `pyarrow.Table`.
    pub(super) fn _findings_stream(&self, py: Python<'_>) -> PyResult<arrow::ArrowStream> {
        let d = self.data.clone();
        let batch = py
            .detach(move || arrow::findings_batch(&d))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(arrow::ArrowStream::new(batch))
    }
    pub(super) fn _resources_stream(&self, py: Python<'_>) -> PyResult<arrow::ArrowStream> {
        let d = self.data.clone();
        let batch = py
            .detach(move || arrow::resources_batch(&d))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(arrow::ArrowStream::new(batch))
    }
    pub(super) fn __repr__(&self) -> String {
        let s = &self.data.result.stats;
        format!(
            "ScanResult(findings={}, roots={}, resources={}, files={})",
            s.findings, s.roots, s.resources, s.files
        )
    }
}

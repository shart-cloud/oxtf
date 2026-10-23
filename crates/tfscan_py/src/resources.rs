use super::*;

// ---------------------------------------------------------------------------
// Resource
// ---------------------------------------------------------------------------

pub(super) enum ResSrc {
    /// From a finished scan: shared data plus indices.
    Scan(Arc<ScanData>, (u32, u32, u32)),
    /// Inside a callback rule: a copy of the resource (the analysis is
    /// borrowed by the engine during the scan, so it cannot be shared).
    Owned(Arc<tf_semantic::Resource>),
}

/// A resource or data-source instance of the analysed model.
#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct Resource {
    pub(super) src: ResSrc,
}

impl Resource {
    pub(super) fn res(&self) -> &tf_semantic::Resource {
        match &self.src {
            ResSrc::Scan(d, i) => d.resource(*i),
            ResSrc::Owned(r) => r,
        }
    }
    pub(super) fn data(&self) -> Option<Arc<ScanData>> {
        match &self.src {
            ResSrc::Scan(d, _) => Some(d.clone()),
            ResSrc::Owned(_) => None,
        }
    }
    pub(super) fn value(&self, v: tf_eval::Value) -> Value {
        Value {
            v,
            files: self.data(),
        }
    }
}

#[pymethods]
impl Resource {
    #[getter]
    pub(super) fn address(&self) -> &str {
        &self.res().address
    }
    #[getter]
    pub(super) fn base_address(&self) -> &str {
        &self.res().base_address
    }
    #[getter]
    pub(super) fn r#type(&self) -> &str {
        &self.res().ty
    }
    #[getter]
    pub(super) fn name(&self) -> &str {
        &self.res().name
    }
    #[getter]
    pub(super) fn module(&self) -> &str {
        &self.res().module
    }
    #[getter]
    pub(super) fn key(&self) -> Option<&str> {
        self.res().key.as_deref()
    }
    #[getter]
    pub(super) fn mode(&self) -> &'static str {
        mode_str(self.res().mode)
    }
    /// `"true"`, `"tainted"` (count/for_each on an unconstrained variable)
    /// or `"unknown"`.
    #[getter]
    pub(super) fn existence(&self) -> &'static str {
        truth_str(self.res().existence)
    }
    #[getter]
    pub(super) fn root(&self) -> Option<String> {
        match &self.src {
            ResSrc::Scan(d, (a, _, _)) => {
                Some(d.analyses[*a as usize].root_dir.display().to_string())
            }
            ResSrc::Owned(_) => None,
        }
    }
    #[getter]
    pub(super) fn file(&self) -> Option<String> {
        self.data().map(|d| loc(d.files(), self.res().span).0)
    }
    #[getter]
    pub(super) fn line(&self) -> Option<u32> {
        self.data().map(|d| loc(d.files(), self.res().span).1)
    }
    /// Names of the top-level attributes set in configuration.
    pub(super) fn keys(&self) -> Vec<String> {
        self.res()
            .body
            .attrs
            .iter()
            .map(|a| a.name.to_string())
            .collect()
    }
    /// Attribute value (`KeyError` if not set).
    pub(super) fn __getitem__(&self, name: &str) -> PyResult<Value> {
        self.res()
            .value(name)
            .map(|v| self.value(v))
            .ok_or_else(|| PyKeyError::new_err(name.to_string()))
    }
    pub(super) fn __contains__(&self, name: &str) -> bool {
        self.res().attr(name).is_some()
    }
    /// Attribute value, or `None` if not set.
    pub(super) fn get(&self, name: &str) -> Option<Value> {
        self.res().value(name).map(|v| self.value(v))
    }
    /// Attribute value, or the provider default from the defaults overlay.
    pub(super) fn get_or_default(&self, name: &str) -> Option<Value> {
        self.res().value_or_default(name).map(|v| self.value(v))
    }
    /// All attributes and nested blocks as abstract JSON.
    pub(super) fn to_json(&self) -> String {
        body_json(&self.res().body).to_string()
    }
    /// Configured values in Checkov's dict-of-lists shape, retaining unknowns.
    pub(super) fn checkov_configuration(&self) -> Value {
        self.value(tf_rule_ir::checkov::configuration(&self.res().body))
    }
    pub(super) fn __repr__(&self) -> String {
        format!("Resource({})", self.res().address)
    }
}

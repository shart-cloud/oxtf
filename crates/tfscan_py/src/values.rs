use super::*;

// ---------------------------------------------------------------------------
// Value
// ---------------------------------------------------------------------------

/// An abstract value (`known`, `unknown`, `tainted`, `one_of`) with
/// provenance.
#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct Value {
    pub(super) v: tf_eval::Value,
    pub(super) files: Option<Arc<ScanData>>,
}

impl Value {
    pub(super) fn wrap(&self, v: tf_eval::Value) -> Value {
        Value {
            v,
            files: self.files.clone(),
        }
    }
}

pub(super) fn number_to_py(py: Python<'_>, n: f64) -> PyResult<Py<PyAny>> {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        Ok((n as i64).into_pyobject(py)?.into_any().unbind())
    } else {
        Ok(n.into_pyobject(py)?.into_any().unbind())
    }
}

/// Convert to Python: Known scalars/lists/objects to Python objects, any
/// abstract part to a `Value` handle.
pub(super) fn to_py(
    py: Python<'_>,
    v: &tf_eval::Value,
    files: &Option<Arc<ScanData>>,
) -> PyResult<Py<PyAny>> {
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

pub(super) fn steps_to_py<'py>(
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
pub(super) fn json_to_py(py: Python<'_>, j: &serde_json::Value) -> PyResult<Py<PyAny>> {
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
    pub(super) fn kind(&self) -> &'static str {
        match &self.v.kind {
            Kind::Known(_) => "known",
            Kind::Unknown(_) => "unknown",
            Kind::Tainted(_) => "tainted",
            Kind::OneOf(_) => "one_of",
        }
    }
    #[getter]
    pub(super) fn is_known(&self) -> bool {
        self.v.is_known()
    }
    #[getter]
    pub(super) fn is_wholly_known(&self) -> bool {
        self.v.is_wholly_known()
    }
    #[getter]
    pub(super) fn is_null(&self) -> bool {
        self.v.is_null()
    }
    /// Type of a Known value (`null`, `bool`, `number`, `string`, `list`,
    /// `object`), else the kind.
    #[getter]
    pub(super) fn type_name(&self) -> &'static str {
        self.v.type_name()
    }
    /// The unconstrained variable a Tainted value depends on.
    #[getter]
    pub(super) fn variable(&self) -> Option<String> {
        match &self.v.kind {
            Kind::Tainted(t) => Some(t.variable.to_string()),
            _ => None,
        }
    }
    /// Why an Unknown value is unknown.
    #[getter]
    pub(super) fn origin(&self) -> Option<String> {
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
    pub(super) fn sensitive(&self) -> bool {
        self.v.is_sensitive()
    }
    /// Alternatives of a OneOf (provenance joined), else `[]`.
    #[getter]
    pub(super) fn alternatives(&self) -> Vec<Value> {
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
    pub(super) fn tainted(&self) -> bool {
        match &self.v.kind {
            Kind::OneOf(o) => o.tainted,
            Kind::Tainted(_) => true,
            _ => false,
        }
    }
    /// Elements of a Known list as Values (provenance joined), else `None`.
    pub(super) fn items(&self) -> Option<Vec<Value>> {
        self.v
            .as_list()
            .map(|l| l.iter().map(|x| self.wrap(x.child_of(&self.v))).collect())
    }
    /// Field of an object (missing → null), lifted over OneOf; Unknown /
    /// Tainted receivers return themselves.
    pub(super) fn get(&self, name: &str) -> Value {
        self.wrap(self.v.field_or_null(name))
    }
    /// A Known `null`.
    #[staticmethod]
    pub(super) fn null() -> Value {
        Value {
            v: tf_eval::Value::null(),
            files: None,
        }
    }
    /// Terraform string conversion of a Known primitive (else `None`).
    pub(super) fn to_str(&self) -> Option<String> {
        self.v.to_str().map(|s| s.to_string())
    }
    pub(super) fn as_number(&self) -> Option<f64> {
        self.v.as_number()
    }
    pub(super) fn as_bool(&self) -> Option<bool> {
        self.v.as_bool()
    }
    /// Python conversion; abstract parts stay `Value` handles.
    pub(super) fn py(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        to_py(py, &self.v, &self.files)
    }
    /// JSON with the lattice explicit (`{"$unknown": ...}` etc.).
    pub(super) fn to_json(&self) -> String {
        abstract_json(&self.v).to_string()
    }
    /// Origin-first provenance steps.
    #[getter]
    pub(super) fn provenance<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        steps_to_py(
            py,
            &self.v.prov.steps(),
            self.files.as_deref().map(|d| d.files()),
        )
    }
    pub(super) fn __repr__(&self) -> String {
        format!("Value({})", self.v)
    }
    pub(super) fn __str__(&self) -> String {
        self.v.to_string()
    }
}

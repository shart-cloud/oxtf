use super::*;

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// A rule compiled from the JSON rule IR (validated in Rust).
#[pyclass(frozen, module = "tfscan._tfscan")]
pub struct CompiledRule {
    pub(super) json: String,
    pub(super) name: String,
}

#[pymethods]
impl CompiledRule {
    #[getter]
    pub(super) fn name(&self) -> &str {
        &self.name
    }
    /// The IR re-serialized by Rust (`serde_json`), for round-trip checks.
    pub(super) fn to_json(&self) -> String {
        self.json.clone()
    }
}

/// Parse + validate rule IR JSON (one rule, a list, or `{"rules": [...]}`).
#[pyfunction]
pub(super) fn compile_rules(json: &str) -> PyResult<Vec<CompiledRule>> {
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
pub(super) struct CallbackRule {
    pub(super) info: RuleInfo,
    pub(super) func: Py<PyAny>,
    pub(super) error: Arc<Mutex<Option<PyErr>>>,
    pub(super) calls: Arc<std::sync::atomic::AtomicU64>,
    pub(super) record_errors: bool,
}

pub(super) struct Report {
    pub(super) message: String,
    pub(super) witness: Option<tf_eval::Value>,
    pub(super) conditional: bool,
    pub(super) indeterminate: bool,
    pub(super) hidden: Vec<tf_linter::Hidden>,
}

pub(super) fn parse_reports(ret: &Bound<'_, PyAny>, out: &mut Vec<Report>) -> PyResult<()> {
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

pub(super) fn level_of(s: &str) -> PyResult<Level> {
    Ok(match s {
        "low" => Level::Low,
        "medium" => Level::Medium,
        "high" => Level::High,
        "critical" => Level::Critical,
        _ => return Err(PyValueError::new_err(format!("unknown level {s:?}"))),
    })
}

pub(super) fn category_of(s: &str) -> PyResult<Category> {
    Ok(match s {
        "network" => Category::Network,
        "storage" => Category::Storage,
        "iam" => Category::Iam,
        "encryption" => Category::Encryption,
        "other" => Category::Other,
        _ => return Err(PyValueError::new_err(format!("unknown category {s:?}"))),
    })
}

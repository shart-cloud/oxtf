use super::*;

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

pub(super) type CallbackError = Arc<Mutex<Option<PyErr>>>;
pub(super) type CallCount = Arc<std::sync::atomic::AtomicU64>;

/// The catalog a Python call describes: seed rules (or not), rule-IR
/// documents, callback rules and Rego policies.
pub(super) struct PyCatalog {
    pub(super) catalog: Catalog,
    pub(super) error: CallbackError,
    pub(super) calls: CallCount,
}

/// Rule files and policy options, as `oxtf --rule-file` and its policy
/// flags take them.
#[derive(Default)]
pub(super) struct PolicyArgs {
    /// Any format, detected per file (`--rule-file`, `--policy`).
    pub(super) rule_files: Vec<PathBuf>,
    pub(super) data: Vec<PathBuf>,
    pub(super) namespaces: Vec<String>,
    pub(super) all_namespaces: bool,
    pub(super) entries: Vec<String>,
    pub(super) shape: Option<String>,
    pub(super) rego_v0: bool,
}

impl PolicyArgs {
    pub(super) fn catalog(
        self,
        builtin: bool,
        bundled: bool,
        ir_rules: Vec<String>,
    ) -> PyResult<Catalog> {
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

pub(super) fn build_catalog(
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

pub(super) fn scan_error(e: tf_scan::ScanError) -> PyErr {
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
pub(super) fn scan(
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
pub(super) struct ScanArgs<'py, 's> {
    pub(super) limits: tf_scan::Limits,
    pub(super) paths: Vec<PathBuf>,
    pub(super) recursive: bool,
    pub(super) plan: Option<PathBuf>,
    pub(super) source: Option<PathBuf>,
    pub(super) var_files: Vec<PathBuf>,
    pub(super) data_dir: Option<PathBuf>,
    pub(super) builtin: bool,
    pub(super) select: Option<Vec<String>>,
    pub(super) ir_rules: Vec<String>,
    pub(super) callbacks: Vec<Bound<'py, PyAny>>,
    pub(super) policies: Vec<PathBuf>,
    pub(super) policy_shape: Option<&'s str>,
    pub(super) policy_entry: Option<String>,
    pub(super) overlay: Vec<(PathBuf, String)>,
    pub(super) threads: Option<usize>,
    pub(super) rule_files: Vec<PathBuf>,
    pub(super) data: Vec<PathBuf>,
    pub(super) namespaces: Vec<String>,
    pub(super) all_namespaces: bool,
    pub(super) policy_entries: Vec<String>,
    pub(super) rego_v0: bool,
    pub(super) bundled: bool,
    pub(super) profiles: Option<Vec<String>>,
}

pub(super) fn parse_limits(limits: Option<&Bound<'_, PyDict>>) -> PyResult<tf_scan::Limits> {
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

pub(super) fn scan_request(
    a: ScanArgs<'_, '_>,
) -> PyResult<(ScanRequest, CallbackError, CallCount)> {
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

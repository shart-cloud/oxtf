use super::*;

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
pub(super) fn fix_finding<'py>(
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
        Some("input") => Some(tf_scan::FixSite::Input),
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
pub(super) fn rule_dict<'py>(py: Python<'py>, r: &RuleInfo) -> PyResult<Bound<'py, PyDict>> {
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
pub(super) fn rules_info<'py>(
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
pub(super) type TestRow = (String, String, String, Option<String>);

/// Run the `test_*` rules of the Rego in `rule_files`, as `oxtf rules
/// test` (Conftest's `verify`). Returns `(rule, file, result, error)` with
/// result `pass`, `fail`, `skip` or `error`.
#[pyfunction]
#[pyo3(signature = (rule_files, data=vec![], namespaces=vec![], rego_v0=false))]
pub(super) fn test_policies(
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
pub(super) fn builtin_rules<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
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
pub(super) fn fetch(
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

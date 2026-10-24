//! Plan JSON front end.
//!
//! Reads `terraform show -json <planfile>` into the same owned resource
//! model the HCL front end produces ([`tf_semantic::Analysis`]), so the W4
//! rules and the `tf_linter` engine run on it unchanged.
//!
//! ```no_run
//! use tf_plan::{scan_plan, PlanOptions};
//! let linter = tf_linter::Linter::with_seed_rules();
//! let opts = PlanOptions { source: Some("infra/".into()), ..PlanOptions::default() };
//! let r = scan_plan(&linter, "plan.json".as_ref(), &opts).unwrap();
//! for f in &r.findings {
//!     println!("{}", tf_linter::render::render_finding(&r.files, f, false));
//! }
//! ```
//!
//! **Values.** Each resource instance's planned object (`change.after`) is
//! converted to the lattice: known JSON values are `Known`; nodes marked in
//! `after_unknown` are `Unknown`. The origin of an unknown top-level
//! attribute comes from the plan's `configuration` section: when the
//! attribute's expression references exactly one resource attribute
//! (`bucket = aws_s3_bucket.data.id` → `references: ["aws_s3_bucket.data.id",
//! ...]`), the value is `Unknown { Computed { resource: "aws_s3_bucket.data",
//! attr: "id" } }`, exactly what the HCL evaluator produces for the same
//! expression, so cross-resource joins work unchanged. Top-level attributes
//! that are unknown **and not set in configuration** (provider-computed:
//! `id`, `arn`, optional+computed attributes left unset) are omitted from
//! the body, as in the HCL model, so the defaults overlay applies to them.
//! There is no `Tainted` and no `OneOf`: terraform requires a value for
//! every variable and resolves every conditional before planning.
//! Values marked in `after_sensitive` stay `Known` (the plan JSON carries
//! them in clear text and rules need them); the provenance label says
//! `(sensitive)` and never prints the value.
//!
//! **Spans.** Plan JSON carries no source positions. When the source module
//! directory is available (`PlanOptions::source`, or the plan file's own
//! directory if it holds `.tf` files), it is analysed with the HCL front end
//! and used only as a span index: resource address → `resource` block header,
//! attribute → attribute (or first block of that type), `var.x` / `local.y`
//! references → their declarations. Local child modules are followed by the
//! source analysis, so `module.m.aws_x.y` maps into the child's files. A
//! resource that cannot be found in source (remote module, no source given)
//! points at its `"address"` entry in the plan JSON file itself, and an
//! `plan-unmapped` info diagnostic is emitted.

pub mod refs;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde_json::Value as J;
use tf_eval::{Origin, Prov, Step, StepKind, Truth, Value};
use tf_linter::{Linter, ScanResult, ScanStats};
use tf_semantic::model::{AnalysisStats, VariableInfo};
use tf_semantic::{Address, InstanceKey};
use tf_semantic::{
    Analysis, AnalyzeOptions, Attr, Block, Body, DiagSeverity, Diagnostic, FileTable, Mode, Module,
    Resource, SymbolRef, analyze_module,
};
use tf_span::{FileId, FileSpan, Span};

use crate::refs::{Ref, classify, parent_module, strip_keys};

/// Options for reading a plan.
#[derive(Clone, Debug, Default)]
pub struct PlanOptions {
    /// Scan input admission and per-root evaluation/rule allowances.
    pub limits: tf_limits::Limits,
    /// Root module source directory used to map findings back to `.tf`
    /// spans. `None`: the plan file's directory if it contains `.tf` files,
    /// else no source (spans point into the plan JSON).
    pub source: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug)]
pub enum PlanError {
    Io(PathBuf, std::io::Error),
    Json(PathBuf, serde_json::Error),
    Format(String),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            PlanError::Json(p, e) => write!(f, "{}: invalid JSON: {e}", p.display()),
            PlanError::Format(m) => write!(f, "not a terraform plan JSON: {m}"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Read a plan JSON file into an [`Analysis`]. Source files (and the plan
/// file itself) are registered in `files`.
#[expect(clippy::too_many_lines)]
pub fn load_plan(
    path: &Path,
    opts: &PlanOptions,
    files: &FileTable,
) -> Result<Analysis, PlanError> {
    let plan_file = files
        .load(path)
        .map_err(|e| PlanError::Io(path.to_path_buf(), e))?;
    let plan: J = serde_json::from_str(&plan_file.text)
        .map_err(|e| PlanError::Json(path.to_path_buf(), e))?;
    if !plan.is_object() || plan.get("format_version").is_none() {
        return Err(PlanError::Format("no top-level format_version".into()));
    }
    if plan.get("planned_values").is_none() && plan.get("resource_changes").is_none() {
        return Err(PlanError::Format(
            "no planned_values / resource_changes (is this `terraform show -json` of a state?)"
                .into(),
        ));
    }
    let source_dir = opts.source.clone().or_else(|| {
        let dir = path.parent()?;
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        has_tf_files(files, dir).then(|| dir.to_path_buf())
    });
    let source = source_dir.as_ref().map(|d| {
        analyze_module(
            d,
            &AnalyzeOptions {
                limits: opts.limits,
                data_dir: opts.data_dir.clone(),
                ..AnalyzeOptions::default()
            },
            files,
        )
    });
    let b = Builder::new(&plan, plan_file.id, &plan_file.text, source.as_ref());
    let analysis = b.build(source_dir.unwrap_or_else(|| path.to_path_buf()));
    fn mark_body(body: &Body, files: &FileTable) {
        for a in &body.attrs {
            if a.value.is_sensitive() {
                files.mark_sensitive(a.span);
                for step in a.value.prov.steps() {
                    files.mark_sensitive(step.at);
                }
            }
        }
        for b in &body.blocks {
            mark_body(&b.body, files);
        }
    }
    fn has_sensitive_metadata(value: &J) -> bool {
        match value {
            J::Object(map) => map.iter().any(|(key, value)| {
                (matches!(
                    key.as_str(),
                    "sensitive" | "sensitive_values" | "after_sensitive" | "before_sensitive"
                ) && any_true(value))
                    || has_sensitive_metadata(value)
            }),
            J::Array(values) => values.iter().any(has_sensitive_metadata),
            _ => false,
        }
    }
    if analysis.modules.iter().any(Module::is_sensitive) || has_sensitive_metadata(&plan) {
        // Plan source locations can refer to whole resource objects. Never
        // show raw JSON context from a plan containing sensitive values.
        files.mark_sensitive(FileSpan::new(
            plan_file.id,
            Span::new(0, plan_file.text.len() as u32),
        ));
    }
    for m in &analysis.modules {
        for r in &m.resources {
            mark_body(&r.body, files);
        }
    }
    Ok(analysis)
}

/// Read a plan and run `linter` over it.
pub fn scan_plan(
    linter: &Linter,
    path: &Path,
    opts: &PlanOptions,
) -> Result<ScanResult, PlanError> {
    scan_plan_with_model(
        linter,
        path,
        opts,
        Arc::new(FileTable::with_limits(opts.limits)),
    )
    .map(|(r, _)| r)
}

/// [`scan_plan`], also returning the analysed model built from the plan.
/// `files` is the scan's file table (an overlay shadows the plan file and
/// the source directory alike).
pub fn scan_plan_with_model(
    linter: &Linter,
    path: &Path,
    opts: &PlanOptions,
    files: Arc<FileTable>,
) -> Result<(ScanResult, Analysis), PlanError> {
    let start = Instant::now();
    let a = load_plan(path, opts, &files)?;
    let mut out = linter.run_with_storage(&a, None, opts.limits, files.input_budget());
    tf_linter::engine::protect_fix_hints(&mut out.findings, &a, &files);
    // No parsed modules here: only skips in a resource's own block apply.
    let (findings, suppressed) = tf_linter::suppress::checkov_skips(out.findings, &a, &files, None);
    let stats = ScanStats {
        roots: 1,
        module_instances: a.modules.len(),
        resources: a.stats.resources,
        files: files.len(),
        elapsed: start.elapsed(),
        ..ScanStats::from_findings(&findings)
    };
    let root = tf_linter::scan::RootOutcome {
        dir: a.root_dir.clone(),
        coverage: out.coverage.clone(),
        unresolved_inputs: tf_linter::coverage::unresolved_inputs(&a, &files),
        diagnostics: a.diagnostics.clone(),
        rule_errors: out.rule_errors.clone(),
        resources: a.stats.resources,
        module_instances: a.modules.len(),
        status: tf_linter::scan::status_of(&a.diagnostics, &out.rule_errors),
        needs_install: a
            .diagnostics
            .iter()
            .any(|d| d.code == tf_linter::scan::NOT_INSTALLED),
    };
    let mut diagnostics = a.diagnostics.clone();
    diagnostics.retain(|d| d.code != "coverage-storage");
    diagnostics.extend(files.limit_diagnostic());
    diagnostics.extend(files.results_diagnostic());
    Ok((
        ScanResult {
            findings,
            diagnostics,
            stats,
            rule_errors: out.rule_errors,
            files,
            suppressed,
            input_kind: tf_linter::record::InputKind::Plan,
            roots: vec![root],
            selected_rules: linter.rules().iter().map(|r| r.name.to_string()).collect(),
        },
        a,
    ))
}

fn has_tf_files(files: &FileTable, dir: &Path) -> bool {
    files
        .read_dir(dir)
        .iter()
        .any(|p| tf_semantic::module::is_config(p))
}

// ---------------------------------------------------------------------------

/// One resource instance as found in the plan.
struct PlanRes<'p> {
    address: String,
    module: String,
    mode: Mode,
    ty: String,
    name: String,
    key: Option<String>,
    after: &'p J,
    unknown: &'p J,
    sensitive: &'p J,
}

/// One module call's configuration: resource local address → `expressions`.
#[derive(Default)]
struct ConfigModule<'p> {
    resources: HashMap<String, &'p serde_json::Map<String, J>>,
    resource_blocks: HashMap<String, &'p J>,
    outputs: HashMap<String, &'p J>,
    inputs: HashMap<String, &'p J>,
}

struct Builder<'p> {
    plan: &'p J,
    plan_file: FileId,
    plan_text: &'p str,
    source: Option<&'p Analysis>,
    /// Source module instances by key-stripped address.
    src_modules: HashMap<String, &'p Module>,
    config: HashMap<String, ConfigModule<'p>>,
    /// Whether the source analysis was evaluated with the plan's root
    /// inputs, so a source instance may supply a resource's graph edges.
    source_inputs_match: bool,
    /// Every module instance address in the plan (resource modules and
    /// their ancestors), for resolving `module.<name>` references.
    module_instances: BTreeSet<String>,
    diagnostics: Vec<Diagnostic>,
}

static NULL: J = J::Null;
static FALSE: J = J::Bool(false);
static TRUE: J = J::Bool(true);

impl<'p> Builder<'p> {
    fn new(
        plan: &'p J,
        plan_file: FileId,
        plan_text: &'p str,
        source: Option<&'p Analysis>,
    ) -> Self {
        let mut src_modules = HashMap::new();
        if let Some(a) = source {
            for m in &a.modules {
                src_modules.entry(strip_keys(&m.address)).or_insert(m);
            }
        }
        let mut config = HashMap::new();
        if let Some(root) = plan.pointer("/configuration/root_module") {
            index_config(root, String::new(), &mut config);
        }
        let mut diagnostics = source.map(|a| a.diagnostics.clone()).unwrap_or_default();
        if plan.get("errored").and_then(J::as_bool) == Some(true) {
            diagnostics.push(Diagnostic {
                severity: DiagSeverity::Warning,
                code: "plan-errored",
                message: "the plan is marked errored: it may be incomplete".into(),
                at: None,
            });
        }
        if let Some(v) = plan.get("format_version").and_then(J::as_str)
            && !v.starts_with("1.")
        {
            diagnostics.push(Diagnostic {
                severity: DiagSeverity::Warning,
                code: "plan-format",
                message: format!("plan JSON format_version {v}; this reader targets 1.x"),
                at: None,
            });
        }
        // A representative source instance can supply display spans, but must
        // not supply a sibling instance's graph edges. The source analysis
        // evaluated the root with variable defaults: a planned input whose
        // source value is known and differs was overridden on the command
        // line, so source edges may not match the plan. An input the source
        // could not evaluate (no default) contradicts nothing.
        let source_inputs_match =
            plan.get("variables")
                .and_then(J::as_object)
                .is_none_or(|variables| {
                    source.and_then(|a| a.modules.first()).is_some_and(|root| {
                        variables.iter().all(|(name, planned)| {
                            root.variables
                                .iter()
                                .find(|v| v.name.as_ref() == name)
                                .is_some_and(|v| {
                                    !v.value.is_known()
                                        || tf_eval::value::to_json(&v.value).as_ref()
                                            == planned.get("value")
                                })
                        })
                    })
                });
        Builder {
            plan,
            plan_file,
            plan_text,
            source,
            src_modules,
            config,
            source_inputs_match,
            module_instances: BTreeSet::new(),
            diagnostics,
        }
    }

    fn build(mut self, root_dir: PathBuf) -> Analysis {
        let resources = self.collect();
        // Module instances: every module address seen, plus ancestors.
        let mut addrs: BTreeSet<String> = BTreeSet::new();
        addrs.insert(String::new());
        for r in &resources {
            let mut m = Some(r.module.clone());
            while let Some(a) = m {
                m = parent_module(&a);
                addrs.insert(a);
            }
        }
        self.module_instances = addrs.clone();
        let addrs: Vec<String> = addrs.into_iter().collect();
        let index: HashMap<&str, usize> = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (a.as_str(), i))
            .collect();
        let mut modules: Vec<Module> = addrs
            .iter()
            .map(|a| {
                let src = self.src_modules.get(&strip_keys(a)).copied();
                Module {
                    address: a.as_str().into(),
                    dir: src
                        .map(|m| m.dir.clone())
                        .unwrap_or_else(|| root_dir.clone()),
                    parent: parent_module(a).and_then(|p| index.get(p.as_str()).copied()),
                    package: src.and_then(|m| m.package.clone()),
                    resources: Vec::new(),
                    variables: self.variables(a, src),
                    outputs: Vec::new(),
                    locals: src.map(|m| m.locals.clone()).unwrap_or_default(),
                    block_values: src.map(|m| m.block_values.clone()).unwrap_or_default(),
                    module_calls: src.map(|m| m.module_calls.clone()).unwrap_or_default(),
                    symbols: src.map(|m| m.symbols.clone()).unwrap_or_default(),
                    references: src.map(|m| m.references.clone()).unwrap_or_default(),
                }
            })
            .collect();
        let mut stats = AnalysisStats {
            loader_steps: self.source.map_or(0, |a| a.stats.loader_steps),
            evaluation_steps: self.source.map_or(0, |a| a.stats.evaluation_steps),
            files: 0,
            module_instances: modules.len(),
            resources: 0,
            attributes: 0,
        };
        for pr in &resources {
            let r = self.resource(pr);
            stats.resources += 1;
            stats.attributes += r.body.attrs.len();
            modules[index[pr.module.as_str()]].resources.push(r);
        }
        stats.files = self.source.map(|a| a.stats.files).unwrap_or_default() + 1;
        Analysis {
            root_dir,
            modules,
            diagnostics: self.diagnostics,
            stats,
        }
    }

    /// Managed resources from `resource_changes` (skipping pure deletes),
    /// data sources from `resource_changes` (deferred reads) and
    /// `prior_state` (read during planning).
    fn collect(&self) -> Vec<PlanRes<'p>> {
        let mut out: Vec<PlanRes<'p>> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        if let Some(rcs) = self.plan.get("resource_changes").and_then(J::as_array) {
            for rc in rcs {
                let Some(change) = rc.get("change") else {
                    continue;
                };
                let actions: Vec<&str> = change
                    .get("actions")
                    .and_then(J::as_array)
                    .map(|a| a.iter().filter_map(J::as_str).collect())
                    .unwrap_or_default();
                if actions == ["delete"] || actions == ["forget"] {
                    continue;
                }
                let after = change.get("after").unwrap_or(&NULL);
                if after.is_null() {
                    continue;
                }
                if let Some(r) = plan_res(
                    rc,
                    after,
                    change.get("after_unknown").unwrap_or(&FALSE),
                    change.get("after_sensitive").unwrap_or(&FALSE),
                ) {
                    seen.insert(r.address.clone());
                    out.push(r);
                }
            }
        }
        if let Some(root) = self.plan.pointer("/prior_state/values/root_module") {
            let mut stack = vec![root];
            while let Some(m) = stack.pop() {
                for r in m
                    .get("resources")
                    .and_then(J::as_array)
                    .into_iter()
                    .flatten()
                {
                    if r.get("mode").and_then(J::as_str) != Some("data") {
                        continue;
                    }
                    let addr = r.get("address").and_then(J::as_str).unwrap_or("");
                    if seen.contains(addr) {
                        continue;
                    }
                    if let Some(pr) = plan_res(
                        r,
                        r.get("values").unwrap_or(&NULL),
                        &FALSE,
                        r.get("sensitive_values").unwrap_or(&FALSE),
                    ) {
                        seen.insert(pr.address.clone());
                        out.push(pr);
                    }
                }
                stack.extend(
                    m.get("child_modules")
                        .and_then(J::as_array)
                        .into_iter()
                        .flatten(),
                );
            }
        }
        out
    }

    fn variables(&self, module: &str, src: Option<&Module>) -> Vec<VariableInfo> {
        let src_vars = src.map(|m| m.variables.as_slice()).unwrap_or_default();
        if !module.is_empty() {
            // Child module inputs are not in the plan JSON.
            return src_vars
                .iter()
                .map(|v| VariableInfo {
                    name: v.name.clone(),
                    value: Value::other("module input (not recorded in plan JSON)")
                        .inherit_sensitive(&v.value),
                    span: v.span,
                })
                .collect();
        }
        let Some(vars) = self.plan.get("variables").and_then(J::as_object) else {
            return Vec::new();
        };
        vars.iter()
            .map(|(name, v)| {
                let span = src_vars
                    .iter()
                    .find(|sv| &*sv.name == name)
                    .map(|sv| sv.span)
                    .unwrap_or_else(|| self.plan_span(&format!("\"{name}\"")));
                let sensitive = self
                    .plan
                    .pointer("/configuration/root_module/variables")
                    .and_then(|vars| vars.get(name))
                    .and_then(|v| v.get("sensitive"))
                    .and_then(J::as_bool)
                    == Some(true)
                    || src_vars
                        .iter()
                        .any(|v| &*v.name == name && v.value.is_sensitive());
                let value = json_value(
                    v.get("value").unwrap_or(&NULL),
                    &FALSE,
                    if sensitive { &TRUE } else { &FALSE },
                    &|_| Origin::Other("unknown".into()),
                )
                .with_prov(Prov::single(Step::new(
                    StepKind::Variable,
                    span,
                    format!("variable {name} (plan input)"),
                )));
                VariableInfo {
                    name: name.as_str().into(),
                    value,
                    span,
                }
            })
            .collect()
    }

    /// A span inside the plan JSON file: the first occurrence of `needle`.
    fn plan_span(&self, needle: &str) -> FileSpan {
        let span = match self.plan_text.find(needle) {
            Some(at) => Span::new(at as u32, (at + needle.len()) as u32),
            None => Span::empty(0),
        };
        FileSpan::new(self.plan_file, span)
    }

    fn address_span(&self, address: &str) -> FileSpan {
        let q = serde_json::to_string(address).unwrap_or_default();
        for needle in [format!("\"address\": {q}"), format!("\"address\":{q}")] {
            if self.plan_text.contains(&needle) {
                return self.plan_span(&needle);
            }
        }
        self.plan_span(&q)
    }

    fn src_module(&self, module: &str) -> Option<&'p Module> {
        self.src_modules.get(&strip_keys(module)).copied()
    }

    fn src_resource(&self, module: &str, mode: Mode, ty: &str, name: &str) -> Option<&'p Resource> {
        self.src_instance(module, mode, ty, name, None)
    }

    /// The source resource instance with instance key `key` if the source
    /// analysis expanded it, else its first (representative) instance.
    fn src_instance(
        &self,
        module: &str,
        mode: Mode,
        ty: &str,
        name: &str,
        key: Option<&str>,
    ) -> Option<&'p Resource> {
        let m = self.src_module(module)?;
        let mut it = m
            .resources
            .iter()
            .filter(|r| r.mode == mode && &*r.ty == ty && &*r.name == name);
        let first = it.clone().next();
        match key {
            Some(k) => it.find(|r| r.key.as_deref() == Some(k)).or(first),
            None => first,
        }
    }

    #[expect(clippy::too_many_lines)]
    fn resource(&mut self, pr: &PlanRes<'p>) -> Resource {
        // The plan's own spelling of the address is authoritative for the
        // instance key's kind (`[0]` versus `["0"]`).
        let id = match Address::parse(&pr.address) {
            Ok(id) => id,
            Err(_) => Address::new(
                pr.module.as_str(),
                pr.mode,
                pr.ty.as_str(),
                pr.name.as_str(),
                pr.key.as_deref().map(|k| InstanceKey::Key(k.into())),
            ),
        };
        let local = id.local();
        let src = self.src_instance(&pr.module, pr.mode, &pr.ty, &pr.name, pr.key.as_deref());
        let span = match src {
            Some(s) => s.span,
            None => {
                self.diagnostics.push(Diagnostic {
                    severity: DiagSeverity::Info,
                    code: "plan-unmapped",
                    message: format!(
                        "{}: resource block not found in source; locations point into the plan JSON",
                        pr.address
                    ),
                    at: None,
                });
                self.address_span(&pr.address)
            }
        };
        let exprs = self
            .config
            .get(&strip_keys(&pr.module))
            .and_then(|c| c.resources.get(&local))
            .copied();
        let schema = tf_schema::lookup(
            match pr.mode {
                Mode::Managed => tf_schema::SchemaKind::Resource,
                Mode::Data => tf_schema::SchemaKind::DataSource,
            },
            &pr.ty,
        );
        let ctx = ResCtx {
            id: &id,
            module: &pr.module,
            header: span,
        };
        let body = self.body(
            &ctx,
            pr.after,
            pr.unknown,
            pr.sensitive,
            schema.map(|s| s.block()),
            "",
            src.map(|s| &s.body),
            exprs,
        );
        let mut resource = Resource::new(
            id.clone(),
            span,
            body,
            Truth::True,
            None,
            None,
            schema.map(|s| s.provider),
        );
        // Keep configuration edges even when planned values are already known.
        // Plan JSON can omit dynamic indices; those edges remain uncertain.
        let resource_config = self
            .config
            .get(&strip_keys(&pr.module))
            .and_then(|c| c.resource_blocks.get(&local));
        // Prefer plan references; a source instance supplies edges only when
        // the source was evaluated with the plan's inputs.
        let graph_source = self
            .source
            .filter(|_| self.source_inputs_match)
            .and_then(|a| a.modules.iter().find(|m| m.address.as_ref() == pr.module))
            .and_then(|m| {
                m.resources.iter().find(|r| {
                    r.mode == pr.mode
                        && r.ty.as_ref() == pr.ty
                        && r.name.as_ref() == pr.name
                        && r.key.as_deref() == pr.key.as_deref()
                })
            });
        resource.dependencies_complete = resource_config.is_some();
        if let Some(config) = resource_config {
            let mut refs = Vec::new();
            collect_refs(config, &mut refs);
            if let Some(dependencies) = config.get("depends_on").and_then(J::as_array) {
                refs.extend(
                    dependencies
                        .iter()
                        .filter_map(J::as_str)
                        .map(str::to_string),
                );
            }
            resource.dependencies_complete = self.graph_dependencies(
                &pr.module,
                refs,
                Truth::True,
                0,
                &mut resource.dependencies,
            );
        }
        if !resource.dependencies_complete
            && let Some(source) = graph_source
        {
            resource
                .dependencies
                .extend(source.dependencies.iter().cloned());
            tf_semantic::graph::body_dependencies(&source.body, &mut resource.dependencies);
            for value in source.count.iter().chain(source.for_each.iter()) {
                tf_semantic::graph::value_dependencies(value, &mut resource.dependencies);
            }
            resource.dependencies_complete = source.dependencies_complete;
        }
        resource
    }

    /// Follow configuration references through module outputs and arguments.
    /// Plan JSON does not contain local definitions; source is required there.
    #[expect(clippy::too_many_lines)]
    fn graph_dependencies(
        &self,
        module: &str,
        refs: Vec<String>,
        certainty: Truth,
        depth: usize,
        out: &mut Vec<tf_eval::prov::ResourceDependency>,
    ) -> bool {
        if depth > 64 {
            return false;
        }
        let mut complete = true;
        for reference in &refs {
            // Terraform includes traversal prefixes in the references array.
            if refs.iter().any(|r| {
                r.len() > reference.len()
                    && r.starts_with(reference)
                    && matches!(r.as_bytes()[reference.len()], b'.' | b'[')
            }) {
                continue;
            }
            match classify(reference) {
                Ref::Resource { local, key, .. } => {
                    if let Ok(target) = Address::parse_local(module, &local) {
                        out.push(tf_eval::prov::ResourceDependency {
                            resource: target.base_string().into(),
                            key: key.map(Into::into),
                            certainty,
                        });
                    }
                }
                Ref::Local(_) => complete = false,
                Ref::Var(name) => {
                    if let Some(parent) = parent_module(module)
                        && let Some(expr) = self
                            .config
                            .get(&strip_keys(module))
                            .and_then(|c| c.inputs.get(&name))
                    {
                        let mut refs = Vec::new();
                        collect_refs(expr, &mut refs);
                        complete &=
                            self.graph_dependencies(&parent, refs, certainty, depth + 1, out);
                    }
                }
                Ref::Module(name) => {
                    use crate::refs::{Seg, segments};
                    let segments = segments(reference);
                    let (key, output) = match segments.get(2) {
                        Some(Seg::Index(key)) => (Some(key.as_str()), segments.get(3)),
                        output => (None, output),
                    };
                    let child = if module.is_empty() {
                        format!("module.{name}")
                    } else {
                        format!("{module}.module.{name}")
                    };
                    // Instances of the child module: `child` itself, or its
                    // keyed instances `child[...]`, which sort right after it.
                    let candidates: Vec<String> = self
                        .module_instances
                        .range(child.clone()..)
                        .take_while(|m| m.starts_with(&child))
                        .filter(|m| {
                            parent_module(m).as_deref() == Some(module)
                                && strip_keys(m) == strip_keys(&child)
                                && key.is_none_or(|k| **m == format!("{child}[{k}]"))
                        })
                        .cloned()
                        .collect();
                    if candidates.is_empty() {
                        complete = false;
                    }
                    for target in candidates {
                        let certainty = if key.is_none() && target != child {
                            Truth::Unknown
                        } else {
                            certainty
                        };
                        if let Some(config) = self.config.get(&strip_keys(&target)) {
                            for (name, expr) in &config.outputs {
                                if let Some(Seg::Name(want)) = output
                                    && want != name
                                {
                                    continue;
                                }
                                let mut refs = Vec::new();
                                collect_refs(expr, &mut refs);
                                complete &= self.graph_dependencies(
                                    &target,
                                    refs,
                                    certainty,
                                    depth + 1,
                                    out,
                                );
                            }
                        } else {
                            complete = false;
                        }
                    }
                }
                Ref::Other => {}
            }
        }
        complete
    }

    #[allow(clippy::too_many_arguments)]
    #[expect(clippy::too_many_lines)]
    fn body(
        &self,
        ctx: &ResCtx<'_>,
        after: &J,
        unknown: &J,
        sensitive: &J,
        schema: Option<&tf_schema::Block<'static>>,
        path: &str,
        src: Option<&Body>,
        exprs: Option<&serde_json::Map<String, J>>,
    ) -> Body {
        let top = path.is_empty();
        let mut out = Body {
            span: src.map(|b| b.span).unwrap_or(ctx.header),
            attrs: Vec::new(),
            blocks: Vec::new(),
        };
        let mut names: BTreeSet<&str> = BTreeSet::new();
        if let Some(o) = after.as_object() {
            names.extend(o.keys().map(String::as_str));
        }
        if let Some(o) = unknown.as_object() {
            names.extend(o.keys().map(String::as_str));
        }
        for name in names {
            let av = after.get(name).unwrap_or(&NULL);
            let uv = unknown.get(name).unwrap_or(&FALSE);
            let sv = if sensitive.as_bool() == Some(true)
                || schema
                    .and_then(|s| s.attribute(name))
                    .is_some_and(|a| a.is_sensitive())
            {
                &TRUE
            } else {
                sensitive.get(name).unwrap_or(&FALSE)
            };
            let expr = exprs.and_then(|e| e.get(name));
            let wholly_unknown = uv.as_bool() == Some(true);
            if top && wholly_unknown && expr.is_none() {
                // Provider-computed and not set in configuration: absent, as
                // in the HCL model (the defaults overlay then applies).
                continue;
            }
            let src_attr = src.and_then(|b| b.attr(name));
            let src_block = src.and_then(|b| b.blocks_of(name).next());
            let at = src_attr
                .map(|a| a.span)
                .or(src_block.map(|b| b.body.span))
                .unwrap_or(ctx.header);
            let full = format!("{path}{name}");
            if let Some(tf_schema::Member::Block(nb)) = schema.and_then(|s| s.member(name)) {
                let elems: Vec<(&J, &J, &J)> = match av {
                    J::Array(a) => a
                        .iter()
                        .enumerate()
                        .map(|(i, e)| {
                            (
                                e,
                                uv.get(i).unwrap_or(&FALSE),
                                if sv.as_bool() == Some(true) {
                                    sv
                                } else {
                                    sv.get(i).unwrap_or(&FALSE)
                                },
                            )
                        })
                        .collect(),
                    J::Object(_) => vec![(av, uv, sv)],
                    _ => Vec::new(),
                };
                if wholly_unknown {
                    out.blocks.push(Block {
                        ty: name.into(),
                        body: Body {
                            span: at,
                            ..Body::default()
                        },
                        dynamic: false,
                        existence: Truth::Unknown,
                    });
                }
                let src_blocks: Vec<&Block> =
                    src.map(|b| b.blocks_of(name).collect()).unwrap_or_default();
                for (i, (e, u, s)) in elems.into_iter().enumerate() {
                    let sb = src_blocks.get(i).map(|b| &b.body);
                    out.blocks.push(Block {
                        ty: name.into(),
                        body: self.body(
                            ctx,
                            e,
                            u,
                            s,
                            Some(nb.block()),
                            &format!("{full}."),
                            sb,
                            None,
                        ),
                        dynamic: src_blocks.get(i).is_some_and(|b| b.dynamic),
                        existence: Truth::True,
                    });
                }
                continue;
            }
            // An attribute.
            let refs: Vec<Ref> = expr
                .map(|e| {
                    let mut v = Vec::new();
                    collect_refs(e, &mut v);
                    v.iter().map(|r| classify(r)).collect()
                })
                .unwrap_or_default();
            let origin_top = top.then(|| {
                self.origin_from_refs(
                    ctx,
                    &refs,
                    &full,
                    expr.is_some(),
                    src_attr.map(|a| &a.value),
                )
            });
            let value = json_value(av, uv, sv, &|sub: &str| {
                if sub.is_empty()
                    && let Some(o) = &origin_top
                {
                    return o.clone();
                }
                ctx.id.computed(if sub.is_empty() {
                    full.clone()
                } else {
                    format!("{full}{sub}")
                })
            });
            let sensitive_any = any_true(sv);
            let mut prov = Prov::EMPTY;
            if top {
                for s in self.ref_steps(ctx, &refs, sensitive_any) {
                    prov = prov.push(s);
                }
            }
            // Configured attributes get the same label shape as the HCL
            // front end (`<address> <path>`), so rule messages that quote the
            // deciding step read the same for both inputs.
            let what = if sensitive_any {
                " (sensitive)".to_string()
            } else if top && expr.is_none() {
                match short(&value) {
                    Some(s) => format!(" not set in configuration: planned {s}"),
                    None => " not set in configuration (planned value)".to_string(),
                }
            } else {
                String::new()
            };
            prov = prov.push(
                Step::new(StepKind::Attribute, at, format!("{} {full}{what}", ctx.id))
                    .with_resource(ctx.id.base_string().into())
                    .with_attribute(full.as_str()),
            );
            out.attrs.push(Attr {
                name: name.into(),
                value: value.with_prov(prov),
                span: at,
                from_blocks: src_attr.is_some_and(|a| a.from_blocks),
            });
        }
        out
    }

    /// Origin of an unknown top-level attribute, from its references.
    ///
    /// Plan JSON drops the attribute after a dynamic index:
    /// `aws_s3_bucket.b[each.key].id` is recorded as
    /// `references: ["aws_s3_bucket.b", "each.key"]`. For a single resource
    /// referenced without an attribute, the origin is taken from the source
    /// model's value of the same attribute when that is `Computed` on the
    /// same resource (the HCL evaluator saw the whole traversal).
    fn origin_from_refs(
        &self,
        ctx: &ResCtx<'_>,
        refs: &[Ref],
        full: &str,
        configured: bool,
        src_value: Option<&Value>,
    ) -> Origin {
        let mut resources: BTreeMap<&str, (Option<&str>, Option<&str>)> = BTreeMap::new();
        let mut others = false;
        for r in refs {
            match r {
                Ref::Resource { local, key, attr } => {
                    let e = resources.entry(local.as_str()).or_insert((None, None));
                    if e.0.is_none() {
                        e.0 = key.as_deref();
                    }
                    if e.1.is_none() {
                        e.1 = attr.as_deref();
                    }
                }
                Ref::Module(_) => others = true,
                _ => {}
            }
        }
        if resources.len() == 1
            && !others
            && let Some((local, (key, Some(attr)))) = resources.iter().next()
            && let Ok(target) = Address::parse_local(ctx.module, local)
        {
            return target
                .with_key(key.map(|k| InstanceKey::Key(k.into())))
                .computed(*attr);
        }
        if resources.len() == 1
            && !others
            && let Some(local) = resources.keys().next()
            && let Some(o @ Origin::Computed { resource, .. }) = src_value.and_then(Value::origin)
            && let Ok(target) = Address::parse_local(ctx.module, local)
            && **resource == *target.base_string()
        {
            return o.clone();
        }
        if !configured {
            return ctx.id.computed(full);
        }
        let names: Vec<String> = refs
            .iter()
            .filter_map(|r| match r {
                Ref::Resource { local, .. } => Some(local.clone()),
                Ref::Module(m) => Some(format!("module.{m}")),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if names.is_empty() {
            Origin::Other("unknown until apply".into())
        } else {
            Origin::Other(format!("unknown until apply (depends on {})", names.join(", ")).into())
        }
    }

    /// Provenance steps for an attribute's direct references: variables,
    /// locals and referenced resource attributes (oldest first).
    /// Variable values are quoted in labels unless the variable is declared
    /// `sensitive` or the attribute is sensitive (`redact`).
    #[expect(clippy::too_many_lines)]
    fn ref_steps(&self, ctx: &ResCtx<'_>, refs: &[Ref], redact: bool) -> Vec<Step> {
        let src = self.src_module(ctx.module);
        let mut steps = Vec::new();
        let mut done: BTreeSet<String> = BTreeSet::new();
        for r in refs {
            match r {
                Ref::Var(n) if done.insert(format!("var.{n}")) => {
                    let span = src
                        .and_then(|m| m.variables.iter().find(|v| &*v.name == n))
                        .map(|v| v.span);
                    let var_sensitive = self
                        .plan
                        .pointer(&format!(
                            "/configuration/root_module/variables/{}/sensitive",
                            pointer_escape(n)
                        ))
                        .and_then(J::as_bool)
                        == Some(true);
                    let value = if ctx.module.is_empty() && !redact && !var_sensitive {
                        self.plan
                            .pointer(&format!("/variables/{}/value", pointer_escape(n)))
                            .map(|v| compact(v, 60))
                    } else {
                        None
                    };
                    let label = match value {
                        Some(v) => format!("variable {n} = {v} (plan input)"),
                        None if redact || var_sensitive => format!("variable {n} (sensitive)"),
                        None => format!("variable {n}"),
                    };
                    steps.push(Step::new(
                        StepKind::Variable,
                        span.unwrap_or(ctx.header),
                        label,
                    ));
                }
                Ref::Local(n) if done.insert(format!("local.{n}")) => {
                    let span = src.and_then(|m| {
                        m.symbols
                            .iter()
                            .find(|s| matches!(&s.symbol, SymbolRef::Local(l) if l == n))
                            .map(|s| s.span)
                    });
                    steps.push(Step::new(
                        StepKind::Local,
                        span.unwrap_or(ctx.header),
                        format!("local.{n}"),
                    ));
                }
                Ref::Resource { local, attr, .. }
                    if attr.is_some()
                        && done.insert(format!("{local}.{}", attr.as_deref().unwrap_or(""))) =>
                {
                    let attr = attr.as_deref().unwrap_or("");
                    let Ok(referenced) = Address::parse_local(ctx.module, local) else {
                        continue;
                    };
                    let target: Arc<str> = referenced.base_string().into();
                    let span = self
                        .src_resource(
                            ctx.module,
                            referenced.mode,
                            &referenced.ty,
                            &referenced.name,
                        )
                        .map(|r| r.attr(attr).map(|a| a.span).unwrap_or(r.span))
                        .unwrap_or(ctx.header);
                    steps.push(
                        Step::new(
                            StepKind::Attribute,
                            span,
                            format!("{target}.{attr} (reference in plan configuration)"),
                        )
                        .with_resource(target)
                        .with_attribute(attr),
                    );
                }
                _ => {}
            }
        }
        steps
    }
}

struct ResCtx<'c> {
    id: &'c Address,
    module: &'c str,
    header: FileSpan,
}

fn plan_res<'p>(r: &'p J, after: &'p J, unknown: &'p J, sensitive: &'p J) -> Option<PlanRes<'p>> {
    let s = |k: &str| r.get(k).and_then(J::as_str).map(str::to_string);
    let mode = match s("mode")?.as_str() {
        "managed" => Mode::Managed,
        "data" => Mode::Data,
        _ => return None,
    };
    let key = r.get("index").and_then(|i| match i {
        J::String(s) => Some(s.clone()),
        J::Number(n) => Some(n.to_string()),
        _ => None,
    });
    Some(PlanRes {
        address: s("address")?,
        module: s("module_address").unwrap_or_default(),
        mode,
        ty: s("type")?,
        name: s("name")?,
        key,
        after,
        unknown,
        sensitive,
    })
}

fn index_config<'p>(m: &'p J, prefix: String, out: &mut HashMap<String, ConfigModule<'p>>) {
    let entry = out.entry(prefix.clone()).or_default();
    if let Some(outputs) = m.get("outputs").and_then(J::as_object) {
        entry
            .outputs
            .extend(outputs.iter().map(|(name, expr)| (name.clone(), expr)));
    }
    for r in m
        .get("resources")
        .and_then(J::as_array)
        .into_iter()
        .flatten()
    {
        let Some(addr) = r.get("address").and_then(J::as_str) else {
            continue;
        };
        entry.resource_blocks.insert(addr.to_string(), r);
        if let Some(e) = r.get("expressions").and_then(J::as_object) {
            entry.resources.insert(addr.to_string(), e);
        }
    }
    if let Some(calls) = m.get("module_calls").and_then(J::as_object) {
        for (name, call) in calls {
            if let Some(child) = call.get("module") {
                let p = if prefix.is_empty() {
                    format!("module.{name}")
                } else {
                    format!("{prefix}.module.{name}")
                };
                index_config(child, p.clone(), out);
                if let Some(inputs) = call.get("expressions").and_then(J::as_object) {
                    out.entry(p)
                        .or_default()
                        .inputs
                        .extend(inputs.iter().map(|(name, expr)| (name.clone(), expr)));
                }
            }
        }
    }
}

/// All `references` strings in an expression subtree.
fn collect_refs(e: &J, out: &mut Vec<String>) {
    match e {
        J::Object(o) => {
            if let Some(J::Array(rs)) = o.get("references") {
                out.extend(rs.iter().filter_map(J::as_str).map(str::to_string));
            }
            for (k, v) in o {
                if k != "references" && k != "constant_value" {
                    collect_refs(v, out);
                }
            }
        }
        J::Array(a) => a.iter().for_each(|x| collect_refs(x, out)),
        _ => {}
    }
}

fn any_true(j: &J) -> bool {
    match j {
        J::Bool(b) => *b,
        J::Array(a) => a.iter().any(any_true),
        J::Object(o) => o.values().any(any_true),
        _ => false,
    }
}

/// Planned JSON (+ unknown / sensitive markers) → lattice value. `origin`
/// gets the path below the attribute (`""`, `[0].cidr_blocks`).
fn json_value(j: &J, unknown: &J, sensitive: &J, origin: &dyn Fn(&str) -> Origin) -> Value {
    fn go(j: &J, u: &J, s: &J, path: &mut String, origin: &dyn Fn(&str) -> Origin) -> Value {
        if u.as_bool() == Some(true) {
            let value = Value::unknown(origin(path));
            return if s.as_bool() == Some(true) {
                value.sensitive()
            } else {
                value
            };
        }
        let value = match j {
            J::Null => Value::null(),
            J::Bool(b) => Value::bool(*b),
            J::Number(n) => Value::number(n.as_f64().unwrap_or(f64::NAN)),
            J::String(x) => Value::string(x.as_str()),
            J::Array(a) => {
                let mut v = Vec::with_capacity(a.len());
                for (i, e) in a.iter().enumerate() {
                    let len = path.len();
                    path.push_str(&format!("[{i}]"));
                    v.push(go(
                        e,
                        u.get(i).unwrap_or(&FALSE),
                        s.get(i).unwrap_or(&FALSE),
                        path,
                        origin,
                    ));
                    path.truncate(len);
                }
                // Unknown trailing elements (marked but absent in `after`).
                Value::list(v)
            }
            J::Object(o) => {
                let mut m = tf_eval::value::Map::new();
                let mut keys: BTreeSet<&str> = o.keys().map(String::as_str).collect();
                if let Some(uo) = u.as_object() {
                    keys.extend(uo.keys().map(String::as_str));
                }
                for k in keys {
                    let len = path.len();
                    path.push('.');
                    path.push_str(k);
                    m.insert(
                        k.into(),
                        go(
                            o.get(k).unwrap_or(&NULL),
                            u.get(k).unwrap_or(&FALSE),
                            s.get(k).unwrap_or(&FALSE),
                            path,
                            origin,
                        ),
                    );
                    path.truncate(len);
                }
                Value::object(m)
            }
        };
        if s.as_bool() == Some(true) {
            value.sensitive()
        } else {
            value
        }
    }
    go(j, unknown, sensitive, &mut String::new(), origin)
}

/// Short rendering of a scalar for provenance labels.
fn short(v: &Value) -> Option<String> {
    let s = match v.as_known()? {
        tf_eval::Known::String(s) => format!("{s:?}"),
        tf_eval::Known::List(_) | tf_eval::Known::Object(_) | tf_eval::Known::Json(_) => {
            return None;
        }
        _ => v.to_string(),
    };
    (s.len() <= 60).then_some(s)
}

fn compact(j: &J, max: usize) -> String {
    let s = j.to_string();
    if s.len() <= max {
        s
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

fn pointer_escape(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_sensitive_mapping() {
        let after: J = serde_json::json!({"a": "x", "l": ["1", null]});
        let unknown: J = serde_json::json!({"l": [false, true], "b": true});
        let sens: J = serde_json::json!({"a": true});
        let v = json_value(&after, &unknown, &sens, &|p| Origin::Other(p.into()));
        let m = v.as_object().unwrap();
        assert_eq!(m["a"].as_str(), Some("x"));
        assert!(m["a"].is_sensitive());
        assert!(v.is_sensitive());
        let l = m["l"].as_list().unwrap();
        assert_eq!(l[0].as_str(), Some("1"));
        assert!(matches!(l[1].origin(), Some(Origin::Other(p)) if &**p == ".l[1]"));
        assert!(m["b"].is_unknown());
        assert!(any_true(&sens));
    }
}

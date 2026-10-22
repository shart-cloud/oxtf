//! The engine: a type → rules dispatch table built once, run per module
//! instance.

use std::collections::HashMap;
use std::sync::Arc;

use tf_eval::Truth;
use tf_semantic::Analysis;
use tf_semantic::source::FileTable;
use tf_semantic::store::ModuleStore;

use crate::RuleBudget;
use crate::record::RuleError;
use crate::rule::{ConfigFile, DynRule, Engine, Finding, Judgement, RuleInfo, Subject};

/// Foreign/custom programs can interpolate arbitrary input into a message.
/// Without a dependency trace for that string, redact the whole message
/// when its input scope contained sensitive values.
fn protect(info: &RuleInfo, mut j: Judgement, sensitive: bool) -> Judgement {
    if sensitive
        && (info.source.engine != Engine::Builtin
            || j.witness.as_ref().is_some_and(tf_eval::Value::is_sensitive))
    {
        j.message = format!(
            "{} (policy message redacted: sensitive input)",
            info.description
        );
        j.witness = j.witness.map(tf_eval::Value::sensitive);
    }
    j
}

fn failure(message: String, sensitive: bool) -> String {
    if sensitive {
        "rule execution failed on sensitive input (details redacted)".into()
    } else {
        message
    }
}

/// Where a root's parsed source lives while its rules run, for rules that
/// judge whole files.
#[derive(Clone, Copy)]
pub struct Sources<'s> {
    pub limits: tf_limits::Limits,
    pub store: &'s ModuleStore,
    pub files: &'s FileTable,
}

/// What one module-instance pass produced.
#[derive(Default)]
pub struct RunOutput {
    /// Successful rule charges for this root; refused charges are excluded.
    pub rule_steps: u64,
    /// Admitted elapsed Rego execution, capped at its configured allowance on timeout.
    pub rego_elapsed: std::time::Duration,
    pub rule_exhaustion: Option<tf_limits::Exhaustion>,
    /// Set when this root stopped at the scan's `results` allowance.
    pub results_exhaustion: Option<tf_limits::Exhaustion>,
    pub findings: Vec<Finding>,
    /// Hooks that returned `Err`, one per (rule, resource) or (rule, module).
    pub rule_errors: Vec<RuleError>,
    /// Filled by the caller from [`crate::suppress`].
    pub suppressed: Vec<crate::suppress::Suppressed>,
}

pub struct Linter {
    rules: Vec<Box<dyn DynRule>>,
    infos: Vec<RuleInfo>,
    by_type: HashMap<Arc<str>, Vec<usize>>,
    /// Rules whose `resource_types` is `["*"]`: judged on every managed
    /// resource instance (foreign policies declare no types).
    any_type: Vec<usize>,
    module_rules: Vec<usize>,
}

/// The resource type that means "every managed resource".
pub const ANY_TYPE: &str = "*";

impl Linter {
    pub fn new(rules: Vec<Box<dyn DynRule>>) -> Self {
        let infos: Vec<RuleInfo> = rules.iter().map(|r| r.info()).collect();
        let mut by_type: HashMap<Arc<str>, Vec<usize>> = HashMap::new();
        let mut any_type = Vec::new();
        let mut module_rules = Vec::new();
        for (i, info) in infos.iter().enumerate() {
            for t in &info.resource_types {
                if &**t == ANY_TYPE {
                    any_type.push(i);
                } else {
                    by_type.entry(t.clone()).or_default().push(i);
                }
            }
            if info.runs_on_module {
                module_rules.push(i);
            }
        }
        Linter {
            rules,
            infos,
            by_type,
            any_type,
            module_rules,
        }
    }

    /// The five seed rules.
    pub fn with_seed_rules() -> Self {
        Linter::new(crate::rules::all())
    }

    /// Select rules by ID, rejecting every unknown ID before dispatch is built.
    /// An explicitly empty selection is valid and runs no rules.
    pub fn filtered(
        rules: Vec<Box<dyn DynRule>>,
        ids: &[String],
    ) -> Result<Self, RuleSelectionError> {
        select_rules(rules, ids).map(Self::new)
    }

    /// Whether any rule judges whole files (see [`Linter::run_with`]).
    pub fn needs_files(&self) -> bool {
        self.rules.iter().any(|r| r.needs_files())
    }

    pub fn rules(&self) -> &[RuleInfo] {
        &self.infos
    }

    /// Run every rule over every module instance of `analysis`. This is
    /// the only place findings are constructed, and the only place a rule
    /// failure is turned into a [`RuleError`].
    pub fn run(&self, analysis: &Analysis) -> RunOutput {
        self.run_with(analysis, None)
    }

    /// [`Linter::run`] with the parsed source available to whole-file
    /// rules.
    pub fn run_with(&self, analysis: &Analysis, sources: Option<Sources<'_>>) -> RunOutput {
        let limits = sources.map(|s| s.limits).unwrap_or_default();
        self.run_with_limits(analysis, sources, limits)
    }

    /// Explicit root allowance, also used for plan inputs without parsed sources.
    /// Without a scan file table, graph storage and results use a local allowance.
    pub fn run_with_limits(
        &self,
        analysis: &Analysis,
        sources: Option<Sources<'_>>,
        limits: tf_limits::Limits,
    ) -> RunOutput {
        match sources {
            Some(s) => self.run_with_storage(analysis, sources, limits, s.files.input_budget()),
            None => {
                let local = tf_limits::input::InputBudget::new(limits);
                self.run_with_storage(analysis, None, limits, &local)
            }
        }
    }

    /// `storage` is the scan's shared allowance: graph edges and the scan-wide
    /// `results` count of findings and rule errors are admitted against it.
    pub fn run_with_storage(
        &self,
        analysis: &Analysis,
        sources: Option<Sources<'_>>,
        limits: tf_limits::Limits,
        storage: &tf_limits::input::InputBudget,
    ) -> RunOutput {
        let mut run = RuleRun {
            linter: self,
            analysis,
            budget: RuleBudget::new(limits),
            storage,
            results_refused: false,
            refused_error_kept: false,
            out: RunOutput::default(),
            sensitive: analysis
                .modules
                .iter()
                .any(tf_semantic::Module::is_sensitive),
        };
        run.graphs();
        run.files(sources);
        run.modules();
        attach_packages(&mut run.out.findings, analysis);
        if let Some(sources) = sources {
            protect_fix_hints(&mut run.out.findings, analysis, sources.files);
        }
        run.out.rule_steps = run.budget.used();
        run.out.rego_elapsed = run.budget.rego_elapsed();
        run.out.rule_exhaustion = run.budget.exhaustion();
        run.out.results_exhaustion = storage.results_exhaustion().filter(|_| run.results_refused);
        run.out
    }

    fn graph_rules(&self, analysis: &Analysis) -> Vec<usize> {
        // A graph is needed only when at least one graph rule has a target.
        let present: std::collections::HashSet<String> = analysis
            .modules
            .iter()
            .flat_map(|m| &m.resources)
            .map(|r| match r.mode {
                tf_semantic::Mode::Data => format!("data.{}", r.ty),
                _ => r.ty.to_string(),
            })
            .collect();
        (0..self.rules.len())
            .filter(|&i| {
                let types = &self.infos[i].resource_types;
                self.rules[i].needs_graph()
                    && (types.is_empty()
                        || types
                            .iter()
                            .any(|t| &**t == ANY_TYPE || present.contains(&**t)))
            })
            .collect()
    }
}

struct RuleRun<'a> {
    linter: &'a Linter,
    analysis: &'a Analysis,
    budget: RuleBudget,
    storage: &'a tf_limits::input::InputBudget,
    /// This root stopped because the scan's `results` allowance refused an entry.
    results_refused: bool,
    /// One refused rule error is kept so a failure keeps precedence over incomplete.
    refused_error_kept: bool,
    out: RunOutput,
    sensitive: bool,
}

impl RuleRun<'_> {
    fn stopped(&self) -> bool {
        self.budget.exhaustion().is_some() || self.results_refused
    }

    /// Admit one result; refusal stops this root's later hooks.
    fn admit_result(&mut self) -> bool {
        if self.results_refused {
            return false;
        }
        self.results_refused = self.storage.admit_result().is_err();
        !self.results_refused
    }

    fn push_error(&mut self, error: RuleError) {
        if self.admit_result() || !self.refused_error_kept {
            self.refused_error_kept |= self.results_refused;
            self.out.rule_errors.push(error);
        }
    }

    fn invoke<T>(
        &mut self,
        i: usize,
        resource: Option<&tf_semantic::Resource>,
        sensitive: bool,
        call: impl FnOnce(&dyn DynRule, &RuleBudget) -> Result<T, String>,
    ) -> Option<T> {
        assert!(!self.stopped());
        let result = self
            .budget
            .charge(1)
            .and_then(|()| call(&*self.linter.rules[i], &self.budget));
        match self.budget.finish(result) {
            Ok(result) => Some(result),
            Err(message) => {
                // Exhaustion text contains only the resource name and allowance,
                // so sensitivity must not hide the reason a root stopped.
                let message = match self.budget.exhaustion() {
                    Some(exhaustion) => exhaustion.to_string(),
                    None => failure(message, sensitive),
                };
                self.push_error(RuleError {
                    rule: self.linter.infos[i].name.to_string(),
                    resource: resource.map(|r| r.address.to_string()),
                    message,
                });
                None
            }
        }
    }

    fn finding(
        &mut self,
        i: usize,
        resource: &tf_semantic::Resource,
        j: Judgement,
        sensitive: bool,
    ) {
        if self.results_refused {
            return;
        }
        let info = &self.linter.infos[i];
        let built = Finding::build(
            info,
            resource,
            protect(info, j, sensitive),
            &self.analysis.root_dir,
        );
        // A resource that cannot exist yields no finding and consumes no allowance.
        if let Some(finding) = built
            && self.admit_result()
        {
            self.out.findings.push(finding);
        }
    }

    fn graphs(&mut self) {
        let rules = self.linter.graph_rules(self.analysis);
        if rules.is_empty() {
            return;
        }
        let built = tf_semantic::graph::ResourceGraph::with_budget(
            self.analysis,
            self.budget.work(),
            self.storage,
        );
        let graph = match built {
            Ok(graph) => graph,
            Err(exhaustion) => {
                // No graph rule ran: each records the typed refusal, never an empty verdict.
                for i in rules {
                    self.push_error(RuleError {
                        rule: self.linter.infos[i].name.to_string(),
                        resource: None,
                        message: exhaustion.to_string(),
                    });
                }
                return;
            }
        };
        for i in rules {
            if self.stopped() {
                return;
            }
            if let Some(judgements) = self.invoke(i, None, self.sensitive, |rule, budget| {
                rule.judge_graph_with_budget(&graph, budget)
            }) {
                for (r, j) in judgements {
                    self.finding(i, r, j, self.sensitive);
                }
            }
        }
    }

    fn files(&mut self, sources: Option<Sources<'_>>) {
        if self.stopped() || !self.linter.needs_files() {
            return;
        }
        let config = config_files(self.analysis, sources);
        for (i, rule) in self.linter.rules.iter().enumerate() {
            if self.stopped() {
                return;
            }
            if !rule.needs_files() {
                continue;
            }
            if let Some(judgements) = self.invoke(i, None, self.sensitive, |rule, budget| {
                rule.judge_files_with_budget(self.analysis, &config, budget)
            }) {
                for (subject, j) in judgements {
                    match subject {
                        Subject::Resource(r) => self.finding(i, r, j, self.sensitive),
                        Subject::File { module, file } => {
                            if !self.admit_result() {
                                continue;
                            }
                            let source = config
                                .iter()
                                .find(|c| c.source.id == file)
                                .expect("a file subject names a loaded file");
                            self.out.findings.push(Finding::for_file(
                                &self.linter.infos[i],
                                module,
                                &source.source,
                                protect(&self.linter.infos[i], j, self.sensitive),
                                &self.analysis.root_dir,
                            ));
                        }
                    }
                }
            }
        }
    }

    fn modules(&mut self) {
        for module in &self.analysis.modules {
            if self.stopped() {
                return;
            }
            for &i in &self.linter.module_rules {
                if self.stopped() {
                    return;
                }
                if let Some(judgements) =
                    self.invoke(i, None, module.is_sensitive(), |rule, budget| {
                        rule.judge_module_with_budget(module, budget)
                    })
                {
                    for (r, j) in judgements {
                        self.finding(i, r, j, module.is_sensitive());
                    }
                }
            }
            for resource in &module.resources {
                if self.stopped() {
                    return;
                }
                self.resource(resource);
            }
        }
    }

    fn resource(&mut self, resource: &tf_semantic::Resource) {
        if resource.existence == Truth::False || resource.mode != tf_semantic::Mode::Managed {
            return;
        }
        let typed = self.linter.by_type.get(&*resource.ty).into_iter().flatten();
        for &i in typed.chain(&self.linter.any_type) {
            if self.stopped() {
                return;
            }
            let sensitive = resource.body.is_sensitive();
            if let Some(judgements) = self.invoke(i, Some(resource), sensitive, |rule, budget| {
                rule.judge_resource_with_budget(resource, budget)
            }) {
                for j in judgements {
                    self.finding(i, resource, j, sensitive);
                }
            }
        }
    }
}

fn config_files<'a>(analysis: &'a Analysis, sources: Option<Sources<'a>>) -> Vec<ConfigFile<'a>> {
    static RUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let run = RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut config = Vec::new();
    if let Some(src) = sources {
        for module in &analysis.modules {
            let Ok(definition) = src
                .store
                .module_with_limits(src.files, &module.dir, src.limits)
            else {
                break;
            };
            for (source, ast) in &definition.files {
                if tf_semantic::module::is_override(&source.path) && ast.body.items.is_empty() {
                    continue;
                }
                config.push(ConfigFile {
                    module,
                    definition,
                    source: source.clone(),
                    ast,
                    run,
                });
            }
        }
    }
    config
}

fn attach_packages(findings: &mut [Finding], analysis: &Analysis) {
    let packages: HashMap<_, _> = analysis
        .modules
        .iter()
        .filter_map(|m| m.package.as_ref().map(|p| (m.address.as_ref(), p)))
        .collect();
    for f in findings {
        f.package = packages.get(f.module.as_ref()).map(|p| (*p).clone());
        if f.package.is_some()
            || f.fix_hint
                .as_ref()
                .is_some_and(|h| packages.contains_key(h.resource.module.as_ref()))
        {
            f.fix_hint = None;
        }
    }
}

/// The HCL writer cannot edit JSON or installed packages. Resolve the actual
/// target, including insertions and cross-resource hints, before exposing it.
pub fn protect_fix_hints(findings: &mut [Finding], analysis: &Analysis, files: &FileTable) {
    let writable = |at: tf_span::FileSpan| {
        let sf = files.get(at.file);
        !files.is_protected(&sf.path) && sf.path.extension().is_none_or(|e| e != "json")
    };
    for f in findings {
        let Some(h) = &mut f.fix_hint else { continue };
        let target = h.site.or_else(|| {
            let r = analysis
                .modules
                .iter()
                .flat_map(|m| &m.resources)
                .find(|r| r.id == h.resource)?;
            let mut body = &r.body;
            let path: Vec<_> = h.attribute.split('.').collect();
            for name in &path[..path.len().saturating_sub(1)] {
                if let Some(block) = body.blocks_of(name).next() {
                    body = &block.body;
                } else {
                    break;
                }
            }
            Some(body.span)
        });
        if !writable(f.primary) || !target.is_some_and(writable) {
            f.fix_hint = None;
        } else if h.variable.as_ref().is_some_and(|(_, at)| !writable(*at)) {
            h.variable = None;
        }
    }
}

/// Invalid explicit rule selection. No partial selection is executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSelectionError {
    pub unknown_ids: Vec<String>,
}

impl std::fmt::Display for RuleSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown rule ID(s): {}", self.unknown_ids.join(", "))
    }
}

impl std::error::Error for RuleSelectionError {}

/// Validate and select from the caller's whole catalog (built-in, loaded
/// and runtime rules alike): selection means one thing everywhere.
pub fn select_rules(
    rules: Vec<Box<dyn DynRule>>,
    ids: &[String],
) -> Result<Vec<Box<dyn DynRule>>, RuleSelectionError> {
    // A rule is selected by its name or any of its aliases.
    let names: Vec<Vec<Arc<str>>> = rules
        .iter()
        .map(|r| {
            let info = r.info();
            std::iter::once(info.name).chain(info.aliases).collect()
        })
        .collect();
    let named = |names: &[Arc<str>], id: &str| names.iter().any(|n| &**n == id);
    let mut unknown_ids = Vec::new();
    for id in ids {
        if !names.iter().any(|n| named(n, id)) && !unknown_ids.contains(id) {
            unknown_ids.push(id.clone());
        }
    }
    if !unknown_ids.is_empty() {
        return Err(RuleSelectionError { unknown_ids });
    }
    Ok(rules
        .into_iter()
        .zip(names)
        .filter_map(|(rule, n)| ids.iter().any(|id| named(&n, id)).then_some(rule))
        .collect())
}

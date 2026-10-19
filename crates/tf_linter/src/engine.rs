//! The engine: a type → rules dispatch table built once, run per module
//! instance.

use std::collections::HashMap;
use std::sync::Arc;

use tf_eval::Truth;
use tf_semantic::Analysis;
use tf_semantic::source::FileTable;
use tf_semantic::store::ModuleStore;

use crate::record::RuleError;
use crate::rule::{ConfigFile, DynRule, Finding, RuleInfo, Subject};

/// Where a root's parsed source lives while its rules run, for rules that
/// judge whole files.
#[derive(Clone, Copy)]
pub struct Sources<'s> {
    pub store: &'s ModuleStore,
    pub files: &'s FileTable,
}

/// What one module-instance pass produced.
#[derive(Default)]
pub struct RunOutput {
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
        let root = analysis.root_dir.as_path();
        let mut out = Vec::new();
        let mut rule_errors = Vec::new();
        // A graph rule judges only resources of its declared types (data
        // sources as `data.TYPE`), so one with none of them in this root
        // has nothing to judge; nor is the graph built for no rule.
        let present: std::collections::HashSet<String> = analysis
            .modules
            .iter()
            .flat_map(|m| &m.resources)
            .map(|r| match r.mode {
                tf_semantic::Mode::Data => format!("data.{}", r.ty),
                _ => r.ty.to_string(),
            })
            .collect();
        let graph_rules: Vec<usize> = (0..self.rules.len())
            .filter(|&i| {
                let types = &self.infos[i].resource_types;
                self.rules[i].needs_graph()
                    && (types.is_empty()
                        || types
                            .iter()
                            .any(|t| &**t == ANY_TYPE || present.contains(&**t)))
            })
            .collect();
        let graph =
            (!graph_rules.is_empty()).then(|| tf_semantic::graph::ResourceGraph::new(analysis));
        for i in graph_rules {
            let rule = &self.rules[i];
            match rule.judge_graph(graph.as_ref().expect("graph requested")) {
                Ok(judgements) => {
                    for (r, j) in judgements {
                        out.extend(Finding::build(
                            &self.infos[i],
                            r,
                            j.severity,
                            j.witness.as_ref(),
                            &j.message,
                            root,
                            j.hidden,
                            j.fix_hint,
                        ));
                    }
                }
                Err(message) => rule_errors.push(RuleError {
                    rule: self.infos[i].name.to_string(),
                    resource: None,
                    message,
                }),
            }
        }
        if self.rules.iter().any(|r| r.needs_files()) {
            static RUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let run = RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut config = Vec::new();
            if let Some(src) = sources {
                for m in &analysis.modules {
                    for (sf, ast) in &src.store.module(src.files, &m.dir).files {
                        config.push(ConfigFile {
                            module: m,
                            source: sf.clone(),
                            ast,
                            run,
                        });
                    }
                }
            }
            for (i, rule) in self
                .rules
                .iter()
                .enumerate()
                .filter(|(_, r)| r.needs_files())
            {
                match rule.judge_files(analysis, &config) {
                    Ok(judgements) => {
                        for (subject, j) in judgements {
                            match subject {
                                Subject::Resource(r) => out.extend(Finding::build(
                                    &self.infos[i],
                                    r,
                                    j.severity,
                                    j.witness.as_ref(),
                                    &j.message,
                                    root,
                                    j.hidden,
                                    j.fix_hint,
                                )),
                                Subject::File { module, file } => {
                                    let sf = config
                                        .iter()
                                        .find(|c| c.source.id == file)
                                        .map(|c| c.source.clone())
                                        .expect("a file subject names a loaded file");
                                    out.push(Finding::for_file(
                                        &self.infos[i],
                                        module,
                                        &sf,
                                        j.severity,
                                        j.witness.as_ref(),
                                        &j.message,
                                        root,
                                        j.hidden,
                                    ));
                                }
                            }
                        }
                    }
                    Err(message) => rule_errors.push(RuleError {
                        rule: self.infos[i].name.to_string(),
                        resource: None,
                        message,
                    }),
                }
            }
        }
        for m in &analysis.modules {
            for &i in &self.module_rules {
                let judged = match self.rules[i].judge_module(m) {
                    Ok(j) => j,
                    Err(message) => {
                        rule_errors.push(RuleError {
                            rule: self.infos[i].name.to_string(),
                            resource: None,
                            message,
                        });
                        continue;
                    }
                };
                for (r, j) in judged {
                    out.extend(Finding::build(
                        &self.infos[i],
                        r,
                        j.severity,
                        j.witness.as_ref(),
                        &j.message,
                        root,
                        j.hidden,
                        j.fix_hint,
                    ));
                }
            }
            for r in &m.resources {
                if r.existence == Truth::False || r.mode != tf_semantic::Mode::Managed {
                    continue;
                }
                let typed = self.by_type.get(&*r.ty).into_iter().flatten();
                for &i in typed.chain(&self.any_type) {
                    let judged = match self.rules[i].judge_resource(r) {
                        Ok(j) => j,
                        Err(message) => {
                            rule_errors.push(RuleError {
                                rule: self.infos[i].name.to_string(),
                                resource: Some(r.address.to_string()),
                                message,
                            });
                            continue;
                        }
                    };
                    for j in judged {
                        out.extend(Finding::build(
                            &self.infos[i],
                            r,
                            j.severity,
                            j.witness.as_ref(),
                            &j.message,
                            root,
                            j.hidden,
                            j.fix_hint,
                        ));
                    }
                }
            }
        }
        RunOutput {
            findings: out,
            rule_errors,
            suppressed: Vec::new(),
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

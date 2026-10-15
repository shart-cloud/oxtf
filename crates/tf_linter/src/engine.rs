//! The engine: a type → rules dispatch table built once, run per module
//! instance.

use std::collections::HashMap;
use std::sync::Arc;

use tf_eval::Truth;
use tf_semantic::Analysis;

use crate::record::RuleError;
use crate::rule::{DynRule, Finding, RuleInfo};

/// What one module-instance pass produced.
#[derive(Default)]
pub struct RunOutput {
    pub findings: Vec<Finding>,
    /// Hooks that returned `Err`, one per (rule, resource) or (rule, module).
    pub rule_errors: Vec<RuleError>,
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

    pub fn rules(&self) -> &[RuleInfo] {
        &self.infos
    }

    /// Run every rule over every module instance of `analysis`. This is
    /// the only place findings are constructed, and the only place a rule
    /// failure is turned into a [`RuleError`].
    pub fn run(&self, analysis: &Analysis) -> RunOutput {
        let root = analysis.root_dir.as_path();
        let mut out = Vec::new();
        let mut rule_errors = Vec::new();
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
    let names: Vec<_> = rules.iter().map(|r| r.info().name).collect();
    let mut unknown_ids = Vec::new();
    for id in ids {
        if !names.iter().any(|name| name.as_ref() == id) && !unknown_ids.contains(id) {
            unknown_ids.push(id.clone());
        }
    }
    if !unknown_ids.is_empty() {
        return Err(RuleSelectionError { unknown_ids });
    }
    Ok(rules
        .into_iter()
        .zip(names)
        .filter_map(|(rule, name)| ids.iter().any(|id| name.as_ref() == id).then_some(rule))
        .collect())
}

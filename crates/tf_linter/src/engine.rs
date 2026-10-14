//! The engine: a type → rules dispatch table built once, run per module
//! instance.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use tf_eval::Truth;
use tf_semantic::Analysis;

use crate::rule::{DynRule, Finding, RuleContext, RuleInfo};

pub struct Linter {
    rules: Vec<Box<dyn DynRule>>,
    infos: Vec<RuleInfo>,
    by_type: HashMap<Arc<str>, Vec<usize>>,
    module_rules: Vec<usize>,
}

impl Linter {
    pub fn new(rules: Vec<Box<dyn DynRule>>) -> Self {
        let infos: Vec<RuleInfo> = rules.iter().map(|r| r.info()).collect();
        let mut by_type: HashMap<Arc<str>, Vec<usize>> = HashMap::new();
        let mut module_rules = Vec::new();
        for (i, info) in infos.iter().enumerate() {
            for t in &info.resource_types {
                by_type.entry(t.clone()).or_default().push(i);
            }
            if info.runs_on_module {
                module_rules.push(i);
            }
        }
        Linter {
            rules,
            infos,
            by_type,
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

    /// Run every rule over every module instance of `analysis`.
    pub fn run(&self, analysis: &Analysis) -> Vec<Finding> {
        let mut out = Vec::new();
        for m in &analysis.modules {
            for &i in &self.module_rules {
                let mut ctx = self.ctx(i, &analysis.root_dir, m, &mut out);
                self.rules[i].run_on_module(m, &mut ctx);
            }
            for r in &m.resources {
                if r.existence == Truth::False || r.mode != tf_semantic::Mode::Managed {
                    continue;
                }
                if let Some(rs) = self.by_type.get(&*r.ty) {
                    for &i in rs {
                        let mut ctx = self.ctx(i, &analysis.root_dir, m, &mut out);
                        self.rules[i].run_on_resource(r, &mut ctx);
                    }
                }
            }
        }
        out
    }

    fn ctx<'c>(
        &self,
        i: usize,
        root: &'c Path,
        module: &'c tf_semantic::Module,
        out: &'c mut Vec<Finding>,
    ) -> RuleContext<'c> {
        RuleContext {
            rule: self.infos[i].name.clone(),
            level: self.infos[i].level,
            root,
            module,
            out,
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

/// Validate and select from the caller's catalog. CLI callers pass built-in
/// and loaded rules; Python's `builtin` option passes only built-in rules.
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

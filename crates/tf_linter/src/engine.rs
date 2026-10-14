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

    /// Keep only rules whose id is in `ids`.
    pub fn filtered(rules: Vec<Box<dyn DynRule>>, ids: &[String]) -> Self {
        Linter::new(
            rules
                .into_iter()
                .filter(|r| ids.iter().any(|i| *i == *r.info().name))
                .collect(),
        )
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

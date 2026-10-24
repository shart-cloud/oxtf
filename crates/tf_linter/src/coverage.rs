//! Execution accounting counts engine hooks, not policy passes. A completed
//! hook can return no finding because its inputs are unknown or inapplicable.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tf_semantic::Analysis;

/// One resource, module, graph, or whole-file rule invocation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckCounts {
    pub planned: usize,
    pub executed: usize,
    pub completed: usize,
    pub failed: usize,
    /// Planned hooks never invoked (for example after an allowance refusal).
    pub skipped: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCoverage {
    pub selected_rules: usize,
    /// At scan level, every selected rule, including those without model subjects.
    /// At root level, only rules with planned hooks, keeping large scans compact.
    pub rules: BTreeMap<String, CheckCounts>,
}

impl RuleCoverage {
    pub fn totals(&self) -> CheckCounts {
        let mut sum = CheckCounts::default();
        for counts in self.rules.values() {
            sum.planned += counts.planned;
            sum.executed += counts.executed;
            sum.completed += counts.completed;
            sum.failed += counts.failed;
            sum.skipped += counts.skipped;
        }
        sum
    }

    pub fn merge(&mut self, other: &Self) {
        for (rule, counts) in &other.rules {
            let sum = self.rules.entry(rule.clone()).or_default();
            sum.planned += counts.planned;
            sum.executed += counts.executed;
            sum.completed += counts.completed;
            sum.failed += counts.failed;
            sum.skipped += counts.skipped;
        }
    }
}

/// A variable whose full value was not available. Values and expression text
/// are deliberately excluded, including for sensitive variables.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedInput {
    pub module: String,
    pub variable: String,
    pub location: crate::record::Location,
}

pub fn unresolved_inputs(
    analysis: &Analysis,
    files: &tf_semantic::FileTable,
) -> Vec<UnresolvedInput> {
    analysis
        .modules
        .iter()
        .flat_map(|module| {
            module
                .variables
                .iter()
                .filter(|v| unresolved(&v.value))
                .map(|v| UnresolvedInput {
                    module: module.address.to_string(),
                    variable: v.name.to_string(),
                    location: crate::record::location(files, v.span),
                })
        })
        .collect()
}

fn unresolved(value: &tf_eval::Value) -> bool {
    use tf_eval::{Kind, Known};
    match &value.kind {
        Kind::Known(Known::List(values)) => values.iter().any(unresolved),
        Kind::Known(Known::Object(values)) => values.values().any(unresolved),
        Kind::Known(Known::Json(value)) => unresolved(value),
        Kind::Known(_) => false,
        _ => true,
    }
}

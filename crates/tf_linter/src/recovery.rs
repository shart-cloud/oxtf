//! Machine actions depend on diagnostic codes, never on rendered error text.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    InstallModules,
    InspectDependencyAccess,
    RepairConfiguration,
    RepairPolicy,
    InspectRuleExecution,
    ReviewLimits,
    ReviewScope,
    ReviewUnsupportedFeature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticAction {
    pub kind: RecoveryKind,
    /// Whether repeating the identical request can remedy this diagnostic.
    /// Known actions require an input/configuration/environment change first.
    pub retryable: bool,
    /// Names of inputs to obtain or inspect; never credential values.
    pub required_input: Vec<String>,
    pub explanation: String,
}

pub fn action(code: &str) -> Option<DiagnosticAction> {
    use RecoveryKind::*;
    let (kind, required, explanation) = match code {
        "coverage-module-not-installed" => (
            InstallModules,
            vec!["module installation", "configured data directory"],
            "Install dependencies with oxtf fetch or scan --fetch using this root's data directory, then repeat the original scan.",
        ),
        "coverage-fetch" => (
            InspectDependencyAccess,
            vec![
                "module source and ref",
                "network access",
                "credential configuration",
            ],
            "Inspect the fetch failure. Verify source/ref and network access; configure a Git credential helper, SSH agent, or registry token if access requires it. Do not infer that every fetch failure needs credentials.",
        ),
        "rule-skipped" => (
            RepairPolicy,
            vec!["policy source"],
            "Correct or explicitly exclude the unsupported policy, then repeat the scan. Exclusion narrows coverage.",
        ),
        "evaluation-error" | "parse-error" | "module-missing" | "module-cycle" | "plan-errored"
        | "plan-format" => (
            RepairConfiguration,
            vec!["configuration or plan at diagnostic location"],
            "Correct the located configuration or regenerate a valid plan, then repeat the original scan.",
        ),
        "coverage-no-input" => (
            ReviewScope,
            vec!["scan directories"],
            "Check the selected directories and root discovery. An empty scan does not establish a clean configuration.",
        ),
        "module-depth" => (
            ReviewLimits,
            vec!["module nesting", "analysis limits"],
            "Inspect nesting and the reported limit; narrow the scan or adjust a configurable allowance if appropriate.",
        ),
        _ if code.starts_with("coverage-") => {
            if matches!(
                code,
                "coverage-storage" | "coverage-results" | "coverage-loader" | "coverage-instances"
            ) {
                (
                    ReviewLimits,
                    vec!["reported allowance", "limits configuration"],
                    "Inspect the exhausted allowance. Narrow the scope or adjust the applicable limit, then repeat the scan; partial results do not establish full coverage.",
                )
            } else {
                (
                    ReviewUnsupportedFeature,
                    vec!["diagnostic location and feature", "analysis limits"],
                    "Inspect the diagnostic for an unsupported feature or fixed analysis limit. Supply supported inputs or narrow the analysis; repeating unchanged will not close the gap.",
                )
            }
        }
        _ => return None,
    };
    Some(DiagnosticAction {
        kind,
        retryable: false,
        required_input: required.into_iter().map(str::to_owned).collect(),
        explanation: explanation.into(),
    })
}

pub fn rule_action() -> DiagnosticAction {
    DiagnosticAction {
        kind: RecoveryKind::InspectRuleExecution,
        retryable: false,
        required_input: vec!["rule source".into(), "affected resource or module".into(), "reported analysis allowances".into()],
        explanation: "Inspect the rule failure and any exhausted allowance. Correct the policy or its supported inputs, or adjust the applicable limit, then repeat the original scan. A rule error is not a policy pass.".into(),
    }
}

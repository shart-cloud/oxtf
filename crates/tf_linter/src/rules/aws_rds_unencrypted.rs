use tf_eval::Verdict;
use tf_semantic::Resource;

use super::not_true;
use crate::rule::{Category, Level, Rule, RuleContext, RuleMeta};

/// `aws_db_instance` with `storage_encrypted` false, or absent (the
/// defaults overlay says the provider/API default is `false`).
///
/// Read replicas (`replicate_source_db` set) inherit encryption from the
/// source and are skipped.
pub struct AwsRdsUnencrypted;

impl RuleMeta for AwsRdsUnencrypted {
    const NAME: &'static str = "aws-rds-unencrypted";
    const CATEGORY: Category = Category::Encryption;
    const LEVEL: Level = Level::High;
    const DESCRIPTION: &'static str = "RDS instance storage is not encrypted";
    const RESOURCE_TYPES: &'static [&'static str] = &["aws_db_instance"];
}

impl Rule for AwsRdsUnencrypted {
    fn run_on_resource(&self, r: &Resource, ctx: &mut RuleContext<'_>) {
        if r.value("replicate_source_db").is_some_and(|v| !v.is_null()) {
            return;
        }
        let Some(v) = r.value_or_default("storage_encrypted") else {
            return;
        };
        let verdict: Verdict = not_true(&v);
        Self::report(r, ctx, &verdict);
    }
}

impl AwsRdsUnencrypted {
    /// Shared finding presentation for native and Rego verdicts.
    pub fn report(r: &Resource, ctx: &mut RuleContext<'_>, verdict: &Verdict) {
        ctx.report(r, verdict, |w| match w.and_then(|w| w.as_bool()) {
            Some(false) if r.value("storage_encrypted").is_none_or(|x| x.is_null()) => {
                "storage_encrypted is not set (provider default: false)".to_string()
            }
            Some(_) => "storage_encrypted is false".to_string(),
            None => "storage_encrypted may be false".to_string(),
        });
    }
}

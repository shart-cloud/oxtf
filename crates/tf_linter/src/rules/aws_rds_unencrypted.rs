use tf_eval::Verdict;
use tf_semantic::Resource;

use super::{not_true, set_attribute};
use crate::rule::{Category, FixHint, Level, Rule, RuleMeta};

/// `aws_db_instance` with `storage_encrypted` false, or absent (the
/// defaults overlay says the provider/API default is `false`).
///
/// Read replicas (`replicate_source_db` set) inherit encryption from the
/// source and are skipped.
pub struct AwsRdsUnencrypted;

impl RuleMeta for AwsRdsUnencrypted {
    const NAME: &'static str = "aws-rds-unencrypted";
    const CATEGORY: Category = Category::Encryption;
    const LEVEL: Level = Level::Medium;
    const DESCRIPTION: &'static str = "RDS instance storage is not encrypted";
    const RESOURCE_TYPES: &'static [&'static str] = &["aws_db_instance"];
    const RATIONALE: Option<&'static str> = Some(
        "Unencrypted database storage lacks protection for storage and snapshot copies. This does not establish public reachability or unauthorized database access.",
    );
    const REMEDIATION: Option<&'static str> = Some(
        "Set storage_encrypted = true for new instances. For an existing unencrypted instance, copy a snapshot with encryption enabled, restore a new instance, and plan a tested cutover. Review Terraform replacement and KMS permissions before applying; a verified source edit is not an in-place data migration.",
    );
    const GUIDELINE: Option<&'static str> =
        Some("https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html");
}

impl Rule for AwsRdsUnencrypted {
    fn verdict(&self, r: &Resource) -> Option<Verdict> {
        if r.value("replicate_source_db").is_some_and(|v| !v.is_null()) {
            return None;
        }
        Some(not_true(&r.value_or_default("storage_encrypted")?))
    }

    fn fix_hint(&self, r: &Resource, _v: &Verdict) -> Option<FixHint> {
        Some(set_attribute(
            r,
            "storage_encrypted",
            serde_json::Value::Bool(true),
        ))
    }

    fn message(&self, r: &Resource, v: &Verdict) -> String {
        match v.witness.as_ref().and_then(|w| w.as_bool()) {
            Some(false) if r.value("storage_encrypted").is_none_or(|x| x.is_null()) => {
                "storage_encrypted is not set (provider default: false)".to_string()
            }
            Some(_) => "storage_encrypted is false".to_string(),
            None => "storage_encrypted may be false".to_string(),
        }
    }
}

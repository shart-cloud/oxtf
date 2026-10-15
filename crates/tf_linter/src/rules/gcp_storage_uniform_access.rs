use tf_eval::Verdict;
use tf_semantic::Resource;

use super::{not_true, set_attribute};
use crate::rule::{Category, FixHint, Level, Rule, RuleMeta};

/// `google_storage_bucket` without uniform bucket-level access:
/// `uniform_bucket_level_access` false or absent (defaults overlay: false;
/// the attribute is optional+computed, so an org policy can still force it).
pub struct GcpStorageUniformAccess;

impl RuleMeta for GcpStorageUniformAccess {
    const NAME: &'static str = "gcp-storage-uniform-access";
    const CATEGORY: Category = Category::Storage;
    const LEVEL: Level = Level::Medium;
    const DESCRIPTION: &'static str =
        "Cloud Storage bucket does not enforce uniform bucket-level access";
    const RESOURCE_TYPES: &'static [&'static str] = &["google_storage_bucket"];
}

impl Rule for GcpStorageUniformAccess {
    fn verdict(&self, r: &Resource) -> Option<Verdict> {
        Some(not_true(&r.value_or_default("uniform_bucket_level_access")?))
    }

    fn fix_hint(&self, r: &Resource, _v: &Verdict) -> Option<FixHint> {
        Some(set_attribute(r, "uniform_bucket_level_access", serde_json::Value::Bool(true)))
    }

    fn message(&self, r: &Resource, v: &Verdict) -> String {
        if v.witness.as_ref().is_some_and(|w| !w.is_known()) {
            "uniform_bucket_level_access may be false".to_string()
        } else if r
            .value("uniform_bucket_level_access")
            .is_none_or(|x| x.is_null())
        {
            "uniform_bucket_level_access is not set (provider default: false)".to_string()
        } else {
            "uniform_bucket_level_access is false".to_string()
        }
    }
}

use tf_semantic::Resource;

use super::not_true;
use crate::rule::{Category, Level, Rule, RuleContext, RuleMeta};

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
    fn run_on_resource(&self, r: &Resource, ctx: &mut RuleContext<'_>) {
        let Some(v) = r.value_or_default("uniform_bucket_level_access") else {
            return;
        };
        let verdict = not_true(&v);
        ctx.report(r, &verdict, |w| {
            if w.is_some_and(|w| !w.is_known()) {
                "uniform_bucket_level_access may be false".to_string()
            } else if r
                .value("uniform_bucket_level_access")
                .is_none_or(|x| x.is_null())
            {
                "uniform_bucket_level_access is not set (provider default: false)".to_string()
            } else {
                "uniform_bucket_level_access is false".to_string()
            }
        });
    }
}

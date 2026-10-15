//! The five seed rules and shared helpers.

mod aws_iam_wildcard_policy;
mod aws_rds_unencrypted;
mod aws_s3_public_access_block;
mod aws_sg_open_ssh;
mod gcp_storage_uniform_access;

pub use aws_iam_wildcard_policy::AwsIamWildcardPolicy;
pub use aws_rds_unencrypted::AwsRdsUnencrypted;
pub use aws_s3_public_access_block::AwsS3PublicAccessBlock;
pub use aws_sg_open_ssh::AwsSgOpenSsh;
pub use gcp_storage_uniform_access::GcpStorageUniformAccess;

use tf_eval::{Value, Verdict, truth};

use crate::rule::{DynRule, FixAction, FixHint};

pub fn all() -> Vec<Box<dyn DynRule>> {
    vec![
        Box::new(AwsSgOpenSsh),
        Box::new(AwsS3PublicAccessBlock),
        Box::new(AwsIamWildcardPolicy),
        Box::new(AwsRdsUnencrypted),
        Box::new(GcpStorageUniformAccess),
    ]
}

/// A fix that sets top-level `attribute` of `r` to `value`: at the attribute
/// when it is written, else by insertion into the block.
pub(crate) fn set_attribute(r: &tf_semantic::Resource, attribute: &str, value: serde_json::Value) -> FixHint {
    FixHint {
        resource: r.id.clone(),
        attribute: attribute.to_string(),
        action: FixAction::Set,
        value,
        site: r.attr(attribute).map(|a| a.span),
    }
}

/// The string value (`to_str` of a Known primitive) equals one of `set`.
pub(crate) fn str_in(v: &Value, set: &[&str]) -> bool {
    v.to_str().is_some_and(|s| set.contains(&s.trim()))
}

/// "`v` is not `true`" over the lattice, for boolean security switches.
pub(crate) fn not_true(v: &Value) -> Verdict {
    truth::test(v, &|x| x.as_bool() != Some(true))
}

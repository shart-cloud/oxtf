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

use tf_eval::{Kind, Known, Value, Verdict, truth};

use crate::rule::DynRule;

pub fn all() -> Vec<Box<dyn DynRule>> {
    vec![
        Box::new(AwsSgOpenSsh),
        Box::new(AwsS3PublicAccessBlock),
        Box::new(AwsIamWildcardPolicy),
        Box::new(AwsRdsUnencrypted),
        Box::new(GcpStorageUniformAccess),
    ]
}

/// Field `name` of an object value; a missing field of a Known object is
/// null (attributes not written in a block are unset). Lifts over `OneOf`.
pub(crate) fn field(obj: &Value, name: &str) -> Value {
    match &obj.kind {
        Kind::Known(Known::Object(m)) => match m.get(name) {
            Some(v) => v.child_of(obj),
            None => Value::null(),
        },
        Kind::Known(Known::Null) => Value::null(),
        Kind::OneOf(o) => Value::one_of(
            o.alternatives
                .iter()
                .map(|a| field(&a.child_of(obj), name))
                .collect(),
            o.tainted,
        ),
        _ => obj.get_attr(name),
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

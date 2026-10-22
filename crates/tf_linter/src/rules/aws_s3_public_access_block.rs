use tf_eval::{StepKind, Truth, Verdict};
use tf_semantic::references::{ReferenceMatch as Match, match_resource_reference};
use tf_semantic::{Address, Module, Resource};

use super::not_true;
use crate::rule::{Category, FixAction, FixHint, Level, Rule, RuleMeta};

/// Every `aws_s3_bucket` needs an `aws_s3_bucket_public_access_block` in
/// the same module instance whose `bucket` refers to it, with all four
/// flags `true` (absent flags use the defaults overlay: `false`).
///
/// "Refers to it" (the join): the PAB's `bucket` value is
/// - Unknown, computed by the provider, with origin `<bucket address>.id`
///   or `.bucket` (e.g. `bucket = aws_s3_bucket.data.id`); or
/// - a Known string equal to the bucket's Known `bucket` name.
///
/// A PAB whose `bucket` cannot be resolved (remote module output, tainted,
/// ...) *may* refer to any bucket; when no PAB definitely matches but one
/// may, the bucket is not reported.
pub struct AwsS3PublicAccessBlock;

impl RuleMeta for AwsS3PublicAccessBlock {
    const NAME: &'static str = "aws-s3-public-access-block";
    const CATEGORY: Category = Category::Storage;
    const LEVEL: Level = Level::Medium;
    const DESCRIPTION: &'static str =
        "S3 bucket has no aws_s3_bucket_public_access_block with all four protections enabled";
    const RUNS_ON_MODULE: bool = true;
    const RATIONALE: Option<&'static str> = Some(
        "Missing explicit bucket-level guardrails can permit public grants, but does not prove the bucket is public. New-bucket defaults and account or organization controls may already block public access.",
    );
    const REMEDIATION: Option<&'static str> = Some(
        "Manage an aws_s3_bucket_public_access_block for the bucket with block_public_acls, ignore_public_acls, block_public_policy, and restrict_public_buckets set to true. Review effective account controls and any intentional public-content workflow before applying; inspect bucket policies and ACLs separately.",
    );
    const GUIDELINE: Option<&'static str> = Some(
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    );
}

const FLAGS: &[&str] = &[
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
];

/// "This PAB leaves the bucket unprotected" (some flag not true).
fn permissive(pab: &Resource) -> Verdict {
    let mut acc = Verdict::FALSE;
    for f in FLAGS {
        if let Some(v) = pab.value_or_default(f) {
            acc = acc.or(not_true(&v));
        }
    }
    // A PAB that may not exist protects nothing for sure.
    match pab.existence {
        Truth::Tainted => acc.or(Verdict::new(Truth::Tainted, None)),
        _ => acc,
    }
}

impl Rule for AwsS3PublicAccessBlock {
    fn module_verdicts<'m>(&self, m: &'m Module) -> Vec<(&'m Resource, Verdict)> {
        let pabs: Vec<&Resource> = m
            .resources_of("aws_s3_bucket_public_access_block")
            .filter(|p| p.existence != Truth::False)
            .collect();
        let mut out = Vec::new();
        for b in m.resources_of("aws_s3_bucket") {
            let mut best: Option<Verdict> = None; // min over matching PABs
            let mut maybe = false;
            for p in &pabs {
                let Some(bv) = p.value("bucket") else {
                    continue;
                };
                match match_resource_reference(&bv, b, "bucket", &["id", "bucket"]) {
                    Match::Yes => {
                        let v = permissive(p);
                        best = Some(match best {
                            None => v,
                            Some(cur) => cur.and(v),
                        });
                    }
                    Match::Maybe => maybe = true,
                    Match::No => {}
                }
            }
            match best {
                None if maybe => {}
                // TRUE without a witness: no PAB refers to this bucket at all.
                None => out.push((b, Verdict::new(Truth::True, None))),
                Some(v) => out.push((b, v)),
            }
        }
        out
    }

    /// Set the deciding flag to true on the public-access block that carries
    /// it. No hint when no block refers to the bucket: adding a resource is
    /// not a mechanical edit.
    fn fix_hint(&self, _b: &Resource, v: &Verdict) -> Option<FixHint> {
        let step = v.witness.as_ref()?.prov.last()?.clone();
        let resource = Address::parse(step.resource.as_deref()?).ok()?;
        Some(FixHint {
            resource,
            attribute: step.attribute.as_deref()?.to_string(),
            action: FixAction::Set,
            value: serde_json::Value::Bool(true),
            site: (step.kind != StepKind::Default).then_some(step.at),
            variable: None,
        })
    }

    fn message(&self, _b: &Resource, v: &Verdict) -> String {
        let flag = v
            .witness
            .as_ref()
            .and_then(|w| w.prov.last())
            .map(|s| s.label.to_string())
            .unwrap_or_default();
        if v.truth == Truth::True && v.witness.is_none() {
            "no aws_s3_bucket_public_access_block in this module refers to this bucket".to_string()
        } else if flag.is_empty() {
            "public access block for this bucket may not exist".to_string()
        } else {
            format!("public access block for this bucket is not fully enabled ({flag})")
        }
    }
}

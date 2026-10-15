use tf_eval::{Truth, Verdict};
use tf_semantic::references::{ReferenceMatch as Match, match_resource_reference};
use tf_semantic::{Module, Resource};

use super::not_true;
use crate::rule::{Category, Level, Rule, RuleMeta};

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
    const LEVEL: Level = Level::High;
    const DESCRIPTION: &'static str =
        "S3 bucket has no aws_s3_bucket_public_access_block with all four protections enabled";
    const RUNS_ON_MODULE: bool = true;
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

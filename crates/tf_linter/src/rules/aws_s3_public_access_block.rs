use tf_eval::{Kind, Origin, Truth, Value, Verdict};
use tf_semantic::{Module, Resource};

use super::not_true;
use crate::rule::{Category, Level, Rule, RuleContext, RuleMeta};

/// Every `aws_s3_bucket` needs an `aws_s3_bucket_public_access_block` in
/// the same module instance whose `bucket` refers to it, with all four
/// flags `true` (absent flags use the defaults overlay: `false`).
///
/// "Refers to it" (the join): the PAB's `bucket` value is
/// - Unknown, computed by the provider, with origin `<bucket address>.id`
///   or `.bucket` (e.g. `bucket = aws_s3_bucket.data.id`); or
/// - a value whose provenance passes through the bucket's own `bucket`
///   attribute (e.g. `bucket = aws_s3_bucket.data.bucket`); or
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

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Match {
    Yes,
    Maybe,
    No,
}

fn key_compatible(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x == y,
        _ => true,
    }
}

fn matches(v: &Value, bucket: &Resource) -> Match {
    let via_bucket_attr = v
        .prov
        .any(|s| s.resource.as_deref() == Some(&*bucket.base_address));
    match &v.kind {
        Kind::Unknown(o) => match &**o {
            Origin::Computed {
                resource,
                key,
                attr,
            } => {
                if **resource == *bucket.base_address
                    && (&**attr == "id" || &**attr == "bucket")
                    && key_compatible(key.as_deref(), bucket.key.as_deref())
                {
                    Match::Yes
                } else {
                    Match::No
                }
            }
            Origin::Error(_) => Match::No,
            _ => Match::Maybe,
        },
        Kind::Known(_) => {
            if via_bucket_attr {
                return Match::Yes;
            }
            match (
                v.as_str(),
                bucket
                    .value("bucket")
                    .as_ref()
                    .map(|b| (b.as_str().map(str::to_string), b.is_known())),
            ) {
                (Some(s), Some((Some(name), _))) if s == name => Match::Yes,
                (Some(_), Some((None, false))) => Match::Maybe,
                (Some(_), None) => Match::Maybe, // bucket name chosen by the provider
                _ => Match::No,
            }
        }
        Kind::Tainted(_) => {
            if via_bucket_attr {
                Match::Yes
            } else {
                Match::Maybe
            }
        }
        Kind::OneOf(o) => {
            let ms: Vec<Match> = o
                .alternatives
                .iter()
                .map(|a| matches(&a.child_of(v), bucket))
                .collect();
            if ms.iter().all(|m| *m == Match::Yes) {
                Match::Yes
            } else if ms.iter().all(|m| *m == Match::No) {
                Match::No
            } else {
                Match::Maybe
            }
        }
    }
}

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
    fn run_on_module(&self, m: &Module, ctx: &mut RuleContext<'_>) {
        let pabs: Vec<&Resource> = m
            .resources_of("aws_s3_bucket_public_access_block")
            .filter(|p| p.existence != Truth::False)
            .collect();
        for b in m.resources_of("aws_s3_bucket") {
            let mut best: Option<Verdict> = None; // min over matching PABs
            let mut maybe = false;
            for p in &pabs {
                let Some(bv) = p.value("bucket") else {
                    continue;
                };
                match matches(&bv, b) {
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
                None => ctx.report(b, &Verdict::new(Truth::True, None), |_| {
                    "no aws_s3_bucket_public_access_block in this module refers to this bucket"
                        .to_string()
                }),
                Some(v) => {
                    let flag = v
                        .witness
                        .as_ref()
                        .and_then(|w| w.prov.last())
                        .map(|s| s.label.to_string())
                        .unwrap_or_default();
                    ctx.report(b, &v, |_| {
                        if flag.is_empty() {
                            "public access block for this bucket may not exist".to_string()
                        } else {
                            format!(
                                "public access block for this bucket is not fully enabled ({flag})"
                            )
                        }
                    })
                }
            }
        }
    }
}

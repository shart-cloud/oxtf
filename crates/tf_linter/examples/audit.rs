//! Corpus audit for W4: for every resource a seed rule targets, print the
//! evaluated inputs the rule reads, so false negatives can be spot-checked.
//! cargo run -p tf_linter --release --example audit -- corpus/repos

use std::collections::BTreeMap;

use tf_linter::{Linter, ScanOptions, discover_roots, scan_with};

const ATTRS: &[(&str, &[&str])] = &[
    ("aws_security_group", &["ingress"]),
    (
        "aws_vpc_security_group_ingress_rule",
        &[
            "cidr_ipv4",
            "cidr_ipv6",
            "from_port",
            "to_port",
            "ip_protocol",
        ],
    ),
    (
        "aws_security_group_rule",
        &["type", "cidr_blocks", "from_port", "to_port", "protocol"],
    ),
    (
        "aws_db_instance",
        &["storage_encrypted", "replicate_source_db"],
    ),
    ("aws_iam_policy", &["policy"]),
    ("aws_iam_role_policy", &["policy"]),
    ("aws_iam_user_policy", &["policy"]),
    ("aws_iam_group_policy", &["policy"]),
    ("google_storage_bucket", &["uniform_bucket_level_access"]),
    ("aws_s3_bucket", &["bucket"]),
    (
        "aws_s3_bucket_public_access_block",
        &[
            "bucket",
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        ],
    ),
];

fn class(v: &tf_eval::Value) -> &'static str {
    use tf_eval::Kind;
    match &v.kind {
        Kind::Known(_) if v.is_wholly_known() => "known",
        Kind::Known(_) => "partial",
        Kind::Unknown(_) => "unknown",
        Kind::Tainted(_) => "tainted",
        Kind::OneOf(_) => "one-of",
    }
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "corpus/repos".into());
    let verbose = std::env::args().any(|a| a == "-v");
    let (r, analyses) = scan_with(
        &Linter::with_seed_rules(),
        &discover_roots(dir.as_ref(), true),
        &ScanOptions {
            recursive: true,
            ..Default::default()
        },
    );
    let mut counts: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut instances: BTreeMap<String, usize> = BTreeMap::new();
    for a in &analyses {
        for m in &a.modules {
            for res in &m.resources {
                let Some((_, attrs)) = ATTRS.iter().find(|(t, _)| **t == *res.ty) else {
                    continue;
                };
                if res.existence == tf_eval::Truth::False {
                    continue;
                }
                *instances.entry(res.ty.to_string()).or_default() += 1;
                for at in *attrs {
                    let v = res.value(at);
                    let c = match &v {
                        None => "absent",
                        Some(v) if v.is_null() => "null",
                        Some(v) => class(v),
                    };
                    *counts
                        .entry((res.ty.to_string(), at.to_string(), c.to_string()))
                        .or_default() += 1;
                    if verbose {
                        let s = v
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "<absent>".into());
                        let s: String = s.chars().take(160).collect();
                        println!("{} {} {} = {}", a.root_dir.display(), res.address, at, s);
                    }
                }
            }
        }
    }
    println!("| resource type | instances (all roots) |\n|---|---:|");
    for (t, n) in &instances {
        println!("| {t} | {n} |");
    }
    println!("\n| resource type | attribute | evaluated as | count |\n|---|---|---|---:|");
    for ((t, a, c), n) in &counts {
        println!("| {t} | {a} | {c} | {n} |");
    }
    println!("\nfindings: {}", r.findings.len());
}

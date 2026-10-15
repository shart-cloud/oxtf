//! Regressions from the final code review.

use std::path::{Path, PathBuf};

use tf_linter::{ScanOptions, discover_roots, scan_dir};

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("oxtf-review-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A resource whose existence is Unknown (count from a data source) gets
/// no finding, like any other verdict that depends on an Unknown value.
#[test]
fn unknown_existence_gives_no_finding() {
    let d = temp_dir("existence");
    std::fs::write(
        d.join("main.tf"),
        r#"
data "aws_subnets" "x" {}

resource "aws_db_instance" "maybe" {
  count             = length(data.aws_subnets.x.ids)
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
}

resource "aws_db_instance" "always" {
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
}
"#,
    )
    .unwrap();
    let res = scan_dir(&d, &ScanOptions::default());
    let addrs: Vec<_> = res.findings.iter().map(|f| f.address.to_string()).collect();
    assert_eq!(addrs, ["aws_db_instance.always"], "{addrs:?}");
    std::fs::remove_dir_all(&d).unwrap();
}

/// Recursive root discovery does not follow a symlink to an ancestor.
#[cfg(unix)]
#[test]
fn recursive_discovery_skips_directory_symlinks() {
    let d = temp_dir("symlink");
    std::fs::create_dir_all(d.join("mod")).unwrap();
    std::fs::write(d.join("mod/main.tf"), "locals {}\n").unwrap();
    std::os::unix::fs::symlink(Path::new(".."), d.join("mod/loop")).unwrap();
    let roots = discover_roots(&d, true);
    assert_eq!(roots, [d.join("mod")]);
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn s3_join_uses_value_identity_not_dependency_provenance() {
    for (case, reference, expected) in [
        (
            "sibling",
            "aws_s3_bucket.b[\"a\"].bucket",
            vec!["aws_s3_bucket.b[\"b\"]"],
        ),
        (
            "computed",
            "aws_s3_bucket.b[\"a\"].id",
            vec!["aws_s3_bucket.b[\"b\"]"],
        ),
        (
            "transformed",
            "\"${aws_s3_bucket.b[\"a\"].bucket}-other\"",
            vec!["aws_s3_bucket.b[\"a\"]", "aws_s3_bucket.b[\"b\"]"],
        ),
        ("local", "local.selected", vec!["aws_s3_bucket.b[\"b\"]"]),
    ] {
        let d = temp_dir(case);
        std::fs::write(
            d.join("main.tf"),
            format!(
                r#"
resource "aws_s3_bucket" "b" {{
  for_each = toset(["a", "b"])
  bucket = "example-${{each.key}}"
}}
locals {{ selected = aws_s3_bucket.b["a"].bucket }}
resource "aws_s3_bucket_public_access_block" "p" {{
  bucket = {reference}
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}}
"#
            ),
        )
        .unwrap();
        let r = scan_dir(&d, &ScanOptions::default());
        assert!(r.diagnostics.is_empty(), "{case}: {:?}", r.diagnostics);
        let got: Vec<_> = r.findings.iter().map(|f| f.address.as_ref()).collect();
        assert_eq!(got, expected, "{case}");
        std::fs::remove_dir_all(d).unwrap();
    }
}

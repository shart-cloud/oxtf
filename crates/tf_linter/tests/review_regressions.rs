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

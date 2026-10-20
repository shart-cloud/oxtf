//! `tf_scan::fix`: a fix hint applied to the source and verified by a
//! rescan. Nested attributes create the blocks they need when the provider
//! schema allows it; the edit is laid out the way `terraform fmt` lays it
//! out; a value written as `var.x` is fixed at the variable's default
//! unless a caller overrides it.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tf_scan::{FixSite, ScanRequest, scan};

fn request(dir: &Path, files: &[(&str, &str)], rule: &str) -> ScanRequest {
    let mut req = ScanRequest::dirs(vec![dir.to_path_buf()], true);
    req.catalog = tf_scan::Catalog::standard();
    req.selection = Some(vec![rule.into()]);
    req.overlay = files
        .iter()
        .map(|(p, t)| (dir.join(p), Arc::from(*t)))
        .collect();
    req
}

/// The one finding of `rule`: its fingerprint and fix hint.
fn finding(req: ScanRequest) -> (String, Option<tf_linter::FixHint>) {
    let out = scan(req).unwrap();
    let rec = out.record();
    let [f] = rec.findings.as_slice() else {
        panic!("{:#?}", rec.findings)
    };
    let hint = out.result.findings.iter().find_map(|f| f.fix_hint.clone());
    (f.fingerprint.clone(), hint)
}

/// Fix the one finding of `rule` in `main.tf`; the outcome's edit.
fn fixed(name: &str, text: &str, rule: &str) -> tf_scan::FixOutcome {
    let dir = PathBuf::from(format!("/nonexistent/oxtf-fix-{name}"));
    let files = [("main.tf", text)];
    let (fp, _) = finding(request(&dir, &files, rule));
    let o = tf_scan::fix(request(&dir, &files, rule), &fp, None).unwrap();
    assert!(o.verified, "{}", o.edit.text);
    o
}

#[test]
fn a_nested_attribute_creates_its_block() {
    let o = fixed(
        "nested",
        "resource \"aws_ecr_repository\" \"r\" {\n  name                 = \"r\"\n  image_tag_mutability = \"IMMUTABLE\"\n}\n",
        "CKV_AWS_163",
    );
    assert_eq!(
        o.hint.attribute,
        "image_scanning_configuration.scan_on_push"
    );
    assert_eq!(
        o.edit.text,
        "resource \"aws_ecr_repository\" \"r\" {\n  name                 = \"r\"\n  image_tag_mutability = \"IMMUTABLE\"\n  image_scanning_configuration {\n    scan_on_push = true\n  }\n}\n"
    );
}

#[test]
fn an_empty_one_line_block_is_opened_and_filled() {
    let o = fixed(
        "one-line",
        "resource \"google_container_cluster\" \"g\" {\n  name     = \"g\"\n  location = \"x\"\n  master_auth {}\n}\n",
        "CKV_GCP_13",
    );
    assert_eq!(
        o.edit.text,
        "resource \"google_container_cluster\" \"g\" {\n  name     = \"g\"\n  location = \"x\"\n  master_auth {\n    client_certificate_config {\n      issue_client_certificate = false\n    }\n  }\n}\n"
    );
}

#[test]
fn an_attribute_joins_its_written_block_aligned() {
    let o = fixed(
        "aligned",
        "resource \"aws_eks_cluster\" \"c\" {\n  name     = \"c\"\n  role_arn = \"arn\"\n  vpc_config {\n    subnet_ids = [\"a\"]\n  }\n}\n",
        "CKV_AWS_39",
    );
    // The new name is the longest: the run above is re-padded.
    assert!(
        o.edit.text.contains(
            "  vpc_config {\n    subnet_ids             = [\"a\"]\n    endpoint_public_access = false\n  }\n"
        ),
        "{}",
        o.edit.text
    );
}

#[test]
fn a_shorter_name_is_padded_to_the_run() {
    let o = fixed(
        "padded",
        "resource \"aws_instance\" \"web\" {\n  ami                         = \"ami-123\"\n  associate_public_ip_address = false\n}\n",
        "CKV_AWS_126",
    );
    assert!(
        o.edit.text.contains(
            "  associate_public_ip_address = false\n  monitoring                  = true\n}"
        ),
        "{}",
        o.edit.text
    );
}

#[test]
fn a_written_value_is_replaced_keeping_its_alignment() {
    let o = fixed(
        "replace",
        "resource \"aws_instance\" \"web\" {\n  ami           = \"ami-123\"\n  monitoring    = false\n  instance_type = \"t3.micro\"\n}\n",
        "CKV_AWS_126",
    );
    assert!(
        o.edit.text.contains("  monitoring    = true\n"),
        "{}",
        o.edit.text
    );
}

/// `vpc_config` needs `subnet_ids`: a block holding only the fixed
/// attribute would not be valid, so there is no hint.
#[test]
fn no_hint_creates_a_block_missing_required_attributes() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-required");
    let files = [(
        "main.tf",
        "resource \"aws_eks_cluster\" \"c\" {\n  name     = \"c\"\n  role_arn = \"arn\"\n}\n",
    )];
    let (_, hint) = finding(request(&dir, &files, "CKV_AWS_39"));
    assert!(hint.is_none(), "{hint:#?}");
}

const VARIABLES: &str = "variable \"monitoring\" {\n  type    = bool\n  default = false\n}\n";
const INSTANCE: &str = "resource \"aws_instance\" \"web\" {\n  ami        = \"ami-123\"\n  monitoring = var.monitoring\n}\n";

#[test]
fn a_variable_default_is_fixed_before_the_attribute() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-default");
    let files = [("main.tf", INSTANCE), ("variables.tf", VARIABLES)];
    let (fp, _) = finding(request(&dir, &files, "CKV_AWS_126"));
    let o = tf_scan::fix(request(&dir, &files, "CKV_AWS_126"), &fp, None).unwrap();
    assert_eq!(o.site, FixSite::Default);
    assert!(o.verified);
    assert_eq!(o.edit.file, dir.join("variables.tf"));
    assert!(
        o.edit.text.contains("  default = true\n"),
        "{}",
        o.edit.text
    );

    let o = tf_scan::fix(
        request(&dir, &files, "CKV_AWS_126"),
        &fp,
        Some(FixSite::Attribute),
    )
    .unwrap();
    assert_eq!(o.site, FixSite::Attribute);
    assert!(
        o.edit.text.contains("  monitoring = true\n"),
        "{}",
        o.edit.text
    );
}

/// A caller passes its own value: the default edit leaves that occurrence,
/// so the fix falls back to the attribute.
#[test]
fn an_overridden_default_falls_back_to_the_attribute() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-override");
    let files = [
        ("modules/web/main.tf", INSTANCE),
        ("modules/web/variables.tf", VARIABLES),
        (
            "main.tf",
            "module \"web\" {\n  source     = \"./modules/web\"\n  monitoring = false\n}\n",
        ),
    ];
    let (fp, _) = finding(request(&dir, &files, "CKV_AWS_126"));
    let o = tf_scan::fix(request(&dir, &files, "CKV_AWS_126"), &fp, None).unwrap();
    assert_eq!(o.site, FixSite::Attribute);
    assert!(o.verified);
    let o = tf_scan::fix(
        request(&dir, &files, "CKV_AWS_126"),
        &fp,
        Some(FixSite::Default),
    )
    .unwrap();
    assert!(!o.verified);
}

/// Two roots each declare `aws_instance.this`: the fix edits the file of
/// the root the finding came from.
#[test]
fn an_insertion_edits_the_finding_root() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-roots");
    let instance = "resource \"aws_instance\" \"this\" {\n  ami = \"ami-123\"\n}\n";
    let files = [("a/main.tf", instance), ("b/main.tf", instance)];
    let out = scan(request(&dir, &files, "CKV_AWS_126")).unwrap();
    let rec = out.record();
    assert_eq!(rec.findings.len(), 2);
    for f in &rec.findings {
        let o = tf_scan::fix(request(&dir, &files, "CKV_AWS_126"), &f.fingerprint, None).unwrap();
        assert!(o.verified);
        let file = f.location.file.clone();
        assert!(
            o.edit.file.ends_with(&file),
            "{} for {file}",
            o.edit.file.display()
        );
    }
}

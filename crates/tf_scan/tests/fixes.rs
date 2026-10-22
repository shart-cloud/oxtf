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
    assert!(o.target_resolved && o.no_new_findings);
    assert_eq!((o.finding_delta.before, o.finding_delta.after), (1, 0));
    assert_eq!(o.finding_delta.removed[0].fingerprint, fp);
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

/// A caller passes its own value: the fix writes where the caller sets it.
/// Rewriting the module's attribute would override that input for every caller.
#[test]
fn a_passed_in_value_is_fixed_where_the_caller_sets_it() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-input");
    let secure_default = VARIABLES.replace("default = false", "default = true");
    let files = [
        ("modules/web/main.tf", INSTANCE),
        ("modules/web/variables.tf", secure_default.as_str()),
        (
            "main.tf",
            "module \"web\" {\n  source     = \"./modules/web\"\n  monitoring = false\n}\n",
        ),
    ];
    let (fp, hint) = finding(request(&dir, &files, "CKV_AWS_126"));
    assert!(hint.unwrap().input_site().is_some());
    let o = tf_scan::fix(request(&dir, &files, "CKV_AWS_126"), &fp, None).unwrap();
    assert_eq!(o.site, FixSite::Input);
    assert!(o.verified);
    assert_eq!(o.edit.file, dir.join("main.tf"));
    assert!(
        o.edit.text.contains("  monitoring = true\n"),
        "{}",
        o.edit.text
    );
    for site in [FixSite::Attribute, FixSite::Default] {
        let refused = tf_scan::fix(request(&dir, &files, "CKV_AWS_126"), &fp, Some(site));
        assert!(refused.is_err(), "{site:?}");
    }
}

/// A root variable bound in tfvars is fixed in the tfvars file.
#[test]
fn a_tfvars_value_is_fixed_in_the_tfvars_file() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-tfvars");
    let files = [
        ("main.tf", INSTANCE),
        ("variables.tf", VARIABLES),
        ("terraform.tfvars", "monitoring = false\n"),
    ];
    let (fp, _) = finding(request(&dir, &files, "CKV_AWS_126"));
    let o = tf_scan::fix(request(&dir, &files, "CKV_AWS_126"), &fp, None).unwrap();
    assert_eq!(o.site, FixSite::Input);
    assert!(o.verified);
    assert_eq!(o.edit.file, dir.join("terraform.tfvars"));
    assert_eq!(o.edit.text, "monitoring = true\n");
}

/// A value the caller computes has no single place a literal belongs: no hint.
#[test]
fn a_computed_input_gets_no_hint() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-computed");
    let files = [
        ("modules/web/main.tf", INSTANCE),
        (
            "modules/web/variables.tf",
            "variable \"monitoring\" {\n  type = bool\n}\n",
        ),
        (
            "main.tf",
            "locals { off = false }\nmodule \"web\" {\n  source     = \"./modules/web\"\n  monitoring = local.off\n}\n",
        ),
    ];
    let out = scan(request(&dir, &files, "CKV_AWS_126")).unwrap();
    let definite: Vec<_> = out
        .result
        .findings
        .iter()
        .filter(|f| f.root == dir)
        .collect();
    assert_eq!(definite.len(), 1, "{:#?}", out.result.findings);
    assert!(definite[0].fix_hint.is_none());
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
        assert!(o.target_resolved && o.no_new_findings);
        assert_eq!((o.finding_delta.before, o.finding_delta.after), (2, 1));
        assert_eq!(o.finding_delta.unchanged, 1);
        let file = f.location.file.clone();
        assert!(
            o.edit.file.ends_with(&file),
            "{} for {file}",
            o.edit.file.display()
        );
    }
}

// The default edit fixes one database but breaks another. A lower or equal
// total finding count is not sufficient to establish no new findings.
fn shared_default(other: &str) -> ScanRequest {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-delta");
    let source = format!(
        "variable \"encrypted\" {{\n  default = false\n}}\n\
         resource \"aws_db_instance\" \"target\" {{\n  storage_encrypted = var.encrypted\n}}\n\
         resource \"aws_db_instance\" \"other\" {{\n{other}\n}}\n"
    );
    request(&dir, &[("main.tf", &source)], "aws-rds-unencrypted")
}

fn target_fingerprint(req: &ScanRequest) -> String {
    scan(req.try_clone().unwrap())
        .unwrap()
        .record()
        .findings
        .into_iter()
        .find(|f| {
            f.occurrences
                .iter()
                .any(|o| o.address == "aws_db_instance.target")
        })
        .unwrap()
        .fingerprint
}

#[test]
fn resolving_the_target_can_introduce_a_finding_elsewhere() {
    let req = shared_default("  storage_encrypted = !var.encrypted");
    let fp = target_fingerprint(&req);
    let outcome = tf_scan::fix(req, &fp, Some(FixSite::Default)).unwrap();
    assert!(outcome.verification_errors.is_empty());
    assert!(outcome.target_resolved);
    assert!(!outcome.no_new_findings && !outcome.verified);
    let delta = &outcome.finding_delta;
    assert_eq!((delta.before, delta.after), (1, 1));
    assert_eq!(delta.removed[0].fingerprint, fp);
    assert_eq!(
        delta.added[0].occurrences[0].address,
        "aws_db_instance.other"
    );
    assert!(delta.changed.is_empty());
    assert_eq!(delta.unchanged, 0);
}

#[test]
fn verification_includes_other_selected_rules() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-other-rule");
    let files = [(
        "main.tf",
        "resource \"aws_db_instance\" \"target\" { storage_encrypted = false }\n",
    )];
    let mut req = request(&dir, &files, "aws-rds-unencrypted");
    req.catalog.rule_json.push(
        serde_json::json!({
            "version": 2, "name": "conflicting-policy", "message": "Require unencrypted storage",
            "clauses": [{"resource_types": ["aws_db_instance"], "condition": {
                "op": "checkov_value", "path": ["storage_encrypted"], "values": [false],
                "negative": false, "any_value": false, "missing": "pass"
            }}]
        })
        .to_string(),
    );
    req.selection
        .as_mut()
        .unwrap()
        .push("conflicting-policy".into());
    let fp = target_fingerprint(&req);
    let outcome = tf_scan::fix(req, &fp, None).unwrap();
    assert!(outcome.target_resolved);
    assert!(!outcome.no_new_findings && !outcome.verified);
    assert_eq!(outcome.finding_delta.added[0].rule, "conflicting-policy");
}

#[test]
fn a_regressing_default_falls_back_to_the_attribute() {
    let req = shared_default("  storage_encrypted = !var.encrypted");
    let fp = target_fingerprint(&req);
    let outcome = tf_scan::fix(req, &fp, None).unwrap();
    assert_eq!(outcome.site, FixSite::Attribute);
    assert!(outcome.target_resolved && outcome.no_new_findings && outcome.verified);
    assert_eq!(
        (outcome.finding_delta.before, outcome.finding_delta.after),
        (1, 0)
    );
}

#[test]
fn a_new_occurrence_of_an_existing_finding_is_a_regression() {
    let req = shared_default(
        "  count = 2\n  storage_encrypted = count.index == 0 ? false : !var.encrypted",
    );
    let fp = target_fingerprint(&req);
    let outcome = tf_scan::fix(req, &fp, Some(FixSite::Default)).unwrap();
    assert!(outcome.target_resolved);
    assert!(!outcome.no_new_findings && !outcome.verified);
    let delta = &outcome.finding_delta;
    assert_eq!((delta.before, delta.after), (2, 1));
    assert!(delta.added.is_empty());
    assert_eq!(delta.removed[0].fingerprint, fp);
    let [change] = delta.changed.as_slice() else {
        panic!("{delta:?}")
    };
    assert_eq!(change.before.occurrences.len(), 1);
    assert_eq!(change.after.occurrences.len(), 2);
    assert_eq!(
        change.added_occurrences[0].address,
        "aws_db_instance.other[1]"
    );
    assert!(change.removed_occurrences.is_empty());
}

#[test]
fn an_insertion_does_not_turn_shifted_findings_into_new_ones() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-delta-shift");
    let files = [(
        "main.tf",
        concat!(
            "resource \"aws_instance\" \"target\" {}\n",
            "resource \"aws_instance\" \"other\" {}\n",
        ),
    )];
    let req = request(&dir, &files, "CKV_AWS_126");
    let before = scan(req.try_clone().unwrap()).unwrap().record();
    let outcome = tf_scan::fix(req, &before.findings[0].fingerprint, None).unwrap();
    assert!(outcome.verified && outcome.no_new_findings);
    assert_eq!(outcome.finding_delta.unchanged, 1);
    assert!(outcome.finding_delta.added.is_empty());
    assert!(outcome.finding_delta.changed.is_empty());
}

/// An installed package is never edited, but a value the user's root passes to
/// it is the user's own code: the fix writes the caller's argument.
#[test]
fn an_installed_module_is_fixed_through_the_callers_argument() {
    let dir = PathBuf::from("/nonexistent/oxtf-fix-installed");
    let manifest = r#"{"Modules": [{"Key": "web", "Source": "acme/web/aws", "Version": "1.0.0", "Dir": "cache/modules/web"}]}"#;
    let files = [
        (
            "main.tf",
            "module \"web\" {\n  source     = \"acme/web/aws\"\n  monitoring = false\n}\n",
        ),
        ("cache/modules/modules.json", manifest),
        ("cache/modules/web/main.tf", INSTANCE),
        ("cache/modules/web/variables.tf", VARIABLES),
    ];
    let with_data_dir = || {
        let mut req = request(&dir, &files, "CKV_AWS_126");
        req.input = tf_scan::ScanInput::Dirs {
            paths: vec![dir.clone()],
            recursive: false,
        };
        req.data_dir = Some("cache".into());
        req
    };
    let (fp, hint) = finding(with_data_dir());
    assert!(hint.unwrap().input_site().is_some());
    let o = tf_scan::fix(with_data_dir(), &fp, None).unwrap();
    assert_eq!(o.site, FixSite::Input);
    assert!(o.verified, "{:?}", o.verification_errors);
    assert_eq!(o.edit.file, dir.join("main.tf"));
    assert!(
        o.edit.text.contains("  monitoring = true\n"),
        "{}",
        o.edit.text
    );
}

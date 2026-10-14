//! W3 exit criterion: an open CIDR flows tfvars -> variable -> local ->
//! attribute, and the evaluator returns the value with the full chain.

use std::path::{Path, PathBuf};

use tf_eval::{Kind, StepKind};
use tf_semantic::{AnalyzeOptions, FileTable, analyze_module};

fn fixture(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rules")
        .join(p)
}

#[test]
fn tfvars_through_local_full_chain() {
    let files = FileTable::new();
    let a = analyze_module(
        &fixture("aws-sg-open-ssh/fail_tfvars_through_local"),
        &AnalyzeOptions::default(),
        &files,
    );
    assert!(a.diagnostics.is_empty(), "{:?}", a.diagnostics);
    let sg = a.modules[0]
        .resource("aws_security_group", "admin")
        .next()
        .expect("resource");
    // `ingress` is a set(object) attribute written in block syntax.
    let ingress = sg.attr("ingress").expect("ingress attribute");
    assert!(ingress.from_blocks);
    let rules = ingress.value.as_list().expect("list of ingress objects");
    assert_eq!(rules.len(), 1);
    let rule = rules[0].child_of(&ingress.value);
    let cidrs = rule.get_attr("cidr_blocks");
    // Known ["0.0.0.0/0"]
    let elems = cidrs.as_list().expect("cidr_blocks is a known list");
    assert_eq!(elems.len(), 1);
    let open = elems[0].child_of(&cidrs);
    assert_eq!(open.as_str(), Some("0.0.0.0/0"));
    assert!(matches!(open.kind, Kind::Known(_)));

    let steps = open.prov.steps();
    let rendered: Vec<String> = steps
        .iter()
        .map(|s| {
            let f = files.get(s.at.file);
            format!(
                "{}:{} [{}] {}",
                f.path.file_name().unwrap().to_string_lossy(),
                f.line(s.at.span.start),
                s.kind.as_str(),
                s.label
            )
        })
        .collect();
    println!("{}", rendered.join("\n"));
    let kinds: Vec<StepKind> = steps.iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        [
            StepKind::Tfvars,
            StepKind::Variable,
            StepKind::Local,
            StepKind::Attribute
        ],
        "{rendered:#?}"
    );
    assert_eq!(
        rendered[0],
        "terraform.tfvars:1 [tfvars] terraform.tfvars: admin_cidr = \"0.0.0.0/0\""
    );
    assert_eq!(rendered[1], "variables.tf:1 [variable] variable admin_cidr");
    assert_eq!(rendered[2], "locals.tf:2 [local] local.ssh_sources");
    assert_eq!(
        rendered[3],
        "main.tf:6 [attribute] aws_security_group.admin ingress.cidr_blocks"
    );
    // The attribute step carries the resource address for joins.
    assert_eq!(
        steps[3].resource.as_deref(),
        Some("aws_security_group.admin")
    );
}

#[test]
fn tfvars_override_default_and_unconstrained_taint() {
    let files = FileTable::new();
    let a = analyze_module(
        &fixture("aws-sg-open-ssh/pass_tfvars_overrides_open_default"),
        &AnalyzeOptions::default(),
        &files,
    );
    let v = &a.modules[0].variables[0];
    assert_eq!(v.value.as_str(), Some("192.168.10.0/24"));

    let a = analyze_module(
        &fixture("aws-sg-open-ssh/conditional_unconstrained_variable"),
        &AnalyzeOptions::default(),
        &files,
    );
    let sg = &a.modules[0].resources[0];
    let rule = sg.value("ingress").unwrap();
    let rule = rule.as_list().unwrap()[0].clone();
    let cidrs = rule.get_attr("cidr_blocks");
    let e = &cidrs.as_list().unwrap()[0];
    assert!(e.is_tainted(), "{e:?}");
}

#[test]
fn dynamic_block_expansion() {
    let files = FileTable::new();
    let a = analyze_module(
        &fixture("aws-sg-open-ssh/pass_dynamic_restricted"),
        &AnalyzeOptions::default(),
        &files,
    );
    let sg = &a.modules[0].resources[0];
    let ing = sg.value("ingress").unwrap();
    assert_eq!(
        ing.to_string(),
        "[{cidr_blocks = [\"0.0.0.0/0\"], from_port = 443, protocol = \"tcp\", to_port = 443}, {cidr_blocks = [\"10.1.0.0/16\"], from_port = 22, protocol = \"tcp\", to_port = 22}]"
    );
}

#[test]
fn computed_reference_keeps_resource_address() {
    let files = FileTable::new();
    let a = analyze_module(
        &fixture("aws-s3-public-access-block/pass_full_block"),
        &AnalyzeOptions::default(),
        &files,
    );
    let pab = a.modules[0]
        .resource("aws_s3_bucket_public_access_block", "data")
        .next()
        .unwrap();
    // `.bucket` is set in config: Known, and the chain names the bucket.
    let b = pab.value("bucket").unwrap();
    assert_eq!(b.as_str(), Some("my-data"));
    assert!(
        b.prov
            .any(|s| s.resource.as_deref() == Some("aws_s3_bucket.data"))
    );

    let a = analyze_module(
        &fixture("aws-s3-public-access-block/fail_permissive_block"),
        &AnalyzeOptions::default(),
        &files,
    );
    let pab = a.modules[0]
        .resource("aws_s3_bucket_public_access_block", "data")
        .next()
        .unwrap();
    let b = pab.value("bucket").unwrap();
    match b.origin() {
        Some(tf_eval::Origin::Computed { resource, attr, .. }) => {
            assert_eq!(&**resource, "aws_s3_bucket.data");
            assert_eq!(&**attr, "id");
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn jsonencode_for_over_variable() {
    let files = FileTable::new();
    let a = analyze_module(
        &fixture("aws-iam-wildcard-policy/fail_dynamic_statements"),
        &AnalyzeOptions::default(),
        &files,
    );
    let p = a.modules[0].resources[0].value("policy").unwrap();
    assert_eq!(
        p.to_str().unwrap().as_ref(),
        r#"{"Statement":[{"Action":["s3:GetObject"],"Effect":"Allow","Resource":["arn:aws:s3:::b/*"]},{"Action":["*"],"Effect":"Allow","Resource":["*"]}],"Version":"2012-10-17"}"#
    );
}

#[test]
fn local_modules_and_strict_bool() {
    let dir = tempdir("semantic_modules");
    std::fs::create_dir_all(dir.join("child")).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        r#"
variable "open" { default = "0.0.0.0/0" }
module "sg" {
  source = "./child"
  cidr   = var.open
}
module "remote" {
  source = "terraform-aws-modules/vpc/aws"
}
resource "aws_db_instance" "db" {
  storage_encrypted = "true"
  identifier        = module.sg.name
  db_subnet_group_name = module.remote.database_subnet_group
}
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child/main.tf"),
        r#"
variable "cidr" {}
resource "aws_security_group" "this" {
  name = "x"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.cidr]
  }
}
output "name" { value = "db-${aws_security_group.this.name}" }
"#,
    )
    .unwrap();
    let files = FileTable::new();
    let a = analyze_module(&dir, &AnalyzeOptions::default(), &files);
    assert_eq!(a.modules.len(), 2);
    assert_eq!(&*a.modules[1].address, "module.sg");
    let sg = &a.modules[1].resources[0];
    assert_eq!(&*sg.address, "module.sg.aws_security_group.this");
    let ing = sg.value("ingress").unwrap();
    let c = ing.as_list().unwrap()[0]
        .child_of(&ing)
        .get_attr("cidr_blocks");
    let e = c.as_list().unwrap()[0].child_of(&c);
    assert_eq!(e.as_str(), Some("0.0.0.0/0"));
    let labels: Vec<String> = e.prov.steps().iter().map(|s| s.label.to_string()).collect();
    assert_eq!(
        labels,
        [
            "variable open default",
            "module.sg argument cidr",
            "variable cidr",
            "module.sg.aws_security_group.this ingress.cidr_blocks"
        ]
    );
    let db = &a.modules[0].resources[0];
    assert_eq!(
        db.value("storage_encrypted")
            .unwrap()
            .as_known()
            .map(|k| matches!(k, tf_eval::Known::Bool(true))),
        Some(true)
    );
    assert!(
        a.diagnostics.iter().any(|d| d.code == "strict-bool"),
        "{:?}",
        a.diagnostics
    );
    assert_eq!(db.value("identifier").unwrap().as_str(), Some("db-x"));
    let sub = db.value("db_subnet_group_name").unwrap();
    assert!(
        matches!(sub.origin(), Some(tf_eval::Origin::RemoteModule { .. })),
        "{sub:?}"
    );
}

fn tempdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("oxtf-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

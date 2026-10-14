use std::path::PathBuf;
use std::process::Command;

use tf_schema::ir::{Provider, SchemaKind};
use tf_schema_codegen::*;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tf_schema_codegen_test_{}_{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A small aws "schema JSON" holding only the given resources, optionally with
/// one attribute removed: `(resource, attribute)`.
fn mini_aws_schema(resources: &[&str], remove: Option<(&str, &str)>) -> serde_json::Value {
    let full: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("schemas/providers/aws.json")).unwrap())
            .unwrap();
    let p = &full["provider_schemas"]["registry.terraform.io/hashicorp/aws"];
    let mut rs = serde_json::Map::new();
    for r in resources {
        rs.insert(r.to_string(), p["resource_schemas"][*r].clone());
    }
    if let Some((r, a)) = remove {
        rs[r]["block"]["attributes"]
            .as_object_mut()
            .unwrap()
            .remove(a)
            .expect("attr existed");
    }
    serde_json::json!({
        "format_version": "1.0",
        "provider_schemas": { "registry.terraform.io/hashicorp/aws": {
            "resource_schemas": rs, "data_source_schemas": {} } }
    })
}

fn write_json(path: &PathBuf, v: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec(v).unwrap()).unwrap();
}

#[test]
fn generated_files_are_fresh() {
    // Equivalent to `tf_schema_codegen check`: committed output == generator output.
    let paths = Paths { root: root() };
    let g = generate_from_disk(&paths).expect("generation succeeds on committed inputs");
    for (name, bytes) in &g.files {
        let on_disk = std::fs::read(paths.out_dir().join(name)).unwrap_or_default();
        assert!(
            on_disk == *bytes,
            "{name} is stale: run `cargo run -p tf_schema_codegen --release -- generate`"
        );
    }
}

#[test]
fn blob_round_trips() {
    let loaded = load_all(&root().join("schemas/providers")).unwrap();
    let entries = build_entries(&loaded).unwrap();
    let blob = build_blob(&entries).unwrap();
    let blob_bytes: &'static [u8] = Box::leak(blob.blob.clone().into_boxed_slice());
    let sym_bytes: &'static [u8] = Box::leak(blob.symbols.clone().into_boxed_slice());
    let syms: &'static [&'static str] = Box::leak(
        tf_schema::decode_symbols(sym_bytes)
            .unwrap()
            .into_boxed_slice(),
    );
    for (e, (s, t)) in entries.iter().zip(&blob.ranges) {
        let decoded = tf_schema::decode_body(&blob_bytes[*s as usize..*t as usize], syms).unwrap();
        assert_eq!(decoded, e.body, "{}", e.name);
    }
}

#[test]
fn removed_attribute_used_by_view_fails_generation() {
    let dir = scratch("gen");
    let path = dir.join("aws.json");
    write_json(
        &path,
        &mini_aws_schema(
            &["aws_db_instance"],
            Some(("aws_db_instance", "storage_encrypted")),
        ),
    );
    let loaded = [load_schema_file(&path).unwrap()];
    let allow = parse_allowlist(
        r#"[[view]]
type = "aws_db_instance"
uses = ["storage_encrypted", "publicly_accessible"]"#,
    )
    .unwrap();
    let err = generate(&loaded, &allow, &[])
        .err()
        .expect("generation must fail");
    assert!(
        err.contains("aws_db_instance uses `storage_encrypted`"),
        "{err}"
    );
    assert!(!err.contains("publicly_accessible"), "{err}");

    // Without the `uses` entry, generation succeeds but the accessor is gone,
    // so downstream code calling `.storage_encrypted()` stops compiling.
    let allow = parse_allowlist("[[view]]\ntype = \"aws_db_instance\"").unwrap();
    let entries = build_entries(&loaded).unwrap();
    let src = views_source(&entries, &allow.view).unwrap();
    assert!(!src.contains("pub fn storage_encrypted("));
    assert!(src.contains("pub fn publicly_accessible("));
}

#[test]
fn diff_cli_reports_breakage_and_uncovered_resources() {
    let dir = scratch("diff");
    let old = dir.join("old.json");
    let new = dir.join("new.json");
    write_json(
        &old,
        &mini_aws_schema(&["aws_db_instance", "aws_s3_bucket"], None),
    );
    // NEW: storage_encrypted removed, plus a resource no rule targets.
    write_json(
        &new,
        &mini_aws_schema(
            &["aws_db_instance", "aws_s3_bucket", "aws_vpc"],
            Some(("aws_db_instance", "storage_encrypted")),
        ),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_tf_schema_codegen"))
        .args(["diff", old.to_str().unwrap(), new.to_str().unwrap()])
        .env("OXTF_ROOT", root())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "diff must fail\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("+ resource aws_vpc  (no rule targets it)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("~ resource aws_db_instance: - storage_encrypted: bool [optional]"),
        "{stdout}"
    );
    assert!(
        stderr.contains("BREAKING: allowlist: view aws_db_instance uses `storage_encrypted`"),
        "{stderr}"
    );
    // views of resources absent from both snapshots are not reported as breaking
    assert!(!stderr.contains("aws_security_group"), "{stderr}");

    // Same snapshot both sides: no changes, exit 0.
    let ok = Command::new(env!("CARGO_BIN_EXE_tf_schema_codegen"))
        .args(["diff", old.to_str().unwrap(), old.to_str().unwrap()])
        .env("OXTF_ROOT", root())
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
}

#[test]
fn defaults_are_validated_against_schema() {
    let dir = scratch("defaults");
    let path = dir.join("aws.json");
    write_json(&path, &mini_aws_schema(&["aws_db_instance"], None));
    let loaded = [load_schema_file(&path).unwrap()];
    let allow = Allowlist { view: vec![] };
    let bad = parse_defaults(
        "[aws_db_instance]\nstorage_encrypted = \"no\"\nstorage_encryptd = false\n[aws_nope]\nx = 1\n",
        "test",
    )
    .unwrap();
    let err = generate(&loaded, &allow, &bad).err().unwrap();
    assert!(
        err.contains("storage_encrypted = String(\"no\") does not match schema type bool"),
        "{err}"
    );
    assert!(
        err.contains("aws_db_instance.storage_encryptd does not exist"),
        "{err}"
    );
    assert!(err.contains("unknown resource type aws_nope"), "{err}");
    let good = parse_defaults("[aws_db_instance]\nstorage_encrypted = false\n", "test").unwrap();
    assert!(generate(&loaded, &allow, &good).is_ok());
}

#[test]
fn committed_overlays_and_rule_targets_resolve() {
    let paths = Paths { root: root() };
    let loaded = load_all(&paths.schemas_dir()).unwrap();
    let entries = build_entries(&loaded).unwrap();
    let targets = parse_rule_targets(&std::fs::read_to_string(paths.rule_targets()).unwrap());
    assert_eq!(targets.len(), 11);
    for (k, n) in &targets {
        assert!(find_entry(&entries, *k, n).is_some(), "{n}");
    }
    assert!(targets.contains(&(SchemaKind::DataSource, "aws_iam_policy_document".into())));
    let unc = uncovered(&entries, &targets);
    assert_eq!(unc.len(), entries.len() - 11);
    assert!(unc.iter().any(|e| e.provider == Provider::Azurerm));
}

/// A small cloudflare schema JSON holding only `cloudflare_ruleset`,
/// optionally edited by `f`.
fn mini_cloudflare_ruleset(f: impl FnOnce(&mut serde_json::Value)) -> serde_json::Value {
    let full: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root().join("schemas/providers/cloudflare.json")).unwrap(),
    )
    .unwrap();
    let addr = "registry.terraform.io/cloudflare/cloudflare";
    let mut r = full["provider_schemas"][addr]["resource_schemas"]["cloudflare_ruleset"].clone();
    f(&mut r);
    serde_json::json!({
        "format_version": "1.0",
        "provider_schemas": { addr: {
            "resource_schemas": { "cloudflare_ruleset": r }, "data_source_schemas": {} } }
    })
}

#[test]
fn providers_resolve_by_registry_address() {
    assert_eq!(
        provider_from_address("registry.terraform.io/integrations/github"),
        Some(Provider::Github)
    );
    assert_eq!(
        provider_from_address("registry.terraform.io/cloudflare/cloudflare"),
        Some(Provider::Cloudflare)
    );
    // Same type name, wrong namespace: not ours.
    assert_eq!(
        provider_from_address("registry.terraform.io/hashicorp/github"),
        None
    );
    let loaded = load_all(&root().join("schemas/providers")).unwrap();
    let got: Vec<Provider> = loaded.iter().map(|l| l.provider).collect();
    assert_eq!(got, Provider::ALL);

    // A snapshot with no Provider variant is an error, not silently skipped.
    let dir = scratch("unknown_provider");
    for p in Provider::ALL {
        std::fs::copy(
            root().join(format!("schemas/providers/{}.json", p.name())),
            dir.join(format!("{}.json", p.name())),
        )
        .unwrap();
    }
    std::fs::write(dir.join("datadog.json"), "{}").unwrap();
    let err = load_all(&dir).err().unwrap();
    assert!(err.contains("[\"datadog\"]"), "{err}");
}

#[test]
fn nested_attributes_in_uses_defaults_and_diff() {
    let dir = scratch("nested");
    let old = dir.join("old.json");
    write_json(&old, &mini_cloudflare_ruleset(|_| {}));
    let loaded = [load_schema_file(&old).unwrap()];
    assert_eq!(loaded[0].provider, Provider::Cloudflare);

    // `uses` paths and defaults resolve through nested attributes.
    let allow = parse_allowlist(
        "[[view]]\ntype = \"cloudflare_ruleset\"\nuses = [\"rules.action_parameters.headers\", \"rules.enabled\"]",
    )
    .unwrap();
    let defs = parse_defaults(
        "[cloudflare_ruleset]\n\"rules.enabled\" = true\nrules = []\n",
        "test",
    )
    .unwrap();
    let g = generate(&loaded, &allow, &defs).unwrap();
    let views = String::from_utf8(
        g.files
            .iter()
            .find(|f| f.0 == "views.rs")
            .unwrap()
            .1
            .clone(),
    )
    .unwrap();
    assert!(views.contains("pub fn rules(&self) -> Option<N::Value>"));
    assert!(views.contains("`rules`: nested attribute, list of objects (optional, computed)"));
    // No block-syntax accessor for nested attributes.
    assert!(!views.contains("fn rules_blocks("));
    let bad = parse_defaults("[cloudflare_ruleset]\n\"rules.enabled\" = \"yes\"\n", "t").unwrap();
    let err = generate(&loaded, &allow, &bad).err().unwrap();
    assert!(
        err.contains("rules.enabled = String(\"yes\") does not match schema type bool"),
        "{err}"
    );

    // Diff sees changes inside nested attributes, and a removed nested child
    // used by a view is breaking.
    let new = dir.join("new.json");
    write_json(
        &new,
        &mini_cloudflare_ruleset(|r| {
            let kids = r["block"]["attributes"]["rules"]["nested_type"]["attributes"]
                .as_object_mut()
                .unwrap();
            kids.remove("enabled").unwrap();
            kids["expression"]["optional"] = true.into();
            kids["expression"]
                .as_object_mut()
                .unwrap()
                .remove("required");
        }),
    );
    let new_l = [load_schema_file(&new).unwrap()];
    let r = diff_entries(
        &build_entries(&loaded).unwrap(),
        &build_entries(&new_l).unwrap(),
    );
    let paths: Vec<_> = r
        .changed
        .iter()
        .map(|c| (c.2.as_str(), c.3.as_str(), c.4.as_str()))
        .collect();
    assert!(
        paths.contains(&("rules.enabled", "bool [optional, computed]", "")),
        "{paths:?}"
    );
    assert!(
        paths.contains(&("rules.expression", "string [required]", "string [optional]")),
        "{paths:?}"
    );
    let errs = check_allowlist(&build_entries(&new_l).unwrap(), &allow);
    assert_eq!(
        errs,
        [
            "allowlist: view cloudflare_ruleset uses `rules.enabled`, which does not exist in the schema"
        ]
    );
}

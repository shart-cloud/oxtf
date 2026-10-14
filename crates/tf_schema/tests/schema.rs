use std::collections::HashMap;

use tf_schema::views::{
    AwsDbInstance, AwsSecurityGroup, DataAwsIamPolicyDocument, GoogleStorageBucket,
};
use tf_schema::*;

#[test]
fn counts_match_snapshots() {
    let count = |p: Provider, k: SchemaKind| entries().filter(|e| e.2 == p && e.1 == k).count();
    // From `jq '.provider_schemas[] | (.resource_schemas|length), (.data_source_schemas|length)'`.
    assert_eq!(count(Provider::Aws, SchemaKind::Resource), 1730);
    assert_eq!(count(Provider::Aws, SchemaKind::DataSource), 685);
    assert_eq!(count(Provider::Azurerm, SchemaKind::Resource), 1106);
    assert_eq!(count(Provider::Azurerm, SchemaKind::DataSource), 396);
    assert_eq!(count(Provider::Google, SchemaKind::Resource), 1346);
    assert_eq!(count(Provider::Google, SchemaKind::DataSource), 465);
}

#[test]
fn every_schema_decodes() {
    for (name, kind, _) in entries() {
        let s = lookup(kind, name).unwrap();
        assert_eq!(s.name, name);
        assert!(
            !s.attributes().is_empty() || !s.block_types().is_empty(),
            "{name}"
        );
        assert!(
            s.attributes().windows(2).all(|w| w[0].name < w[1].name),
            "{name} unsorted"
        );
    }
    assert!(!contains(SchemaKind::Resource, "aws_nope"));
    assert!(
        lookup_resource("aws_iam_policy_document").is_none(),
        "data source, not resource"
    );
    assert!(lookup_data_source("aws_iam_policy_document").is_some());
}

#[test]
fn w3_queries() {
    let sg = lookup_resource("aws_security_group").unwrap();
    assert_eq!(sg.provider, Provider::Aws);
    // `ingress` is an *attribute* (set of object) that also accepts block syntax.
    let ingress = sg.attribute("ingress").unwrap();
    assert!(sg.block_type("ingress").is_none());
    assert!(matches!(sg.member("ingress"), Some(Member::Attribute(_))));
    assert!(ingress.accepts_block_syntax());
    assert!(ingress.is_optional() && ingress.is_computed());
    let elem = ingress.ty().element().unwrap();
    assert!(
        elem.object_attr("cidr_blocks")
            .unwrap()
            .ty
            .element()
            .unwrap()
            .is_string()
    );
    assert!(elem.object_attr("from_port").unwrap().ty.is_number());
    assert!(sg.attribute("arn").unwrap().is_computed_only());
    assert!(sg.block_type("timeouts").is_some());

    let db = lookup_resource("aws_db_instance").unwrap();
    let enc = db.attribute("storage_encrypted").unwrap();
    assert!(enc.is_bool() && enc.is_optional() && !enc.is_computed());
    assert!(db.attribute("instance_class").unwrap().is_required());
    assert!(db.attribute("password").unwrap().is_sensitive());
    assert!(db.attribute("password_wo").unwrap().is_write_only());

    let gsb = lookup_resource("google_storage_bucket").unwrap();
    let lr = gsb.block_type("lifecycle_rule").unwrap();
    assert_eq!(lr.nesting(), NestingMode::List);
    assert_eq!(lr.max_items(), Some(100));
    assert!(
        gsb.descend(&["lifecycle_rule", "action"])
            .unwrap()
            .attribute("type")
            .is_some()
    );
    assert!(gsb.block_type("versioning").unwrap().is_singleton());

    let doc = lookup_data_source("aws_iam_policy_document").unwrap();
    assert_eq!(doc.kind, SchemaKind::DataSource);
    assert!(
        doc.block_type("statement")
            .unwrap()
            .block
            .attribute("actions")
            .is_some()
    );
}

#[test]
fn defaults_overlay() {
    assert_eq!(
        default_for("aws_db_instance", "storage_encrypted"),
        Some(DefaultValue::Bool(false))
    );
    assert_eq!(
        default_for("aws_db_instance", "publicly_accessible"),
        Some(DefaultValue::Bool(false))
    );
    for a in [
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    ] {
        assert_eq!(
            default_for("aws_s3_bucket_public_access_block", a),
            Some(DefaultValue::Bool(false))
        );
    }
    assert_eq!(
        default_for("google_storage_bucket", "uniform_bucket_level_access"),
        Some(DefaultValue::Bool(false))
    );
    assert_eq!(
        default_for("aws_security_group", "ingress"),
        Some(DefaultValue::Empty)
    );
    assert_eq!(
        default_for("google_storage_bucket", "versioning.enabled"),
        Some(DefaultValue::Bool(false))
    );
    assert_eq!(default_for("aws_db_instance", "engine"), None);
    assert!(defaults_for("nope").is_empty());
}

// --- typed views over a toy ResourceNode -------------------------------------

#[derive(Debug, Default)]
struct Body {
    attrs: HashMap<&'static str, &'static str>,
    blocks: Vec<(&'static str, Body)>,
}

impl<'a> ResourceNode for &'a Body {
    type Value = &'static str;
    type Block = &'a Body;
    fn attr(&self, name: &str) -> Option<&'static str> {
        self.attrs.get(name).copied()
    }
    fn blocks(&self, name: &str) -> impl Iterator<Item = &'a Body> {
        let blocks: &'a [(&'static str, Body)] = &self.blocks;
        blocks
            .iter()
            .filter(move |(n, _)| *n == name)
            .map(|(_, b)| b)
    }
}

#[test]
fn typed_views() {
    let sg = Body {
        attrs: HashMap::from([("name", "web")]),
        blocks: vec![
            (
                "ingress",
                Body {
                    attrs: HashMap::from([("from_port", "22"), ("cidr_blocks", "0.0.0.0/0")]),
                    ..Default::default()
                },
            ),
            (
                "ingress",
                Body {
                    attrs: HashMap::from([("from_port", "443")]),
                    ..Default::default()
                },
            ),
            (
                "timeouts",
                Body {
                    attrs: HashMap::from([("create", "5m")]),
                    ..Default::default()
                },
            ),
        ],
    };
    let v = AwsSecurityGroup(&sg);
    assert_eq!(v.name(), Some("web"));
    assert_eq!(v.description(), None);
    let ports: Vec<_> = v.ingress_blocks().map(|i| i.from_port()).collect();
    assert_eq!(ports, [Some("22"), Some("443")]);
    assert_eq!(
        v.ingress_blocks().next().unwrap().cidr_blocks(),
        Some("0.0.0.0/0")
    );
    assert_eq!(v.timeouts().unwrap().create(), Some("5m"));
    assert_eq!(
        <AwsSecurityGroup<&Body> as TypedView>::TYPE_NAME,
        "aws_security_group"
    );
    assert!(lookup_resource(<AwsSecurityGroup<&Body> as TypedView>::TYPE_NAME).is_some());

    let db = Body {
        attrs: HashMap::from([("storage_encrypted", "true")]),
        ..Default::default()
    };
    assert_eq!(AwsDbInstance(&db).storage_encrypted(), Some("true"));
    assert_eq!(AwsDbInstance(&db).publicly_accessible(), None);

    let doc = Body {
        blocks: vec![(
            "statement",
            Body {
                attrs: HashMap::from([("effect", "Allow")]),
                ..Default::default()
            },
        )],
        ..Default::default()
    };
    assert_eq!(
        DataAwsIamPolicyDocument(&doc)
            .statement()
            .next()
            .unwrap()
            .effect(),
        Some("Allow")
    );

    let b = Body::default();
    assert!(GoogleStorageBucket(&b).versioning().is_none());

    // zero-cost: same size as the wrapped node
    assert_eq!(size_of::<AwsSecurityGroup<&Body>>(), size_of::<&Body>());
    assert_eq!(views::ALLOWLIST.len(), 11);
}

//! Protocol-6 nested attributes (`nested_type`), as used by
//! terraform-plugin-framework providers (cloudflare 5.x, parts of kubernetes
//! 3.x). They are attributes (written `x = {...}` / `x = [{...}]`), not
//! blocks, but they have a schema of their own that can be walked.

use std::collections::HashMap;

use tf_schema::views::{
    CloudflareRuleset, CloudflareZoneSetting, GithubBranchProtection, GithubRepository,
    KubernetesPodV1,
};
use tf_schema::*;

#[test]
fn cloudflare_ruleset_rules_is_a_nested_list_attribute() {
    let rs = lookup_resource("cloudflare_ruleset").unwrap();
    assert_eq!(rs.provider, Provider::Cloudflare);
    assert!(rs.block_types().is_empty(), "framework resource: no blocks");

    // `rules` is an attribute, not a block, and does not take block syntax.
    let m = rs.member("rules").unwrap();
    assert!(m.is_attribute());
    let Member::Attribute(rules) = m else {
        unreachable!()
    };
    assert!(rs.block_type("rules").is_none());
    assert!(rules.is_nested());
    assert!(!rules.accepts_block_syntax());
    assert!(rules.is_optional() && rules.is_computed() && !rules.is_required());
    assert_eq!(rules.nested().map(|n| n.0), Some(NestingMode::List));
    assert_eq!(m.nesting(), Some(NestingMode::List));
    assert!(rules.ty().element().is_none() && !rules.ty().is_collection());

    // Children carry their own flags.
    let kids = rules.nested_block().unwrap();
    assert!(kids.block_types().is_empty());
    let action = kids.attribute("action").unwrap();
    assert!(action.is_required() && action.ty().is_string());
    let id = kids.attribute("id").unwrap();
    assert!(id.is_computed_only());

    // Walk with member_at / descend through nested attributes.
    let expr = rs.member_at(&["rules", "expression"]).unwrap();
    assert!(matches!(expr, Member::Attribute(a) if a.is_required() && a.ty().is_string()));
    let ap = rs.member_at(&["rules", "action_parameters"]).unwrap();
    assert_eq!(ap.nesting(), Some(NestingMode::Single));
    let ap_block = rs.descend(&["rules", "action_parameters"]).unwrap();
    assert!(std::ptr::eq(ap_block, ap.inner().unwrap()));
    // Three levels: rules[*].action_parameters.headers is a nested map.
    let headers = rs
        .member_at(&["rules", "action_parameters", "headers"])
        .unwrap();
    assert_eq!(headers.nesting(), Some(NestingMode::Map));
    assert!(rs.descend_blocks(&["rules"]).is_none(), "not a block");
    assert!(rs.member_at(&["rules", "nope"]).is_none());
    assert!(
        rs.member_at(&["kind", "x"]).is_none(),
        "kind is a plain string"
    );
}

#[test]
fn cloudflare_set_map_single_and_sensitive_children() {
    // set
    let am = lookup_resource("cloudflare_account_member").unwrap();
    let pol = am.attribute("policies").unwrap();
    assert_eq!(pol.nested().unwrap().0, NestingMode::Set);
    let pg = am.member_at(&["policies", "permission_groups"]).unwrap();
    assert_eq!(pg.nesting(), Some(NestingMode::Set));
    assert!(matches!(pg, Member::Attribute(a) if a.is_required()));

    // single, with sensitive required child
    let hd = lookup_resource("cloudflare_hyperdrive_config").unwrap();
    let origin = hd.attribute("origin").unwrap();
    assert_eq!(origin.nested().unwrap().0, NestingMode::Single);
    let pw = origin
        .nested_block()
        .unwrap()
        .attribute("password")
        .unwrap();
    assert!(pw.is_sensitive() && pw.is_required());
    assert!(!origin.is_sensitive(), "sensitivity is per child");

    // map, nested 3 deep
    let pp = lookup_resource("cloudflare_pages_project").unwrap();
    let ev = pp
        .member_at(&["deployment_configs", "preview", "env_vars"])
        .unwrap();
    assert_eq!(ev.nesting(), Some(NestingMode::Map));
    let val = ev.inner().unwrap().attribute("value").unwrap();
    assert!(val.is_sensitive() && val.is_required());

    // nested_type with no attributes decodes to an empty block
    let br = pp
        .member_at(&["deployment_configs", "preview", "browsers"])
        .unwrap();
    assert_eq!(br.nesting(), Some(NestingMode::Map));
    assert!(br.inner().unwrap().attributes().is_empty());
}

#[test]
fn kubernetes_mixes_nested_attributes_and_blocks() {
    // kubernetes_validating_admission_policy_v1 is a framework resource:
    // `metadata`/`spec` are nested attributes, `timeouts` is a block.
    let vap = lookup_resource("kubernetes_validating_admission_policy_v1").unwrap();
    assert_eq!(vap.provider, Provider::Kubernetes);
    let spec = vap.attribute("spec").unwrap();
    assert!(spec.is_required() && spec.is_nested());
    assert_eq!(spec.nested().unwrap().0, NestingMode::Single);
    assert!(vap.block_type("spec").is_none());
    assert!(matches!(vap.member("timeouts"), Some(Member::Block(_))));
    assert!(vap.descend(&["timeouts"]).is_some());

    let ops = vap
        .member_at(&["spec", "match_constraints", "resource_rules", "operations"])
        .unwrap();
    let Member::Attribute(ops) = ops else {
        panic!("attribute")
    };
    assert!(ops.is_required());
    assert!(ops.ty().element().unwrap().is_string());
    assert_eq!(
        vap.member_at(&["spec", "match_constraints", "resource_rules"])
            .unwrap()
            .nesting(),
        Some(NestingMode::List)
    );

    // kubernetes_pod_v1 is SDKv2: classic nested blocks all the way down.
    let pod = lookup_resource("kubernetes_pod_v1").unwrap();
    let sc = pod
        .descend_blocks(&["spec", "container", "security_context"])
        .unwrap();
    assert!(sc.attribute("privileged").unwrap().is_bool());
    assert!(std::ptr::eq(
        sc,
        pod.descend(&["spec", "container", "security_context"])
            .unwrap()
    ));
    assert!(matches!(
        pod.member_at(&["spec", "container"]),
        Some(Member::Block(b)) if b.nesting() == NestingMode::List
    ));
}

#[test]
fn nested_attribute_counts() {
    // Every nested attribute in the embedded IR, per provider (recursively).
    fn count(b: &Block<'_>) -> usize {
        b.attributes()
            .iter()
            .map(|a| a.nested_block().map_or(0, |nb| 1 + count(nb)))
            .sum::<usize>()
            + b.block_types()
                .iter()
                .map(|nb| count(nb.block()))
                .sum::<usize>()
    }
    let mut per: HashMap<Provider, usize> = HashMap::new();
    for (name, kind, p) in entries() {
        *per.entry(p).or_default() += count(lookup(kind, name).unwrap());
    }
    // Matches the number of `"nested_type"` keys in each snapshot (grep -o | wc -l).
    assert_eq!(per[&Provider::Cloudflare], 2997);
    assert_eq!(per[&Provider::Kubernetes], 16);
    for p in [
        Provider::Aws,
        Provider::Azurerm,
        Provider::Google,
        Provider::Github,
    ] {
        assert_eq!(per[&p], 0, "{p:?}");
    }
}

// --- views over a toy node --------------------------------------------------

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
fn views_for_new_providers() {
    // Nested attributes come back as the whole value, like any attribute.
    let rs = Body {
        attrs: HashMap::from([
            ("phase", "http_request_firewall_custom"),
            ("rules", "[...]"),
        ]),
        ..Default::default()
    };
    let v = CloudflareRuleset(&rs);
    assert_eq!(v.phase(), Some("http_request_firewall_custom"));
    assert_eq!(v.rules(), Some("[...]"));
    assert_eq!(v.kind(), None);

    let zs = Body {
        attrs: HashMap::from([("setting_id", "ssl"), ("value", "strict")]),
        ..Default::default()
    };
    assert_eq!(CloudflareZoneSetting(&zs).value(), Some("strict"));

    let pod = Body {
        blocks: vec![(
            "spec",
            Body {
                attrs: HashMap::from([("host_network", "true")]),
                blocks: vec![(
                    "container",
                    Body {
                        blocks: vec![(
                            "security_context",
                            Body {
                                attrs: HashMap::from([("privileged", "true")]),
                                ..Default::default()
                            },
                        )],
                        ..Default::default()
                    },
                )],
            },
        )],
        ..Default::default()
    };
    let spec = KubernetesPodV1(&pod).spec().unwrap();
    assert_eq!(spec.host_network(), Some("true"));
    let privileged: Vec<_> = spec
        .container()
        .filter_map(|c| c.security_context())
        .map(|sc| sc.privileged())
        .collect();
    assert_eq!(privileged, [Some("true")]);

    let repo = Body {
        attrs: HashMap::from([("visibility", "public")]),
        ..Default::default()
    };
    assert_eq!(GithubRepository(&repo).visibility(), Some("public"));
    let bp = Body::default();
    assert_eq!(GithubBranchProtection(&bp).enforce_admins(), None);
    assert!(
        GithubBranchProtection(&bp)
            .required_pull_request_reviews()
            .next()
            .is_none()
    );
}

#[test]
fn defaults_for_new_providers() {
    use DefaultValue::*;
    assert_eq!(default_for("cloudflare_ruleset", "rules"), Some(Empty));
    assert_eq!(
        default_for("cloudflare_ruleset", "rules.enabled"),
        Some(Bool(true))
    );
    assert_eq!(
        default_for("cloudflare_dns_record", "proxied"),
        Some(Bool(false))
    );
    assert_eq!(
        default_for(
            "kubernetes_pod_v1",
            "spec.container.security_context.privileged"
        ),
        Some(Bool(false))
    );
    assert_eq!(
        default_for(
            "kubernetes_pod_v1",
            "spec.container.security_context.allow_privilege_escalation"
        ),
        Some(Bool(true))
    );
    assert_eq!(
        default_for("github_branch_protection", "enforce_admins"),
        Some(Bool(false))
    );
    assert_eq!(
        default_for("github_repository", "visibility"),
        Some(String("public"))
    );
    let n = [
        "cloudflare_dns_record",
        "cloudflare_ruleset",
        "kubernetes_pod_v1",
        "github_repository",
        "github_branch_protection",
    ]
    .iter()
    .map(|r| defaults_for(r).len())
    .sum::<usize>();
    assert_eq!(n, 15);
    assert!(
        defaults_for("github_repository")
            .iter()
            .all(|e| !e.note.is_empty())
    );
}

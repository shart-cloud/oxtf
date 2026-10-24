//! The finding record: its field set is the contract (schema 3), it survives
//! a JSON round trip, and fix hints say what the plan promised.

use std::path::Path;

use tf_linter::record::{FindingRecord, SCHEMA, ScanRecord, SubjectRecord};
use tf_linter::{ScanOptions, scan_dir};

fn scan(case: &str) -> ScanRecord {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rules")
        .join(case);
    ScanRecord::from_result(&scan_dir(&root, &ScanOptions::default()).unwrap())
}

fn keys(v: &serde_json::Value) -> Vec<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

/// Breaking changes bump `SCHEMA`; additive fields update this list and
/// `docs/FINDING_SCHEMA.md`.
#[test]
#[expect(clippy::too_many_lines)]
fn schema_3_field_set_is_pinned() {
    assert_eq!(SCHEMA, 3);
    let r = scan("aws-rds-unencrypted/fail_absent_uses_default");
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(
        keys(&json),
        [
            "coverage",
            "diagnostics",
            "findings",
            "input_kind",
            "roots",
            "rule_errors",
            "rules",
            "schema",
            "stats",
            "status",
            "suppressed"
        ]
    );
    assert_eq!(
        keys(&json["stats"]),
        [
            "conditional",
            "definite",
            "elapsed_ms",
            "files",
            "findings",
            "findings_by_rule",
            "indeterminate",
            "module_instances",
            "occurrences",
            "resources",
            "roots"
        ]
    );
    let f = &json["findings"][0];
    assert_eq!(
        keys(f),
        [
            "attribute",
            "certainty",
            "configured",
            "effective",
            "fingerprint",
            "fix_hint",
            "hidden",
            "level",
            "location",
            "message",
            "occurrences",
            "provenance",
            "root",
            "rule",
            "subject"
        ]
    );
    assert_eq!(f["rule"], "aws-rds-unencrypted");
    assert_eq!(
        keys(&json["rules"]["aws-rds-unencrypted"]),
        [
            "aliases",
            "category",
            "description",
            "guideline",
            "level",
            "profile",
            "rationale",
            "remediation",
            "source"
        ]
    );
    assert_eq!(
        json["rules"]["aws-rds-unencrypted"]["source"],
        serde_json::json!({"engine": "builtin", "file": null, "line": null})
    );
    assert_eq!(
        keys(&f["subject"]),
        [
            "address",
            "base_address",
            "key",
            "kind",
            "mode",
            "module",
            "name",
            "type"
        ]
    );
    assert_eq!(f["subject"]["kind"], "resource");
    assert_eq!(keys(&f["occurrences"][0]), ["address", "certainty", "root"]);
    assert_eq!(
        keys(&f["location"]),
        ["column", "end", "file", "line", "start"]
    );
    assert_eq!(keys(&f["effective"]), ["display", "kind", "value"]);
    assert_eq!(
        keys(&f["provenance"][0]),
        ["attribute", "kind", "label", "location", "resource"]
    );
    assert_eq!(
        keys(&f["fix_hint"]),
        ["action", "attribute", "resource", "site", "value"]
    );
}

#[test]
fn records_round_trip_through_json() {
    for case in [
        "aws-rds-unencrypted/conditional_unconstrained_variable",
        "aws-s3-public-access-block/fail_permissive_block",
        "aws-sg-open-ssh/fail_tfvars_through_local",
    ] {
        let mut r = scan(case);
        r.stats.elapsed_ms = 0.0;
        let text = serde_json::to_string(&r).unwrap();
        let back: ScanRecord = serde_json::from_str(&text).unwrap();
        let (a, b) = (
            serde_json::to_value(&back).unwrap(),
            serde_json::to_value(&r).unwrap(),
        );
        assert_eq!(a, b, "{case}");
        assert_eq!(back, r, "{case}");
        for f in &r.findings {
            let one: FindingRecord =
                serde_json::from_str(&serde_json::to_string(f).unwrap()).unwrap();
            assert_eq!(&one, f);
        }
    }
}

fn address(f: &FindingRecord) -> &str {
    match &f.subject {
        SubjectRecord::Resource(r) => &r.address,
        SubjectRecord::File { file, .. } => file,
    }
}

#[test]
fn fix_hints_name_the_edit_and_its_site() {
    // Absent attribute: insert into the block (no site).
    let r = scan("aws-rds-unencrypted/fail_absent_uses_default");
    let h = r.findings[0].fix_hint.as_ref().unwrap();
    assert_eq!(
        (h.action.as_str(), h.attribute.as_str()),
        ("set", "storage_encrypted")
    );
    assert_eq!(h.value, serde_json::json!(true));
    assert!(h.site.is_none());
    assert_eq!(h.resource.address, address(&r.findings[0]));
    assert!(r.findings[0].configured.is_none());
    assert_eq!(
        r.findings[0].effective.as_ref().unwrap().value,
        Some(serde_json::json!(false))
    );

    // Written attribute: the site is that attribute.
    let r = scan("aws-rds-unencrypted/fail_explicit_false");
    let f = &r.findings[0];
    let h = f.fix_hint.as_ref().unwrap();
    assert_eq!(h.site.as_ref().unwrap(), &f.location);
    assert_eq!(
        f.configured.as_ref().unwrap().value,
        Some(serde_json::json!(false))
    );

    // S3: the edit is on the public-access block, not the bucket.
    let r = scan("aws-s3-public-access-block/fail_permissive_block");
    let f = &r.findings[0];
    let h = f.fix_hint.as_ref().unwrap();
    assert_eq!(h.resource.ty, "aws_s3_bucket_public_access_block");
    assert_ne!(h.resource.address, address(f));
    assert!(
        f.attribute.is_none(),
        "the deciding value is not on the bucket"
    );

    // No block at all: adding a resource is not a mechanical edit.
    let r = scan("aws-s3-public-access-block/fail_missing_block");
    assert!(r.findings[0].fix_hint.is_none());

    // Foreign findings have no hint; native findings hide nothing.
    assert!(r.findings.iter().all(|f| f.hidden.is_empty()));
}

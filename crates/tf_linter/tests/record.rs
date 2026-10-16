//! The finding record: its field set is the contract (schema 2), it survives
//! a JSON round trip, and fix hints say what the plan promised.

use std::collections::BTreeSet;
use std::path::Path;

use tf_linter::record::{FindingRecord, SCHEMA, ScanRecord};
use tf_linter::{ScanOptions, scan_dir};

fn scan(case: &str) -> ScanRecord {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rules")
        .join(case);
    ScanRecord::from_result(&scan_dir(&root, &ScanOptions::default()))
}

fn keys(v: &serde_json::Value) -> Vec<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

/// Adding, removing or renaming a field here is a schema change: bump
/// `SCHEMA` and `docs/FINDING_SCHEMA.md` together with this list.
#[test]
fn schema_2_field_set_is_pinned() {
    assert_eq!(SCHEMA, 2);
    let r = scan("aws-rds-unencrypted/fail_absent_uses_default");
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(
        keys(&json),
        [
            "diagnostics",
            "findings",
            "rule_errors",
            "schema",
            "stats",
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
            "resources",
            "roots"
        ]
    );
    let f = &json["findings"][0];
    assert_eq!(
        keys(f),
        [
            "attribute",
            "configured",
            "effective",
            "fingerprint",
            "fix_hint",
            "hidden",
            "location",
            "message",
            "provenance",
            "resource",
            "root",
            "rule",
            "schema",
            "severity",
            "subject"
        ]
    );
    assert_eq!(
        f["subject"],
        serde_json::json!({"kind": "resource", "address": "aws_db_instance.db"})
    );
    assert_eq!(
        keys(&f["rule"]),
        [
            "category",
            "description",
            "guideline",
            "id",
            "level",
            "source"
        ]
    );
    assert_eq!(
        f["rule"]["source"],
        serde_json::json!({"engine": "builtin", "file": null, "line": null})
    );
    assert_eq!(
        keys(&f["resource"]),
        [
            "address",
            "base_address",
            "key",
            "mode",
            "module",
            "name",
            "type"
        ]
    );
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

#[test]
fn fingerprints_are_unique_within_a_scan_and_ignore_presentation() {
    let r = scan("aws-sg-open-ssh/fail_tfvars_through_local");
    let fps: BTreeSet<_> = r.findings.iter().map(|f| f.fingerprint.clone()).collect();
    assert_eq!(fps.len(), r.findings.len());
    let f = &r.findings[0];
    assert_eq!(
        f.fingerprint,
        tf_linter::record::fingerprint(
            &f.rule.id,
            &f.resource.as_ref().unwrap().address,
            f.attribute.as_deref()
        )
    );
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
    assert_eq!(
        h.resource.address,
        r.findings[0].resource.as_ref().unwrap().address
    );
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
    assert_ne!(h.resource.address, f.resource.as_ref().unwrap().address);
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

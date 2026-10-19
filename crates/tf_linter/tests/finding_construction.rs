//! `Finding::from_verdict` in isolation: the existence gate, the certainty
//! mapping, the primary location and the message suffixes, with no engine,
//! no fixture directory and no rule.

use std::path::Path;
use std::sync::Arc;

use tf_eval::{Prov, Step, StepKind, Truth, Value, Verdict};
use tf_linter::{Category, Finding, Level, RuleInfo, Severity};
use tf_semantic::{Address, Resource};
use tf_span::{FileId, FileSpan, Span};

fn info() -> RuleInfo {
    RuleInfo {
        name: "test-rule".into(),
        category: Category::Storage,
        level: Level::High,
        description: "test".into(),
        resource_types: vec!["aws_s3_bucket".into()],
        runs_on_module: false,
        guideline: None,
        source: Default::default(),
        aliases: Vec::new(),
    }
}

fn header() -> FileSpan {
    FileSpan::new(FileId(1), Span { start: 10, end: 40 })
}

fn resource(existence: Truth) -> Resource {
    Resource::new(
        Address::parse("module.m.aws_s3_bucket.b").unwrap(),
        header(),
        Default::default(),
        existence,
        None,
        None,
        None,
    )
}

fn step(kind: StepKind, at: u32, resource: Option<&str>) -> Step {
    let s = Step::new(
        kind,
        FileSpan::new(
            FileId(2),
            Span {
                start: at,
                end: at + 1,
            },
        ),
        "step",
    );
    match resource {
        Some(r) => s.with_resource(Arc::from(r)),
        None => s,
    }
}

fn build(existence: Truth, verdict: &Verdict) -> Option<Finding> {
    Finding::from_verdict(
        &info(),
        &resource(existence),
        verdict,
        "msg",
        Path::new("/root"),
    )
}

#[test]
fn truth_times_existence_table() {
    use Truth::*;
    let table = [
        // (verdict truth, resource existence, expected severity)
        (True, True, Some(Severity::Definite)),
        (True, Tainted, Some(Severity::Conditional)),
        (True, Unknown, None),
        (True, False, None),
        (Tainted, True, Some(Severity::Conditional)),
        (Tainted, Tainted, Some(Severity::Conditional)),
        (Tainted, Unknown, None),
        (Tainted, False, None),
        (Unknown, True, None),
        (Unknown, Tainted, None),
        (False, True, None),
        (False, Tainted, None),
    ];
    for (truth, existence, expected) in table {
        let got = build(existence, &Verdict::new(truth, Some(Value::bool(false))));
        assert_eq!(
            got.as_ref().map(|f| f.severity),
            expected,
            "verdict {truth:?} on existence {existence:?}"
        );
    }
}

#[test]
fn finding_carries_rule_and_resource_identity() {
    let f = build(Truth::True, &Verdict::new(Truth::True, None)).unwrap();
    assert_eq!(&*f.rule, "test-rule");
    assert_eq!(f.level, Level::High);
    assert_eq!(&*f.address, "module.m.aws_s3_bucket.b");
    assert_eq!(f.resource_type.as_deref(), Some("aws_s3_bucket"));
    assert_eq!(&*f.module, "module.m");
    assert_eq!(f.root, Path::new("/root"));
    assert_eq!(f.message, "msg");
    assert!(f.provenance.is_empty());
}

#[test]
fn primary_is_newest_step_on_this_resource_else_header() {
    // No witness: header.
    let f = build(Truth::True, &Verdict::new(Truth::True, None)).unwrap();
    assert_eq!(f.primary, header());

    // Witness whose steps never touch this resource: header, provenance kept.
    let w = Value::bool(false).with_prov(Prov::single(step(StepKind::Tfvars, 1, None)));
    let f = build(Truth::True, &Verdict::new(Truth::True, Some(w))).unwrap();
    assert_eq!(f.primary, header());
    assert_eq!(f.provenance.len(), 1);

    // Steps on another resource do not count; the newest step on this one wins.
    let w = Value::bool(false)
        .with_prov(Prov::single(step(StepKind::Tfvars, 1, None)))
        .push(step(
            StepKind::Attribute,
            2,
            Some("module.m.aws_s3_bucket.b"),
        ))
        .push(step(
            StepKind::Attribute,
            3,
            Some("module.m.aws_s3_bucket.b"),
        ))
        .push(step(
            StepKind::Attribute,
            4,
            Some("module.m.aws_s3_bucket.other"),
        ));
    let f = build(Truth::True, &Verdict::new(Truth::True, Some(w))).unwrap();
    assert_eq!(f.primary.span.start, 3);
    assert_eq!(
        f.provenance.len(),
        4,
        "provenance is origin-first and complete"
    );
}

#[test]
fn conditional_suffix_names_the_variable_when_known() {
    let w = Value::tainted("admin_cidr");
    let f = build(Truth::True, &Verdict::new(Truth::Tainted, Some(w))).unwrap();
    assert_eq!(f.severity, Severity::Conditional);
    assert_eq!(
        f.message,
        "msg (depends on unconstrained variable var.admin_cidr)"
    );

    // Synthetic taint labels (parenthesised) are not variable names.
    let w = Value::tainted("(expression)");
    let f = build(Truth::True, &Verdict::new(Truth::Tainted, Some(w))).unwrap();
    assert_eq!(f.message, "msg (depends on an unconstrained variable)");

    // Tainted verdict with a non-tainted witness (a OneOf decided it).
    let f = build(
        Truth::True,
        &Verdict::new(Truth::Tainted, Some(Value::bool(false))),
    )
    .unwrap();
    assert_eq!(f.message, "msg (depends on an unconstrained variable)");
}

#[test]
fn tainted_existence_downgrades_and_says_so() {
    let f = build(
        Truth::Tainted,
        &Verdict::new(Truth::True, Some(Value::bool(false))),
    )
    .unwrap();
    assert_eq!(f.severity, Severity::Conditional);
    assert_eq!(
        f.message,
        "msg (resource exists depending on an unconstrained variable)"
    );

    // When the verdict itself is tainted, the variable wins over existence.
    let w = Value::tainted("enc");
    let f = build(Truth::Tainted, &Verdict::new(Truth::Tainted, Some(w))).unwrap();
    assert_eq!(f.message, "msg (depends on unconstrained variable var.enc)");
}

#[test]
fn caller_decided_severity_is_gated_and_downgraded_the_same_way() {
    let build = |existence, severity| {
        Finding::with_severity(
            &info(),
            &resource(existence),
            severity,
            None,
            "msg",
            Path::new("/r"),
        )
    };
    assert_eq!(
        build(Truth::True, Severity::Indeterminate)
            .unwrap()
            .severity,
        Severity::Indeterminate
    );
    // Tainted existence never makes a finding more certain.
    assert_eq!(
        build(Truth::Tainted, Severity::Indeterminate)
            .unwrap()
            .severity,
        Severity::Indeterminate
    );
    assert_eq!(
        build(Truth::Tainted, Severity::Conditional)
            .unwrap()
            .message,
        "msg (depends on an unconstrained variable)"
    );
    assert_eq!(
        build(Truth::Tainted, Severity::Definite).unwrap().message,
        "msg (resource exists depending on an unconstrained variable)"
    );
    assert!(build(Truth::Unknown, Severity::Indeterminate).is_none());
    assert!(build(Truth::False, Severity::Definite).is_none());
    // Indeterminate wording is the adapter's; no suffix is added.
    assert_eq!(
        build(Truth::True, Severity::Indeterminate).unwrap().message,
        "msg"
    );
}

#[test]
fn definite_message_is_untouched() {
    let f = build(
        Truth::True,
        &Verdict::new(Truth::True, Some(Value::bool(false))),
    )
    .unwrap();
    assert_eq!(f.severity, Severity::Definite);
    assert_eq!(f.message, "msg");
}

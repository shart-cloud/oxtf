//! The finding record: the resolved, versioned, machine-readable form of a
//! scan that every output (JSON, Arrow, Python, text) is a projection of.
//!
//! Everything here is plain data with locations already resolved against
//! the scan's file table, so a reader needs no further context. The shape
//! is versioned by [`SCHEMA`]; any breaking change bumps it. The worked
//! example and field semantics live in `docs/FINDING_SCHEMA.md`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tf_eval::{Kind, Known, Step, Truth, Value};
use tf_semantic::{Address, Diagnostic, FileTable, InstanceKey, Mode};
use tf_span::FileSpan;

use crate::rule::{Category, Finding, FixHint, Hidden, Level, Severity};
use crate::scan::{ScanResult, ScanStats};

/// Version of the record shape. Bumped on any breaking change.
pub const SCHEMA: u32 = 1;

/// A resolved source location.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    /// 1-based.
    pub line: u32,
    /// 1-based.
    pub column: u32,
    /// Byte offsets into the file.
    pub start: u32,
    pub end: u32,
}

pub fn location(files: &FileTable, at: FileSpan) -> Location {
    let sf = files.get(at.file);
    let (line, column) = sf.line_col(at.span.start);
    Location {
        file: sf.path.display().to_string(),
        line,
        column,
        start: at.span.start,
        end: at.span.end,
    }
}

/// A resource instance's identity, structured and as strings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRef {
    /// Full address, module path and instance key included.
    pub address: String,
    /// Address without the instance key.
    pub base_address: String,
    /// Module instance path, `""` for the root.
    pub module: String,
    /// `managed` or `data`.
    pub mode: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub name: String,
    /// `count` index (number) or `for_each` key (string).
    pub key: Option<Json>,
}

impl From<&Address> for ResourceRef {
    fn from(a: &Address) -> Self {
        ResourceRef {
            address: a.to_string(),
            base_address: a.base_string(),
            module: a.module.to_string(),
            mode: match a.mode {
                Mode::Managed => "managed",
                Mode::Data => "data",
            }
            .into(),
            ty: a.ty.to_string(),
            name: a.name.to_string(),
            key: a.key.as_ref().map(|k| match k {
                InstanceKey::Index(i) => Json::from(*i),
                InstanceKey::Key(k) => Json::from(k.as_ref()),
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    pub id: String,
    pub category: Category,
    pub level: Level,
    pub description: String,
}

/// An abstract value as a reader can use it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValueRecord {
    /// `known`, `unknown`, `tainted` or `one_of`.
    pub kind: String,
    /// The value as JSON when it is wholly known.
    pub value: Option<Json>,
    /// Human rendering (strings quoted; abstract values described).
    pub display: String,
}

pub fn value_record(v: &Value) -> ValueRecord {
    let kind = match &v.kind {
        Kind::Known(_) => "known",
        Kind::Unknown(_) => "unknown",
        Kind::Tainted(_) => "tainted",
        Kind::OneOf(_) => "one_of",
    };
    let value = match &v.kind {
        Kind::Known(Known::Json(inner)) => tf_eval::value::to_json(inner),
        _ => tf_eval::value::to_json(v),
    };
    ValueRecord {
        kind: kind.into(),
        value,
        display: v.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    pub kind: String,
    pub label: String,
    /// Base address of the resource whose attribute this step reads.
    pub resource: Option<String>,
    /// Attribute path within that resource.
    pub attribute: Option<String>,
    pub location: Location,
}

pub fn step_record(files: &FileTable, s: &Step) -> StepRecord {
    StepRecord {
        kind: s.kind.as_str().into(),
        label: s.label.to_string(),
        resource: s.resource.as_deref().map(str::to_string),
        attribute: s.attribute.as_deref().map(str::to_string),
        location: location(files, s.at),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenRecord {
    pub path: String,
    /// `tainted` (unconstrained variable) or `unknown` (apply-time).
    pub kind: String,
}

impl From<&Hidden> for HiddenRecord {
    fn from(h: &Hidden) -> Self {
        HiddenRecord {
            path: h.path.clone(),
            kind: match h.truth {
                Truth::Tainted => "tainted",
                _ => "unknown",
            }
            .into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FixHintRecord {
    pub resource: ResourceRef,
    pub attribute: String,
    /// `set`.
    pub action: String,
    pub value: Json,
    /// Where the attribute is written today; `None` means insert it into
    /// the resource block at `site_block`.
    pub site: Option<Location>,
}

fn fix_hint_record(files: &FileTable, h: &FixHint) -> FixHintRecord {
    FixHintRecord {
        resource: ResourceRef::from(&h.resource),
        attribute: h.attribute.clone(),
        action: h.action.as_str().into(),
        value: h.value.clone(),
        site: h.site.map(|at| location(files, at)),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingRecord {
    pub schema: u32,
    /// Stable identity across scans: rule, address and attribute path.
    /// Excludes locations, message and severity on purpose.
    pub fingerprint: String,
    pub rule: RuleRef,
    pub severity: Severity,
    pub resource: ResourceRef,
    /// Root module directory the finding was produced in.
    pub root: String,
    /// Attribute path of the deciding value within the resource.
    pub attribute: Option<String>,
    /// The deciding top-level attribute as written; absent when not set.
    pub configured: Option<ValueRecord>,
    /// The same after the defaults overlay.
    pub effective: Option<ValueRecord>,
    /// Where to point: the deciding attribute, else the resource header.
    pub location: Location,
    /// Origin-first explanation of the deciding value.
    pub provenance: Vec<StepRecord>,
    pub message: String,
    /// Inputs a foreign policy could not see; empty for native rules.
    pub hidden: Vec<HiddenRecord>,
    pub fix_hint: Option<FixHintRecord>,
}

/// FNV-1a 64-bit of `rule`, `address` and `attribute`, hex. Stable across
/// builds and platforms; not a security hash.
pub fn fingerprint(rule: &str, address: &str, attribute: Option<&str>) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in [rule, "\0", address, "\0", attribute.unwrap_or("")] {
        for b in part.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

pub fn finding_record(files: &FileTable, f: &Finding) -> FindingRecord {
    FindingRecord {
        schema: SCHEMA,
        fingerprint: fingerprint(&f.rule, &f.address, f.attribute.as_deref()),
        rule: RuleRef {
            id: f.rule.to_string(),
            category: f.category,
            level: f.level,
            description: f.description.to_string(),
        },
        severity: f.severity,
        resource: ResourceRef::from(&f.resource),
        root: f.root.display().to_string(),
        attribute: f.attribute.as_deref().map(str::to_string),
        configured: f.configured.as_ref().map(value_record),
        effective: f.effective.as_ref().map(value_record),
        location: location(files, f.primary),
        provenance: f.provenance.iter().map(|s| step_record(files, s)).collect(),
        message: f.message.clone(),
        hidden: f.hidden.iter().map(HiddenRecord::from).collect(),
        fix_hint: f.fix_hint.as_ref().map(|h| fix_hint_record(files, h)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticRecord {
    /// `error`, `warning` or `info`.
    pub severity: String,
    pub code: String,
    pub message: String,
    pub location: Option<Location>,
}

pub fn diagnostic_record(files: &FileTable, d: &Diagnostic) -> DiagnosticRecord {
    DiagnosticRecord {
        severity: format!("{:?}", d.severity).to_lowercase(),
        code: d.code.to_string(),
        message: d.message.clone(),
        location: d.at.map(|at| location(files, at)),
    }
}

/// A rule that failed to run. Never silent: a reader must not take the
/// absence of a finding from this rule as a pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleError {
    pub rule: String,
    /// The resource instance the rule was evaluating, when known.
    pub resource: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatsRecord {
    pub roots: usize,
    pub module_instances: usize,
    pub files: usize,
    pub resources: usize,
    pub findings: usize,
    pub definite: usize,
    pub conditional: usize,
    pub indeterminate: usize,
    pub findings_by_rule: BTreeMap<String, usize>,
    pub elapsed_ms: f64,
}

impl From<&ScanStats> for StatsRecord {
    fn from(s: &ScanStats) -> Self {
        StatsRecord {
            roots: s.roots,
            module_instances: s.module_instances,
            files: s.files,
            resources: s.resources,
            findings: s.findings,
            definite: s.definite,
            conditional: s.conditional,
            indeterminate: s.indeterminate,
            findings_by_rule: s.findings_by_rule.clone(),
            elapsed_ms: s.elapsed.as_secs_f64() * 1000.0,
        }
    }
}

/// A whole scan, resolved.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanRecord {
    pub schema: u32,
    pub findings: Vec<FindingRecord>,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub rule_errors: Vec<RuleError>,
    pub stats: StatsRecord,
}

impl ScanRecord {
    pub fn from_result(r: &ScanResult) -> ScanRecord {
        ScanRecord {
            schema: SCHEMA,
            findings: r.findings.iter().map(|f| finding_record(&r.files, f)).collect(),
            diagnostics: r
                .diagnostics
                .iter()
                .map(|d| diagnostic_record(&r.files, d))
                .collect(),
            rule_errors: r.rule_errors.clone(),
            stats: StatsRecord::from(&r.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_ignores_presentation() {
        let a = fingerprint("aws-rds-unencrypted", "module.m.aws_db_instance.db", Some("storage_encrypted"));
        assert_eq!(a, fingerprint("aws-rds-unencrypted", "module.m.aws_db_instance.db", Some("storage_encrypted")));
        assert_eq!(a.len(), 16);
        assert_ne!(a, fingerprint("aws-rds-unencrypted", "module.m.aws_db_instance.db", None));
        assert_ne!(a, fingerprint("other", "module.m.aws_db_instance.db", Some("storage_encrypted")));
        // Pinned: a change here is a change in every backlog's identities.
        assert_eq!(a, "146d70bdfd611a35");
    }

    #[test]
    fn value_records_carry_known_json_and_a_display() {
        let v = value_record(&Value::bool(false));
        assert_eq!((v.kind.as_str(), v.value, v.display.as_str()), ("known", Some(Json::Bool(false)), "false"));
        let t = value_record(&Value::tainted("x"));
        assert_eq!((t.kind.as_str(), t.value), ("tainted", None));
        let j = value_record(&Value::json(Value::object(Default::default())));
        assert_eq!(j.value, Some(Json::Object(Default::default())));
    }
}

//! Projections of the scan record for other readers: NDJSON (one line
//! per finding, for agents and line-oriented tools) and SARIF 2.1.0 (code
//! scanning). Both are built from [`ScanRecord`] alone, so they cannot
//! disagree with the JSON output.

use serde_json::{Value as J, json};

use crate::record::{FindingRecord, ScanRecord};
use crate::rule::{Certainty, Level};

/// NDJSON: one `{"type": "finding"}` line per finding, then a line per
/// rule error and diagnostic, then one `{"type": "summary"}` line. A
/// finding line keeps what an agent needs to act on it; the full record
/// (provenance, values, occurrences) is in the JSON output.
pub fn ndjson(r: &ScanRecord) -> String {
    let mut out = String::new();
    let mut line = |v: J| {
        out.push_str(&v.to_string());
        out.push('\n');
    };
    for f in &r.findings {
        line(finding_line(f));
    }
    for e in &r.rule_errors {
        line(json!({
            "type": "rule_error",
            "code": "rule-execution-failed",
            "action": crate::recovery::rule_action(),
            "rule": e.rule,
            "resource": e.resource,
            "message": e.message,
        }));
    }
    for d in &r.diagnostics {
        line(json!({
            "type": "diagnostic",
            "severity": d.severity,
            "code": d.code,
            "action": d.action,
            "message": d.message,
            "file": d.location.as_ref().map(|l| &l.file),
            "line": d.location.as_ref().map(|l| l.line),
        }));
    }
    let s = &r.stats;
    line(json!({
        "type": "summary",
        "schema": r.schema,
        "input_kind": r.input_kind,
        "status": r.status,
        "rules": r.rules,
        "findings": s.findings,
        "occurrences": s.occurrences,
        "definite": s.definite,
        "conditional": s.conditional,
        "indeterminate": s.indeterminate,
        "rule_errors": r.rule_errors.len(),
        "diagnostics": r.diagnostics.len(),
        "suppressed": r.suppressed.len(),
        "roots": s.roots,
        "root_summaries": r.roots,
        "coverage": r.coverage,
        "resources": s.resources,
        "elapsed_ms": s.elapsed_ms,
    }));
    out
}

fn finding_line(f: &FindingRecord) -> J {
    let mut v = json!({
        "type": "finding",
        "fingerprint": f.fingerprint,
        "rule": f.rule,
        "level": f.level,
        "certainty": f.certainty,
        "file": f.location.file,
        "line": f.location.line,
        "column": f.location.column,
        "address": address(f),
        "attribute": f.attribute,
        "message": f.message,
        "occurrences": f.occurrences.len(),
    });
    if let Some(package) = &f.package {
        v["package"] = json!(package);
    }
    if let Some(h) = &f.fix_hint {
        v["fix_hint"] = json!({
            "resource": h.resource.address,
            "attribute": h.attribute,
            "action": h.action,
            "value": h.value,
            "site": h.site.as_ref().map(|l| json!({"file": l.file, "line": l.line, "column": l.column})),
        });
        if let Some(l) = &h.default_site {
            v["fix_hint"]["default_site"] =
                json!({"file": l.file, "line": l.line, "column": l.column});
        }
        if let Some(l) = &h.input_site {
            v["fix_hint"]["input_site"] =
                json!({"file": l.file, "line": l.line, "column": l.column});
        }
    }
    v
}

fn address(f: &FindingRecord) -> &str {
    match &f.subject {
        crate::record::SubjectRecord::Resource(r) => &r.address,
        crate::record::SubjectRecord::File { file, .. } => file,
    }
}

/// SARIF's level for a finding: the rule's level, lowered to `note` when
/// the finding needs a human to confirm it.
fn sarif_level(level: Level, certainty: Certainty) -> &'static str {
    match (certainty, level) {
        (Certainty::Indeterminate, _) | (_, Level::Low) => "note",
        (_, Level::Medium) => "warning",
        (_, Level::High | Level::Critical) => "error",
    }
}

fn region(l: &crate::record::Location) -> J {
    json!({"startLine": l.line, "startColumn": l.column})
}

/// SARIF 2.1.0, one run. Rules are the record's `rules` table; each result
/// carries the fingerprint as `partialFingerprints["oxtf/v1"]`, the
/// provenance chain as related locations, and certainty, occurrences and
/// any fix hint as properties.
#[expect(clippy::too_many_lines)]
pub fn sarif(r: &ScanRecord) -> J {
    let ids: Vec<&String> = r.rules.keys().collect();
    let rules: Vec<J> = r
        .rules
        .iter()
        .map(|(id, rule)| {
            let mut v = json!({
                "id": id,
                "shortDescription": {"text": rule.description},
                "defaultConfiguration": {"level": sarif_level(rule.level, Certainty::Definite)},
                "properties": {
                    "category": rule.category,
                    "level": rule.level,
                    "engine": rule.source.engine,
                },
            });
            if let Some(g) = &rule.guideline {
                v["helpUri"] = J::from(g.as_str());
            }
            if let Some(remediation) = &rule.remediation {
                v["help"] = json!({"text": remediation});
            }
            if let Some(rationale) = &rule.rationale {
                v["properties"]["rationale"] = J::from(rationale.as_str());
            }
            v
        })
        .collect();
    let results: Vec<J> = r
        .findings
        .iter()
        .map(|f| {
            let related: Vec<J> = f
                .provenance
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    json!({
                        "id": i,
                        "message": {"text": s.label},
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri(&s.location.file)},
                            "region": region(&s.location),
                        },
                    })
                })
                .collect();
            let mut properties = json!({
                "certainty": f.certainty,
                "occurrences": f.occurrences.len(),
            });
            if let Some(package) = &f.package {
                properties["package"] = json!(package);
            }
            if let Some(a) = &f.attribute {
                properties["attribute"] = J::from(a.as_str());
            }
            if let Some(h) = &f.fix_hint {
                properties["fix_hint"] = serde_json::to_value(h).expect("fix hint is JSON");
            }
            json!({
                "ruleId": f.rule,
                "ruleIndex": ids.binary_search(&&f.rule).ok(),
                "level": sarif_level(f.level, f.certainty),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri(&f.location.file)},
                        "region": region(&f.location),
                    },
                    "logicalLocations": [{"fullyQualifiedName": address(f), "kind": "resource"}],
                }],
                "partialFingerprints": {"oxtf/v1": f.fingerprint},
                "relatedLocations": related,
                "properties": properties,
            })
        })
        .collect();
    let notifications: Vec<J> = r
        .rule_errors
        .iter()
        .map(|e| {
            json!({
                "level": "error",
                "message": {"text": match &e.resource {
                    Some(res) => format!("{} on {res}: {}", e.rule, e.message),
                    None => format!("{}: {}", e.rule, e.message),
                }},
                "associatedRule": {"id": e.rule},
                "properties": {"code": "rule-execution-failed", "action": crate::recovery::rule_action()},
            })
        })
        .chain(r.diagnostics.iter().map(|d| {
            let mut notification = json!({
                "level": match d.severity.as_str() {
                    "error" => "error",
                    "warning" => "warning",
                    _ => "note",
                },
                "descriptor": {"id": d.code},
                "properties": {"action": d.action},
                "message": {"text": d.message},
            });
            if let Some(l) = &d.location {
                notification["locations"] = json!([{"physicalLocation": {
                    "artifactLocation": {"uri": uri(&l.file)},
                    "region": region(l),
                }}]);
            }
            notification
        }))
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "oxtf", "rules": rules}},
            "results": results,
            "properties": {"coverage": r.coverage, "root_summaries": r.roots, "input_kind": r.input_kind},
            "invocations": [{
                "executionSuccessful": r.status == crate::ScanStatus::Complete,
                "toolExecutionNotifications": notifications,
            }],
        }],
    })
}

/// A record path as a SARIF URI reference: `/`-separated, relative paths
/// kept relative.
fn uri(path: &str) -> String {
    path.replace('\\', "/")
}

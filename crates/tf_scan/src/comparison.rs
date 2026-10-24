//! Compare recorded findings without treating lost scan coverage as a fix.
use crate::FindingDelta;
use serde::Serialize;
use std::collections::BTreeSet;
use tf_linter::{
    ScanStatus,
    record::{FindingRecord, ScanRecord},
};

#[derive(Clone, Debug, Serialize)]
pub struct ScanComparison {
    pub schema: u32,
    pub before_status: ScanStatus,
    pub after_status: ScanStatus,
    /// Both scans completed with the same recorded roots and selected rules.
    /// This compares observations, not policy implementations or provider state.
    pub comparable: bool,
    pub issues: Vec<String>,
    /// Disappeared findings verified under comparable, completed scan scopes.
    pub resolved: Vec<String>,
    /// Disappeared findings whose resolution cannot be established.
    pub unverified_removed: Vec<String>,
    pub certainty_changes: Vec<CertaintyChange>,
    pub delta: FindingDelta,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertaintyChange {
    pub fingerprint: String,
    pub before: tf_linter::Certainty,
    pub after: tf_linter::Certainty,
    pub occurrences: Vec<OccurrenceCertaintyChange>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OccurrenceCertaintyChange {
    pub root: String,
    pub address: String,
    pub before: tf_linter::Certainty,
    pub after: tf_linter::Certainty,
}

impl ScanComparison {
    pub fn between(before: &ScanRecord, after: &ScanRecord) -> Result<Self, String> {
        validate(before)?;
        validate(after)?;
        let mut issues = completion_issues("before", before);
        issues.extend(completion_issues("after", after));
        issues.extend(scope_issues(before, after));
        let delta = FindingDelta::between(&before.findings, &after.findings);
        let comparable = issues.is_empty();
        let removed = delta
            .removed
            .iter()
            .map(|f| f.fingerprint.clone())
            .collect();
        let (resolved, unverified_removed) = if comparable {
            (removed, Vec::new())
        } else {
            (Vec::new(), removed)
        };
        let index: std::collections::HashMap<_, _> = before
            .findings
            .iter()
            .map(|f| (f.fingerprint.as_str(), f))
            .collect();
        let certainty_changes = after
            .findings
            .iter()
            .filter_map(|f| {
                let old = index.get(f.fingerprint.as_str())?;
                let occurrences = certainty_changes(old, f);
                (old.certainty != f.certainty || !occurrences.is_empty()).then(|| CertaintyChange {
                    fingerprint: f.fingerprint.clone(),
                    before: old.certainty,
                    after: f.certainty,
                    occurrences,
                })
            })
            .collect();
        Ok(Self {
            schema: 1,
            before_status: before.status,
            after_status: after.status,
            comparable,
            issues,
            resolved,
            unverified_removed,
            certainty_changes,
            delta,
        })
    }

    pub fn has_regressions(&self) -> bool {
        self.delta.has_new_findings()
            || self
                .certainty_changes
                .iter()
                .any(|c| c.after < c.before || c.occurrences.iter().any(|o| o.after < o.before))
    }
}

fn completion_issues(label: &str, record: &ScanRecord) -> Vec<String> {
    let mut issues = Vec::new();

    if record.status != ScanStatus::Complete {
        issues.push(format!("{label} scan is {}", record.status.as_str()));
    }
    if record.roots.is_empty() {
        issues.push(format!("{label} scan has no root completion records"));
    }
    if record
        .roots
        .iter()
        .any(|r| r.status != ScanStatus::Complete)
    {
        issues.push(format!("{label} scan contains roots that did not complete"));
    }
    if record.coverage.is_none() || record.roots.iter().any(|r| r.coverage.is_none()) {
        issues.push(format!("{label} scan lacks rule coverage accounting"));
    }
    if record.coverage.as_ref().is_some_and(|c| {
        c.rules
            .values()
            .any(|counts| counts.failed > 0 || counts.skipped > 0)
    }) {
        issues.push(format!("{label} scan has failed or skipped rule checks"));
    }
    issues
}

fn scope_issues(before: &ScanRecord, after: &ScanRecord) -> Vec<String> {
    let mut issues = Vec::new();
    let roots = |r: &ScanRecord| {
        r.roots
            .iter()
            .map(|r| r.path.clone())
            .collect::<BTreeSet<_>>()
    };
    if roots(before) != roots(after) {
        issues.push("selected root directories changed".into());
    }
    if let (Some(old), Some(new)) = (&before.coverage, &after.coverage)
        && old.rules.keys().collect::<Vec<_>>() != new.rules.keys().collect::<Vec<_>>()
    {
        issues.push("selected rule IDs changed".into());
    }
    if before.input_kind.is_none() || after.input_kind.is_none() {
        issues.push("scan input kind is not recorded".into());
    } else if before.input_kind != after.input_kind {
        issues.push("scan input kind changed (source versus plan)".into());
    }
    let suppressions = |r: &ScanRecord| {
        r.suppressed
            .iter()
            .map(|s| (s.rule.clone(), s.resource.clone(), s.location.file.clone()))
            .collect::<BTreeSet<_>>()
    };
    if suppressions(before) != suppressions(after) {
        issues.push("finding suppression scope changed".into());
    }
    let inputs = |r: &ScanRecord| {
        r.roots
            .iter()
            .flat_map(|root| {
                root.unresolved_inputs
                    .iter()
                    .map(move |v| (root.path.clone(), v.module.clone(), v.variable.clone()))
            })
            .collect::<BTreeSet<_>>()
    };
    if !inputs(after).is_subset(&inputs(before)) {
        issues.push("after scan has additional unresolved input variables".into());
    }
    issues
}

fn validate(record: &ScanRecord) -> Result<(), String> {
    if record.schema != tf_linter::record::SCHEMA {
        return Err(format!("unsupported scan record schema {}", record.schema));
    }
    let mut roots = BTreeSet::new();
    for root in &record.roots {
        if !roots.insert(root.path.as_str()) {
            return Err("duplicate root path in scan record".into());
        }
    }
    if let Some(coverage) = &record.coverage {
        if coverage.selected_rules != coverage.rules.len() {
            return Err("selected rule count disagrees with coverage rule IDs".into());
        }
        for counts in coverage.rules.values() {
            if counts.completed.checked_add(counts.failed) != Some(counts.executed)
                || counts.executed.checked_add(counts.skipped) != Some(counts.planned)
            {
                return Err("inconsistent rule check accounting".into());
            }
        }
    }
    let mut fingerprints = BTreeSet::new();
    for f in &record.findings {
        if !fingerprints.insert(&f.fingerprint) {
            return Err("duplicate finding fingerprint in scan record".into());
        }
        validate_finding(f, &roots)?;
    }
    Ok(())
}

fn validate_finding(f: &FindingRecord, roots: &BTreeSet<&str>) -> Result<(), String> {
    // Legacy records can lack root completion records; report unknown coverage
    // rather than rejecting observations that remain useful to compare.
    if !roots.is_empty()
        && f.occurrences
            .iter()
            .any(|o| !roots.contains(o.root.as_str()))
    {
        return Err(format!(
            "finding {} references an unrecorded root",
            f.fingerprint
        ));
    }
    Ok(())
}

fn certainty_changes(
    before: &FindingRecord,
    after: &FindingRecord,
) -> Vec<OccurrenceCertaintyChange> {
    let collect = |finding: &FindingRecord| {
        let mut grouped = std::collections::BTreeMap::new();
        for o in &finding.occurrences {
            grouped
                .entry((o.root.clone(), o.address.clone()))
                .or_insert_with(Vec::new)
                .push(o.certainty);
        }
        for values in grouped.values_mut() {
            values.sort_unstable();
        }
        grouped
    };
    let old = collect(before);
    let new = collect(after);
    let mut changes = Vec::new();
    for ((root, address), values) in new {
        if let Some(previous) = old.get(&(root.clone(), address.clone())) {
            for (before, after) in previous.iter().zip(values) {
                if *before != after {
                    changes.push(OccurrenceCertaintyChange {
                        root: root.clone(),
                        address: address.clone(),
                        before: *before,
                        after,
                    });
                }
            }
        }
    }
    changes
}

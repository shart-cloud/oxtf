use std::collections::HashMap;

use serde::Serialize;
use tf_linter::record::{FindingRecord, OccurrenceRecord};

/// Observed findings before and after an edit, across the request's selected
/// rules and roots. Counts are grouped findings, as in the scan record.
/// A delta from incomplete scans is still useful evidence, but cannot prove
/// that an edit resolved its target or introduced no findings.
#[derive(Clone, Debug, Serialize)]
pub struct FindingDelta {
    pub before: usize,
    pub after: usize,
    /// New fingerprints, with evidence from the rescan.
    pub added: Vec<FindingRecord>,
    /// Disappeared fingerprints, with evidence from the original scan.
    pub removed: Vec<FindingRecord>,
    /// Existing fingerprints whose affected roots, instances, or certainty changed.
    pub changed: Vec<FindingChange>,
    /// Fingerprints with the same occurrence identities and certainty; evidence and positions may differ.
    pub unchanged: usize,
}

/// A finding that persists but changes occurrences or certainty. A new occurrence
/// counts as a regression even if the grouped finding already existed.
#[derive(Clone, Debug, Serialize)]
pub struct FindingChange {
    pub before: FindingRecord,
    pub after: FindingRecord,
    pub added_occurrences: Vec<OccurrenceRecord>,
    pub removed_occurrences: Vec<OccurrenceRecord>,
}

impl FindingDelta {
    pub(crate) fn between(before: &[FindingRecord], after: &[FindingRecord]) -> Self {
        let index = |findings: &[FindingRecord]| {
            findings
                .iter()
                .enumerate()
                .map(|(i, f)| (f.fingerprint.clone(), i))
                .collect::<HashMap<_, _>>()
        };
        let before_index = index(before);
        let after_index = index(after);
        let mut delta = Self {
            before: before.len(),
            after: after.len(),
            added: Vec::new(),
            removed: before
                .iter()
                .filter(|f| !after_index.contains_key(&f.fingerprint))
                .cloned()
                .collect(),
            changed: Vec::new(),
            unchanged: 0,
        };
        for new in after {
            let Some(&i) = before_index.get(&new.fingerprint) else {
                delta.added.push(new.clone());
                continue;
            };
            let old = &before[i];
            let added_occurrences = occurrence_difference(&new.occurrences, &old.occurrences);
            let removed_occurrences = occurrence_difference(&old.occurrences, &new.occurrences);
            if added_occurrences.is_empty()
                && removed_occurrences.is_empty()
                && old.certainty == new.certainty
                && occurrence_certainties(&old.occurrences)
                    == occurrence_certainties(&new.occurrences)
            {
                delta.unchanged += 1;
            } else {
                delta.changed.push(FindingChange {
                    before: old.clone(),
                    after: new.clone(),
                    added_occurrences,
                    removed_occurrences,
                });
            }
        }
        delta
    }

    /// Whether the observed delta adds a finding or an occurrence. This does
    /// not establish scan completeness; use `FixOutcome::no_new_findings` for that.
    pub fn has_new_findings(&self) -> bool {
        !self.added.is_empty() || self.changed.iter().any(|f| !f.added_occurrences.is_empty())
    }
}

// Compare root/address identities as a multiset: inserting a line must not
// make every later occurrence look new, while additional occurrences at the
// same address (such as alternative dynamic blocks) must remain visible.
fn occurrence_difference(a: &[OccurrenceRecord], b: &[OccurrenceRecord]) -> Vec<OccurrenceRecord> {
    let mut counts = HashMap::new();
    for occurrence in b {
        *counts
            .entry((&occurrence.root, &occurrence.address))
            .or_insert(0usize) += 1;
    }
    a.iter()
        .filter(|occurrence| {
            let count = counts
                .entry((&occurrence.root, &occurrence.address))
                .or_default();
            if *count == 0 {
                true
            } else {
                *count -= 1;
                false
            }
        })
        .cloned()
        .collect()
}

fn occurrence_certainties(
    occurrences: &[OccurrenceRecord],
) -> Vec<(&str, &str, tf_linter::Certainty)> {
    let mut values: Vec<_> = occurrences
        .iter()
        .map(|o| (o.root.as_str(), o.address.as_str(), o.certainty))
        .collect();
    values.sort_unstable();
    values
}

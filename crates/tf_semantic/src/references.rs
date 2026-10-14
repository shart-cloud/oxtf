//! Resource identity matching for rules over either source or plan models.
//!
//! Explanation provenance records dependencies, not equality: transformations
//! and sibling instances can share provenance without naming the same resource.

use tf_eval::{Kind, Origin, Value};

use crate::Resource;

/// Certainty that a value identifies a particular resource instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceMatch {
    Yes,
    Maybe,
    No,
}

/// Match a resource identifier against a resource's evaluated name or a
/// computed reference. `name_attribute` is its concrete identifier;
/// `reference_attributes` lists attributes that identify it (e.g. S3's
/// `id` and `bucket`). Callers supply domain knowledge, not lattice handling.
///
/// A missing key on only one side is ambiguous, never an exact match.
/// Unknown and tainted names remain uncertain; provenance is never evidence
/// of identity. This also keeps matching independent of provenance truncation.
pub fn match_resource_reference(
    value: &Value,
    resource: &Resource,
    name_attribute: &str,
    reference_attributes: &[&str],
) -> ReferenceMatch {
    use ReferenceMatch::{Maybe, No, Yes};
    match &value.kind {
        Kind::Known(_) => {
            let Some(name) = value.as_str() else {
                return No;
            };
            match resource.value(name_attribute) {
                Some(target) => match &target.kind {
                    Kind::OneOf(o) => consensus(o.alternatives.iter().map(|v| match v.as_str() {
                        Some(target) if target == name => Yes,
                        Some(_) => No,
                        _ => Maybe,
                    })),
                    _ => match target.as_str() {
                        Some(target) if target == name => Yes,
                        Some(_) => No,
                        // Null/unset names may be assigned by the provider.
                        _ => Maybe,
                    },
                },
                None => Maybe,
            }
        }
        Kind::Unknown(origin) => match origin.as_ref() {
            Origin::Computed {
                resource: base,
                key,
                attr,
            } => {
                if base != &resource.base_address || !reference_attributes.contains(&attr.as_ref())
                {
                    No
                } else {
                    match (key.as_deref(), resource.key.as_deref()) {
                        (Some(a), Some(b)) if a == b => Yes,
                        (Some(_), Some(_)) => No,
                        (None, None) => Yes,
                        _ => Maybe,
                    }
                }
            }
            Origin::Error(_) => No,
            _ => Maybe,
        },
        Kind::Tainted(_) => Maybe,
        Kind::OneOf(o) => {
            consensus(o.alternatives.iter().map(|v| {
                match_resource_reference(v, resource, name_attribute, reference_attributes)
            }))
        }
    }
}

fn consensus(matches: impl Iterator<Item = ReferenceMatch>) -> ReferenceMatch {
    let mut matches = matches;
    let Some(first) = matches.next() else {
        return ReferenceMatch::Maybe;
    };
    if matches.all(|m| m == first) {
        first
    } else {
        ReferenceMatch::Maybe
    }
}

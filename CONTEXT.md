# Domain language

This glossary records the concepts sharpened during the architecture review.
Existing implementation decisions and spike limitations remain in `SPIKE_REPORT.md`.

- **Resource instance**: one managed resource or data-source instance in the owned analysis model. Its identity includes its module instance and its `count` or `for_each` key; a base address alone does not identify an expanded instance.
- **Resource reference**: a value used to identify a resource instance. Known identifiers match by value; computed references carry an address, instance key, and attribute. Matching can be definite, impossible, or uncertain.
- **Explanation provenance**: the source locations and dependency steps explaining a value. Sharing provenance does not prove equal values or equal resource identity.
- **Rule selection**: an explicit selection from a rule catalog. Unknown IDs are errors; an empty selection is valid. CLI selection includes loaded custom rules, while Python's `builtin` selection applies only to built-in rules.
- **Finding record**: the resolved, versioned (`schema`), machine-readable form of a finding; every output format is a projection of it (`docs/FINDING_SCHEMA.md`).
- **Fingerprint**: a finding's stable identity across scans, from rule, resource address and attribute path; never from locations, message or certainty.
- **Fix hint**: the part of a finding record that says what a mechanical edit would do (resource, attribute, literal, site). Whether and where to apply it is the caller's judgement.
- **Projection**: the evaluated model rendered into the input shape a foreign policy family expects. Only Known values are projected; abstract values become absent and are listed.
- **Abstraction list**: for one projected resource instance, the attribute paths whose values were Unknown, Tainted or OneOf and so did not reach the foreign policy. It decides the certainty of any foreign finding on that resource.
- **Indeterminate**: the certainty of a foreign finding on a resource whose abstraction list holds only provider-computed values. Neither Definite nor Conditional; needs a human.

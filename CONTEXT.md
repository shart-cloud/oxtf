# Domain language

This glossary records the concepts sharpened during the architecture review.
Existing implementation decisions and spike limitations remain in `SPIKE_REPORT.md`.

- **Resource instance**: one managed resource or data-source instance in the owned analysis model. Its identity includes its module instance and its `count` or `for_each` key; a base address alone does not identify an expanded instance.
- **Resource reference**: a value used to identify a resource instance. Known identifiers match by value; computed references carry an address, instance key, and attribute. Matching can be definite, impossible, or uncertain.
- **Explanation provenance**: the source locations and dependency steps explaining a value. Sharing provenance does not prove equal values or equal resource identity.
- **Rule catalog**: where a scan's rules come from, resolved in order: the seed rules, rule-IR files and documents, runtime rules (Python callbacks), then Rego policies. A later source shadows an earlier rule of the same name, which is how a native-tier Rego policy replaces its seed rule. `tf_scan::Catalog`.
- **Rule selection**: an explicit selection of IDs from the whole resolved rule catalog, the same in the CLI (`--rule`) and Python (`select=`). Unknown IDs are errors; an empty selection is valid and runs nothing.
- **Scan request**: the one front door (`tf_scan::ScanRequest`): input (directories or a plan), catalog, selection, var files, threads. Every adapter (CLI, Python, tests) builds one; the result is a `ScanResult` plus the analysed model. Errors before rules run (bad path, bad rule file, bad policy, unknown ID) refuse the scan; a rule failing on a resource is a **rule error** on the result.
- **Rule error**: a rule hook that returned an error for a resource (a Rego runtime failure, a Python callback that raised). Recorded as `rule_errors` on the result with the rule and resource; the scan still completes. The CLI exits 1 when any exist and 2 when the scan could not run.
- **Finding record**: the resolved, versioned (`schema`), machine-readable form of a finding; every output format is a projection of it (`docs/FINDING_SCHEMA.md`).
- **Fingerprint**: a finding's stable identity across scans, from rule, resource address and attribute path; never from locations, message or certainty.
- **Fix hint**: the part of a finding record that says what a mechanical edit would do (resource, attribute, literal, site). Whether and where to apply it is the caller's judgement.
- **Projection**: the evaluated model rendered into the input shape a foreign policy family expects. Only Known values are projected; abstract values become absent and are listed.
- **Abstraction list**: for one projected resource instance, the attribute paths whose values were Unknown, Tainted or OneOf and so did not reach the foreign policy. It decides the certainty of any foreign finding on that resource.
- **Indeterminate**: the certainty of a foreign finding on a resource whose abstraction list holds only provider-computed values. Neither Definite nor Conditional; needs a human.

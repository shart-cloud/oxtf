# Domain language

This glossary records the concepts sharpened during the architecture review.
Existing implementation decisions and spike limitations remain in `SPIKE_REPORT.md`.

- **Resource instance**: one managed resource or data-source instance in the owned analysis model. Its identity includes its module instance and its `count` or `for_each` key; a base address alone does not identify an expanded instance.
- **Resource reference**: a value used to identify a resource instance. Known identifiers match by value; computed references carry an address, instance key, and attribute. Matching can be definite, impossible, or uncertain.
- **Explanation provenance**: the source locations and dependency steps explaining a value. Sharing provenance does not prove equal values or equal resource identity.
- **Rule selection**: an explicit selection from a rule catalog. Unknown IDs are errors; an empty selection is valid. CLI selection includes loaded custom rules, while Python's `builtin` selection applies only to built-in rules.

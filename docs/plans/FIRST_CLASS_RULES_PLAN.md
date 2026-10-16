# Plan: first-class foreign rules (Checkov YAML, Rego, Conftest)

Oct 16, 2026 · follows [`RULE_ENGINES_PLAN.md`](RULE_ENGINES_PLAN.md)

## Summary

People should be able to point oxtf at the rules they already have, whether
Checkov YAML custom policies, OPA Rego, or Conftest policy directories, and
get exactly what a seed rule gets. That means no Python, no export step, no
pack to build, and no second-class findings.

Today we execute Checkov graph policies natively (184/186 of the pinned
catalog, zero differences across 14,880 conformance cases), but only after a
Python importer has loaded Checkov to translate them. Foreign Rego runs
through `tf_rego`, but as one file per flag, with a filename-derived ID, a
fixed `medium` level and no metadata. Both engines are in place. What is
missing is the front door.

This plan makes each format a **front-end** that compiles to the engine we
already have:

```
 Checkov YAML/JSON ──► Rust front-end ──► rule IR (GraphExpr, AttributeOp, JSONPath)  ─┐
                                                                                      ├─► DynRule ─► Finding
 OPA / Conftest .rego ──► Rust loader ──► regorus over the Known-only projection   ───┘
```

The Python importer for graph policies is retired. It stays only as the
offline oracle in the conformance harness, where Checkov has to be anyway.

## What "first class" means

These are the acceptance criteria for every format. A format that misses one
is not shipped as first class.

1. **One entry point, no Python.** `--rule-file PATH` accepts a file or a
   directory; the format is detected from the extension and content (`.json`
   rule IR, `.yaml`/`.yml`/`.json` Checkov policy, `.rego`). The same paths
   work from `oxtf rules` and `tfscan.scan(rules=[...])`.
2. **Same finding.** The same schema ([`FINDING_SCHEMA.md`](../FINDING_SCHEMA.md)),
   Definite/Conditional/Indeterminate certainty, and provenance through
   `.tfvars` as seed rules.
3. **Same identity and controls.** The rule ID is the author's (`metadata.id`
   for Checkov, the annotated ID for Rego) and works with `--rule`, the
   suppressions and `oxtf rules`. Severity, category, name and guideline URL
   come from the rule's own metadata. ID collisions across sources are a load
   error, not a silent shadow.
4. **Fails loud, with a location in the rule file.** An unsupported
   operator, a bad path or a Rego compile error is a diagnostic with a span
   in the *user's* file (miette, as for Terraform diagnostics). There is never
   a silent skip and never a pass that came from a rule we could not run.
5. **Compile once.** All parsing and validation happens at load time. The
   0.5 s corpus-scan budget ([`ARCHITECTURE_PLAN.md`](ARCHITECTURE_PLAN.md))
   applies with foreign rules enabled.
6. **Fix hints.** The patch chain needs them, and foreign formats don't
   carry them. IR front-ends derive hints from the predicate where the fix
   is unambiguous (`equals: true` sets the attribute; `exists` adds it; a
   `within` with one value sets that value). Rego policies may return an
   optional structured `fix` field (convention defined in F4). Imported
   rules end up *better* than they are in their home engine.

### Semantic contract

Where a source engine's behavior differs from what Terraform will actually do:

- **The predicate follows the source engine.** What `contains`,
  `one_exists`, `within` on a string, or a Conftest `deny` set means is
  exactly what the pinned engine version does. The conformance harness is the
  arbiter.
- **Values follow oxtf.** Expression resolution, unknowns, provider-computed
  values and certainty are oxtf's. A Checkov policy never sees `${var.x}` as
  a literal string. A value Checkov would see unresolved is Unknown and lifts
  through the predicate with the normal lattice.

Every place where the two produce different outcomes on the same input is a
documented, tested divergence, never an accident. This is what we already
do for imported Checkov checks. This plan writes it down as the contract.

## Workstreams

### F1. Native Checkov YAML front-end (implemented 2026-10-16)

`--rule-file` now takes a Checkov policy (`.yaml`/`.yml`, or `.json` with
`metadata` and `definition`) or a directory of policies and rule IR, walked
recursively as Checkov walks a policy directory. No Python and no export step
are involved. The code is in `tf_rule_ir`: `pyyaml.rs` (loading) and
`checkov_policy.rs` (translation, JSONPath, diagnostics).

- [x] YAML parser: **yaml-rust2 0.13.0** (2026-09-11; transitive
  `hashlink` 0.12.2, `arraydeque` 0.5.1, `foldhash` 0.2.0, all past the
  two-week rule), with default features off. It provides events with
  positions. Scalar resolution and mapping construction are our own, because
  Checkov loads YAML with PyYAML `safe_load` (YAML 1.1) followed by a JSON
  round trip. So `on`/`yes` are booleans, `012` is octal, `1:30` is
  sexagesimal, `1e3` is a string, merge keys work, and non-string keys are
  stringified as `json.dumps` would. Timestamps, binary, sets, NaN and
  infinities are errors, as they are for Checkov.
- [x] Policy schema → `GraphExpr`, a line-for-line port of
  `_translate_graph`: the same blocker codes, reasons and JSON Pointer
  paths, and every branch visited. Checkov's required metadata (`id`, `name`,
  `category`) is enforced. `metadata.severity` sets the level (INFO/NONE →
  `low`; unknown names → `medium`, as Checkov ignores them). Category stays
  `other` until F5's metadata model.
- [x] Export-time normalizations ported: Python `int()` thresholds
  (whitespace, sign, single underscores, float truncation, bool), scalar-list
  and filter operand typing.
- [x] JSONPath: a recursive-descent parser for the admitted grammar replaces
  `bc_jsonpath_ng`. Lexing hazards in that lexer (`true…`/`false…` prefixes,
  `where`/`contains` keywords) are rejected rather than reproduced.
- [x] `--rule-file .../checkov/terraform/checks/graph_checks` reads the
  built-in catalog directly.
- [x] Load errors point into the policy file: `file:line:col: ID: reason
  [code] at /pointer`, for YAML (parser marks) and JSON (a pointer scanner).
  A file named directly that does not load is an error. In a directory, each
  bad file (unparsable, unsupported, or redefining an earlier rule name,
  where the first wins as in Checkov) is skipped with one warning per file.
  The warning is printed to stderr even with `--no-diagnostics`, and is
  listed first in the scan record's `diagnostics` as `rule-skipped`. So the
  built-in `graph_checks` directory loads its 184 supported policies and
  names the 2 it skipped.

**Gate results.**

- *IR equality:* `tests/checkov_policy.rs` (run with `CHECKOV_GRAPH_CHECKS`
  and `CHECKOV_PACK`, `--include-ignored`). All 184 translated graph policies
  produce `RuleSpec`s equal to a fresh export from the pinned importer. The
  two rejected policies (`CKV2_AWS_69`, `CKV2_OCI_4`) produce identical
  blocker lists.
- *Corpus:* scanning `corpus/repos` with the policy directory (minus those
  two files) and with the exported graph rules gives identical findings
  (349). Medians over 10 runs: scan 153 ms vs 156 ms; loading the 184 files
  takes 17 ms vs 7 ms for the single pack.
- *Differential fixtures:* `bench/checkov/frontend_fixtures.py` runs PyYAML
  6.0.2 and the importer's JSONPath compiler over 266 YAML documents and 84
  attributes (`tests/fixtures/checkov_frontend.json`). The YAML loader agrees
  on every case except `!!omap`, which it rejects. The JSONPath compiler never
  accepts anything the importer rejects or compiles differently; it is stricter
  on 5 spellings (`a[:]`, `a.[*]`, quoted fields before a selector, a bare
  `@v` filter value). Both stricter lists are pinned in the test.

**Deliberate divergences from the old importer** (each follows Checkov
instead):

- `resource_types: all` (or a missing value, or `*`) is rejected. The
  importer treated it as "any type". Checkov expands it from a provider table
  keyed by `scope.provider` (or matches nothing without one). No built-in
  policy uses it. Reproducing the table is an F2 item.
- `resource_types: provider` (Checkov's provider-block selector) is rejected.

**Still open from F1:**

- `tfscan` still loads Checkov packs through the Python importer; switching
  it to these paths and deleting the graph half of the importer is F5.

### F2. Full Checkov operator coverage

User policies can use any operator, not only the ones the built-in catalog
happens to use. The pinned 3.2.328 attribute-solver registry has 45
operators; `AttributeOp` covers 24. Missing:

| Group | Operators |
| --- | --- |
| String | `ending_with`, `not_ending_with`, `regex_match`, `not_regex_match` |
| Collections | `intersects`, `not_intersects`, `not_subset`, `any` |
| Length | `length_equals`, `length_not_equals`, `length_greater_than_or_equal`, `length_less_than` |
| Word count | `number_of_words_equals`, `_greater_than`, `_greater_than_or_equal`, `_less_than`, `_less_than_or_equal` |
| Network / range | `cidr_range_subset`, `cidr_range_not_subset`, `range_includes`, `range_not_includes` |

- [ ] `resource_types: all` / `connected_resource_types: all`: Checkov's
  per-provider resource-type table, with `scope.provider`, generated from
  the pinned version (see F1 divergences).

- [ ] Generate the operator inventory from the pinned registry, including the
  `jsonpath_*` variants, and commit it as a table; the loader rejects any
  operator not in it with a pointer to that table.
- [ ] Implement each group with pass/fail fixtures, missing/null/empty and
  unknown cases, and differential checks against the pinned solver. Regex
  follows Python `re` semantics for the subset the pinned solver uses; any
  construct the Rust engine can't match exactly is a load error, not an
  approximation.
- [ ] Close the two remaining built-in blockers (`CKV2_AWS_69`, `CKV2_OCI_4`:
  regex predicates/filters and numeric filter comparisons). This reaches 186/186.
- [ ] Extend the graph conformance generator to produce cases for operators
  the built-in catalog doesn't use, from synthetic policies.

**Gate:** every registry operator is either implemented with zero
differential disagreements or listed as unsupported with a reason;
186/186 built-in graph policies.

### F3. Rego / OPA as a first-class format

- [ ] Load `.rego` files and directories, with library packages shared
  across policies, plus optional `data` JSON/YAML documents.
- [ ] Metadata from OPA `# METADATA` annotations (`title`, `description`,
  `custom.id`, `custom.severity`, `related_resources`), falling back to
  `__rego_metadata__` objects, then to the current `rego:<file>` ID.
  Severity maps to `Level`; resource types from metadata narrow which
  instances are projected.
- [ ] Verify regorus handles both Rego v0 and v1 (`import rego.v1` and the
  OPA 1.0 default) on a sample of real-world policies; record gaps.
- [ ] Result mapping beyond a message: accept structured results (`msg`,
  plus optional `resource`/`address`, attribute path and `fix`), so a
  finding can point at an attribute rather than only at the resource.
- [ ] **Cross-resource policies.** Today each managed resource is projected
  and evaluated alone, so a policy that joins two resources (bucket and
  public-access block) only ever sees one. Add a whole-document mode
  (one evaluation per root module), with results attributed back by
  address. Decide per policy, from metadata or by detecting iteration over
  the whole input, and measure the cost against the per-resource mode.

**Gate:** the seed-rule Rego ports and a set of community policies produce
the same findings as `opa eval` on the corpus. Certainty stays
classified by the projection's hidden values, as today.

### F4. Conftest compatibility

- [ ] Conftest's rule conventions: `deny`, `violation` and `warn`, including
  prefixed rules (`deny_*`, `warn_*`), across namespaces (`--namespace`,
  `--all-namespaces`, default `main`). This replaces the single
  `--policy-entry`. `warn` maps to a lower `Level` (decide which) but
  keeps full certainty semantics; `exception` rules suppress as Conftest does.
- [ ] Input shapes per policy: Conftest's hcl2 parser shape (`Shape::Hcl`)
  and plan JSON (`Shape::Plan`). Make the shape configurable per policy
  directory instead of the global `--policy-shape`.
- [ ] `oxtf rules test` runs a policy directory's `test_*` rules, like
  `conftest verify`, so authors can keep their existing test workflow.
- [ ] Define and document the optional `fix` field (criterion 6) in a way
  that is harmless to real Conftest.

**Gate:** pinned `conftest test` and oxtf agree on the corpus for a policy
set covering every rule convention above, compared per (policy, resource).

### F5. Unified loading, metadata and UX

- [ ] `--rule-file` format detection for file and directory, with
  `--policy` kept as an alias. Mixed directories load each file by its format.
- [ ] A common rule metadata model across sources: ID, name, level,
  category, guideline URL, source engine, and source file/line. `oxtf rules`
  shows the source engine and file; JSON output includes it.
- [ ] Load diagnostics with spans for all three formats (criterion 4).
- [ ] `tfscan` takes the same paths (`rules=["policies/"]`); the Python-side
  Checkov graph importer is deleted.
- [ ] Fix-hint derivation from IR predicates (criterion 6), with
  fixtures that apply each hint and rescan to a pass.
- [ ] Suppression-comment compatibility: `#checkov:skip=ID:reason` applies
  to Checkov-sourced rules as it would in Checkov.

**Gate:** corpus scan with the full Checkov graph catalog and the Conftest
set loaded stays within the perf budget; measured with the method in
[the execution baseline](RULE_ENGINES_PLAN.md#execution-baseline).

## Order

F1 → F2 (F2 needs the Rust front-end to add operators in one place). F3 →
F4 (Conftest builds on the Rego loader). F1 and F3 can run in parallel; F5
lands incrementally alongside each and closes last.

## Roadmap (not in this plan)

- **Checkov Python checks** (the ~390 custom `scan_resource_conf` checks and
  45 overridden value checks). These are programs, not policies. The planned
  direction is a one-time translation of each into rule IR or Rego, with the
  existing differential harness as the gate, rather than embedding a Python
  interpreter. Nine shared base classes cover about 40 of them. Value checks
  still need the Python exporter until then.
- **KICS** (R2 of the previous plan) and **Trivy** checks, on top of the F3
  loader.
- Bring-your-own Python checks.

## Instructions for the executing agent

1. **Pin oracles.** Checkov stays at 3.2.328; pin `opa` and `conftest`
   versions for the harnesses and record them. Oracles run offline in the
   bench harness only, never at scan time.
2. **Gate on equality first.** F1 is a pure port: if the Rust front-end's IR
   differs from the Python importer's on any built-in policy, fix the port
   before adding anything.
3. **No approximations.** An operator, regex construct or Rego feature we
   can't reproduce exactly is a load error with a reason, never a
   best-effort match.
4. **Keep the 34 fixtures and both conformance runs green** throughout.
5. **No invented numbers.** Every count and timing in reports comes from a
   command you ran and kept the output of.

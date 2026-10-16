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

- `resource_types: all` (or a missing value) expands from Checkov's
  provider table keyed by `scope.provider`, as Checkov does (F2). The
  importer treated it as "any type". `*` is rejected: Checkov matches it
  literally.
- `resource_types: provider` (Checkov's provider-block selector) is rejected.

**Still open from F1:**

- `tfscan` still loads Checkov packs through the Python importer; switching
  it to these paths and deleting the graph half of the importer is F5.

### F2. Full Checkov operator coverage (implemented 2026-10-16)

User policies can use any operator, not only the ones the built-in catalog
happens to use. The pinned 3.2.328 attribute-solver registry has 45
operators. `AttributeOp` had 24 and now covers all 45, plain and as
`jsonpath_<operator>`. The 21 added:

| Group | Operators |
| --- | --- |
| String | `ending_with`, `not_ending_with`, `regex_match`, `not_regex_match` |
| Collections | `intersects`, `not_intersects`, `not_subset`, `any` |
| Length | `length_equals`, `length_not_equals`, `length_greater_than_or_equal`, `length_less_than` |
| Word count | `number_of_words_equals`, `_greater_than`, `_greater_than_or_equal`, `_less_than`, `_less_than_or_equal` |
| Network / range | `cidr_range_subset`, `cidr_range_not_subset`, `range_includes`, `range_not_includes` |

- [x] `resource_types: all` / `connected_resource_types: all` expand from
  Checkov's per-provider table (`data/checkov_resource_types.json`, written
  by `scripts/gen_checkov_resource_types.py` from the pinned version) and
  `scope.provider`.
- [x] Operator inventory: all 45 registry operators are implemented, so
  there is no reject list. `every_registry_operator_is_implemented` in
  `tests/checkov_policy.rs` pins the registry's names. A name outside it is
  still a load error (`attribute_operator`), as it is for Checkov.
- [x] Python semantics are ported, not approximated. `py.rs` covers `str()`,
  `int()`/`force_int` and `ipaddress.ip_network(strict=False)`. `pyre.rs`
  translates `re.match`/`re.search` patterns into the `regex` crate (new
  dependency, `=1.13.1`) and admits only constructs with identical meaning
  in both. Everything else (backreferences, lookaround, `\b`, flags other
  than `i`, a non-final `$`) is a load error. Fixture tests check `\s`/`\w`/`\d`
  over every code point, plus `str()`/`int()`/`ip_network`, against Python.
- [x] Both remaining built-in blockers are closed (`CKV2_AWS_69`,
  `CKV2_OCI_4`: regex filters and numeric filter comparisons). 186/186.
- [x] The graph conformance generator (`bench/checkov/graph_compare.py`) now
  loads every policy through the native front-end (`--rule-file DIR`) and
  adds 211 synthetic policies (`synthetic_policies.py`). They put every
  operator in a plain attribute, under a wildcard path and as `jsonpath_*`,
  and selected ones in connection trees and `resource_types: all` scopes.
  Operand pools per operator family cover missing, null, empty, mistyped and
  malformed values.

**Gate results.**

- *Differential:* `graph_compare.py` against Checkov 3.2.328's parser and
  solvers: 397 policies (186 built-in, 211 synthetic), 41,208 cases (17,000
  built-in, 24,208 synthetic), **0 disagreements, 0 skipped, 0 reference
  errors**. It takes about 5 minutes.
- *IR equality:* the 184 policies the importer translated still produce
  identical `RuleSpec`s. The importer's 2 rejects now translate natively.
- *Unknowns* (Checkov has none, so the harness cannot see them): each of
  the 21 new operators on an attribute bound to an unset variable yields a
  `conditional` finding, never a `definite` one. `any` yields no finding,
  because it never fails.
- Regenerating `checkov_frontend.json` with PyYAML 6.0.3 changes only the
  version stamp. The committed file stays pinned to 6.0.2.

### F3. Rego / OPA as a first-class format (implemented 2026-10-16; gate open on regorus)

The reference is `opa eval -d PATH...` with OPA 1.17.0. The code is in
`tf_rego` (`foreign.rs`) and `tf_rule_ir::goyaml`.

**Design.**

- *One bundle.* Every `--policy` path (file or directory, walked recursively
  in name order, hidden files included) loads into one regorus engine, as
  `opa eval -d a -d b` does. Packages merge across files, so two
  `package main` files form one `data.main.deny`. A `.json`/`.yaml`/`.yml`
  file is a data document, placed at its directory's path below the `-d`
  root and deep-merged. A scalar conflict, a non-object document, or a rule
  that collides with data is a load error, as in OPA.
- *YAML* (data files and annotations) is read as OPA reads it, by go-yaml
  v2 and sigs.k8s.io/yaml (`goyaml.rs`). That is not PyYAML: plain `y`/`n`
  are booleans, `1e3` is 1000, `08` is the float 8, `1:30` and timestamps
  stay strings, and a `<<` merge applies where it appears. It shares the
  event and node layer with `pyyaml.rs`. The tests pin 60+ scalars, keys
  and merges to `opa eval` output. Float keys, `!!binary`, `!!set` and
  local tags on collections are rejected; OPA accepts them.
- *Policy unit = entry rule.* Each `--policy-entry REF` (repeatable;
  default `data.main.deny`) is one oxtf rule. A missing entry is a load
  error, and so is an entry that does not evaluate to a set on an empty
  document. Discovering entries by Conftest's conventions (`deny_*`,
  namespaces) is F4.
- *Rego version.* v1 by default, as OPA 1.x. `--rego-v0` matches
  `opa eval --v0-compatible`, where a file with `import rego.v1` is still
  v1; regorus follows the same per-file rule.
- *Builtins.* regorus with the OPA builtin families on (`regex`, `glob`,
  `net`, `time`, encodings, `semver`, `uuid`, `urlquery`, `yaml`,
  `jsonpatch`, `graph`). `http.send` and `opa.runtime` stay off: no network
  or environment access at scan time. regorus's line, file-size and
  line-count limits are raised, since OPA has none. Builtin errors are
  strict, as with `opa eval --strict-builtin-errors`, so they surface as
  rule errors. Default OPA would make the expression undefined, but a
  builtin that regorus gets wrong would then be a silent pass. The harness
  compares against strict OPA.
- *Metadata.* The ID, level, description and resource types come from
  `# METADATA` annotations, attached as OPA attaches them: to the next
  package or rule, across blank lines, and not inside a rule body. Each
  field is taken from the nearest annotation in the chain rule → document
  → package → subpackages. Then come the package's `__rego_metadata__`
  object (Trivy/tfsec style), then `rego:<file stem>`, or
  `rego:<package>.<rule>` when the entry spans files or the stem is
  ambiguous. The fields read are `custom.id`, `custom.severity`
  (critical/high/medium/low/info, case-insensitive; any other value is a
  load error), `title` and `description`. The oxtf-specific
  `custom.oxtf.resource_types` narrows which instances are projected, and
  `custom.oxtf.input` picks the input mode. Duplicate IDs among entries
  are a load error. `related_resources` (guideline URL) and the category
  wait for F5's metadata model.
- *Results.* A violation is a string, or an object with `msg` and optional
  `address` and `path` (`a.b[0].c` or a list). `path` makes the finding
  point at that attribute when it is definite. Other keys are ignored. An
  `address` naming another resource in resource mode is a rule error.
- *Input modes.* `resource` (the default) projects one instance per
  evaluation, as before. `module` evaluates once per root, with every
  managed instance of the declared types projected into one plan document,
  for policies that join resources. It needs the plan shape (Conftest's
  HCL file semantics are F4). A module-mode result is attributed by its
  `address`; a result without one, or with an unknown one, is a rule error.
  Certainty in module mode is the worst over the abstractions (and
  uncertain existence) of every projected instance. That is sound for the
  policy's declared contract and conservative across unrelated resources.
- *Conformance hook.* `OXTF_POLICY_TRACE=FILE` appends each evaluation's
  entry, input and result (or error) as JSON lines.

- [x] Load `.rego` files and directories, with library packages shared
  across policies, plus `data` JSON/YAML documents.
- [x] Metadata from `# METADATA` annotations and `__rego_metadata__`, with
  the old `rego:<file>` ID as the fallback.
- [x] Verify v0 and v1 on real-world policies and record gaps (below).
- [x] Structured results with `msg`, `address` and `path`. `fix` is F4.
- [x] Cross-resource policies through `custom.oxtf.input: module`, opt-in
  per policy. Detecting whole-input iteration automatically would be a
  heuristic, so it is not done.
- [x] Seed-rule ports: `fixtures/rego/ports` (5 policies; the S3 one in
  module mode), with fixtures in `fixtures/rego/ports_tf`.

**Gate results** (`bench/rego/opa_compare.py`, corpus `corpus/repos`, OPA
1.17.0 with `--strict-builtin-errors`). Both engines evaluate the same
inputs (oxtf's projections), and results are compared per (entry, input):

| Set | Evaluations | Agree | oxtf error, OPA result | Differ |
| --- | ---: | ---: | ---: | ---: |
| seed ports (5 entries) | 276 | 241 | 35 (`some .. in null`) | 0 |
| Conftest hcl2 example (`--policy-shape hcl`) | 2,145 | 949 | 1,196 (`sprintf("%q")`) | 0 |
| v0 fixture (`--rego-v0`) | 2,850 | 2,850 | 0 | 0 |
| Azure AVM security, 26 entries, commit `c840dd7`, 1 workaround | 74,100 | 74,100 | 0 | 0 |

There are **no silent differences**. Every disagreement is a rule error
oxtf reports, caused by a regorus gap. The AVM run renames one
comprehension variable (gap 3 below) in the staged copy of both engines'
input. Without that rename, regorus cannot load the set. The gate is
therefore not met yet: it needs the regorus gaps closed.

**regorus 0.12.0 vs OPA 1.17.0.** Each gap is reproduced in
`known_regorus_divergences_fail_loudly` (`foreign.rs`). Compile checks with
`examples/rego_check.rs` against `opa check` covered Trivy checks (1,127
files, v1), Regula (700, v0), Azure AVM (133), Scalr samples (62) and
Conftest examples (56). Errors that OPA also reports (Trivy's and
Conftest's own builtins, Scalr's conflicting rules) are excluded.

1. `some x in <scalar or null>` is a runtime error; OPA treats it as
   undefined. It is common in real policies, and it is the 35 above.
2. `sprintf` `%q` is unsupported; OPA formats any value. regorus 0.13.0
   adds `%q` for strings.
3. A comprehension variable named like its enclosing function, or bound
   later in the comprehension, fails with "used before definition".
   1 AVM file and 1 Conftest example. Possibly fixed by 0.13.0
   ("schedule comprehensions in rule outputs").
4. An `import` after rules is a parse error. 1 Trivy file.
5. v0 rules with several bodies (`p[x] { … } { … }`) are rejected as
   `else`. 119 of Regula's 700 files.

regorus 0.13.0 (2026-10-14) passes the two-week rule on 2026-10-28. The
next step is to upgrade, rerun the harness, and report 1, 4 and 5
upstream.

**Not runnable unchanged** (input shape, not engine): Scalr's samples read
`input.tfplan`, Trivy checks read Trivy's adapted `cloud` state, and Regula
reads its own resource view. KICS and Trivy are roadmap items.

**Cost.** Corpus scan with the 26 AVM entries: 5.5 s wall (8 threads)
against 0.12 s without policies, 74,100 evaluations. About 70% of it is
regorus evaluating AVM's `utils.resource` comprehensions. Input conversion
and engine clone/drop take about 5% each. AVM declares no resource types,
so every entry runs on every resource. `custom.oxtf.resource_types`
removes that, and the budget is F5's gate.

**Not yet carried over.** Python `tfscan.scan` still takes one
`policy_entry` and no `rego_v0` (F5). Plan JSON's `configuration` section
is not projected, so a policy that reads `input.configuration` (some AVM
helpers do) sees none. Module resources sit flat in
`planned_values.root_module`, not under `child_modules`.

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

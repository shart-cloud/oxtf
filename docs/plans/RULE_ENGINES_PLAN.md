# Plan: Checkov and Rego (regorus) rule engines for oxtf

Oct 14, 2026 · follows [`SPIKE_REPORT.md`](../../SPIKE_REPORT.md) (recommendation: go)

## Checkov support implemented (2026-10-15)

`scripts/import_checkov.py` and `tfscan.checkov` import the installed **Checkov
3.2.328** Terraform catalog. The version is deliberately pinned to the existing
parity pilot. A different version is rejected; the older 3.3.29 research counts
below are not the inventory used by this implementation.

The exported pack contains **691 native rules**: 508 resource value checks and
184 graph policy files, with one shared ID merged into a single rule. All 910
resource checks and 186 graph policy files are inventoried. The remaining
**404 entries** (including two graph files) have an explicit unsupported reason. In particular, inheriting a value-check base class does not qualify a
check when it overrides the predicate. Translation must account for the actual
implementation, not just its inspected-key metadata.

The importer writes `rules.json`, `manifest.json`, and `LICENSE.checkov` to a new
directory. The manifest records IDs, source paths and hashes, translation status,
missing severity defaults, and the generated rules' checksum. It performs no
downloads. Unsupported graph entries also contain a `blockers` list with every
rejected capability or shape, its `code`, `reason`, and JSON Pointer `path` into
the policy definition. The original `reason` remains the first blocker for
compatibility. Validation visits sibling branches and checks independent
constraints within each leaf, including regex inside JSONPath predicates.
Generated third-party packs live outside tracked source; the local
output directory below is gitignored. Checkov is required to export the pack,
but neither Python nor Checkov is needed by the Rust CLI to execute it.

```sh
# Use the interpreter in an environment containing checkov==3.2.328.
CHECKOV_PYTHON=/path/to/checkov/venv/bin/python
"$CHECKOV_PYTHON" scripts/import_checkov.py \
  --output bench/results/out/checkov-3.2.328
cargo build --release -p tf_cli
target/release/oxtf rules --rule-file bench/results/out/checkov-3.2.328/rules.json
target/release/oxtf scan path/to/terraform --recursive --format json \
  --rule-file bench/results/out/checkov-3.2.328/rules.json

# Select one imported ID through the shared catalog.
target/release/oxtf scan path/to/terraform --rule CKV_AWS_16 \
  --rule-file bench/results/out/checkov-3.2.328/rules.json
```

Portable packs also work through the Python API:

```python
import tfscan
from tfscan import checkov

rules = checkov.load_rules("bench/results/out/checkov-3.2.328")
result = tfscan.scan("path/to/terraform", recursive=True, builtin=False, rules=rules)
```

`load_rules` verifies the pack checksum before compilation. CLI `--rule-file`
loads the IR directly, as it does for other rule files. IR version 2 adds resource
predicates; version 3 adds `checkov_graph` as a complete clause condition. Versions
1 and 2 remain readable. Re-export old packs to include relationship checks.
Original Checkov IDs are retained, so native seed rules and imported checks can
coexist even where their scope overlaps. Missing impact levels default to medium;
this does not change finding certainty.

Value predicates use configured values in Checkov's dict-of-lists shape, preserve
the upstream missing/null policy, and run through oxtf's abstract-value lattice.
Provider defaults are not substituted into imported predicates.

### Graph policies

Graph policies run once per analysed root over a shared resource dependency graph,
including data sources and local child modules. Source edges come from evaluated
traversals (including locals, outputs, transformed values, nested blocks and
`depends_on`), independently of the bounded human-readable provenance chain.
Equal literal strings do not create edges. `for_each` keys are preserved;
unresolved indices and conditional targets retain uncertainty. Source `count > 1`
currently uses the existing representative-instance model, so an indexed edge to
that representative is unknown. Plan instances retain their explicit keys.

The importer supports connection `exists`, `not_exists`, and `one_exists`, nested
`and`/`or`/`not`, and resource-type `within`/`not_within` filters. Connections work
in either direction. Attribute conditions can constrain connected endpoints;
filters restrict reported resources. `one_exists` follows the pinned Checkov
solver's any-passing-connection behavior, not an exact cardinality of one.
Dotted paths and `*` elements support existence, equality (including case-insensitive
equality), membership, containment, prefixes, numeric ordering, empty values and
boolean predicates. Negative containment checks every wildcard match.

The first coverage extension adds `number_of_words_not_equals`,
`length_greater_than`, `length_less_than_or_equal`, and `subset`. It enables
`CKV2_AWS_49`, `CKV2_AZURE_27`, `CKV2_AZURE_28`, `CKV2_AZURE_35`,
`CKV2_AZURE_36`, `CKV2_AZURE_39`, `CKV2_AZURE_41`, and `CKV2_OCI_3`.
Size thresholds are normalized using Checkov's Python integer conversion during
export and stored as signed 64-bit integers in native IR. Subset operands must be
lists of scalars. Evaluation preserves the pinned solver's behavior: word counts
use Python whitespace rules, nonstrings satisfy word-count inequality, strings
are measured in Unicode code points, objects have length one, and object subsets
compare keys. Unknown elements retain uncertainty when membership needs them;
known collection lengths and object keys do not depend on unknown child values.

The second extension adds attribute `within` filters to connection policies,
enabling `CKV2_AWS_23`, `CKV2_AWS_27`, and `CKV2_AWS_30`. Filters restrict results
after relationship evaluation in both `and` and `or` groups; they do not remove
connected endpoints before joins. The pinned filter solver ignores its
`resource_types` metadata. A string operand uses substring membership, while a
list operand uses Python equality; missing/null and other falsy values are
excluded. Unknown eligibility preserves uncertainty and source evidence when a
policy would otherwise fail. This extension admits literal top-level configured
attributes and string or scalar-list operands. Nested filter paths, other
attribute-filter operators, and attribute filters outside connection groups
remain explicit unsupported forms.

The third extension adds literal-field JSONPath `exists`, `not_exists`, and
`equals`, enabling `CKV2_GCP_27`, `CKV2_GCP_28`, `CKV2_GCP_32`, `CKV2_GCP_35`,
and `CKV2_GCP_36`. Paths compile to field segments at export time, with the
pinned parser validating the admitted grammar. The native evaluator preserves
Checkov's object/block projection, singleton-list normalization, and flattened-key
fallback. Literal JSONPath has at most one match and does not itself search lists
or decode JSON strings. Missing/null values, unknown descendants, alternative
values, and dynamic block cardinality retain their existing certainty semantics
and source evidence. If a dotted map key collides with a nested field, the native
map no longer has the source insertion order used by Checkov; evaluation retains
both possible values and produces a conditional result when they disagree.
The subsequent extension below adds array wildcards and filters; indices and
recursive descent remain explicit unsupported forms.

The fourth extension adds `[*]`, filters with string `==`/`!=` comparisons,
compound filter conjunctions, and JSONPath `not_equals`/`not_contains`. It enables
`CKV2_AWS_40`, `CKV2_AWS_68`, `CKV2_AWS_72`, and `CKV2_GCP_13`–`CKV2_GCP_17`.
The pinned parser's AST compiles into native field, array, and filter operations;
query strings are not interpreted at scan time. A filter accepts a single object
or a list, and missing filter fields do not satisfy inequality. Final predicates
must hold for every selected match; no matches use the operator's missing-value
result. Unknown filter eligibility and matched values retain uncertainty, while
known excluded candidates and decisive failures keep their definite outcomes.
Filtered queries traverse symbolic `jsonencode` values and literal JSON strings
as structured data, matching the Terraform renderer's policy representation.
Containment follows Python's shallow object membership behavior; scalar operands
that raise upstream remain indeterminate. Existing ordinary attribute wildcards
also recognize Checkov's index-free paths for singleton blocks. Regex, numeric
filter coercion, filter disjunction, slices, and other JSONPath constructs remain
explicit unsupported forms.

This implements the R4 graph execution path directly in native IR v3 instead of
the originally proposed generated Rego. It reuses the evaluator's abstract-value
lattice and deciding evidence, including conditional findings for unconstrained
inputs. Both CLI and Python use the same graph hook and return ordinary findings,
JSON/SARIF, and Arrow output. No Python or Checkov runtime is used during native
execution.

For example, `--rule CKV2_AWS_11` checks VPC flow-log connections,
`--rule CKV2_AWS_6` checks connected S3 public-access blocks, and
`--rule CKV2_GIT_1` checks repository branch protection, using the same
`--rule-file` option shown above.

Plan edges are retained from configuration expressions even when the planned
values are known. Module inputs and outputs are followed; source with matching module/resource instances and root input values can supply
references such as locals that plan JSON omits. If a relationship policy needs
unavailable configuration/source dependencies, the scan records a rule error
instead of claiming that a connection is absent. Attribute-only policies can
still evaluate those plan values.

### Original Python resource checks

Custom resource checks can run through the existing Python callback dispatcher
when Checkov 3.2.328 is installed in the Python environment:

```python
rules = checkov.custom_rules(["CKV_AWS_134", "CKV_AWS_24"])
result = tfscan.scan("path/to/terraform", builtin=False, rules=rules)
for error in result.rule_errors:
    print(error)
```

Each invocation copies the upstream check and calls `scan_entity_conf` on the
projected resource. Unknown inputs are omitted and recorded in `hidden`.
Failures involving projected inputs are conditional or indeterminate; a passed
result with hidden inputs, an upstream UNKNOWN/SKIPPED outcome, or an exception
becomes a rule error. Unresolved checks therefore cannot appear as proven passes.
This adapter is conservative about unrelated unknown fields. It retains deciding
value evidence when the check supplies evaluated keys and otherwise points at the
resource. Ordinary Python callbacks still propagate exceptions by default;
`record_errors=True` enables the adapter's continue-and-record behavior.

### Validation and limits

`bench/checkov/compare.py` generates real HCL inputs and compares the native pack
with the pinned resource implementations (and legacy v2 attribute-only solvers).
`bench/checkov/graph_compare.py` separately exercises every translated v3 graph
policy using Checkov's HCL vertex projection and graph solvers. It retains generated
inputs, commands, executable/pack hashes, raw output, and per-case results. It
exits nonzero for disagreements, reference exceptions, or execution errors.

```sh
"$CHECKOV_PYTHON" bench/checkov/compare.py \
  --pack bench/results/out/checkov-3.2.328 \
  --native target/release/oxtf \
  --output bench/results/out/checkov-conformance
"$CHECKOV_PYTHON" bench/checkov/graph_compare.py \
  --native target/release/oxtf \
  --output bench/results/out/checkov-graph-conformance
cargo test --workspace
# With tfscan's extension built and Checkov installed in the test environment:
python -m pytest -q crates/tfscan_py/tests
```

The earlier v2 recorded run generated 7,474 cases: 7,462 comparable pass/fail outcomes with
zero disagreements, plus 12 explicit upstream UNKNOWN outcomes with no native
finding. These are generated predicate cases, not full-runner equivalence or
security precision/recall. Regression tests separately exercise unknown values,
provenance, nested blocks, dynamic cardinality, JSON-encoded unknowns, pack
validation, CLI listing/selection, and custom callbacks.

The expanded graph conformance run covers **184 policy files and 16,880 resource cases**,
with zero disagreements and zero reference exceptions. Generated operands stay
within the input types accepted by the upstream solvers. This tests policy trees,
not full Terraform-runner equivalence. Python integration tests additionally
compare actual Checkov runner findings for VPC flow logs, ALB WAF associations,
GitHub branch protection, all eight policies in the first coverage extension,
all three policies in the attribute-filter extension, and all five policies in
the basic JSONPath extension, and all eight policies in the filtered JSONPath
extension (27 full-runner fixtures in total).
Operator-level tests compare 299 identical evaluated operands with the pinned
solvers, including missing/null values, empty collections, Unicode strings,
numeric threshold coercions, and Python boolean/number equality. These operand
tests do not assert literal-source parser equivalence. An additional 90 filter
cases compare string/list membership, Python truthiness, and result filtering
in `and` and `or` groups. Another 365 JSONPath cases compare actual HCL vertex
projection and the pinned solvers across missing/null/empty values, nested
objects, blocks, and lists. Separate regressions cover ambiguous flattened-key
collisions and abstract values. Rust/Python regressions cover cross-module edges,
conditional targets, data sources, plan configuration, and provenance. Reproduction
commands and hashes for the original graph implementation are recorded in
`bench/results/checkov-graph-support.json`; the first extension's validation and
blocker inventory are recorded in `bench/results/checkov-graph-operators.json`.
The attribute-filter extension is recorded in `bench/results/checkov-graph-filters.json`.
The basic JSONPath extension is recorded in `bench/results/checkov-graph-jsonpath.json`.
The filtered JSONPath extension adds 2,016 comparable solver cases for wildcard
aggregation, string filters, conjunctions, missing/null values, and containment.
Separate Rust tests cover invalid operands, unknown match eligibility, symbolic
JSON, dynamic cardinality, and deciding evidence. Its validation, regression
rechecks, and remaining blockers are recorded in
`bench/results/checkov-graph-jsonpath-filters.json`.

The earlier [recorded release benchmark](../../bench/results/checkov-support.json) scans
504 roots, 2,176 files, and 5,224 resources from the existing local corpus. Median
wall time over five warm runs (one warmup, process startup and pack parsing
included, quiet output) was:

| Catalog | One thread | Eight threads |
| --- | ---: | ---: |
| Five seed rules | 273 ms | 84 ms |
| Seeds plus 545 imported rules | 286 ms | 103 ms |

The expanded catalog produced 634 findings (630 definite, four conditional), with
zero diagnostics or rule errors. These timings exclude full JSON serialization
and are not a speed comparison with the Checkov runner. The record includes
individual timings, commands, corpus-lock and executable hashes, and unsupported
reason counts.

Runner context, suppression comments, external module downloading, and
Checkov's other IaC frameworks are not implemented. The two unsupported graph
files require regex (plus numeric filter comparisons for `CKV2_OCI_4`);
their complete blocker lists remain in the manifest.
The callback adapter supplies a resource configuration, not a Checkov runner;
checks requiring graph/runner state may fail and are not certified compatible.
The resource model omits some Terraform meta-arguments, and the native importer
excludes predicates depending on them. Evaluation resolves Terraform expressions
and normalizes numbers before policy execution, so literal-source behavior is
not guaranteed to match the Checkov parser. Unsupported operators and Python
overrides remain visible in the manifest. This completes the portable value-check
slice of R3, adds native relationship-policy execution for R4, and provides an
explicit resource-check adapter for R5. It does not claim all Checkov operators or
full-corpus runner parity.

### Remaining graph coverage

The first four extensions are complete at 184/186 policy files. Remaining milestones
are ordered by shared capabilities, with cumulative translation targets against
the pinned catalog. A policy is admitted only after every blocker is addressed
and differential checks pass.

| Next capability | Policies | Target |
| --- | --- | ---: |
| Regex predicates, regex filters and numeric filter comparisons | `CKV2_AWS_69`, `CKV2_OCI_4` | 186/186 |

Each milestone requires passing/failing fixtures for every admitted policy,
comparison with the pinned solvers and runner, tests for missing/null/empty and
unknown values, deciding source evidence, and regression coverage of existing
policies. JSONPath should compile into native operations over abstract values;
match aggregation and uncertainty must follow the pinned semantics. The 402
unsupported resource checks remain a separate workstream: nine string-membership
predicates, four meta-argument checks, one raw-expression comparison, and 388
custom or overridden Python predicates requiring behavioral inspection.

## Execution baseline

The first milestone prioritizes trustworthy native Rego and a small Checkov pilot.
The baseline, initial native-versus-Checkov comparison harness, uncertainty
contract experiment, and all five native Rego seed rules are implemented.
Next is stabilizing and documenting the native input/result contract before
external policy loading; the general input schema is not yet frozen.

`crates/tf_scan/tests/native_baseline.rs` checks native output against
[`fixtures/baseline/native.json`](../../fixtures/baseline/native.json):

- 34 existing source cases and 34 existing plan cases, with explicit source mapping for plans.
- Four source regressions for S3 sibling instances, computed IDs, transformed names, and local aliases.
- Two synthetic plan regressions for sibling instances and transformed names. These test the plan adapter; they are not Terraform-generated plans.
- 57 findings: 53 Definite and four Conditional, with no diagnostics in this baseline.

The snapshot includes rule ID, full resource-instance address, root, module, impact level,
certainty, message, primary location, ordered provenance, diagnostics, and deterministic
scan counts. Passing cases retain empty finding lists. Finding and diagnostic order is
normalized without deduplication; provenance order is retained. Only elapsed time and
absolute checkout-directory prefixes are removed. The artifact is a native regression
baseline, not a claim of correctness or foreign-engine parity.

Verify without changing the snapshot:

```sh
cargo test -p tf_scan --test native_baseline
```

After reviewing an intentional semantic or fixture change, regenerate and inspect the diff:

```sh
OXTF_UPDATE_BASELINE=1 cargo test -p tf_scan --test native_baseline
git diff -- fixtures/baseline/native.json
```

Normal test runs never update the snapshot. Inventory assertions require deliberate
review when fixtures are added or removed. The S3 regression cases also assert their
expected resource addresses independently of the snapshot, including during regeneration.
The existing rule-selection tests continue to check unknown-ID errors and intentional
empty selections; those are execution contracts rather than security findings.

## Initial comparison harness

The standard-library Python runner `bench/parity/compare.py` compares
`aws-rds-unencrypted` with `CKV_AWS_16`. Its manifest,
[`bench/parity/rds.json`](../../bench/parity/rds.json), pins Checkov **3.2.328**,
the installed version used for this pilot. This differs from the earlier 3.3.29
research inventory; the pilot makes no claim about the newer version's behavior
or catalog size. Checkov is installed through pipx on the development machine;
the harness does not install or upgrade dependencies.

```sh
cargo build -p tf_cli
python3 -m unittest discover -s bench/parity -p 'test_*.py'
python3 bench/parity/compare.py --output bench/results/out/parity-rds-new-run
```

The output directory must be new. Override `--native`, `--checkov`, or `--manifest`
to select explicit executables or another pilot manifest. Each subprocess has a
60-second default timeout, configurable with `--timeout`. The harness exits 2 for
execution/normalization failures and 0 for a completed comparison, including
semantic disagreements, skips, and unsupported rows. It is an investigation tool,
not a CI parity threshold.

Each manifest root has an explicit inventory of resource-instance addresses.
Rows are keyed by root, mapped check ID, and the full instance address. Module
prefixes and instance keys are retained; duplicate or out-of-inventory records
are flagged rather than silently merged. This first pilot scans source roots;
plan parity and general corpus inventory discovery remain future work.

The report distinguishes `both_reported`, `native_only`, `checkov_only`, and
`neither_reported`. Native certainty remains `definite` or `conditional`;
`no_finding` does not imply that native evaluation proved a pass. Checkov
suppression is `skipped`; unknown or missing check records are `unsupported`.
Errors, parsing diagnostics, malformed reports, version mismatches, and timeouts
cannot become clean results. Reports retain native location/provenance and
Checkov result evidence for manual comparison.

Checkov runs without `--quiet`, because quiet JSON omits passed/skipped records.
The pinned version's summary-only zero-result output is recognized as missing
coverage. Rule-pack downloading and external-module downloads are disabled.
Raw stdout, stderr, commands, return codes, and elapsed time are saved per scan
under the gitignored output directory; `report.json` contains normalized rows,
summary counts, input hashes, and the native executable hash. The harness measures
finding agreement, not precision or recall against a correctness oracle.

### RDS pilot result

The [recorded pilot](../../bench/results/rule-parity-rds.json) covers seven roots
and eight resource/check rows using Checkov 3.2.328:

| Case | Native | Checkov | Comparison |
| --- | --- | --- | --- |
| Explicit false | Definite | Failed | Both reported |
| Absent encryption field | Definite | Failed | Both reported |
| Variable default false | Definite | Failed | Both reported |
| Explicit encryption true | No finding | Passed | Neither reported |
| tfvars overrides false default | No finding | Passed | Neither reported |
| Unconstrained variable | Conditional | No check record | Unsupported for comparison |
| Read replica | No finding | Failed | Checkov only |
| Suppressed Checkov check | Definite | Skipped | Skipped |

There were no execution errors. Six rows have comparable two-valued Checkov
outcomes: three shared findings, two shared non-findings, and one Checkov-only
finding. The missing-record and suppressed rows are excluded from agreement counts.

The read-replica disagreement is explained by the implementations: the native
rule skips a resource with a non-null `replicate_source_db`; the installed Checkov
`RDSEncryption` value check inspects `storage_encrypted` without that exception.
This is a rule-scope difference, not evidence that either tool is universally
correct. The unconstrained-variable case demonstrates why missing foreign results
must not be treated as passes and is an input to the next uncertainty experiment.
The suppressed case demonstrates a deliberate compatibility gap: native rules do
not currently implement Checkov suppression comments.

## Uncertainty experiment and contract direction

An isolated Rust executable at `bench/uncertainty` runs actual Rego on regorus
**0.12.0**, with default features disabled and only `std` and `arc` enabled.
Its own Cargo workspace and lockfile keep the dependency out of the production
scanner. The downloaded release changelog dates 0.12.0 to 2026-09-01, satisfying
the original dependency-age rule on 2026-10-14. No production evaluator, finding
format, or backend interface was changed for this experiment.

Reproduce:

```sh
cargo test --locked --manifest-path bench/uncertainty/Cargo.toml
cargo run --locked --quiet --manifest-path bench/uncertainty/Cargo.toml > bench/results/uncertainty-contract.json
```

The [machine-readable results](../../bench/results/uncertainty-contract.json)
compare three policies on 17 deliberately adversarial cases. Native
`tf_eval::truth` operations are the compatibility reference. Production
`RuleContext::report` applies resource-existence gating for every strategy.

| Strategy | Truth matches | Finding-certainty matches |
| --- | --- | --- |
| Null projection, then taint at the display location | 9 / 17 | 9 / 17 |
| Null projection, then conservative taint/Unknown checks over declared evidence | 12 / 17 | 12 / 17 |
| Tagged values and native four-valued composition in Rego | 17 / 17 | 17 / 17 |

These are test-case counts, not estimated accuracy rates. The matrix covers
known booleans/null, Unknown, Tainted, finite flattened Known alternatives,
AND/OR, taint unrelated to the display location, and False/Unknown/Tainted
resource existence. It does not cover arbitrary Rego, nested abstract containers,
string coercions, all Terraform functions, or correlation between alternatives.
The evidence downgrade is one explicit conservative heuristic, not an exhaustive
search over possible postprocessors.

Concrete failures:

- Unknown projected as null becomes an apparently definite failure under
  `value != true`; native semantics suppress that finding.
- Taint outside the displayed location is missed; unrelated display taint can
  incorrectly downgrade a definite finding.
- For `value == true`, projecting Tainted to null produces no result. A
  postprocessor cannot downgrade or recover a result that does not exist.
- Downgrading based on every referenced value loses expression structure:
  a definite true branch of OR stays definite despite another tainted branch,
  and Tainted OR Unknown differs from Tainted AND Unknown.

A separate two-input fixture uses `storage_encrypted = var.a == var.b` with two
unconstrained booleans. Real Rego produces no violation for the two uniform
substitutions `(false, false)` and `(true, true)`, but does for the two mixed
assignments. Native evaluation reports Conditional. This rejects two uniform
passes as a general repair; it does not reject exhaustive enumeration for bounded
finite domains or establish that any proposed universal insecure witness exists.

Four real-source evidence probes also pass through production finding construction:

- An S3 bucket is the finding target while the deciding tainted protection flag
  belongs to its public-access-block resource. The shared resource-reference
  matcher establishes the relation. Certainty remains Conditional, the primary
  location remains the bucket header, and flag provenance survives.
- An extracted SSH CIDR retains the complete tfvars → variable → local →
  attribute chain. This is a scalar provenance probe, not a Rego port of the SSH rule.
- An absent RDS encryption field and an explicitly null field retain distinct
  configured states while both resolve to the current false defaults overlay,
  including the Default provenance step.

For each probe, the Rego-returned opaque evidence handle resolves to the original
owned Value; complete rendered finding JSON matches a native predicate over that
Value. A fabricated handle is rejected. A valid handle proves a location can be
resolved, not that a policy's verdict is correct or its evidence is complete.

### Constraints for the first native Rego rule

1. Keep configured presence, configured value, and effective/defaulted value
   distinct. Preserve Known null, Unknown, Tainted, and OneOf explicitly; a bare
   null is not an uncertainty representation.
2. Preserve four-valued predicate results during evaluation, including False
   and Unknown outcomes. They are distinct even when neither emits a finding.
   Do not infer certainty from the final display path.
3. Separate the finding target and optional display path from deciding evidence.
   Resolve scoped evidence handles against the original analysis to recover
   provenance. Handles identify a value read, including its full resource instance,
   typed path segments, and configured/effective read mode. Their wire format
   remains a design task; the experiment's numeric truth ranks are not a public format.
4. Compose predicates through reviewed uncertainty-aware helpers and retain a
   deciding witness. A flat list of dependencies is insufficient to reconstruct
   AND/OR, negation, quantifiers, or missing-result behavior.
5. Keep resource-existence gating and final finding construction shared with
   native rules. Use semantic reference matching for joins; a dependency or
   provenance path is not proof of identity. Negative joins additionally need
   explicit knowledge that the candidate set is complete.
6. Treat invalid results, missing/invalid handles, unsupported expressions, and
   execution errors as explicit outcomes. Do not turn these into passes or
   silently label them Definite. Policy absence alone cannot establish that a
   resource/check pair was evaluated.

The evidence supports a restricted native-Rego contract with reviewed helpers.
It does **not** support automatically assigning native-equivalent certainty to
arbitrary unchanged KICS, Checkov, or user policies. Foreign compatibility results
must remain distinguishable until their uncertainty behavior is validated.
The experiment inherits the native lattice's approximations; it is a compatibility
check, not a proof of logical soundness for all unconstrained values.

> **Superseded 2026-10-14.** The slices below re-implemented the truth lattice inside
> Rego. `ARCHITECTURE_PLAN.md` Phase 2 replaced them: Rego never sees an abstract value,
> the RDS and GCS rules run as single-subject leaf policies behind `--rego-native`, and
> foreign policies run unchanged over a Known-only projection behind `--policy`. The
> `--rego-rds` flag and the SSH, IAM and S3 ports are gone.

### First native Rego slice (implemented)

`oxtf scan PATH --rego-rds` (also supported with `--plan`) replaces only
`aws-rds-unencrypted` with the bundled policy in `crates/tf_rego/src/rds.rego`.
Rule selection, rule ID, impact, message construction, existence gating, source
mapping, and provenance remain shared with the native implementation. Native
rules remain the default. This flag does not load arbitrary external policies.

`tf_rego` pins regorus 0.12.0 with only `std` and `arc`; the policy is prepared before
scanning, then the engine is cloned for each resource evaluation. Parallel-root
parity is tested. Full-pack performance and release binary-size cost remain open.
The callback-based scan adapter checks accumulated errors before returning the
result; CLI failures exit 2 without printing a partial successful scan.

The private RDS contract deliberately contains only what this rule needs:

- `target`: full resource-instance address and resource type, separate from evidence.
- `replica.kind`: missing, null, or set, preserving the native replica exception.
- `configured` and `effective`: separate tagged views of `storage_encrypted`;
  effective values use the existing provider-default overlay and its provenance.
- Each value is missing, known, unknown, tainted, or a finite one_of. Known values
  retain their type (including null) and Terraform boolean view (`true`, `false`,
  or null for non-booleans); this is not a general JSON value projection.
- one_of carries its tainted flag and ordered alternatives. Each alternative's
  handle resolves to its original value with parent provenance joined.
- Result: rank 0/1/2/3 for False/Unknown/Tainted/True plus a nullable evidence
  handle. These numeric ranks remain private. Invalid ranks, malformed/undefined
  results, missing required evidence, invalid handles, and evaluator errors fail
  the scan. Handles are scoped to one resource evaluation.

Rego implements the predicate and finite-choice truth/witness selection. Rust
resolves the evidence and calls the shared RDS reporting helper. Coverage includes
full source/plan output parity across the fixture suite, concurrent roots, a
172-case scalar/finite-choice matrix, error propagation and scan isolation, and a
module/local/tfvars chain with unknown, absent, and tainted resource existence.
The 74-scan native golden baseline remains unchanged.

### Second native Rego slice: GCP uniform access (implemented)

`oxtf scan PATH --rego-native` (also supported with `--plan`) runs both
`aws-rds-unencrypted` and `gcp-storage-uniform-access` through bundled Rego.
The other three seed rules remain native. `--rego-rds` retains its RDS-only
behavior; combining both flags selects the two-rule set without duplicating rules.
`--rule` continues to select by existing rule IDs.

The two policies import the same `boolean.rego` predicate, including finite-choice
truth and deciding-witness selection. The GCP policy uses the same tagged boolean
contract for configured/effective `uniform_bucket_level_access`, without a replica
exception. Its metadata and reporting remain shared with the native GCP rule.
The adapter now selects the attribute, policy entry point, and reporter for each
supported boolean rule; it does not introduce a universal backend abstraction.
Each engine is prepared once before scanning and cloned for resource evaluation.

Validation: complete output parity on the source/plan fixture suite, concurrent
roots, both CLI flags and rule selection, the 172-case lattice matrix for each
policy, and GCP-specific null/default, string-boolean, computed/tainted/OneOf,
resource-existence, and module/local/tfvars provenance cases. The 74-scan native
baseline still passes unchanged. Entry-point and runtime errors still invalidate
the scan before output is published.

### Third native Rego slice: SSH ingress (implemented)

`--rego-native` now also replaces `aws-sg-open-ssh` for all three native resource
shapes: inline `aws_security_group` ingress, `aws_security_group_rule` ingress,
and `aws_vpc_security_group_ingress_rule`. RDS-only mode is unchanged.

The private SSH projection adds ordered list elements and selected object fields.
Rust extracts values with the same parent-provenance joins as native traversal,
registers scoped evidence handles, and supplies Terraform string/numeric views.
Rego evaluates CIDR membership, protocol and port predicates, legacy ingress type,
AND/OR, list existence, and finite choices. It preserves the native witness rules:
AND/OR keep the left witness on ties, list existence keeps the first strongest
match (or FALSE without evidence), and mixed finite choices keep the last
strongest alternative. Unknown and Tainted remain distinct at every level.

Projection shapes follow the finite SSH structure: ingress collection, inline rule,
CIDR collection, and scalar. This avoids recursive Rego functions without placing
predicate evaluation in Rust. Comprehensions are bound in rule bodies rather than
nested inside head calls, avoiding a scheduling error in pinned regorus 0.12.0.

Validation includes source/plan parity across the existing fixture suite, all three
resource forms, dynamic ingress through module/local/tfvars bindings, conditional
ports, nested finite choices, and approximately 4,000 direct truth/witness cases
against `tf_eval` composition. Those cases include empty and null containers,
non-object rules, computed/tainted children, numeric strings (including infinities),
and witness ties. The existing native golden baseline remains unchanged.

### Fourth and fifth slices: IAM and S3 (implemented)

`--rego-native` now runs all five seed rules through bundled Rego. Existing IDs,
impact levels, messages, source/plan mapping, and provenance are preserved.
`--rego-rds` still selects only the original RDS replacement.

IAM supports all four native IAM resource types. Rust unwraps structured
`jsonencode` values or parses raw JSON, retaining original provenance; Rego walks
Statement collections, tests Allow/Action/Resource, and combines uncertainty and
witnesses. Scalar/list fields, finite alternatives, and unknown/tainted documents
retain native behavior. Invalid JSON remains a native-compatible non-finding;
it is distinct from a Rego evaluation/contract error, which fails the scan.

S3 is evaluated per bucket within its module instance. The semantic identity
matcher projects Yes/Maybe/No edges for candidate PABs, using concrete names or
computed references and instance keys; dependency provenance is not identity.
Rego selects definite matches, suppresses an unprotected finding when only a
possible match exists, evaluates all four defaulted flags, accounts for tainted
PAB existence, and chooses the least permissive definitely matching PAB. Order
and witness ties match native behavior. Native handling of Unknown existence is
preserved rather than reinterpreted during this port.

S3 adds two narrowly validated structural evidence reasons: `missing_protection`
(TRUE with no value witness) and `pab_existence` (Tainted with no value witness).
Only the S3 entry point accepts them, with the corresponding rank and no handle.
Other positive/unknown decisions still require a valid scoped value handle.
Reporting uses the original bucket as target and the PAB flag as deciding evidence.

SSH, IAM, and S3 share four-valued composition in `lattice.rego`. Validation covers
all existing source/plan fixtures, the unchanged 74-scan native baseline, IAM
raw/structured documents and nested uncertainty, S3 candidate ordering and witness
selection, structural-reason rejection, sibling/computed/transformed references,
module isolation, multiple matching PABs, conditional PAB existence, and IAM
module/local/tfvars provenance. All five rule IDs also pass explicit selection and
parallel-root parity checks.

The five-rule parity milestone is complete. Remaining R1 work: stabilize and
publish the input/result JSON Schema, external policy loading and Python policy
integration, and release-size/performance measurements. A universal backend
interface remains deferred until justified by another real backend. Checkov/KICS
compatibility remains separate from this native-policy milestone.

## Summary

The spike's biggest open risk is rule coverage: oxtf has 5 rules, Checkov ships 1,144 Terraform checks, and KICS 763 Terraform queries. This plan closes that gap by running other projects' rules on oxtf's engine instead of rewriting them by hand, while keeping what makes oxtf different: evaluated values, provenance chains, and Definite vs Conditional severity.

Two rule ecosystems, one shared idea:

- **Rego, through [regorus](https://github.com/microsoft/regorus)** (Microsoft's Rust Rego interpreter, MIT/Apache-2.0, no Go or OPA binary). It gives oxtf user-written policies in a language many teams already use, the KICS query catalog, and cross-resource joins for free.
- **Checkov's rule engine**, in three tiers: its declarative value checks translated to oxtf's rule IR (no Python at scan time), its graph checks compiled to Rego, and its custom Python checks run through the `tfscan` callback path.

The shared idea is a **projection**: render the evaluated `tf_semantic::Analysis` into the input shape each rule family expects, run the foreign rule unchanged, then map each result's resource address and attribute path back into oxtf's model to recover the source span, provenance chain and severity. Foreign rules get oxtf's explanations without knowing it exists.

Suggested timebox: about eight agent-days across the workstreams below. As in the spike, cut scope rather than extend it, and log every cut.

## What we already know (measured 2026-10-14)

Evidence for every line is in the [appendix](#appendix-evidence-gathered-for-this-plan).

| Fact | Evidence |
| --- | --- |
| regorus runs an **unmodified KICS query** against an oxtf-shaped document | `security_group_with_unrestricted_access_to_ssh/query.rego` plus KICS's `common.rego` and `terraform.rego` flagged `aws_security_group.web` (SSH open to 0.0.0.0/0) and not `ok`; 4.2 ms for the first evaluation |
| Two adaptations were needed for KICS | Rego v0 mode (`Engine::set_rego_v0(true)`; 0 of 763 KICS queries import `rego.v1`), and raising regorus's line-length limit: KICS's `common.rego` has lines up to 5,459 columns, regorus defaults to 1,024 (`PolicyLengthConfig::max_col`; the parse error points at the wrong place) |
| KICS needs 2 deprecated builtins regorus doesn't register | `any`, `all` (12 call sites); every other standard builtin KICS calls (48 distinct, 5,268 call sites) is registered. regorus supports custom builtins |
| Trivy's checks need no missing builtins, but a different input | All 38 standard builtins used are registered (`net.*` turned out to be Trivy's own `lib/cloud/net.rego`). But all 366 cloud checks read Trivy's adapted state (`input.aws.ec2.securitygroups`), not Terraform; 361 use `rego.v1` |
| KICS reads Terraform almost as written | 763 Terraform queries over `input.document[i].resource.<type>.<name>` (1,183 uses) and `.module` (93); 761 import `data.generic.*` helper libraries |
| **All 568** declarative Checkov checks are introspectable | Of 927 resource-check IDs, 568 subclass `BaseResourceValueCheck`/`BaseResourceNegativeValueCheck`; for all 568, `get_inspected_key()` and expected/forbidden values load, e.g. `CKV_ALI_10`: `versioning/[0]/status` ∈ `["Enabled"]`. 359 have custom Python logic. Graph checks: 180 `CKV2_*` IDs in 196 JSON files |
| Licences permit reuse with attribution | Checkov 3.3.29: Apache-2.0; KICS: Apache-2.0; trivy-checks: MIT; regorus: MIT AND Apache-2.0 AND BSD-3-Clause |

## Goals and non-goals

**Goals**

- A `RuleBackend` abstraction so native rules, rule-IR rules, Rego policies and Checkov checks all produce the same `Finding` (address, severity, message, primary span, provenance) and run in the same parallel engine.
- **Native Rego:** users write Rego policies against a documented oxtf input schema; findings carry spans and provenance.
- **KICS compatibility:** run KICS's Terraform queries unchanged via a KICS-shaped projection, and measure them against KICS's own positive/negative test suite.
- **Checkov compatibility:** translate the 568 declarative checks to rule IR, compile graph checks to Rego, and run custom Python checks through `tfscan`.
- A **parity harness** that runs Checkov (and KICS) itself on the corpus and diffs findings per (check, resource), turning the spike's top risk into a number.
- Python: `tfscan` gains Rego policies and Checkov checks with the same Arrow outputs.

**Non-goals**

- Re-implementing OPA, or supporting OPA bundles, discovery, decision logs or the OPA server API.
- Trivy check compatibility beyond a measured feasibility note (it needs per-service adapters from Terraform to Trivy's cloud state, the very hand-written layer the spike's schema codegen avoids). See R7.
- Vendoring third-party rule packs into this repository. Rule packs are fetched at a pinned commit (or pointed to on disk) and keep their licences; the repo ships only adapters and generators.
- Non-Terraform frameworks (CloudFormation, Kubernetes manifests, Dockerfiles).
- Autofix or suppression-comment compatibility (`#checkov:skip`, `# kics-scan ignore`) beyond reading them, which is listed as a stretch item.

## Architecture

```
                         tf_semantic::Analysis  (evaluated values + provenance + taint)
                                      │
            ┌───────────────┬─────────┴──────────┬──────────────────────┐
            ▼               ▼                    ▼                      ▼
     native DynRule     rule IR (v2)      projection: oxtf      projection: KICS / Checkov conf
       (Rust)         (JSON, from Python,    native JSON            (foreign input shapes)
                       Checkov value          │                       │
                       checks)                ▼                       ▼
                                          regorus Engine          regorus / Python callback
                                              │                       │
                                              └──── result → (address, attribute path)
                                                            │
                                                     resolve in Analysis
                                                            ▼
                               Finding { span, provenance, Definite | Conditional }
```

Key design points, each to be confirmed by measurement in its workstream:

1. **Projections are generated, not hand-written.** Each is one function from `Analysis` to `serde_json::Value`, keyed by schema (block vs attribute, nesting mode) so block-syntax attributes and nested attributes render the way the foreign rules expect (KICS: a single block is an object, repeated blocks a list; Checkov: every value wrapped in a list).
2. **Results map back through paths.** KICS results carry `searchLine` paths like `["resource", "aws_security_group", "web", "ingress"]`; Checkov reports the resource and `evaluated_keys`. The resolver walks that path in the model for display location; native policies also return deciding evidence separately, since a display path alone cannot establish certainty or complete provenance.
3. **Four-valued semantics over a two-valued engine.** The uncertainty experiment above rejects display-path taint and two uniform evaluations as general repairs. Native policies need tagged values and uncertainty-aware predicate composition, with separate deciding evidence. Foreign-shaped projections may reproduce a tool's unresolved-expression conventions, but that does not establish native-equivalent certainty. Compatibility outcomes must remain explicit until validated.
4. **One compile, many evaluations.** Policies are parsed and compiled once per scan; each root module is an independent regorus evaluation, run in parallel with rayon, which needs per-thread `Engine` clones (open question 4).

## Workstreams

R1 and R3 can run in parallel first; R2 needs R1; R4 needs R1 and R3; R6 needs R2 and R3. R5 and R7 are stretch.

### R1. Backend abstraction and native Rego

- [x] Pin regorus 0.12.0 with `std` and `arc`, satisfying the two-week release-age requirement; smoke and parity tests pass. Release binary-size measurement remains pending.
- [ ] `RuleBackend` trait in `tf_linter` (or a new `tf_rules` crate): `prepare(&Rules) -> Compiled`, `run(&Compiled, &Analysis) -> Vec<RawResult>`, `resolve(RawResult) -> Finding`. Port the native and rule-IR rules onto it without changing their findings (the 34 fixtures must stay green).
- [ ] **oxtf native input schema** for Rego: resource-instance identity, configured presence, effective/defaulted values, explicit Known/Unknown/Tainted/OneOf states, and scoped evidence handles. Apply the uncertainty-experiment constraints above; freeze the first version only after the RDS vertical slice passes. Document it as JSON Schema before extending generated `.pyi`/docs.
- [ ] Result contract: preserve four-valued evaluation outcomes, distinguish target/display location from deciding evidence, and resolve evidence into the original model. Keep impact level separate from certainty. Define explicit unsupported/error outcomes; `{address, path, msg}` alone is insufficient.
- [ ] `oxtf scan --policy DIR` and `tfscan.scan(..., policies=[...])`.
- [x] Port seed rules 1–5 to Rego, including the S3 cross-resource rule. All five match native findings on the source/plan fixture suite, including severity and provenance.

**Exit:** five Rego policies match the native rules on all 34 fixtures, including severity and provenance; a Rego finding prints the full `.tfvars` chain.

### R2. KICS compatibility

- [ ] Fetch KICS at a pinned commit (`oxtf rules fetch kics@<sha>` or a path), never vendored. Load `assets/libraries/{common,terraform}.rego` + `common.json` and the Terraform queries in Rego v0 mode with the raised column limit.
- [ ] Register `any` and `all` as regorus custom builtins, matching OPA v0 semantics.
- [ ] KICS projection: one `document` per file (`id`, `file`, `resource`, `module`, `variable`, `data`, `provider`), single blocks as objects and repeated blocks as lists, unknowns as KICS-style `${...}` strings.
- [ ] Map KICS results (`searchKey`/`searchLine`, `resourceType`, `resourceName`) back to findings; take severity and title from each query's `metadata.json`.
- [ ] **Conformance run:** for each of the 763 queries, scan its `test/positive*.tf` and `test/negative*.tf` and compare with `positive_expected_result.json` (file + line). Report pass rate per query and the top failure causes.

**Exit:** the conformance pass rate is measured and every failure is categorized (projection gap, regorus gap, line-mapping gap, or KICS test issue); the 20 most common failure causes have a fix or a recorded cut.

### R3. Checkov value checks → rule IR

- [ ] Generator (Python, run offline against a pinned Checkov version): introspect every `BaseResourceValueCheck` / `BaseResourceNegativeValueCheck` (`supported_resources`, `get_inspected_key()`, expected or forbidden values, `missing_block_result`/default result, `ANY_VALUE`) and emit rule-IR JSON. The output is generated at fetch time, not committed, with Checkov's licence and check IDs preserved.
- [ ] Rule IR v2 additions needed for these (record each with the check count that needs it): Checkov path syntax (`a/[0]/b`), "attribute absent ⇒ pass/fail" per check, any-value, forbidden-value lists, case-insensitive string compares if needed.
- [ ] Use the defaults overlay where Checkov relies on provider defaults (e.g. absent `storage_encrypted`), and report where Checkov and the overlay disagree.

**Exit:** all 568 checks translate or are logged as untranslatable with a reason; the translated set runs with no Python at scan time.

### R4. Checkov graph checks → Rego

- [ ] Compile Checkov's graph-check JSON (`attribute`, `connection` and `filter` solvers combined with `and`/`or`) to Rego over the oxtf native schema (R1). Rego's joins replace Checkov's graph.
- [ ] Measure how many of the 180 graph checks compile, and why the rest don't.

**Exit:** compiled graph checks agree with Checkov on the corpus per (check, resource), measured in R6.

### R5. Checkov custom Python checks (stretch)

- [ ] In `tfscan` only: a Checkov `conf` adapter (values wrapped in lists, Checkov's key conventions) and a runner that calls a check's `scan_resource_conf` through the existing callback path, with Checkov installed in the Python environment.
- [ ] Measure cost per resource against the spike's ~15 µs callback overhead, and list checks whose logic depends on Checkov internals the adapter can't reproduce.

**Exit:** a measured pass rate and per-check cost for the 359 custom checks; these remain unavailable from the Rust CLI, by design.

### R6. Parity harness and benchmark

- [ ] Run Checkov 3.x (pinned) and KICS (pinned; build with the installed Go toolchain or use its release) on the corpus; normalize their findings to (check ID, resource address).
- [ ] Diff against oxtf's results for the same checks: agree, oxtf-only, incumbent-only. For each disagreement class, sample and classify (oxtf right thanks to evaluation, oxtf wrong, incumbent wrong, out of scope).
- [ ] Re-run the Q9 benchmark with all translated checks and KICS queries enabled: oxtf wall time and memory on the corpus.

**Exit:** a parity table per backend with precision and recall against each incumbent on the shared checks, a classified disagreement sample, and the benchmark with real rule counts.

### R7. Trivy checks feasibility (stretch)

- [ ] Measure the adapter surface: which Trivy cloud-state fields the 366 checks read (by service), and whether a projection can be generated from provider schemas plus a mapping table instead of hand-written adapters. Prototype one service (EC2 security groups) end to end.

**Exit:** a go/no-go note with the measured adapter size per service.

## Open questions

The report must answer each with evidence (a number, a test, or a short code sample).

1. **KICS conformance.** What share of the 763 KICS Terraform queries pass their own positive/negative tests on oxtf's projection, and what are the top failure causes?
2. **Checkov parity.** On the corpus, what are precision and recall of translated Checkov checks against Checkov itself, per tier (value, graph, custom)? Where they disagree, how often is oxtf right because it evaluated the value?
3. **Four-valued semantics on two-valued engines.** Is "Conditional if the result path touches a Tainted value" sound on the fixtures and the corpus, or does it miss cases where the verdict came from a Tainted value off the path? Does a second, pessimistic evaluation (Tainted replaced by an insecure witness) change results, and at what cost?
4. **regorus performance and concurrency.** Compile time for the full KICS set, per-module evaluation time, memory, and whether `Engine` can be cloned per rayon worker or must be rebuilt. Target: report the corpus scan time with all rules on, next to the spike's 0.5 s.
5. **Provenance through foreign rules.** For what share of KICS and Checkov findings can the resolver recover a span and a full provenance chain, versus falling back to the resource block?
6. **Rule IR v2 or Rego for everything?** With Rego available, is rule IR still worth extending (portability from Python, speed), or should Python expression rules compile to Rego? Compare evaluation speed of the same seed rule in native Rust, rule IR and Rego.
7. **Rule-pack distribution.** Fetch at build time, fetch at runtime (`oxtf rules fetch`), or user-supplied path: which keeps licences, reproducibility (pinned commits) and offline use workable?
8. **Trivy.** How large is the generated-adapter surface per service (R7), and is it smaller than Trivy's hand-written adapters?

## Deliverables and success criteria

**Deliverables**

- The `RuleBackend` abstraction with native, rule-IR, Rego, KICS and Checkov backends; CLI and `tfscan` support.
- The oxtf Rego input schema (JSON Schema + docs), the five seed rules as Rego.
- Generators for Checkov value checks (→ IR) and graph checks (→ Rego); KICS loader with the two builtins and limits.
- A conformance runner (KICS test suite) and a parity harness (Checkov, KICS) with committed result tables.
- `RULE_ENGINES_REPORT.md`: answers to every open question, conformance and parity tables, benchmarks with commands and raw output, scope cuts, and a recommendation on which backends to ship by default.

**Success criteria**

- [ ] Seed rules as Rego match the native rules on all 34 fixtures, including Conditional severity and the `.tfvars` provenance chain.
- [ ] The KICS conformance pass rate is measured over all 763 Terraform queries, with every failure categorized.
- [ ] All 568 Checkov value checks are translated or logged with a reason, and run with no Python at scan time.
- [ ] Parity tables against Checkov and KICS on the corpus, with a classified disagreement sample.
- [ ] Corpus scan time and memory with all translated rules enabled, measured with the spike's method.
- [ ] A Python user can run a Rego policy and Checkov checks from `tfscan` and get findings as an Arrow table.

## Instructions for the executing agent

1. **Re-verify versions** of regorus, Checkov and the KICS commit before pinning, and apply the two-week age rule to new dependency releases. Re-run the appendix smoke test on the pinned regorus first.
2. **Never vendor rule packs.** Fetch them at pinned commits into a gitignored cache; keep their licence files alongside; commit only generators, adapters and result tables.
3. **Start R1 and R3 in parallel.** R1's schema decisions bind R2 and R4, so settle the native schema early and record it.
4. **Keep the 34 fixtures green** throughout; every backend must reproduce the seed rules before it is trusted on foreign rules.
5. **Cut scope, not quality,** and log each cut with its reason.
6. **No invented numbers.** Every rate and timing comes from a command you ran; include commands, machine specs and raw output in an appendix.
7. **Independent check before finishing:** a separate agent reads `RULE_ENGINES_REPORT.md` against this plan, as in the spike.

## Appendix: evidence gathered for this plan

All commands run on 2026-10-14 on the spike machine (4 vCPU Intel Xeon @ 2.80 GHz, 15 GiB). Sources were shallow-cloned: `aquasecurity/trivy-checks` @ `6ceb337`, `Checkmarx/kics` @ `bbb3c148`, `microsoft/regorus` @ `b94fc6b`; Checkov 3.3.29 from PyPI.

### regorus releases (crates.io)

```
0.13.0 2026-10-14
0.12.0 2026-09-01
0.11.0 2026-07-21
license: MIT AND Apache-2.0 AND BSD-3-Clause
```

### KICS query on regorus (smoke test, regorus 0.13.0)

```rust
let mut e = regorus::Engine::new();
e.set_rego_v0(true);
// KICS's common.rego has lines up to 5,459 columns; regorus defaults to 1,024.
e.set_policy_length_config(regorus::utils::limits::PolicyLengthConfig {
    max_col: core::num::NonZeroU32::new(8192).unwrap(),
    ..Default::default()
});
for lib in ["common.rego", "terraform.rego"] {
    e.add_policy_from_file(format!("{kics}/assets/libraries/{lib}"))?;
}
e.add_policy_from_file(format!(
    "{kics}/assets/queries/terraform/aws/security_group_with_unrestricted_access_to_ssh/query.rego"))?;
e.set_input(Value::from_json_str(r#"{"document":[{"id":"doc1","file":"main.tf","resource":{
  "aws_security_group":{
    "web":{"name":"web","ingress":{"from_port":22,"to_port":22,"protocol":"tcp","cidr_blocks":["10.0.0.0/8","0.0.0.0/0"]}},
    "ok":{"ingress":[{"from_port":22,"to_port":22,"protocol":"tcp","cidr_blocks":["10.0.0.0/8"]},
                     {"from_port":443,"to_port":443,"protocol":"tcp","cidr_blocks":["0.0.0.0/0"]}]}}}}]}"#)?);
let r = e.eval_rule("data.Cx.CxPolicy".to_string())?;
```

Output (abridged): one result, `"resourceName": "web"`, `"searchKey": "aws_security_group[web].ingress"`, `"searchLine": ["resource", "aws_security_group", "web", "ingress"]`; `eval: 4.196159ms`. Without the length config, loading `common.rego` fails with `common.rego:582:17 error: expecting }` (the real cause, `line exceeds maximum column width of 1024`, is only visible in regorus's lexer source). Line-length check: `awk '{ if (length($0)>m) {m=length($0); n=NR} } END {print n, m}' common.rego` → `599 5459`.

### Rego corpora

```
trivy-checks cloud rego (non-test): 366       files importing rego.v1: 361     files with # METADATA: 366
kics terraform queries: 763                   files importing rego.v1: 0       files importing data.generic: 761
input paths, trivy (aws/ec2):   input.aws.ec2.securitygroups (5), .launchconfigurations (5), .instances (4), .vpcs (3)
input paths, kics (terraform):  input.document[i].id (1269), .resource (1183), .module (93)
regorus registered builtins: 177
trivy: 38 distinct std builtins used, 282 call sites; not in regorus: net.cidr_allows_all_ips, net.is_port_range_include,
       net.is_ssh_or_rdp_port, net.is_tcp_or_udp_protocol, net.is_tcp_protocol, net.protocol   ← all defined in trivy-checks/lib/cloud/net.rego
kics:  48 distinct std builtins used, 5268 call sites; not in regorus: all, any   (12 call sites: 5 in queries, 7 in libraries)
```

Builtin usage was counted by a regex scan of call sites, matched against the names registered in `regorus/src/builtins/**` (`m.insert("<name>", ...)`).

### Checkov

```
$ checkov --list --framework terraform | grep -oE "CKV2?_[A-Z0-9]+_[0-9]+" | sort -u | wc -l
1144                                   (of which CKV2_*: 180)
graph check files under checkov/terraform/checks/graph_checks: 196 JSON
resource-check IDs in the registry: 927 {'custom': 359, 'value': 568}
value checks with introspectable key + values: 568; keys with wildcards: 0
  ('CKV_ALI_10', ['alicloud_oss_bucket'], 'versioning/[0]/status', ['Enabled'])
  ('CKV_ALI_11', ['alicloud_oss_bucket'], 'transfer_acceleration/[0]/enabled', [True])
  ('CKV_ALI_12', ('alicloud_oss_bucket',), 'logging', ['CKV_ANY'])
License: Apache License 2.0
```

The introspection script imports `checkov.terraform.runner` (which registers the built-in checks), iterates `resource_registry.checks`, and calls `get_inspected_key()` plus `get_expected_values()` or `get_forbidden_values()` on each value check.

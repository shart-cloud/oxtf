# Validation and compatibility gates

The review remediation follows five steps:

1. Surface rule execution failures separately from legitimate unknown values.
2. Track scan completion and require completed scans to verify edits.
3. Propagate sensitivity and redact presentation surfaces while preserving
   evaluator inputs.
4. Report unsupported source formats, modules and bounded evaluation.
5. Gate the shared engine, output contracts and reference compatibility in CI.

`.github/workflows/check.yml` runs on pull requests and main pushes:

- Formatting, Clippy with warnings denied, and the Rust workspace suite,
  including the 76-case native output baseline.
- The pinned 17-repository parser corpus, including structural comparison
  with `hcl-edit`. `corpus/fetch.sh` verifies commit IDs and refuses modified
  or mismatched existing checkouts. `OXTF_REQUIRE_CORPUS=1` makes a missing
  corpus a failure.
- Python API, callbacks, importer, typing and Arrow tests, with optional
  dependencies installed so their tests execute.
- Checkov 3.2.328 catalog regeneration against the checked-in artifacts
  and generated known-value predicate cases against Checkov's runner.
  The graph translator is also compared with its retained Python oracle.
- Rego input/result comparisons against OPA 1.17.0 on local rule fixtures.
  Empty comparisons, engine errors and unexplained differences fail.
- Source loading compared with Terraform 1.16.1: mixed HCL/JSON variable
  precedence, literal JSON values, and an installed Git module with a package
  subdirectory and local child. The test uses a local Git repository and no
  public module or provider downloads. It also compares installed registry
  version constraints with Terraform's loader. CI requires this test to run.
  Configuration/override fixtures also cover all four HCL/JSON format pairs,
  decoded templates, literal contexts, variable type/default conversion,
  dynamic collection element conversion, invalid overrides, and lifecycle
  merging. Terraform 1.16.1 uses HCL 2.24.0.
  The lifecycle fixture uses only the built-in `terraform_data` resource.

Reference package versions are in `scripts/ci-python.txt`; Rust uses the
workspace lockfile and CI pins Rust 1.96.0. The catalog's auxiliary data
depends on cloudsplaining 0.7.0 and policy_sentry 0.13.2, also pinned.

Run the main gates locally:

```sh
bash corpus/fetch.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
OXTF_REQUIRE_CORPUS=1 cargo test --workspace --locked
python3 -m venv .venv
.venv/bin/python -m pip install -r scripts/ci-python.txt
VIRTUAL_ENV="$PWD/.venv" .venv/bin/maturin develop --locked --manifest-path crates/tfscan_py/Cargo.toml
.venv/bin/python -m pytest crates/tfscan_py/tests
```

The workflow includes the catalog and differential commands. Checkov
conformance uses known generated cases; OPA conformance compares the same
projected inputs in both engines. These gates do not prove full Terraform
semantics or provider equivalence. The larger upstream Python-check,
graph, Conftest and community-policy harnesses under `bench/` remain
separate experiments and are not claimed as CI coverage.

Targeted regressions live in `tf_scan/tests/{completion,coverage,sensitivity}.rs`,
`tf_eval/tests/eval.rs`, the interpreter/CLI suites, and Python
`tests/test_trust.py`. They cover errors after an edit, malformed input,
unsupported execution, sensitivity across source/plan/module boundaries,
and incomplete scans that would otherwise look clean.

Depth regressions live in `tf_parser/tests/depth.rs`, `tf_eval/tests/depth.rs`,
and `tf_scan/tests/depth.rs`, with CLI and Python coverage in their `limits`
tests. Crash probes run in child processes with a timeout, core dumps disabled,
and a 2 MiB stack. Well-formed input exceeding a nesting guard produces
`coverage-parse-limit` and `incomplete`; malformed syntax still produces
`parse-error` and `failed`. Worker requests outside 1..64 are operating errors,
and the linter tests inject a thread-spawn failure without exhausting threads.
The local ceilings and remaining budget work are described in
[the TigerStyle plan](plans/TIGERSTYLE_PLAN.md). Run the stack probes in release too:

```sh
cargo test --offline --locked --release -p tf_parser -p tf_eval --test depth
```

Shared runtime budgets are covered in `tf_limits` unit tests,
`tf_eval/tests/budget.rs`, `tf_scan/tests/budget.rs`, and CLI/Python `limits`
tests. They check exact boundaries, overflow, nested evaluator re-entry,
worker-independent root allowances, template/child-module sharing, discarded
limit values, plan source mapping, and incomplete fix verification. The work
probe and accounting scope are documented in [LIMITS.md](LIMITS.md).

Runtime input conversion is covered by `tf_semantic/tests/input_budget.rs`,
the conversion module's evidence-preservation tests, `tf_scan/tests/input_budget.rs`,
and CLI/Python `limits` tests. These check exact allowances before collection
copies, cold/warm caches, repeated module inputs, retained optional defaults,
HCL/JSON tfvars, sensitivity/dependencies, error precedence, worker independence,
and refusal to verify a fix after conversion exhaustion. Run the focused Rust
tests in release as well as debug mode.

Root rule allowances are covered in `tf_linter/tests/rule_budget.rs`,
`tf_scan/tests/rule_budget.rs`, strict limits parsing, and the CLI/Python `limits`
tests. They cover every hook pass, exact IR/interpreter boundaries, short-circuit
and unknown-element costs, alternative runs, ignored/caught charge failures,
mutable-cache isolation between runs, lazy bundled rules, graph reservations,
worker independence, plan scans without source mapping, callback admission,
retained findings, and failed fix verification. Run these focused checks in
release too:

Input/storage regressions are in `tf_limits/tests/input.rs`,
`tf_semantic/tests/storage_limits.rs`, and `tf_scan/tests/storage_limits.rs`.
They cover exact byte/count boundaries, one-byte read lookahead, lossy UTF-8
expansion, raw/text/arena copies, concurrent admission, warm caches and input
snapshot isolation, worker-independent incomplete status, rule/plan/policy
inputs, and rejected fix verification. CLI/Python limits tests cover adapters.
Rego unit tests exercise internal timeout interruption and prove that cached
engines release their captured input tables when a root drops. Root-budget tests
cover cumulative elapsed time and scratch cleanup during unwind.

```sh
cargo test --offline --locked --release -p tf_limits --lib
cargo test --offline --locked --release -p tf_linter -p tf_scan --test rule_budget
```

Arena admission regressions live in `tf_allocator` unit tests,
`tf_parser/tests/storage.rs`, and the semantic/scan `storage_limits` tests.
They exercise exact construction boundaries, byte refusal without a placeholder,
zero-sized values, reset, concurrent arenas, every construction point in HCL/JSON
module preparation and overrides, cached failures, independent low-level arenas,
template `try`, Rego `parse_config`, failure precedence, and fix verification.
CLI/Python limits tests cover strict configuration, hidden diagnostics, and plan
source mapping. Expression/template parsing now returns an optional expression;
existing depth and evaluator tests require successful parses explicitly.

```sh
cargo test --release --offline --locked -p tf_allocator --lib
cargo test --release --offline --locked -p tf_parser --test storage --test depth
cargo test --release --offline --locked -p tf_semantic -p tf_scan --test storage_limits
```

`bench/arena_limits.py --before /tmp/oxtf-scan-before-arena` compares the preserved
pre-arena scan executable against the current release `scan_limits` probe. It
checks the old executable against the recorded input-matrix hash, warms both
binaries, alternates paired samples, and asserts unchanged corpus outcomes and
source counters. Run it after builds and tests, with the same corpus and CPU set.
The old executable's source metadata comes from the earlier matrix; the new
metadata hashes the current Rust sources/manifests, including uncommitted work.

Source-coverage regressions are in
`tf_scan/tests/{json_vars,installed_modules,json_config,overrides}.rs`,
the CLI suite, and Python `tests/test_source_coverage.py`. They cover installed
version constraints, stale manifests, root isolation, nested calls, dependencies,
cache-independent fingerprints, and cache edit protection.
JSON and override cases additionally check original byte spans, mixed source
ownership, plan mapping, nested blocks, graph edges, sensitivity, verified edits,
and whole-file policy rendering (`tf_rego/tests/hcl2json.rs`).
Override comparisons preserve the original optional-attribute defaults across
type changes, including replacement defaults, tfvars, and module arguments.
They also check concrete collection types across successive overrides,
including typed nulls, empty collections, and intermediate `any` constraints.
Count regressions in `tf_semantic/tests/count.rs` cover numeric instance identity,
module outputs, full and legacy splats, whole-object references, direct graph
provenance through conditional objects, invalid counts, and per-root budgets.
The Terraform reference cases compare HCL/JSON with overridden module counts
against planned resource addresses and values, and compare regex results.
Additional cases cover numeric-string indices, sensitive selectors in values,
Arrow exports, source snippets and verified fix diffs, and uncertainty for
nested blocks accessed through whole-resource objects.
Fix regressions in `tf_scan/tests/{fixes,completion}.rs`, the CLI suite, and
Python `tests/test_trust.py` distinguish target resolution from new findings.
They cover failures introduced elsewhere, new occurrences of existing findings,
shared-default fallback, unchanged findings after line shifts, incomplete scans,
masked delta evidence, and refusal to write a regressing edit.
Metadata regressions in `tf_scan/tests/guidance.rs`, `tf_rule_ir/tests/bundled.rs`,
and Python `tests/test_guidance.py` check severity distinctions, guidance in
catalogs and outputs, and preservation of the bundled predicates. The native
76-case baseline was refreshed only for severity and guidance fields; finding
identities, values, diagnostics and edit hints remain unchanged.
`python -m unittest discover -s bench -p test_signal.py` checks that the signal
gate measures useful guidance and rejects incomplete scans without rewarding
severity inflation. Current corpus completion limitations are recorded in the
signal plan; they must not be hidden by replacing the trusted baseline.
File-function regressions in `tf_scan/tests/file_functions.rs` cover overlays,
binary hashing, relative child-module paths, template typing and lexical scope,
sensitivity, missing variables in unused branches, catchable errors, and fetched
package boundaries. `test_source_coverage.py` compares file/template/hash results
with Terraform 1.16.1. `test_guidance.py` also reproduces the two null-version
defects directly in pinned Checkov; the Rust completion suite verifies that
these remain rule errors rather than clean scans.

`bench/results/signal-observed.json` is a failed observation, not a baseline.
`bench/signal.py --output PATH` saves measurements, a ranked guidance backlog,
grouped coverage causes, and a byte breakdown without changing
`bench/results/signal.json`. The completion follow-up and remaining blockers are
in `docs/plans/SIGNAL_COMPLETION.md`.
`tf_fetch/tests` and Python `tests/test_fetch.py` use local Git repositories and
loopback registry/download servers to exercise version selection, refresh,
offline reuse, nested dependencies, credential isolation, and archive rejection.
Git fixtures check that export attributes cannot omit configuration or rewrite
its contents, and that oversized downloads cannot publish an installed manifest.
Provider policy fixtures compare nested blocks in both formats, including
custom local provider names and requirements changed by an override.
Run the pinned reference test locally with:

```sh
OXTF_REQUIRE_TERRAFORM=1 .venv/bin/python -m pytest crates/tfscan_py/tests/test_source_coverage.py
```

Terraform binaries and checksums come from the official
[Terraform 1.16.1 release](https://releases.hashicorp.com/terraform/1.16.1/).
Without the requirement flag, only the reference test skips when that version
or Git is unavailable; the other source-coverage tests still run.

Workflow action configuration follows the upstream
[checkout](https://github.com/actions/checkout) and
[setup-python](https://github.com/actions/setup-python) documentation.


Evaluator text admission checks:

```sh
cargo test --offline --locked -p tf_eval --test text
cargo test --offline --locked -p tf_semantic --test storage_limits
cargo test --offline --locked -p tf_scan --test storage_limits
cargo test --offline --locked -p tf_cli --test limits
```

Text regressions cover exact construction boundaries, Unicode lowercase,
replacement/format amplification, nested JSON, concurrent admission, shared
root and loader budgets, warm caches, error precedence, sensitivity/dependencies,
Python/CLI mapping, and refusal to verify incomplete fixes. The full validation
still requires `OXTF_REQUIRE_CORPUS=1` and `OXTF_REQUIRE_TERRAFORM=1`.

Preserve the previous release `scan_limits` executable before rebuilding. With
all builds/tests finished, run the text measurement matrix (one warmup and five
alternating before/after pairs for each catalog/worker/retention combination):

```sh
cargo build --release --offline --locked -p tf_scan --example scan_limits
python bench/text_limits.py --before /tmp/oxtf-scan-before-values --repeats 5
```

The script verifies the baseline executable against the eighth-slice artifact
and asserts identical outcomes and input/arena admission counters. The recorded
text counters measure admitted construction, not live heap or total RSS.


Builtin collection admission checks:

```sh
cargo test --offline --locked -p tf_eval --test collections --test limits
cargo test --offline --locked -p tf_semantic -p tf_scan --test storage_limits
cargo test --offline --locked -p tf_cli --test limits
```

The collection regressions exercise below/exact/above reservation boundaries,
rejected allocation before mapping or JSON deserialization, alternative order,
sensitivity and dependency uncertainty, sticky shared storage, cached defaults,
worker counts, CLI/Python configuration, and incomplete fix verification.
Run the required full Rust/Python gates as above. With all builds and tests
finished, reproduce the tenth-slice comparison with its preserved executable:

```sh
python3 bench/collection_limits.py --before /tmp/oxtf-scan-before-containers --binary /tmp/oxtf-scan-before-expressions --repeats 5 --output /tmp/oxtf-collections-reproduction.json
```

The harness verifies the ninth-slice executable hash and compares scan outcomes
and existing input/arena/text counters for seed/standard catalogs, one/four
workers, and both model-retention settings. Collection bytes are cumulative
reservations, not live heap size.


The collection harness records monotonic subprocess time, internal scan time,
user/system CPU time, and peak RSS. GNU wall-clock samples are retained for
inspection but are not used for the final timing comparison after a negative
sample was observed. To reproduce the isolated investigation sets:

```sh
python3 bench/collection_limits.py --before /tmp/oxtf-scan-before-containers --binary /tmp/oxtf-scan-before-expressions --catalog seed --workers 4 --keep-models false --repeats 11 --output /tmp/oxtf-collections-repeat-reproduction.json
python3 bench/collection_limits.py --before /tmp/oxtf-scan-before-containers --binary /tmp/oxtf-scan-before-expressions --catalog seed --workers 4 --keep-models true --repeats 11 --output /tmp/oxtf-collections-retained-repeat-reproduction.json
```

Run those only after builds and tests finish. Raw matrix outliers and subsequent
repeat evidence must both remain available; a repeat is an investigation, not a
replacement for the original samples.

Expression collection admission adds `tf_eval/tests/expressions.rs`: exact
boundaries for literals, static defaults, splats, comprehensions and filter
copies, argument expansion, operators/projections, catches and template buffers.
It verifies rejection before child evaluation or dispatch, and sweeps refusal
points to check sensitivity and dependency certainty. `tests/limits.rs` also
measures allocation during refusal of 100,000-element inputs. Scan/Python checks
exercise the same expressions through completion and fix-verification paths.

```sh
cargo test --offline --locked -p tf_eval --test expressions --test limits
cargo test --release --offline --locked -p tf_eval
cargo test --release --offline --locked -p tf_semantic -p tf_scan --test storage_limits
```

Preserve the tenth-slice probe as `/tmp/oxtf-scan-before-expressions` before a
release rebuild. Once builds and tests finish, compare it with the new probe:

```sh
cargo build --release --offline --locked -p tf_scan --example scan_limits
python3 bench/collection_limits.py --before /tmp/oxtf-scan-before-expressions --baseline-record bench/results/tigerstyle-collections.json --repeats 5 --output bench/results/tigerstyle-expressions.json
```

The harness verifies the baseline executable fingerprint and compares completion,
outcomes, input/arena/text counters, monotonic elapsed time, and peak RSS across
both catalogs, one/four workers, and both model-retention settings. Collection
admission increases because expression containers now count too. Keep any
initial measurements and investigations if the 10% gate is crossed.

The eleventh-slice investigation keeps the initial matrix and both eleven-pair
repeat sets. To reproduce those cases without replacing the retained evidence:

```sh
python3 bench/collection_limits.py --before /tmp/oxtf-scan-before-expressions --baseline-record bench/results/tigerstyle-collections.json --catalog seed --workers 1 --keep-models true --repeats 11 --output /tmp/oxtf-expressions-retained-repeat.json
python3 bench/collection_limits.py --before /tmp/oxtf-scan-before-expressions --baseline-record bench/results/tigerstyle-collections.json --catalog seed --workers 4 --keep-models false --repeats 11 --output /tmp/oxtf-expressions-parallel-repeat.json
```

## Semantic conversion and default container checks

The twelfth TigerStyle slice covers runtime input conversion, optional-default
application, cached default preparation, common-type inference and type-tree
copies. Unit tests sweep every byte allowance through nested defaults and type
conversion, exercise exact list/map boundaries before child conversion, and
retain sensitivity, uncertain dependencies and earlier errors on refusal.
Loader tests cover partial-definition discard and warm-cache replay at every
storage boundary; scan and Python tests check incomplete status and refused fix
verification. A thread-local allocation probe rejects 100,000-element inputs and
type copies with less than 64 KiB allocated during the operation.

```sh
OXTF_REQUIRE_CORPUS=1 cargo test --workspace --offline --locked
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo test --release --offline --locked -p tf_eval -p tf_semantic -p tf_scan \
  --lib --test expressions --test collections --test limits --test text \
  --test budget --test depth --test storage_limits --test loader_budget
VIRTUAL_ENV=/tmp/oxtf-trust-python /tmp/oxtf-trust-python/bin/maturin develop \
  --offline --locked --manifest-path crates/tfscan_py/Cargo.toml
OXTF_REQUIRE_TERRAFORM=1 /tmp/oxtf-trust-python/bin/python -m pytest crates/tfscan_py/tests
cargo fmt --all -- --check
git diff --check
```

Preserve the final eleventh-slice executable before rebuilding the probe. Its
SHA-256 is `1b3d04b52adaa220e5e57a1fd7fac3604b79a98257d7db840883fd41aa142bb9`.
The measurement harness verifies that identity against the prior artifact and
compares all eight catalog/worker/retention configurations, alternating execution
order across five paired measurements after one warmup per binary and case.
Run these measurements separately from builds and test suites.

```sh
cargo build --release --offline --locked -p tf_scan --example scan_limits
python3 bench/collection_limits.py --before /tmp/oxtf-scan-before-semantic \
  --baseline-record bench/results/tigerstyle-expressions.json --repeats 5 \
  --output bench/results/tigerstyle-semantic.json
```

The result records logical collection admission separately from peak RSS. Its
matched outcomes and input/arena/text counters remain part of acceptance; newly
admitted conversion/type payload is expected to increase `collection_bytes`.
Model containers and semantic key/index text remain explicit subsequent work.

Final twelfth-slice validation: 533 Rust workspace checks pass (two existing
ignored tests), 122 focused release checks pass, and 344 Python checks pass with
Terraform required. Clippy, formatting and whitespace checks pass. All eight
performance cases remain below the 10% median elapsed/RSS regression gate; raw
samples, summary and acceptance are retained in
`bench/results/tigerstyle-semantic.json`. No repeated measurements were needed.

## Analyzer model container checks

The thirteenth TigerStyle slice adds fallible model/instance construction and
per-root memo admission. Semantic unit and integration tests cover reference
copies, inline iterator bindings, exact and sampled model boundaries, dynamic
blocks, IAM policy construction, child modules, warm definitions and refusal
replay. Scan tests preserve completed findings and earlier errors, discard
unfinished bodies, and exercise workers, retention and fix refusal. Python adds
a scalar-only resource case so refusal cannot be attributed to literal payload.

```sh
OXTF_REQUIRE_CORPUS=1 cargo test --workspace --offline --locked
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo test --release --offline --locked -p tf_eval -p tf_semantic -p tf_scan \
  --lib --test expressions --test collections --test limits --test text \
  --test budget --test depth --test storage_limits --test loader_budget --test model_limits
VIRTUAL_ENV=/tmp/oxtf-trust-python /tmp/oxtf-trust-python/bin/maturin develop \
  --offline --locked --manifest-path crates/tfscan_py/Cargo.toml
OXTF_REQUIRE_TERRAFORM=1 /tmp/oxtf-trust-python/bin/python -m pytest crates/tfscan_py/tests
cargo fmt --all -- --check
git diff --check
```

The preserved twelfth-slice baseline is `/tmp/oxtf-scan-before-models`, SHA-256
`76f2ce36f56781fe48ad45bda8d0875e0c3dc8140db79168dfcde7550be86eeb`.
Compare all eight catalog/worker/retention cases after builds and tests finish:

```sh
cargo build --release --offline --locked -p tf_scan --example scan_limits
python3 bench/collection_limits.py --before /tmp/oxtf-scan-before-models \
  --baseline-record bench/results/tigerstyle-semantic.json --repeats 5 \
  --output bench/results/tigerstyle-models.json
```

Input, arena and text counters and analysis outcomes must match. Newly admitted
model/instance payload increases `collection_bytes`; that counter is cumulative
construction, not live memory or RSS. Retain raw samples and investigate any
median elapsed/RSS regression above 10% before accepting the slice.

Final thirteenth-slice validation: 544 Rust workspace checks pass (two existing
ignored tests), 133 focused release checks pass, and 345 Python checks pass with
Terraform required. The native baseline, Clippy, formatting and whitespace checks
pass. All eight paired performance cases stay below the 10% elapsed/RSS gate;
no repeated investigation was needed. Raw samples and acceptance are retained in
`bench/results/tigerstyle-models.json`.

## Parsed-definition and cache metadata checks

The fourteenth TigerStyle slice admits declaration/provider indexes, parsed-file
staging, shared parsed-store metadata and installed-manifest records. Semantic
tests sweep every byte through definition and record construction, exercise JSON
provider preparation and concurrent module/variable-file initialization, and
verify that warm successes and failures do not recharge. The manifest allocation
probe refuses a million-byte field before decoding it, including after an admitted
record, with less than 4 KiB requested allocation during each measured operation.
Scan tests cover installed-module boundaries and accurate storage diagnostics;
Python covers both HCL and JSON variable-file cache refusal.

```sh
OXTF_REQUIRE_CORPUS=1 cargo test --workspace --offline --locked
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo test --release --offline --locked -p tf_eval -p tf_semantic -p tf_scan \
  --lib --test expressions --test collections --test limits --test text \
  --test budget --test depth --test storage_limits --test loader_budget \
  --test model_limits --test metadata_limits --test installed_modules
VIRTUAL_ENV=/tmp/oxtf-trust-python /tmp/oxtf-trust-python/bin/maturin develop \
  --offline --locked --manifest-path crates/tfscan_py/Cargo.toml
OXTF_REQUIRE_TERRAFORM=1 /tmp/oxtf-trust-python/bin/python -m pytest crates/tfscan_py/tests
cargo fmt --all -- --check
git diff --check
```

The preserved thirteenth-slice executable is `/tmp/oxtf-scan-after-models`, SHA-256
`52b301b4285bd051fb9d163bac428781d154ed5abcfb26ba137798c2c478ed75`.
Run the paired comparison separately from builds and tests:

```sh
cargo build --release --offline --locked -p tf_scan --example scan_limits
python3 bench/collection_limits.py --before /tmp/oxtf-scan-after-models \
  --baseline-record bench/results/tigerstyle-models.json --repeats 5 \
  --output bench/results/tigerstyle-metadata.json
```

Require matching outcomes and existing input/arena/text counters. Collection
bytes include the newly admitted metadata and can increase. Retain all raw
samples and investigate any per-case median elapsed/RSS increase above 10%.

Final fourteenth-slice validation: 554 Rust workspace checks pass (two existing
ignored tests), 154 focused release checks pass, and 347 Python checks pass with
Terraform required. The native baseline, Clippy, formatting and whitespace checks
pass. All eight paired performance cases stay below the 10% elapsed/RSS gate;
no repeated investigation was needed. Raw samples and acceptance are retained in
`bench/results/tigerstyle-metadata.json`.

## Composition and parsed-reference checks

The fifteenth TigerStyle slice admits composition ownership/default maps,
validation-name sets, parsed-reference edges and lexical-binding vectors. The
semantic tests exercise every-byte refusal, binding meaning, HCL/JSON overrides,
original source spans and warm caches. The reference allocation probe rejects a
one-million-byte symbol before copying it with less than 4 KiB allocated during
the operation. Scan tests ensure a refused reference list never publishes a model
and does not hide earlier composition errors, under either retention mode.

```sh
OXTF_REQUIRE_CORPUS=1 cargo test --workspace --offline --locked
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo test --release --offline --locked -p tf_eval -p tf_semantic -p tf_scan \
  --lib --test expressions --test collections --test limits --test text \
  --test budget --test depth --test storage_limits --test loader_budget \
  --test model_limits --test metadata_limits --test installed_modules \
  --test composition_limits --test overrides --test defaults --test json_config
VIRTUAL_ENV=/tmp/oxtf-trust-python /tmp/oxtf-trust-python/bin/maturin develop \
  --offline --locked --manifest-path crates/tfscan_py/Cargo.toml
OXTF_REQUIRE_TERRAFORM=1 /tmp/oxtf-trust-python/bin/python -m pytest crates/tfscan_py/tests
cargo fmt --all -- --check
git diff --check
```

The preserved fourteenth-slice executable is `/tmp/oxtf-scan-after-metadata`, SHA-256
`dcd0c1022ab36f39fb54ec033f52b37a95f1b083ad724bbecdb16c3a873a57d9`.
After builds and tests finish, run the eight-case paired comparison:

```sh
cargo build --release --offline --locked -p tf_scan --example scan_limits
python3 bench/collection_limits.py --before /tmp/oxtf-scan-after-metadata \
  --baseline-record bench/results/tigerstyle-metadata.json --repeats 5 \
  --output bench/results/tigerstyle-composition.json
```

Require matching outcomes and existing input/arena/text counters. Collection
bytes include newly admitted composition/reference storage. Retain raw samples
and investigate per-case median elapsed/RSS increases above 10%.

Final fifteenth-slice validation: 561 Rust workspace checks pass (two existing
ignored tests), 186 focused release checks pass, and 347 Python checks pass with
Terraform required. The native baseline, Clippy, formatting and whitespace checks
pass. All eight paired performance cases stay below the 10% elapsed/RSS gate;
no repeated investigation was needed. Raw samples and acceptance are retained in
`bench/results/tigerstyle-composition.json`.

The accepted fifteenth-slice probe is preserved for the next comparison at
`/tmp/oxtf-scan-after-composition`, SHA-256
`8884b6cc9da27a206f60e53c5c5f425ddfe46d07b700a13d8bb7e939bfd2b8bd`.

## Graph and provenance checks

The sixteenth TigerStyle slice charges graph construction to `rule_steps` and
admits graph edges and evaluated provenance unions as collection payload. The
semantic graph test exercises the exact step and byte boundaries; the evaluator
provenance tests cover first-seen order on both deduplication paths, a
30,000-dependency linearity probe, union charging and a stale-allowance check.
The rule-budget hook test accounts for the graph construction step.

```sh
OXTF_REQUIRE_CORPUS=1 cargo test --workspace --offline --locked --no-fail-fast
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo build --release --offline --locked -p tf_scan --example scan_limits
python3 bench/collection_limits.py --before /tmp/oxtf-scan-after-composition \
  --baseline-record bench/results/tigerstyle-composition.json --repeats 5 \
  --output bench/results/tigerstyle-graph.json
VIRTUAL_ENV=/tmp/oxtf-trust-python /tmp/oxtf-trust-python/bin/maturin develop \
  --offline --locked --manifest-path crates/tfscan_py/Cargo.toml
OXTF_REQUIRE_TERRAFORM=1 /tmp/oxtf-trust-python/bin/python -m pytest crates/tfscan_py/tests
cargo fmt --all -- --check
git diff --check
```

Final sixteenth-slice validation: 566 Rust workspace checks pass (two existing
ignored tests), including the unchanged native baseline, and 347 Python checks
pass with Terraform required. Clippy and formatting pass. All eight paired cases
stay below the 10% elapsed/RSS gate.

The accepted sixteenth-slice probe is preserved for the next comparison at
`/tmp/oxtf-scan-after-graph`, SHA-256
`bea75d3bb1ec94a8213e4037592c7c33a27bbf57b68dca421e81811f5095eb71`.

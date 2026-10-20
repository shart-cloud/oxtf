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

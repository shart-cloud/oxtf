# TigerStyle alignment plan

Status: implementation in progress; completion is defined by the cut line under "Remaining work". Shared evaluation/default/rule accounting,
scan input admission, cooperative Rego execution time, and root-owned backend
caches are implemented. Arena/model/output storage, remaining backend and loader
work, explicit AST/evaluator traversal stacks, and final acceptance remain open.

Date: 2026-10-21. Based on the TigerStyle audit of the working tree, including
the source-function and signal changes already in progress.

Make resource consumption predictable and internal contracts explicit, in
TigerStyle's order: safety, performance, then developer experience. Start with
the reproduced crashes and ineffective limits, then extend the same discipline
across the scan pipeline.

This builds on [the architecture plan](ARCHITECTURE_PLAN.md),
[source coverage](SOURCE_COVERAGE_PLAN.md), and
[validation contracts](../VALIDATION.md). The outstanding signal and reference
compatibility work in [SIGNAL_COMPLETION.md](SIGNAL_COMPLETION.md) remains
separate. A bounded scan must still report unsupported or failed analysis.

## Implementation progress

The first slice closes the reproduced product allocation, indentation panic,
and binary alternative expansion failures. It includes focused evaluator and
scan regressions, with changes confined to evaluator behavior and its tests.

| Delivered | Behavior and evidence |
| --- | --- |
| Product preflight | Check rows and tuple elements before allocation; build each final row once. |
| Indentation preflight | Validate width, input bytes, and output bytes before padding allocation. |
| Alternative preflight | Bound binary operations, functions, templates, and flattening. |
| Filter exhaustion | Return a limit even for tainted filters, preserving incomplete scan status. |
| Limit propagation | Preserve sensitivity and possible dependencies on alternative rejection. |
| Completion regressions | Direct limits survive `try`/`can` and conditions; fixes cannot verify. |

The existing ceilings remain 4,096 product rows and 16 alternatives. Candidate
alternatives count before deduplication, so 17 identical candidates also reach
the limit. New interim ceilings are 65,536 tuple elements and 1 MiB each for
indentation input, padding, and output. The tuple-element ceiling allows at most
2 MiB of `Value` payload at the current 32-byte size, excluding allocation
overhead, provenance, and shared backing data. The indentation ceiling matches
the existing regex input ceiling. These remain conservative local ceilings;
the third slice centralizes their definitions, while broader Phase 0
measurements must still inform their review.

The 1,024 by 1,024 product regression now rejects with less than 64 KiB of
allocation during the call, excluding input construction. The 16 by 16 binary
alternative regression invokes the operation zero times. Boundary tests cover
accepted products, empty factors, tuple width, indentation bytes and invalid
widths, sensitivity, and dependency uncertainty. This allocation measurement is
distinct from the original process peak-RSS observation.

First-slice validation: the full Rust workspace suite with `OXTF_REQUIRE_CORPUS=1`, Clippy
with warnings denied, and evaluator regressions in debug and release pass.
All 284 Python tests pass with `OXTF_REQUIRE_TERRAFORM=1`: 276 passed in the
sandbox and eight local-HTTP fetch tests passed on rerun with loopback access.
Normal indentation behavior was also checked against the installed Terraform
reference, including trailing newlines.

The second slice adds temporary depth guards and fallible worker creation:

- Native parser recursion, constructed AST depth, and JSON container nesting
  have conservative ceilings of 64; active evaluation has a ceiling of 128.
  Evaluation needs headroom above the existing 90-local provenance fixture,
  which a trial ceiling of 64 rejected. Parser depth
  counts active guarded calls; AST depth counts expressions, bodies, and
  templates. These are separate allowances, so their effective source nesting
  thresholds can differ. They remain local defaults pending Phase 0 measurements.
- The AST check runs before indexing and recursive consumers, including JSON
  location mapping and the Python AST collector. Excessive files expose an
  empty body plus a typed limit diagnostic; standalone expressions expose an
  error placeholder plus that diagnostic. Callers must inspect diagnostics.
- JSON nesting is checked without recursion before serde validation. Native
  and JSON configuration, native and JSON variable files, raw templates, and
  `templatefile` retain limit outcomes. Scans use `coverage-parse-limit` and
  `incomplete`; genuine syntax errors retain `failed` precedence. Previously,
  serde's nesting limit was reported as a JSON syntax error.
- An active evaluator guard is shared across fresh evaluators on the same
  thread, including resolver re-entry. Depth exhaustion persists until that
  outer evaluation returns and resets for the next independent evaluation.
  RAII releases depth on normal return and panic unwinding. Static values,
  traversal splats, and template directives use the guard too. An established
  expression error retains precedence; enclosing `try`/`can` still cannot
  turn exhaustion into known success.
- Worker requests must be between 1 and 64. Defaults use available CPUs capped
  by 64 and the root count; explicit requests are also capped by the root count.
  No roots means no pool. The existing 64 MiB worker stack remains, giving at
  most 4 GiB of stack reservation per pool, not a promise about RSS. Reducing
  worker stacks requires completing the remaining recursive-consumer audit.
- `tf_linter::scan_dir` and `scan_with` now return `Result`. Discovery and pool
  creation errors propagate through `tf_scan::ScanError::Execution` to the CLI
  and Python. CLI exit codes remain 2 for a scan that could not run and 3 for
  incomplete or failed analysis; Python raises `ValueError` for invalid workers.

The parser and evaluator regression children have a 20-second timeout, disabled
core dumps, and a 2 MiB stack. They cover the original 100,000 unary operators
and 30,000-term chain, nested calls and precedence, collections, blocks,
templates, and JSON. Directly constructed ASTs exercise the evaluator without
the parser guard. Boundary cases and fresh-evaluator re-entry are tested too.
Pool-construction failure is injected through Rayon's spawn handler without
exhausting host threads. Scan, CLI, and Python tests check completion semantics.

Second-slice validation: the full Rust workspace suite with
`OXTF_REQUIRE_CORPUS=1`, parser/evaluator crash probes in debug and release,
Clippy with warnings denied, and formatting checks pass. The 90-local graph
provenance regression remains complete under the selected evaluator ceiling.
All 291 Python tests pass with the rebuilt extension and
`OXTF_REQUIRE_TERRAFORM=1`, including the seven new adapter regressions.

The third slice introduces the runtime evaluation portion of Phase 2:

- New dependency-free `tf_limits` owns Phase 1 ceilings, existing expansion
  defaults, validated `Limits`, typed exhaustion, and a checked monotonic work
  counter. Temporary and retained storage counters are still pending.
- Each root owns an `EvaluationBudget`. Runtime expressions, locals, child
  modules, optional defaults evaluated at runtime, and template files borrow
  it. New evaluator objects cannot reset that root's runtime allowance.
- Runtime limit evidence survives enclosing expressions that discard the
  value, such as `length([indent(...)])`. Work exhaustion stops subsequent
  evaluation and emits one located `coverage-budget` diagnostic with the
  resource and configured allowance. Established failure precedence remains.
- `ScanRequest.limits` survives cloning and both fix scans. Rust, CLI
  `--limits PATH`, and Python `limits` share `evaluation_steps`, defaulting to
  1,000,000 per root. Invalid configuration fails before loading scan inputs;
  fixed stack ceilings cannot be raised. Plan scans apply this allowance to
  their source analysis.
- Work counters do not depend on worker scheduling. Tests cover the exact
  allowance, overflow, resolver re-entry, child modules, templates, discarded
  limit values, sensitivity, invalid configuration, and fix verification.
- A reproducible probe measured 504 corpus roots with `whole_files=true`:
  median 163 steps, p95 4,535, maximum 22,116, and no work exhaustion. The
  default provides about 45 times the largest observed root's allowance.
  [Limits documentation](../LIMITS.md) records the units, API, scope, command,
  corpus pin, machine, timing, and peak RSS. This does not replace the broader
  Phase 0 matrix or establish a memory bound.

Third-slice validation: 413 Rust workspace checks pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests). Clippy with warnings denied,
formatting, and 28 release budget/depth/unit checks pass. All 301 Python tests
pass against the rebuilt extension with `OXTF_REQUIRE_TERRAFORM=1`.

The fourth slice accounts for cached variable-default preparation in Phase 2:

- `loader_steps` defaults to 1,000,000 per root and is configurable through the
  existing Rust, CLI, and Python limits interfaces. It covers evaluated defaults,
  optional default preparation, type inference/conversion, bounded type clones,
  and set comparisons during override composition. Modules without overrides
  continue to evaluate their defaults under the runtime allowance.
- Each cached module records its logical cost and first limit. Every root
  charges that cost once per definition before using it, regardless of cache
  warmth or worker count. Cached entries include the loader allowance in their
  identity, so a small exhausted entry cannot affect a larger request.
- Exhaustion persists outside values, stops further child loading and runtime
  evaluation, and reports incomplete coverage. An exhausted module exposes no
  partially composed declarations; previously observed errors remain failures.
- Tests cover exact boundaries, cache reuse and allowance changes, repeated
  module instances, shared modules across workers, optional defaults, set
  comparisons, discarded limits, error precedence, HCL/JSON, and adapters.

This is default-preparation accounting, not a complete loader or CPU bound.
An uncached entry can consume one full bounded preparation before a root rejects
its cost against the remaining allowance. Concurrent misses may still duplicate
construction. Parsing, I/O, structural composition, applying cached optional
defaults to runtime inputs, memory accounting, and rule execution remain open.
[Limits documentation](../LIMITS.md) records these boundaries and measurements.

Fourth-slice validation: 425 Rust workspace tests pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests), plus 26 release budget/unit
checks. Clippy with warnings denied and formatting checks pass. All 311 Python
tests pass on the full rerun with the rebuilt extension and
`OXTF_REQUIRE_TERRAFORM=1`. The initial Python run had one failure in the existing
module-sensitive-selector fix-verification test. Its isolated test, 100 repeated
scan/fix attempts on the same fixture, and the full rerun pass without changing
that assertion. The intermittent failure's cause remains unresolved.

The fifth slice closes the runtime input-conversion gap left by the fourth:

- Applying cached optional defaults and converting variable inputs now share
  the root's `evaluation_steps`. Cached preparation retains its distinct
  `loader_steps` charge; runtime work is charged per input/module instance,
  independently of cache warmth and worker scheduling.
- Collection copies reserve their element/field counts before allocation, and
  each conversion/default-tree entry charges work. Refused charges stop the
  traversal instead of producing a partially converted collection. Existing
  errors, sensitivity, and uncertain dependency evidence survive exhaustion.
- Conversion is isolated from analyzer orchestration in `input_conversion.rs`.
  Existing type semantics remain unchanged, including the original optional
  defaults retained across an override that replaces a type constraint.
- Regressions cover exact boundaries, lists/sets/maps/tuples/objects, cold/warm
  caches, HCL/JSON tfvars, repeated child instances, worker counts, adapters,
  discarded/caught values, failure precedence, and rejected fix verification.

This remains operation accounting. Primitive conversion internals, memory,
parsing, structural composition, and rule execution remain outside these
allowances. Runtime conversion still descends through the validated, bounded
type/default trees; replacing this recursion remains Phase 4 work.

Fifth-slice validation: 436 Rust workspace checks pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests), including the unchanged
76-case native output baseline. All 20 focused release unit/integration checks,
Clippy with warnings denied, formatting, and `git diff --check` pass. All 313
Python tests pass with the rebuilt extension and `OXTF_REQUIRE_TERRAFORM=1`.
Rust/Python fetch fixtures ran with loopback access; the sandbox denied the Rust
registry listener on the initial attempt. No fixtures were omitted.

The 504-root corpus now records 624,739 runtime steps, median 205, p95 5,595,
maximum 26,223, with no work exhaustion. The unchanged 1,000,000-step default
provides about 38 times the largest observed root's work. Loader measurements
are unchanged. [LIMITS.md](../LIMITS.md) records the timing investigation and
the remaining limits of this evidence.

The sixth slice adds shared rule-execution accounting in Phase 2:

- Each root owns a non-clonable `RuleBudget`, defaulting to 10,000,000 counted
  operations. Graph/file/module/resource admission, generic IR traversal, and
  interpreted Checkov execution borrow it; alternative runs cannot reset it.
- Refusal is sticky and typed. The engine records one exhaustion rule error,
  preserves earlier findings/errors, and stops later hooks for that root.
  Sensitive inputs cannot hide the safe exhaustion message. Status is `failed`,
  and fix verification fails. Ordinary rule failures still allow later hooks.
- Limits propagate through strict JSON/Python configuration, directory scans,
  plan scans without source mapping, and both fix-verification scans. Native,
  Rego, and callback hooks currently charge admission only.
- Checkov auxiliary JSON copies count nodes with a bounded explicit work stack
  instead of an unchecked recursive sum. Mutable interpreter caches distinguish
  root-run identity, preventing repeated scans of the same model from reusing
  state left by an interrupted run.
- Engine orchestration is split into explicit graph, file, module, and resource
  passes. Existing guarded interpreter/IR recursion remains for Phase 4;
  projections, backend built-ins, graph solvers, input bytes, and retained
  storage are not fully metered by this allowance.

The 504-root rule probe records a maximum of 68,146 steps for both the standard
security and all-profile catalogs. The finite default is about 147 times this maximum.
The seed maximum is 46. Standard/all runs each retain 14 ordinary rule errors;
source coverage gaps and unmetered backend internals limit this evidence.
[LIMITS.md](../LIMITS.md) records the exact units, catalog totals, reproduction
commands, and default rationale. This does not complete the performance matrix.

Sixth-slice validation: 450 Rust workspace checks pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests), including the unchanged
76-case native output baseline. All 16 focused release checks, Clippy with
warnings denied, formatting, and `git diff --check` pass. All 323 Python tests
pass with the rebuilt extension and `OXTF_REQUIRE_TERRAFORM=1`. Rust/Python
fetch fixtures ran with loopback access. Repeating the three corpus probes
after the final build reproduced every recorded work count and outcome.

The seventh slice bounds input admission and closes the cache-lifetime gap:

- `input_bytes`, `source_bytes`, `file_entries`, `directory_entries`, and `roots`
  have finite validated defaults. Discovery, catalogs, sources, plans, variable
  files, installed manifests, overlays, and contextual reads share scan-owned
  accounting. CLI overlay/stdin reads stop at the admitted size plus one byte.
- Raw snapshots, decoded text, parser-arena source copies, and Rego source
  copies reserve before allocation. UTF-8 expansion and narrowing to source
  spans/file IDs are checked. Cached snapshots do not charge again. This
  accounts for source payload, not the rest of an arena or exact RSS.
- Directory walks use explicit stacks with admission before queue growth.
  Exhaustion persists outside returned values and yields one terminal
  `coverage-storage` diagnostic. Incomplete before/after scans cannot verify a
  fix; ordinary failures retain precedence.
- Parsed modules and variable files initialize once under concurrent access.
  Their cache keys include input snapshot identity; module keys also include
  the loader allowance. Failed variable-file preparation is cached too.
- Checkov scratch, Rego engines, rendered documents, and exception caches now
  belong to the root's rule budget. They drop on normal return, failure, or
  unwind, including repeated plan scans on a persistent caller thread.
- Rego projection, engine admission, result conversion, and attribution spend
  counted rule work. `rego_time_ms` adds a separate cumulative cooperative
  timer, defaulting to 10 seconds per root. Exceptions and attribution calls
  share it. A typed timeout stops subsequent hooks and reports `failed`.
  Builtins, I/O, and Python callbacks are not forcibly preempted.
- Plan requests now honor `keep_models=false`, as directory requests do.
  A reproducible scan matrix and persistent-plan probe live in
  `tf_scan/examples/scan_limits.rs`; the rule probe also records Rego time.

Seventh-slice validation: 477 Rust workspace checks pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests), including the unchanged
76-case native baseline. All 69 focused release checks and 331 Python tests
pass with `OXTF_REQUIRE_TERRAFORM=1` and the rebuilt extension. Clippy with
warnings denied, formatting, and `git diff --check` pass. No fixtures were
omitted. The first Python run's new timeout test accidentally performed its
expensive work during catalog validation; making that work depend on scan
input exercises the intended runtime allowance. The focused 47-test limits
suite and full rerun then pass.

Measurements are recorded in [LIMITS.md](../LIMITS.md), with reproduction and
regressions in [VALIDATION.md](../VALIDATION.md). At the seventh-slice boundary, Phase 2/3 remained partial: source payload
admission did not bound AST chunks/nodes, values, graphs, provenance, results,
serialization, or Python argument/result allocation. Model/worker memory
admission, remaining backend/loader internals, guarded recursion replacement,
and the final structure/lint gates still require implementation. The seventh-slice
performance matrix was a new measurement anchor; a matching pre-change matrix
was not preserved and must not be invented.

The eighth slice makes arena growth and AST construction fallible:

- `arena_bytes` and `ast_nodes` are validated cumulative scan allowances,
  shared through the existing input budget by cached modules and variable
  files, JSON mapping/reparsing, overrides and default reparsing, template
  files, and Conftest HCL parsing. Low-level arenas have finite defaults.
- Atomic node admission and locked chunk growth prevent concurrent overbooking.
  Already-admitted space needs no shared mutex; fallible growth caps the backing
  bump before allocation and accounts for actual chunk payload growth. Metadata
  and allocations outside the arena remain separate. Construction accounting
  counts boxed values and vector insertions, including zero-sized values.
- Arena operations return typed refusal. Raw bump access and the unbounded
  string alias are removed; vector dereferencing exposes a slice. Reset/drop
  cannot refund cumulative admission or clear a failure. Cached failures do
  not retry or repeat charges.
- File parsers and module composition omit partial trees/definitions.
  Expression/template parsing returns an optional expression, so reporting
  refusal needs no arena-allocated placeholder. Earlier syntax errors retain
  failure precedence. Independent low-level module arenas report their
  refusal through the returned definition too.
- JSON grammar validation no longer builds an unadmitted temporary value
  tree. Python standalone parsing returns `ValueError` if the arena cannot
  construct its document. Scan adapters expose both new limits and retain
  `coverage-storage`, incomplete status, and refusal to verify incomplete fixes.

Eighth-slice validation: 496 Rust workspace tests pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests), including the unchanged
76-case native baseline. All 65 focused release checks and 335 Python tests
pass with `OXTF_REQUIRE_TERRAFORM=1` and the rebuilt extension. Clippy passes
with warnings denied. Construction sweeps cover each interruption point in
HCL/JSON preparation and overrides; other regressions cover concurrent arenas,
zero-sized values/reset, cache reuse, template `try`, Rego extensions, CLI,
plan source mapping, failure precedence, and fix verification.

The initial per-allocation mutex caused a parallel regression. Atomic node
reservation and mutex admission only for potential chunk growth removed it;
final matrix medians increased by at most 5.0% in elapsed time and 2.1% in peak
RSS, within the investigation gate. Outcomes and admission counts are unchanged.

The arena accounting contract and measured headroom are documented in
[LIMITS.md](../LIMITS.md). Phases 2/3 remain partial: parser scratch, value and
result builders, graph/provenance storage, serialization, Python boundaries,
and worker/model memory admission are still open. Input-driven recursion and
final function/lint acceptance remain separate work.

The ninth slice bounds evaluator text construction:

- Validated `text_bytes` is a cumulative scan allowance shared by root evaluators,
  loader/default conversion, contextual file functions, and templates. Atomic
  reservations prevent worker overbooking; warm caches do not repeat charges.
- A fallible text builder admits requested capacity before growth and charges
  the final `Arc<str>` payload copy. Extra allocator capacity grants no extra
  admission. Refusal remains sticky after temporaries are dropped.
- String builtins, literals, evaluated keys, captures, formatting, base64, and
  contextual text use admission. JSON decoding reserves text conversion cost;
  JSON text encoding uses a bounded explicit traversal stack. `jsonencode`
  checks potential expansion before exposing a structured value to later
  predicates. Unknown children remain structured.
- Resolver calls receive the active budget. Nested evaluation and primitive
  default/input conversion cannot reset it. Storage refusal retains uncertainty,
  sensitivity and dependency evidence, produces `coverage-storage`, survives
  `try`/`can` and discarded values, and prevents incomplete fix verification.

Ninth-slice validation: 505 Rust workspace tests pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests), including the unchanged
76-case native baseline. All 31 focused release checks and 337 Python tests pass
with `OXTF_REQUIRE_TERRAFORM=1` and the rebuilt extension. Clippy passes with
warnings denied, and formatting/diff checks pass. Boundary tests cover exact
text costs, Unicode behavior, amplification, cached defaults, shared workers,
uncertainty/sensitivity, prior errors, CLI/Python admission, and fix verification.

The pinned corpus admits 7,539,771 text bytes in every configuration, giving the
256 MiB default 35.6× headroom. Outcomes and input/arena counters are unchanged.
One noisy four-worker timing median crossed the 10% investigation gate; eleven
paired repeats with no code change did not reproduce it. The ranked hypotheses,
raw initial/repeat measurements, and decision to retain the implementation are
recorded in `bench/results/tigerstyle-text*.json` and LIMITS.md. No speedup is
claimed. Peak RSS median changes were below 1% in the full matrix.

The text accounting contract and remaining exclusions are in
[LIMITS.md](../LIMITS.md). This is not full value/output or process-memory
admission: containers, graph/provenance, metadata, generic predicate/presentation
copies, findings/diagnostics, serialized reports, Python boundaries, and
worker/model retention remain open. Standard-library and third-party allocation
failure still needs separate treatment beyond the fallible buffer reservations.

The tenth slice introduces builtin collection admission:

- `collection_bytes` is validated through Rust, CLI JSON and Python, and shared
  by all roots/workers, builtin/contextual calls, and cached default evaluation.
- Fallible vector builders reserve requested capacity before growth or mapping.
  Map insertion charges new logical key/value payload; replacement reuses a slot.
  B-tree overhead, unused slots, and container/Arc headers remain excluded.
- Structural and set builtins, product rows, text-to-collection results, numeric
  scratch and alternative argument rows use admission. Alternative expansion
  constructs complete rows once, avoiding repeated prefix copying.
- JSON decoding reserves parser/abstract container payload before either tree is
  built. `nonsensitive` preflights its copy with a bounded walk; `flatten` uses a
  bounded explicit stack. Shared backing data does not recharge on an Arc clone.
- Refusal remains typed and sticky through catches, discarded values, caches,
  and workers. Terminal storage coverage, failure precedence, uncertain
  dependencies, sensitivity, and incomplete fix rejection are preserved.

Tenth-slice validation: 518 Rust workspace tests pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests), including the unchanged
76-case native baseline. All 79 focused release checks and 339 Python tests pass
with the rebuilt extension and `OXTF_REQUIRE_TERRAFORM=1`. Clippy passes with
warnings denied; formatting and diff checks pass. Regressions cover exact
boundaries, rejection before copying/deserializing, concurrent admission,
alternative order and empty alternatives, error precedence, sensitivity and
uncertain dependencies, cached defaults, scan/plan/CLI/Python adapters, and
incomplete fix rejection. Limit provenance is normalized once per call boundary.

Every corpus configuration reserves 486,768 collection bytes, giving the
256 MiB default 551.5× observed headroom. Outcomes and existing admission counters
match the ninth slice. Two noisy four-worker timings crossed the 10% investigation
gate; eleven alternating pairs for each did not reproduce above-threshold
slowdowns. A negative GNU `time` sample prompted monotonic process timing in the
collection harness. Initial samples, the final matrix, repeat sets, ranked
hypotheses and the acceptance decision are retained in
`bench/results/tigerstyle-collections*.json` and [LIMITS.md](../LIMITS.md).
No scanner code changed during the performance investigation; no speedup is claimed.

This is builtin collection payload admission, not full value storage. Next:
bound expression literal/comprehension/splat and argument containers, semantic
conversion/model containers, graph/provenance, findings/diagnostics and output,
then worker/model retention. Public low-level Value construction, collection
headers and B-tree overhead also remain open. Preserve capacity for terminal
exhaustion reporting. Continue Phase 4 traversal replacement and Phase 6
acceptance after those storage contracts are enforced.

The eleventh slice (2026-10-22) extends collection admission through expression
evaluation:

- Tuple/object literals and static defaults, splats, comprehensions and grouped
  outputs, function arguments and final-argument expansion reserve their payload
  before growth. Exact-size destinations reserve before evaluating children.
- Conditional, unary/binary and traversal alternatives, `try` container copies,
  template parts and concatenation alternatives share the active scan allowance.
  Uncertain filters admit each copied output and the added alternative slots.
- Comprehensions and template directives borrow collections and bind iterators
  on the stack. Template trimming inspects neighboring elements directly.
- Refusal retains prior errors, sensitivity, and uncertain dependencies through
  catches and discarded values. Dependency normalization deduplicates after
  reducing certainty, making repeated refusal boundaries idempotent.
- New evaluator helpers are separated by responsibility into containers,
  comprehensions, catches and templates. Each new helper stays within the
  70-line function and 100-column limits. Existing evaluator dispatch and
  low-level recursive value APIs remain Phase 4/6 work.

Eleventh-slice validation: 526 Rust workspace checks pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests), including the unchanged
76-case native baseline. All 83 focused release checks and 342 Python tests pass
with the rebuilt extension and `OXTF_REQUIRE_TERRAFORM=1`. Clippy passes with
warnings denied. New regressions cover exact payload boundaries, admission
before child evaluation/dispatch, every uncertain-filter copy boundary,
sensitivity and dependency certainty, static/shared budgets, empty alternatives,
prior errors, caches, and incomplete fix verification. The 100,000-element
rejection probe allocates less than 64 KiB during evaluation.

Every corpus configuration admits 7,233,000 collection bytes, giving the 256 MiB
allowance 37.1× observed headroom. Outcomes and existing input/arena/text counts
match the tenth slice. Two initial elapsed medians crossed the 10% gate;
eleven alternating pairs per affected case measured +5.33% and +2.28% elapsed,
with peak RSS changes of +0.09% and +2.74%. The initial outliers, ranked hypotheses,
unchanged-binary repeats, and acceptance decision are retained in
`bench/results/tigerstyle-expressions*.json`. No speedup is claimed.

The expression accounting contract and exclusions are in [LIMITS.md](../LIMITS.md).
The next storage slice is semantic conversion/model containers, starting with
`input_conversion.rs`, `default_budget.rs`, and `variable_defaults.rs`. Graph
and provenance storage, findings/diagnostics and output/Python boundaries,
worker/model retention, remaining loader/rule internals, guarded-recursion
replacement, and final structure/lint acceptance are still unfinished.

The twelfth slice (2026-10-22) admits semantic conversion and default preparation
containers. Tracing the analyzer showed that model builders and expansion caches
need a separate failure-propagation change; they remain the next bounded slice.

- Runtime list/map/tuple/object destinations reserve before converting children.
  Optional defaults charge both intermediate copies and final payloads.
- Cached default preparation admits optional-default maps, child trees,
  common-type inference scratch, retained type payloads and type-tree copies.
  Storage refusal records the shared terminal reason and discards partial cached
  definitions without manufacturing syntax errors.
- Set deduplication compacts its admitted vector in place. Unique strings use
  allocation-free sorting; existing comparison/work charges remain unchanged.
- Conversion and common-type inference are separated into small helpers. New
  helpers stay within 70 physical lines and 100 columns. Existing recursion
  guards remain an intermediate measure, not completion of Phase 4.

Twelfth-slice Rust validation: 533 workspace checks pass with
`OXTF_REQUIRE_CORPUS=1` (two existing ignored tests), including the unchanged
native baseline. All 122 focused release checks pass; Clippy passes with warnings
denied. Boundary regressions cover typed exhaustion, admission before child
conversion, every byte allowance through default application/preparation and
cached overrides, warm-cache reuse, prior errors, sensitivity, dependency
certainty, and incomplete fix verification. The 100,000-element rejection probe
allocates less than 64 KiB during runtime conversion, inference or type copying.

All 344 Python checks pass with the rebuilt extension and
`OXTF_REQUIRE_TERRAFORM=1`. Formatting and whitespace checks pass. All eight paired corpus cases stay
below the 10% performance gate: elapsed medians change by −3.54% to +0.95%, and
peak RSS by −1.04% to +1.01%. Outcomes and existing input/arena/text counters match.
Collection payload rises to 8,350,520 bytes, with 32.1× headroom under the default.
Samples, fingerprints and acceptance are retained in
`bench/results/tigerstyle-semantic.json`; no speedup is claimed. The accounting
contract is in [LIMITS.md](../LIMITS.md).
Model construction, expansion/copy helpers and caches in `analyze.rs`, followed
by graph/provenance, results/output, and worker/model retention remain unfinished.
Semantic key/index text also remains outside text admission. No completion claim
is made for the broader migration.

The model slice should first make `build_module`, `eval_body`, instance/expansion
builders and memo caches propagate typed refusal before allocation. Include
`reference_value`, body-to-object/resource/module projections, and IAM policy
container copies. Replace `collection_items`' eager pair-vector copies with
borrowed iteration so `max_expand` is checked before allocating expansion input.
Keep terminal exhaustion diagnostics available when a partial model is discarded.

The thirteenth slice (2026-10-22) adds analyzer model collection admission:

- `build_module`, body/instance/expansion builders and per-root memo tables
  reserve collection payload before construction and propagate typed refusal.
  Reference-tree, resource/module/body and IAM projections use the same allowance.
- Expansion input is borrowed, with `max_expand` checked before iterator binding
  construction. Single `count`/`each` bindings are inline; splats reuse their
  admitted destination vector for subsequent traversals.
- Refusal discards unfinished resource bodies while retaining completed resources
  and the admitted module prefix. The terminal storage diagnostic remains outside
  ordinary collection admission. Prior errors, sensitivity and possible dependency
  evidence survive; incomplete scans cannot verify fixes.
- Builder, expansion and policy helpers now live under `analyze/`; the new helpers
  stay within 70 physical lines and 100 columns. Existing analyzer reference
  dispatch and guarded recursive walks remain separate structural work.
- Newly constructed models pay even with warm parsed definitions or disabled
  model retention. Parsed-definition indexes and `ModuleStore` entry metadata,
  installed-manifest decoding, plan-owned models, graph/provenance, output, text
  metadata, and live worker/model-memory admission remain open. The immutable
  loaded-module ownership/drop invariant is unchanged.

Thirteenth-slice validation: all 544 Rust workspace checks pass with the corpus
required (two existing ignored tests), including the unchanged native baseline.
All 133 focused release checks and 345 Python checks pass with the extension
rebuilt and Terraform required. Clippy, formatting and whitespace checks pass.
Boundary and allocation regressions cover preflight refusal, completed-resource
retention, error/sensitivity/dependency preservation, warm caches, workers,
retention and fix refusal.

All eight paired corpus comparisons pass the 10% elapsed/RSS gate. Elapsed
medians change by -6.50% to +6.64%, and peak RSS by -1.91% to -0.09%.
Outcomes and existing input/arena/text counters match. Collection payload is
42,055,016 bytes, with 6.38× headroom under the current default.
Samples, fingerprints and acceptance are in `bench/results/tigerstyle-models.json`;
no repeat investigation or speedup claim is needed.

The fourteenth slice (2026-10-22) adds parsed-definition and cache metadata admission:

- Configuration-file staging, retained file references, declaration vectors,
  symbol indexes and provider-name indexes reserve before growth. Indexing uses
  borrowed arena references without a second file list. A refused index discards
  every declaration and symbol lookup while retaining observed diagnostics.
- `ModuleStore` admits the logical map entry, boxed initialization cell and arena
  owner before insertion. A short miss lock couples admission to insertion;
  parsing runs outside it. Concurrent callers share one initialization and charge,
  warm hits do not recharge, and a refused insertion leaves the cache unchanged.
  The definition-before-arena drop order and immutable ownership remain unchanged.
- Installed manifests decode directly into an admitted record map. Each actual
  record reserves before field decoding; no intermediate record vector or copied
  key is needed. Cached failures retain typed storage exhaustion, and package-call
  vectors admit at the resolver boundary. Refusal reports `coverage-storage`
  without a misleading malformed/stale-installation diagnostic.
- Store and resolver callers propagate the fallible APIs. Loader, indexing, cache
  and manifest helpers remain within 70 physical lines and 100 columns. Existing
  guarded reference walks remain separate work.

Fourteenth-slice validation: all 554 Rust workspace checks pass with the corpus
required (two existing ignored tests), including the unchanged native findings
baseline. All 154 focused release checks and 347 Python checks pass with the
extension rebuilt and Terraform required. Clippy, formatting and whitespace
checks pass.

All eight paired corpus comparisons pass the 10% elapsed/RSS gate. Elapsed
medians change by -1.27% to +9.96%, and peak RSS by -1.18% to +0.99%.
Outcomes and existing input/arena/text counters match. Collection payload is
44,359,328 bytes, with 6.05× headroom under the current default.
Raw samples, fingerprints and acceptance are in
`bench/results/tigerstyle-metadata.json`; no repeated investigation was needed,
and no speedup is claimed.

The fifteenth slice (2026-10-22) adds composition and parsed-reference admission:

- `Origins` ownership/default/type-default maps and duplicate-name validation
  reserve logical entries before growth. Fixed singleton/settings membership
  uses inline flags. Terraform settings merge directly by stable file/block
  indices, removing the temporary position vector.
- Parsed-reference output and lexical-binding vectors reserve capacity before
  growth. Scope cleanup runs on both success and refusal. The completed reference
  vector transfers directly into the shared definition without another copy.
- Reference refusal discards declarations, indexes and partial reference edges
  together. Prior diagnostics remain visible; no incomplete dependency list is
  published as a complete definition. Override source ownership and loaded
  definition/arena lifetime invariants remain unchanged.
- Composition is split into preparation, validation, override and merge helpers;
  reference collection lives under `module/`. New production helpers remain within
  70 physical lines and 100 columns. Existing depth-bounded recursive walks remain
  part of the explicit-stack follow-up.

Fifteenth-slice validation: all 561 Rust workspace checks pass with the corpus
required (two existing ignored tests), including the unchanged native findings
baseline. All 186 focused release checks and 347 Python checks pass with the
extension rebuilt and Terraform required. Clippy, formatting and whitespace
checks pass.

All eight paired corpus comparisons pass the 10% elapsed/RSS gate. Elapsed
medians change by -2.49% to +1.72%, and peak RSS by +0.39% to +7.02%.
Outcomes and existing input/arena/text counters match. Collection payload is
52,557,488 bytes, with 5.11× headroom under the current default.
Raw samples, fingerprints and acceptance are in
`bench/results/tigerstyle-composition.json`; no repeated investigation was needed,
and no speedup is claimed.

The sixteenth slice (2026-10-22) completes area 1, graph and value provenance:

- Graph construction charges `rule_steps` per resource, dependency and candidate
  pair, and admits each logical edge and the sorted neighbour copy as collection
  payload. Refusal records a typed rule error for every graph rule; none runs on
  a partial graph.
- Provenance unions deduplicate in linear time; a 30,000-dependency join that
  took 131 seconds now takes milliseconds. Unions built during evaluation charge
  the active collection allowance through the depth guard.

Validation: 566 Rust and 347 Python checks pass; all eight paired comparisons
pass the 10% gate (elapsed -3.04% to +2.70%, RSS -6.77% to +0.34%) with matching
outcomes. Collection payload is 55.7 MB, 4.82× under the default. Contracts and
measurements are in [LIMITS.md](../LIMITS.md); samples in
`bench/results/tigerstyle-graph.json`.

### Remaining work after slice fifteen

Eight work areas remain. These are scope groups, not fixed-size implementation
slices; several will require multiple passes. The overall migration remains incomplete.

1. **Graph and value provenance:** admit graph nodes/edges, dependency sets,
   solver scratch and provenance construction/copies.
2. **Plan models:** bound plan decoding, owned model construction and copies
   through all supported plan entry points.
3. **Remaining metadata and text:** source-table/line indexes, parser scratch,
   path/key/address/manifest text, and other unaccounted metadata containers.
4. **Results and adapters:** findings, diagnostics, rule errors, rendering,
   serialization and Python argument/callback/result conversion. Preserve a
   terminal diagnostic outside ordinary result capacity.
5. **Live memory and scheduling:** admit active roots, worker working sets and
   retained models; justify stack sizes and distinguish cumulative from live memory.
6. **Traversal stacks:** replace remaining parser/evaluator/AST/value/semantic/
   rendering recursion, update generated visitors, and document destruction bounds.
7. **Work/API coverage:** close remaining work-counter gaps in native predicates,
   graph/structural operations and builtin internals; audit low-level entry points
   for allowance resets or unbounded construction routes.
8. **Policy and final acceptance:** finish function decomposition and paired
   invariants, enforce length/arithmetic/narrowing/unsafe policy in CI, review
   narrow exceptions, and run the final behavior/performance acceptance audit.

The next bounded storage slice should start with graph construction and traversal
containers in `graph.rs`, preserving dependency certainty and solver completion.
Value provenance is a separate part of the same remaining work area.

### Completion cut line (2026-10-22)

The list above grew as slices uncovered more containers; admitting every
container has no natural end. Completion is defined by this rule instead:

> A structure whose size is at most linear in already-admitted input is bounded
> transitively by the input limits and needs no reservation of its own. Only
> operations that can amplify — multiply, expand, copy across instances, or
> combine rules with resources — need their own admission.

Each existing slice remains valid; the rule only stops further per-container work.
Applied to the eight areas:

| Area | Decision | Reason |
| --- | --- | --- |
| 1. Graph and provenance | Done (slice 16) | Dependency sets and provenance copies can grow multiplicatively. |
| 2. Plan models | Closed | Plan JSON is admitted input; decoding and ownership are linear in it. |
| 3. Metadata and text | Closed | Line indexes, paths, keys and scratch are linear in admitted source. |
| 4. Results and adapters | Do, narrowed | Findings scale with rules × resources: cap findings and diagnostics, reserve the terminal diagnostic. Rendering and Python conversion are linear in the capped results. |
| 5. Live memory | Do, small | Measure and set the worker stack size after area 6; document live vs cumulative memory. |
| 6. Traversal stacks | Do, narrowed | Parser and evaluator, where input drives depth. Other walks run over depth-checked ASTs and keep their guards. |
| 7. Work coverage | Audit only | Record amplifying gaps and fix those; linear predicates and builtins are bounded by input. |
| 8. Policy | Ratchet | CI rejects new functions over 70 lines; existing ones are allowlisted and shrink over time. |

Remaining slices, in order: findings cap and terminal
diagnostic (4), parser/evaluator explicit stacks followed by stack sizing (6, 5),
then the function-length ratchet and the area 7 audit (8, 7).

Validation cadence: each slice runs the Rust workspace tests with the corpus
required, Clippy, and one corpus timing against the 0.5 s budget. The full paired
benchmark, Python suite and documentation updates run once per completed area.

## Scope and decisions

- Preserve Rust naming, enums, `Result`, RAII, and the arena-based AST. Apply
  units-last names to new limits, rather than renaming unrelated existing APIs.
- Adopt bounded allocation per scan as a documented adaptation of TigerStyle.
  Literal allocation only at process startup would require a different scanner
  architecture. Arena capacity alone is not an allocation limit.
- Validate external inputs and configuration with ordinary errors. Use
  production assertions for internal invariants after that validation.
- Replace recursion driven by input with bounded explicit work stacks. Temporary
  depth guards are an intermediate safety measure, not completion of that work.
- Preserve uncertainty, sensitivity, dependency provenance, finding identities,
  and completion status. Never substitute an empty collection or successful
  result for work omitted because a limit was reached.
- Keep pure refactors separate from behavior changes. Preserve existing
  generated-code conventions and change generators when generated traversal
  behavior needs to change.
- Use the current working tree as the implementation baseline. Existing local
  changes are not a prerequisite cleanup task for this plan.

## Audit evidence and acceptance targets

The probes used the current Rust sources in an isolated debug executable.
Stack probes used an 8 MiB stack; memory observations are process peak RSS,
not production performance targets. Existing parser/evaluator tests, including
the corpus differential test, passed despite these additional failures.

Parsing 100,000 unary operators overflowed the stack. A 30,000-term addition
parsed successfully, then overflowed during evaluation. A 1,024 by 1,024
`setproduct` reached 173 MiB RSS before rejecting its 4,096-row limit. `indent`
with `1e100` panicked with capacity overflow. Two 16-alternative values passed
to `lift2` produced 256 evaluations and alternatives despite the declared
`MAX_ALTERNATIVES = 16`.

| Finding | Evidence or source | Required outcome |
| --- | --- | --- |
| Recursion | Parser/evaluator stack aborts | Bounded traversal and controlled limit outcomes. |
| Late product limit | Product rows built before rejection | Validate cost before construction. |
| Unchecked output size | `indent` capacity panic | Validate arguments and output bytes. |
| Alternative limit bypass | `lift2` exceeds its cap | Bound work and results on every path. |
| Unbounded ingestion | Whole-file reads and growing caches | Per-input and aggregate budgets. |
| Missing invariants | Clamped consumption; reversed spans | Paired producer/consumer assertions. |
| Operating failure panic | Pool construction uses `expect` | Return a scan error. |
| Cache ownership | Rego retention; duplicate parsing | Scoped caches; single initialization. |
| Function size | `dispatch`: 769 lines; `run_with`: 186 | Small helpers; enforced length limit. |

Relevant implementations: [parser](../../crates/tf_parser/src/parser.rs),
[evaluator](../../crates/tf_eval/src/eval.rs),
[built-ins](../../crates/tf_eval/src/functions.rs),
[values](../../crates/tf_eval/src/value.rs),
[source table](../../crates/tf_semantic/src/source.rs),
[module store](../../crates/tf_semantic/src/store.rs),
[scan orchestration](../../crates/tf_linter/src/scan.rs), and
[Rego execution](../../crates/tf_rego/src/foreign.rs).

## Resource and failure contracts

Introduce a small internal `tf_limits` crate with no third-party dependencies.
It owns validated limits, checked counters, reservations, and typed exhaustion
reasons. It depends on no parser, evaluator, linter, or adapter crate. This lets
all layers share accounting without introducing dependency cycles.

`ScanRequest` owns the immutable limits. A scan owns aggregate retained-resource
accounting; each root owns deterministic evaluation counters and temporary-work
accounting. Standalone parser and evaluator entry points use explicit bounded
defaults and offer a caller-supplied limits path. Constructing a new evaluator,
following a module reference, or entering `templatefile` must not reset the
enclosing root's work allowance.

| Resource | Scope and owner | Enforcement point |
| --- | --- | --- |
| Source bytes, files, entries, roots | Scan storage | Before reads, registration, and queuing. |
| AST nodes/depth and arena bytes | Parser/module store | Before construction and arena growth. |
| Steps, value depth, elements, bytes | Root evaluation | Before operations and output allocation. |
| Alternatives and combinations | Expression evaluation | Before enumeration and result growth. |
| Resource/module instances | Root analysis | At the existing expansion boundary. |
| Dependencies and provenance | Analysis/graph builders | Before growing retained structures. |
| Findings, errors, output bytes | Results/rendering | Before appending or serialization. |
| Workers, temporary memory, caches | Scan execution | At admission; release on completion/error. |

Retain the existing 16 alternatives, 4,096 product rows, 64 instances per
expansion, and 16,384 instances per root as starting ceilings. Set the new
literal defaults from Phase 0 measurements before enabling each budget. Record
the measured corpus maximum, selected headroom, and rationale. Every default
must be finite; zero must have an explicit meaning and must not mean unlimited.

Limits describe both cardinality and bytes: a small list can contain huge
strings, and a short expression can produce enormous output. Use checked
addition/multiplication before reservations. Account for retained backing
allocations once when shared through `Arc`, and release temporary reservations
on all exits. Checked conversions protect `u32` spans and file identifiers.

Accounted memory is not a promise about exact RSS: allocator overhead,
third-party engines, and worker stacks must be measured separately. Report
those distinctions in performance results. Do not claim a process-wide hard
memory or time sandbox for in-process user Python callbacks. Such isolation
would be separate work; callback results still obey ingestion/output limits.

Failure behavior is part of the API:

| Condition | Outcome |
| --- | --- |
| Invalid limits or workers | Reject the request before work starts. |
| Required read or pool creation fails | Return an operating error through the adapter error path. |
| Analysis or output limit reached | Typed coverage reason; at least `incomplete` status. |
| Rule execution allowance exhausted | Rule error and `failed` status. |
| Internal invariant fails | Production assertion; never an unknown value. |

Reserve space for a terminal limit diagnostic outside the ordinary diagnostic
allowance, so exhausting the result budget cannot conceal incomplete analysis.
Existing failures retain precedence over incomplete status. Do not discover
exhaustion through string matching. Keep sensitive input values out of diagnostic
messages. `try`/`can` must not turn resource exhaustion into known success, and
fix verification must reject either scan being incomplete.

## Delivery sequence

Each implementation commit carries its own focused regressions and passes the
relevant existing checks. The order below is the default implementation order.

| Phase | Deliverable | Depends on |
| --- | --- | --- |
| 0 | Durable reproductions and comparable measurements | None |
| 1 | Immediate crash and ineffective-limit fixes | 0 |
| 2 | Shared budgets and propagation through public entry points | 1 |
| 3 | Bounded ingestion, storage, and scan scheduling | 2 |
| 4 | Explicit traversal stacks and paired invariants | 2, 3 |
| 5 | Scoped caches and predictable parallel costs | 3, 4 |
| 6 | Function structure, lint policy, and final acceptance | 1–5 |

### Phase 0 — establish regression and performance evidence

**Files:** existing parser/evaluator tests, scan completion tests, and `bench/`.

1. Port the isolated probes into durable regression cases for unary chains,
   flat binary chains, large indentation, products, and binary alternative
   lifting. Add nested templates and block bodies to cover separate paths.
2. Run crash cases in child processes with a timeout and core dumps disabled.
   A stack abort must not kill the test runner. Use small injected limits for
   normal boundary cases; do not make routine tests allocate hundreds of MiB.
3. Record a baseline at one worker and a fixed multi-worker count, for seed and
   standard catalogs, with `keep_models` both off and on. Include repeated plan
   scans with Rego on one persistent thread to expose cache retention.
4. Measure source bytes, file counts, AST depth/nodes, evaluation work, retained
   data, elapsed time, and peak RSS. Record revision, working-tree changes,
   corpus revision, machine, build mode, and exact command.

**Exit:** every observed failure has a reproducible input and intended result;
baseline measurements use the same scope and settings as later comparisons.
Regression tests land with their fixes, not as permanently failing CI jobs.

### Phase 1 — close demonstrated failure paths

**Files:** `tf_eval/src/{functions,eval,value}.rs`, `tf_parser/src/{parser,lib}.rs`,
`tf_linter/src/scan.rs`, `tf_scan/src/lib.rs`, and corresponding tests/adapters.

Land these as separate, reviewable changes:

1. Check `setproduct` row and element counts with checked arithmetic before
   building the next product. Bound tuple width as well as row count. Reserve
   only the approved output size, and assert the produced size afterward.
2. Validate `indent` arguments for finiteness, integer/domain validity, and
   representability. Calculate padding and final output bytes before `repeat`
   or replacement. Return an expression error for invalid arguments and a
   limit value for valid requests exceeding the output allowance.
3. Bound work in `lift2` before calling the supplied operation. Apply the same
   policy to branches, `Value::one_of`, templates, filters, and function lifting.
   Count work before deduplication; document separately how unique-result
   limits are counted. Preserve sensitivity and sound dependency uncertainty
   when returning a limit value.
4. Add temporary parser/evaluator depth guards and a constructed-AST-depth
   guard before downstream recursive consumers. Parser call depth alone does
   not bound a left-associated binary tree. Cover file, expression, template,
   JSON, and variable-file entry points. Carry limit reasons separately from
   syntax errors so well-formed oversized input gets a coverage outcome.
5. Replace thread-pool `expect` with a fallible path through `scan_with`,
   `tf_scan`, CLI, and Python. Reject zero/excessive worker requests and avoid
   creating a pool for no roots. Test a simulated pool-construction error
   without exhausting host threads.

**Exit:** the original probes return controlled outcomes in debug and release;
oversized products and alternative products perform no disallowed enumeration;
all completed under-limit fixtures preserve their results. Temporary guards
remain named follow-up work for Phase 4.

### Phase 2 — centralize budgets and completion semantics

**Files:** new `tf_limits` crate; `ScanRequest`, `ScanOptions`, `AnalyzeOptions`,
parser/evaluator entry points; plan loader; CLI and Python adapters.

1. Move Phase 1 ceilings and existing expansion limits into shared definitions.
   Add validated configuration, typed exhaustion reasons, and separate counters
   for cumulative work, live temporary storage, and retained storage.
2. Thread a budget context through parsing, evaluation, resolvers, contextual
   functions, and rule execution. Low-level public entry points must not offer
   an accidental unlimited route. Keep dependencies in the existing direction.
3. Add `ScanRequest.limits`; preserve it in `try_clone` and both fix scans.
   Expose the same names/defaults through a Python `limits` argument and a CLI
   `--limits PATH` JSON document. Reject unknown fields and invalid relationships
   before resolving inputs. Keep wire-format parsing in the adapters.
4. Connect limit outcomes to the existing completion and rule-error contracts.
   Include the exhausted resource and configured allowance without printing
   source values. Preserve failure precedence and redaction.
5. Make root work limits independent of worker scheduling. Aggregate storage
   exhaustion may stop a scan, but it cannot produce a complete result from
   whichever roots happened to finish first. Normalize diagnostic ordering.

**Exit:** equivalent directory, plan, overlay, Rust, CLI, and Python requests
share defaults and exhaustion behavior. Tests prove that nested evaluation
cannot reset budgets and that incomplete before/after scans never verify fixes.

### Phase 3 — bound ingestion and retained work

**Files:** `tf_semantic/src/{source,store,module,file_functions}.rs`, `tf_allocator`,
`tf_linter/src/{scan,engine}.rs`, `tf_plan`, catalog loaders, and renderers.

1. Enforce bounded reads for source, plan, policy, variable, and contextual
   function files. A metadata size check is an optimization, not enforcement:
   read at most the allowed bytes plus one to detect growth or unknown size.
   Validate overlays and programmatic documents before copying/registering them.
2. Bound directory discovery, queued roots, file IDs, listing caches, and both
   text/raw-byte caches. Account for duplicate representations where source
   text is copied into an arena. Preserve overlay precedence and snapshots.
3. Make arena growth fallible and budgeted. Enforce actual chunk growth as well
   as AST node counts, and audit direct `bump()` access so callers cannot bypass
   the cap. Preallocate reusable workspace only within approved bounds.
4. Bound value containers, strings, templates, graph edges, and provenance
   dependencies at their builders. A per-instance expansion limit does not
   cover nested comprehensions or large attributes.
5. Bound findings, diagnostics, rule errors, and serialization. Existing hooks
   that return whole vectors need budget-aware builders or sinks to prevent
   allocating the excess before the engine can reject it. Apply equivalent
   checks while ingesting Python callback results.
6. Schedule a bounded number of active roots. Derive admission from worker and
   working-set allowances; include `keep_models` in retained accounting. Do not
   claim that dropping one root's model bounds the entire scan by that root.

**Exit:** tests cover each limit at below/exactly/above its boundary and aggregate
exhaustion across several files or roots. Large reads and growth stop before
excess allocation; every stopped scan retains an explicit completion reason.

### Phase 4 — remove input-dependent recursion and assert contracts

**Files:** parser and AST code generator, evaluator/value/provenance traversal,
semantic analysis, span/source types, discovery, and relevant rule projections.

1. Inventory recursive paths reachable from user input, including generated
   visitors, JSON conversion, `Scope::with_all`, value comparison/flattening,
   reporting, rendering, and recursive destruction of owned values. Classify
   each as removed or protected by a validated hard depth bound with a reason.
2. Replace parser and evaluator recursion with explicit frame stacks. Preserve
   operator precedence, source spans, recovery, lexical scopes, sensitivity,
   short-circuiting, and `try` fallback order. Compute depth during construction
   or with an iterative walk; avoid repeated full-tree checks that become
   quadratic. Bound frame count and bytes before growth.
3. Convert downstream AST/value visitors and discovery to bounded iteration.
   Update generated visitors through `tf_ast_codegen`. Retain a depth ceiling
   where owned recursive representations still require it for safe destruction.
4. Replace resolver consumption clamping with a production assertion. Validate
   span ordering at construction and source bounds/UTF-8 boundaries when used.
   Check file IDs before narrowing and assert table index/ID agreement.
5. Pair invariants across boundaries: approved versus produced collection size,
   parser push/pop balance, memo-slot transitions, reservation/release balance,
   and file registration/lookup. Prefer types that make invalid states
   unrepresentable; reserve runtime assertions for remaining relationships.

**Exit:** original crash inputs terminate through normal results on ordinary
stacks; the parser corpus and evaluation semantics remain unchanged below
limits. No input-dependent recursive path is left without a documented bound.
The final policy records any remaining bounded-recursion deviation explicitly.

### Phase 5 — scope caches and control parallel cost

**Files:** `tf_rego/src/foreign.rs`, `tf_semantic/src/store.rs`, scan orchestration,
and performance harnesses.

1. Replace the process-thread lifetime of Rego `WORK`/document caches with an
   execution-session lifetime. Release cached engines, inputs, and documents
   on success and error. Account for nested/reentrant evaluation; an inner
   session must not clear or borrow-conflict with its caller's state.
2. Install a per-key module initialization cell before parsing. Concurrent
   readers share one initialized result or one load failure. Do not hold a
   global map lock during parsing, and test initialization failure/reentrancy
   so the change cannot deadlock.
3. Remeasure stacks after Phase 4 and replace the 64 MiB worker reservation
   with a justified size. Keep worker count within the configured ceiling and
   admitted work. Distinguish stack reservation from resident memory.
4. Document and measure the memory model:
   retained source/AST/cache data + retained results/models + active-root
   working sets + engine/allocator overhead. Reuse bounded temporary buffers
   where measurements identify repeated allocations.

**Exit:** repeated Rego plan scans release session-owned entries instead of
growing by bundle count. Tests observe cache ownership/counts, not a fragile
requirement that RSS immediately falls. Concurrent first access parses a module
once. Comparable benchmarks record throughput and peak memory at each worker
count, with no unexplained regressions.

### Phase 6 — simplify functions and enforce the policy

**Files:** `tf_eval/src/functions.rs`, `tf_linter/src/engine.rs`, remaining touched
core modules, workspace lint configuration, CI, and `docs/VALIDATION.md`.

1. Split the built-in dispatcher into individual operations and small family
   dispatchers. Keep argument validation and budget checks beside each
   operation. Split linter execution into graph, file, module, and resource
   passes while retaining one owner for findings, failures, and redaction.
2. Apply the same responsibility-based decomposition to touched analyzer and
   interpreter functions. Target at most 70 physical lines per handwritten
   production function and 100 columns per line. Audit remaining violations;
   each needs a concrete split or a narrow documented exception.
3. Add workspace lint policy for risky narrowing, unchecked resource arithmetic,
   undocumented unsafe code, and excessive function length. Keep Rust's
   formatter and existing `-D warnings` gate. Measure physical function length
   explicitly if the selected lint uses a different counting convention.
4. Establish a reviewed baseline for legacy exceptions and reject new ones.
   Keep generated files and FFI signatures narrowly scoped; avoid blanket
   lint suppression or source-wide mechanical renaming.
5. Document the Rust adaptation, limit defaults, ownership rules, and review
   checklist. Review meaningful paired invariants rather than enforcing an
   arbitrary assertion count on accessors or type-proven operations.

**Exit:** the audited dispatcher and orchestration functions meet the length
policy; CI enforces the adopted rules; every remaining deviation has a reason
and location. Record observed completion and performance against Phase 0.

## Validation and completion gates

Use focused tests for each change, then the existing checks in
[VALIDATION.md](../VALIDATION.md): formatting, Clippy with warnings denied,
workspace tests with the required corpus, Python tests, and the applicable
Terraform/Checkov/OPA comparisons. Exercise the new assertions and boundary
regressions in release as well as debug builds.

Behavioral gates:

- Under-limit fixtures preserve values, findings, fingerprints, uncertainty,
  provenance, sensitivity, suppression, and fix behavior. Pure refactors keep
  the native baseline byte-identical.
- Limits never produce a clean or verified result by dropping work. Test
  failures inside templates, child modules, rule hooks, output rendering, and
  the second scan of a proposed fix.
- Operating errors return diagnostics/errors; programmer-contract tests fail
  through production assertions. No host-resource exhaustion is needed to
  exercise operating-error branches.
- One and multiple workers produce equivalent completed results. Test limits
  with repeated/shared modules, overlays, and retained models.

Performance gates use release builds, one warmup, and at least five measured
runs with identical corpus, catalogs, worker counts, output, and completion
status. Compare median elapsed time and peak RSS. An unexplained regression
above 10% requires investigation and a recorded decision before acceptance;
safety work must not obtain a faster result by silently analyzing less input.
Treat the current failed signal observation as an observation, not a complete
analysis baseline. Do not overwrite the trusted signal baseline to make these
gates pass.

The plan is complete when all audit findings have regression coverage or an
explicitly justified adaptation, the budget contract reaches every supported
entry point, the original probes no longer crash or allocate beyond their
approved work, cache lifetimes are bounded, and the documented policy is
enforced in CI. Parser/evaluator fixes are the first deliverable; they do not
depend on finishing the broader refactor.

# Scan limits

Scans share input admission across roots and have separate runtime evaluation,
cached default-preparation, counted rule-work, and Rego-time allowances per root.
Child modules share their root's counters. Both scans used to verify a fix start
fresh with the same configuration. Counted work is independent of worker
scheduling; elapsed Rego time also depends on machine load.

| Setting | Default | Valid values |
| --- | --- | --- |
| `evaluation_steps` | 1,000,000 per root | Integers from 1 through 18,446,744,073,709,551,615 |
| `loader_steps` | 1,000,000 per root | Integers from 1 through 18,446,744,073,709,551,615 |
| `rule_steps` | 10,000,000 per root | Integers from 1 through 18,446,744,073,709,551,615 |
| `rego_time_ms` | 10,000 ms per root | Positive `u64` integer |
| `input_bytes` | 16 MiB per representation | 1 through 4,294,967,295 |
| `source_bytes` | 256 MiB per scan | Positive `u64` integer |
| `file_entries` | 16,384 per scan | 1 through 4,294,967,295 |
| `directory_entries` | 262,144 per scan | Positive `u64` integer |
| `roots` | 4,096 per scan | Positive `u64` integer |
| `arena_bytes` | 256 MiB per scan | Positive `u64` integer |
| `ast_nodes` | 4,000,000 per scan | Positive `u64` integer |
| `text_bytes` | 256 MiB per scan | Positive `u64` integer |
| `collection_bytes` | 256 MiB per scan | Positive `u64` integer |

An omitted setting uses the default. Unknown names, null, booleans, fractions,
negative values, and zero are rejected. Zero does not disable accounting.

## Configuration

Save a JSON object as `limits.json`:

```json
{"evaluation_steps": 1000000, "loader_steps": 1000000, "rule_steps": 10000000}
```

```sh
oxtf scan infra --limits limits.json
oxtf fix FINGERPRINT infra --limits limits.json
```

The CLI accepts at most 16 KiB of configuration and validates it before reading
input overlays or resolving scan inputs. Duplicate JSON fields are rejected.

Python accepts the same fields in a mapping:

```python
result = tfscan.scan("infra", limits={"rule_steps": 10000000})
```

`analyze`, `scan_plan`, and `fix` accept the same `limits` argument. Plan scans
apply `rule_steps` to their rules, including plans without source mapping.
The analysis allowances apply to source used for mapping findings to locations.

Rust callers assign validated limits to the request:

```rust
let mut request = tf_scan::ScanRequest::dirs(vec!["infra".into()], false);
request.limits = tf_scan::Limits::default().with_rule_steps(10_000_000)?;
let output = tf_scan::scan(request)?;
```

Low-level evaluators use finite defaults. When constructing nested evaluators,
pass the existing `EvaluationBudget` to `Evaluator::with_budget`; creating a
new budget means starting an independent analysis. Budgets cannot be cloned.

## Runtime accounting

Locals, runtime defaults, and `templatefile` evaluation share `evaluation_steps`.
An expression evaluation or static evaluation charges one step before entering.
A template entry charges one step. A template-parts traversal reserves one step
plus its element count before allocating trim buffers; each loop iteration
reserves the nested template again. A traversal reserves its operator count
before applying operators; splats also reserve the operators for each item.
These reservations can include operations subsequently skipped. Charges are
never refunded and cannot overflow. `AnalysisStats.evaluation_steps` reports
successful runtime charges.

Variable input conversion also uses this root allowance. Each type-conversion
entry and each application of a cached optional-default tree charges one step.
Lists, sets, tuples, and maps reserve their element count before copying;
objects reserve the number of declared fields before constructing the result.
Applying cached object defaults reserves the input fields and default entries
before copying/insertion, then the resulting fields before traversing children.
Nested conversions charge their entries separately. Reservations may include
fields that are subsequently skipped; charges are not refunded.

These charges apply to declaration defaults, HCL/JSON variable files, and child
module arguments. A cached definition's preparation uses `loader_steps` once
per root; applying its defaults and type constraint to each runtime input uses
`evaluation_steps` each time. Memoized variable reads do not repeat conversion.
Conversion exhaustion stops at the first refused charge and returns a limit,
retaining prior errors, sensitivity, and uncertain dependency evidence. It never
exposes a successful prefix of an input collection. The diagnostic points to the
variable declaration; evaluation inside an optional default retains its own
expression location.

Exhaustion stops further runtime evaluation for that root. The scan reports
`incomplete` with one located `coverage-budget` diagnostic naming
`evaluation_steps` and the configured allowance. An established input or rule
failure still gives `failed`. Exhaustion cannot be hidden by `try`, `can`, a
conditional, or discarding an intermediate value. Incomplete before/after scans
cannot verify a fix.

Fixed expansion and nesting limits observed during runtime evaluation also
persist as root coverage evidence, even if a parent discards the limit value.
Their existing per-value diagnostics remain available. Fixed stack ceilings
cannot be increased through the limits configuration.

## Cached default accounting

`loader_steps` covers default preparation during override composition. Modules
without override files skip this preparation; their defaults use the runtime
allowance. Within a composed module, all declarations, optional attribute
defaults, and successive override conversions share one loader counter.

The counter charges evaluator operations as above, plus entries into optional
default preparation, conversion, conversion checking, and type inference. It
reserves input/reference and collection-element traversals before bulk copies,
type-tree nodes before cloning, and candidate comparisons before set
deduplication. Reservations can include skipped work. These units bound the
counted operations, not the cost of each operation.

Each immutable cached module records its successful charges and first limit.
A root charges that recorded cost once per module definition before using its
defaults, even on a cache hit. Repeated instances of the same definition within
one root do not charge it again. Cold and warm caches and different worker
counts therefore have the same logical costs and completion outcomes.
`AnalysisStats.loader_steps` reports successful root charges; refused charges
are excluded, so exhaustion can occur with some allowance remaining.

Cache entries are partitioned by input snapshot and loader allowance. An exhausted entry cannot
poison a later request with a larger allowance. If preparation stops, the
module retains its files and diagnostics but exposes no partially composed
declarations. Work exhaustion yields a located `coverage-budget` diagnostic
naming `loader_steps`; fixed expansion/depth limits yield `coverage-loader`.
Either stops further child loading and runtime evaluation for that root and
makes the scan incomplete. Previously observed input errors retain failure
precedence. Discarding an intermediate limit value cannot hide exhaustion.

An uncached entry is prepared with the full configured loader allowance before
the root charges its recorded cost. If it exceeds the root's remaining
allowance, that one bounded preparation has already occurred. Thus the root
counter is a logical allowance, not a strict physical-work bound. Concurrent misses now share one initialization cell, including cached variable-file
failures. Warm hits do not reserve another source copy.

## Rule accounting

`rule_steps` is shared by all graph, file, module, and resource hooks in one root.
Each hook charges one step before admission. Generic rule IR also charges each
clause, expression/predicate entry, column-path segment, `for_each` element, and
visited comparison or list element. Boolean and collection predicates preserve
their short-circuit behavior. Graph IR reserves resource counts before its
verdict buffer and before applying each graph clause's results.

Interpreted Checkov checks borrow the same counter. Every alternative attempt
charges one step; statement/expression entries, selected comparison/traversal
operations, and copied auxiliary JSON nodes use the shared allowance as well as
the interpreter's existing 200,000-step per-attempt ceiling. The 64-alternative
run ceiling remains. Copying auxiliary JSON counts nodes with an explicit work
stack, reserving children before extending it or materializing the copy.
Mutable Checkov class caches are owned by the root's `RuleBudget` and replaced
per resource. Rego working engines, rendered documents, and exception caches
have the same owner. They are dropped on completion, failure, or unwind, and
nested root runs have separate scratch. No backend engine or mutable input
remains in a thread-local cache after a root finishes.

Charges cannot overflow or be refunded. On the first refused charge the engine
records a rule error naming `rule_steps` and its allowance, then stops later
hooks for that root. The message remains visible for sensitive inputs because
it contains no input values. Previously completed findings and ordinary errors
remain available. Status is `failed`, the CLI exits 3 even with `--fail-on never`,
and the scan cannot verify a fix. An ignored charge failure, interpreter
exception handler, or alternative cannot turn exhaustion into success or an
ordinary unknown. Ordinary rule errors still allow later hooks to run.

Low-level Rust callers can use `Linter::run_with_limits` and share a `RuleBudget`
with budget-aware rule methods. Standalone compiled-rule/Checkov evaluation
uses a finite default allowance. `RunOutput.rule_steps` counts successful
charges; `rule_exhaustion` retains the typed first refusal. These fields do not
change the serialized finding-record schema.

## Input admission and snapshots

The scan's `FileTable` owns one synchronized `InputBudget`. Root discovery,
source and variable loading, installed manifests, contextual file functions,
plan JSON, rule files, Rego policies/data, inline IR, and Conftest input parsing
use it. Standalone file/rule loaders use finite defaults. Low-level callers that
own a `FileTable` configure its input allowance with `FileTable::with_limits`
or `with_overlay_and_limits`; `AnalyzeOptions.limits` controls their root work.
`ScanRequest` configures both owners from the same limits.

Reads consume at most the smaller of the per-input and remaining aggregate
allowance, plus one lookahead byte. Metadata size is not trusted. A refused
read is not cached; a successful snapshot is reused even if disk contents
later change. Reading and admission are serialized to prevent concurrent
misses from overbooking storage. Directory walkers use explicit stacks and
charge each directory attempt and yielded entry before queuing it. Cached
module listings do not charge again. Discovery and module loading use separate
listings and both count; overlay entries count when merged into a listing.

`source_bytes` counts admitted payload, not allocator capacity or RSS. A raw
byte snapshot, decoded text, and parser-arena source copy each reserve their
own bytes. Lossy UTF-8 expansion is measured before text construction. JSON
configuration reparsing reserves another arena source copy. Rego's collected
source strings and engine source copies also reserve bytes. Repeated inline
IR/Conftest documents reserve on each admission. `file_entries` counts these
representations, including empty ones; it is not the number of unique paths.
Retrieving an existing snapshot or parsed definition costs no extra source
reservation. Separate registered paths are charged separately even when a
caller supplied shared text backing.
Reservations are cumulative and are not refunded during a scan. An admitted
source copy remains charged if subsequent arena allocation is refused.

A failed input charge leaves a typed sticky reason and one terminal
`coverage-storage` diagnostic. The scan is at least `incomplete`; earlier
observed errors retain `failed` precedence. Partial findings may vary with
worker scheduling after aggregate exhaustion, but no such result is complete
or verifies a fix. No source values appear in the diagnostic. CLI overlay and
stdin admission happens before constructing the request: refusal prints the
same coverage reason and exits 3, without a scan record. Other CLI read and
configuration errors still exit 2.

Python/Rust inputs already owned by the caller are checked before registration
and parsing. Python argument extraction can allocate before this check; this
is not yet an allocation limit on the adapter itself.

## Arena and AST admission

`arena_bytes` bounds the cumulative growth of parser-arena chunk payload
capacity. It includes alignment padding, unused chunk space, abandoned vector
buffers, source copies, decoded strings, and AST storage. Bump metadata,
global allocator overhead, and allocations outside these arenas are excluded.
Source copies also count toward `source_bytes`; these are independent limits
on overlapping representations, not two disjoint totals to add as heap usage.

Node reservations use a checked atomic counter. Operations that fit in admitted
chunk space disable further bump growth and avoid the shared mutex. Operations
that may grow a chunk hold shared admission while setting the backing bump's
ceiling to its existing capacity plus the scan's remaining allowance. Only
fallible bump operations may grow storage. Actual chunk growth is charged before
releasing admission, including growth during a refused operation.
Concurrent arenas cannot overbook the remaining capacity. Chunk rounding and
fragmentation can cause refusal before the successful byte counter reaches the
allowance. Bumpalo does not distinguish its ceiling from backing-allocator
refusal, so the diagnostic says allocation was refused within the allowance;
it does not claim to diagnose system memory exhaustion.

`ast_nodes` counts each boxed/arena-allocated value and each element inserted
into an arena vector, including labels and body items. It is a construction
count rather than the AST visitor's node count: wrappers and vector entries
count separately, and moving an entry during composition counts another
insertion. Strings use byte accounting. Zero-sized values still count, so an
empty payload cannot bypass the construction allowance. A refused node
reservation does not change a vector or its counter. A successful reservation
remains charged if chunk allocation subsequently fails. Chunk growth is also
counted on failure. Concurrent work already admitted may finish, but aggregate
refusal cannot disappear from the scan's completion status.

Both counters are cumulative. Dropping a temporary arena or resetting one does
not refund admission or clear a refusal. `FileTable::allocator` and
`SourceFile::allocator` share their snapshot's budget. Cached modules, variable
files, JSON mapping/reparsing, override composition and default reparsing,
`templatefile`, and Conftest HCL parsing use that shared budget. A cache hit does
not repeat construction charges. Fresh low-level `Allocator::new` calls use
finite defaults; callers that want shared limits pass an `Arc<InputBudget>` to
`Allocator::with_budget`. Raw bump access and the unbounded arena-string alias
are removed, and vector dereferencing exposes only a slice.

Arena allocation, boxes, string copies, vector `push`, and vector `extend` now
return typed exhaustion. Native/JSON file parsers retain diagnostics and expose
an empty body after refusal. Expression/template parsers return `None` rather
than allocating an error placeholder after exhaustion. Module composition also
discards partial effective definitions. Python's standalone `parse` raises
`ValueError` if its arena cannot construct the document. Normal syntax errors
still return the recoverable document. JSON grammar validation uses a
non-retaining serde visitor before constructing the admitted tree.

Shared refusal is sticky and produces the same terminal `coverage-storage`
diagnostic as input admission. Earlier syntax failures retain precedence;
`try`, cached failures, and Rego extension calls cannot hide the refused work.
Fix verification requires complete before/after scans. Diagnostics use storage
outside the AST arena, so the terminal reason needs no further arena allocation.
The separate diagnostic/output budget is still future work.

## Rego execution

Rego adapter work uses `rule_steps`: body/value projection entries, collection
visits, source/string chunks of 64 bytes, engine evaluation attempts, result
conversion visits, and attribution comparisons. Cached file projections pay
the same preflight charge as cold projections. These are logical operations,
not instructions inside regorus.

`rego_time_ms` separately limits cumulative elapsed engine execution per root.
Every call receives the remaining allowance, with cooperative timer checks
every 128 regorus work units. Working-engine setup and completed calls also
charge elapsed time at the boundary. A typed timeout stops later hooks, reports
a safe rule error, and makes the scan `failed`. Reusing an engine, evaluating
exceptions, and attribution retries cannot reset the allowance. Ordinary
standalone engine operations and catalog preparation have a finite 10-second
per-call timer. Parsing is outside that timer. The default is provisional;
measurements below describe the fixtures used to review it.

The timer is cooperative: it cannot preempt a single builtin, filesystem call,
or arbitrary Python callback. It is not a hard process deadline. Engine-owned
allocations are not currently charged as bytes. `RunOutput.rego_elapsed` reports
admitted elapsed execution, capped at the allowance after timeout.

## Evaluator text admission

`text_bytes` is cumulative across roots, workers, cached default preparation,
runtime conversion, and nested template/file functions. Standalone evaluator
and builtin entry points use finite defaults. Custom resolvers receive the
calling evaluator's budget explicitly. Reusing an admitted `Arc<str>` does not
charge another copy; dropping buffers or cached results does not refund charges.

The counter admits these operations before construction:

- Literal string and evaluated object-key payload copies.
- Text builder capacity growth and the final copied `Arc<str>` payload.
  Builders grow geometrically with checked arithmetic, reserve fallibly, and
  never publish a partial string. Requested capacity excludes allocator metadata and any extra space returned by
  the allocator; extra capacity grants no additional admission.
- Builtin string transformations, replacement, joining, formatting, capture
  strings, splitting, base64 encoding/decoding, and indentation. Substring
  extraction streams characters instead of allocating a character vector.
- Context-sensitive Unicode lowercase reserves three times the input byte
  length for the standard-library transformation, then charges the output copy.
  Floating-point precision reserves precision plus 330 bytes for both formatting
  scratch and the destination before invoking Rust's formatter. Hash encodings
  reserve 1,024 bytes; CIDR formatting reserves 512 plus 128 per argument.
- `jsondecode` reserves four times its input length for decoded text, parser
  text scratch, and abstract-value string/key copies. Its container allocations
  use the separate builtin collection reservation described below. JSON used as text is written directly from
  borrowed values with an explicit traversal stack bounded at 128 frames.
- `jsonencode` admits potential text materialization before exposing its
  structured value to predicates and projections. Unknown children remain
  structured. This preflight can consume admission even when the caller only
  inspects the structure. Later legacy predicate/presentation copies are not
  charged again and remain part of the outstanding output-storage work.
- Contextual file/base64/hash values and template expansion use the same scan
  budget. Loader and runtime primitive-to-string conversions also share it.

These are construction reservations, not a process RSS limit or a promise to
use every last byte. Geometric growth and conservative reservations may refuse
an operation before the counter reaches its allowance. Failure is sticky and
reported by the scan's terminal `coverage-storage` diagnostic. `try`, `can`,
discarded values, another evaluator, and a warm cache cannot clear it. Prior
errors, sensitivity, and uncertain dependency evidence survive. Incomplete
scans cannot verify a fix. String/Vec builder reservation failures are handled;
standard `Arc` and third-party allocations can still abort on system OOM.

## Builtin collection admission

`collection_bytes` is a cumulative scan allowance for collection construction
inside evaluator builtins and pure/contextual function alternative expansion.
It is shared across roots, workers, runtime calls, and cached default evaluation.
A warm cache does not charge again, and dropping a temporary does not refund it.
Standalone builtin calls use finite defaults; callers that make several calls
can share an explicit `InputBudget`.

The accounting contract is logical collection payload, not actual heap size:

- Vector builders charge requested capacity times `size_of::<T>()` before
  fallible reservation. Exact-size collection copies reserve before invoking
  their mapping closures. Incremental builders grow geometrically; extra
  allocator capacity grants no additional admission.
- A new map entry charges `size_of::<(K, V)>()` before insertion. Replacing an
  existing entry charges no new slot. B-tree nodes, unused slots, and allocator
  metadata are excluded. Nested transpose groups charge both their temporary
  map representation and final object entries.
- Structural builtins, products, split/capture results, format-list rows,
  numeric argument scratch, and set-operation scratch use these builders.
  Alternative expansion constructs each complete argument row once and charges
  result and flattened-alternative vectors. Shared `Arc` backing data is not
  copied or charged by an ordinary value clone.
- JSON decoding reserves container payload from input length before parsing or
  constructing the abstract-value tree. This conservative reservation covers
  parser vector capacity and both representations' logical entry payloads.
  The per-input-byte weight is four parser value slots, one abstract value
  slot, and one key/value pair for each representation (264 bytes on the
  measured 64-bit build). Each JSON node needs at least one input byte, and
  four slots cover a parser vector's minimum capacity and geometric growth.
  Container headers and B-tree overhead remain excluded. Text has its own
  existing reservation. It may reject a small result encoded
  in a large document before the allowance is fully used.
- `nonsensitive` preflights all container copies with a bounded explicit walk
  before entering its existing copier. Shared subtrees pay per copied occurrence.
  `flatten` now uses a bounded explicit stack. Both stop at 128 traversal frames.

Refusal is typed and sticky, retains sensitivity and uncertain dependencies,
survives `try`/`can` and discarded values, reports `coverage-storage`, and prevents
incomplete fix verification. Existing failures keep precedence. Vector
reservation failures use this same terminal path; standard B-tree, Arc, and
third-party allocations can still abort on system OOM.

The eleventh through thirteenth slices extend the same allowance to expression,
semantic conversion and analyzer model containers as described below. It does **not** account for
public low-level `Value` constructors, provenance/dependency joins,
graphs, generic predicate/presentation copies, or container/Arc headers. Those
builders remain subsequent migration work. The counter must not be described
as complete value storage or a process memory limit.

## Expression collection admission

`Evaluator` now uses the active scan's `collection_bytes` allowance for tuple
and object literals (including static defaults), splats, comprehensions,
function arguments and final-argument expansion, conditional and operator
alternatives, traversal projections, `try` container copies, and template parts
and concatenation alternatives. Creating a nested evaluator does not reset it.

Exact-size destinations reserve before evaluating or mapping children. A new
object entry reserves its logical key/value slot after the key is known and
before evaluating the value; replacing a key reuses the slot. Comprehension
outputs grow geometrically, and uncertain filters reserve both the additional
alternative slots and each copied list, object, or grouped-list payload before
copying. Grouped results also charge their final object entries. Temporary
alternative and template buffers count their concrete element sizes.

Comprehensions and template directives borrow source collections. Their iterator
bindings live on the stack. Template whitespace trimming inspects neighboring
elements directly. These paths no longer allocate temporary input-pair,
binding, or trimming vectors. Shared `Arc` clones retain their existing
no-new-payload contract.

Refusal preserves errors already observed, sensitivity, and possible dependency
edges. Dependency certainty is normalized before deduplication, so a refusal
crossing several boundaries does not multiply the same dependency. Catches,
discarded expressions, cached defaults, and concurrent roots retain the shared
terminal storage outcome. The allocation regression rejects copying a
100,000-element input through a splat, expanded call, comprehension, or `try`
with less than 64 KiB allocated during evaluation, excluding input construction.

The standalone low-level `lift1`, `lift2`, `binary`, and `Value` construction and
projection APIs remain outside this byte accounting. Evaluator call sites use
budgeted lifting before reaching primitive operations. Provenance allocations,
container headers, B-tree overhead, and system OOM behavior retain the exclusions
above. Existing guarded recursion is not removed by this slice.

## Semantic conversion collection admission

Runtime input conversion and cached default preparation use the active scan's
`collection_bytes` allowance. This includes list, set, tuple, map and object
conversion destinations; optional-default maps and child trees; intermediate
copies while applying defaults; common-type inference scratch; retained tuple,
object, list and map type payloads; and cached concrete-type copies.

Exact-size vector destinations reserve before child conversion. Map conversions
reserve their candidate key/value slots before child processing. Object type
constraints reserve one candidate slot per declared field, including duplicate
or omitted fields, so their charge can exceed the final map's entry count.
Optional-default preparation charges new map entries before evaluating defaults
or constructing child trees. Applying defaults charges the source map copy,
newly added entries, and the final converted map separately.

Inference reference buffers use their known upper bound or geometric growth.
Type-tree copies preflight every tuple/map/boxed payload and charge their
explicit traversal buffer before the existing derived clone runs. Set
conversion compacts its already admitted vector in place and sorts unique
strings without an additional allocation. Work charges for comparisons and
conversion are preserved.

Cached preparation pays once per shared definition; cache hits do not recharge
its payload. Runtime conversion pays for each newly constructed destination.
Refusal records typed storage exhaustion, discards partial cached definitions,
retains existing errors and runtime sensitivity/dependency evidence, and prevents
incomplete fix verification. Boundary sweeps cover every byte allowance across
nested optional defaults, common-type inference and cloning, overrides, and
warm-cache refusal. The allocation probe rejects 100,000-element runtime values,
inference inputs and cached type copies with less than 64 KiB allocated during
the operation, excluding fixture construction.

This slice accounts for collection payload, including type-box payload. New
UTF-8 key/tuple-index text in semantic metadata and schema-derived object keys
remains outside `text_bytes`; scalar coercion still uses text admission. Model
builders, instance/expansion caches and projection copies are admitted by the
following slice. Container headers, B-tree overhead, provenance, and standard allocator OOM
behavior retain the existing exclusions. The validated recursive type/value
walks still require the planned explicit-stack replacement.

## Analyzer model collection admission

The thirteenth slice extends `collection_bytes` to analyzer-owned instances,
model modules/resources/attributes/blocks, variable/output/local/symbol tables,
whole-file values and arguments, expansion containers, and per-root definition,
variable/local/output/resource/child memo entries. Vector growth reserves its
requested payload capacity before construction. Hash maps charge logical
key/value entries before inserting or reserving a slot; spare hash buckets and
control bytes are excluded, as are B-tree node overhead and container headers.
Instance and expansion `Rc` payloads count; reference-count headers do not.

Reference-value copies preflight their full destination tree, including lists,
objects, alternatives and JSON wrappers. Resource and module projections reserve
before evaluating children. Body-to-object and IAM policy projections admit
intermediate grouping, statement, principal and document containers. Resource
splats apply remaining traversals in their admitted vector. Resource, module and
dynamic expansions borrow source collections and check `max_expand` before
constructing iterator bindings. One `count`/`each` binding is stored inline.

The allowance remains cumulative across roots and workers, even when completed
models are discarded. A warm parsed definition does not recharge its cached
payload, but every new instance/model and projection pays for its own containers.
Memo hits only clone shared backing data. Refusal propagates through fallible
builders, preserves already observed errors and sensitive source marks, and
keeps dependencies possible at stopped value boundaries. Unfinished resource
bodies are discarded. Completed resources and the admitted module prefix remain
available with the terminal `coverage-storage` diagnostic; missing entries must
not be interpreted as known absence. Incomplete scans cannot verify fixes.

Boundary tests cover every byte through a two-resource model and a nested
reference copy, sampled boundaries through dynamic/child/resource/module/IAM
projections, cache reuse, prior errors, workers, model retention, and Python.
The allocation probe inspects a 100,000-element expansion input without any
allocation and rejects its reference copy or excessive expansion with less than
64 KiB allocated during the operation, excluding fixture construction.

This is analyzer model payload admission, not complete model memory accounting.
The following slice admits parsed-definition indexes, `ModuleStore` cache-entry
metadata and installed-manifest records. Paths/key/address text, graph/provenance, result/presentation
copies, public low-level `Value` and model constructors, and plan-owned model
construction remain excluded. Worker concurrency and live retained-model memory
still need separate admission. Existing guarded recursion and standard allocator
OOM behavior retain the earlier limitations.

## Parsed-definition and cache metadata admission

The fourteenth slice extends `collection_bytes` to configuration-file staging,
retained source/AST pairs, declaration vectors, symbol and provider-name indexes,
shared parsed-cache entries and installed-manifest records. Vectors reserve
requested capacity before growth; hash maps count logical key/value entries.
Indexing borrows each retained arena reference directly. Module availability
checks borrow the shared directory listing without copying its paths.

Each new `ModuleStore` entry admits the logical key/value pair, boxed `OnceLock`
payload and separately boxed allocator owner before insertion. Arena chunks keep
their separate allowance. The miss lock covers admission and insertion only;
initialization happens outside it. Concurrent misses share the cell and its cost,
and warm hits share both successes and failed initialization. Refused admission
inserts nothing. Input identity and loader allowance remain part of the key.
The owned definition still drops before its arena; references remain immutable
and cannot outlive the store. Cache APIs now return admission errors to callers.

Declaration or provider-index refusal discards the partially indexed definition;
no prefix of declarations or dangling symbol indexes is exposed. Diagnostics
already observed remain available. Shared storage exhaustion stays terminal and
does not manufacture a syntax error. Successful cache hits remain usable for
already completed model output, without another admission charge.

Installed manifests stream each actual record directly into a reserved hash
slot, before deserializing its fields. The record key moves into the map instead
of being copied. There is no intermediate record vector. Duplicate records,
missing fields and trailing input remain invalid; unknown fields remain ignored.
Attempted records consume admission even if later validation fails. Manifest
results are cached per root, including typed storage failure. Resolved package
call vectors reserve in the resolver, including direct callers. Storage refusal
produces the terminal coverage diagnostic without a stale-installation warning.

Boundary tests cover every byte of declaration/index construction and manifest
record admission, JSON provider preparation, warm hits, concurrent module and
variable-file requests, partial-index cleanup and earlier errors. A one-million-
byte record field is rejected before decoding, both as the first record and after
an admitted record, with less than 4 KiB requested allocation during the operation.
Fixture and source construction are excluded from that allocation measurement.

This accounts for logical payload, not actual hash-table capacity, allocator
bookkeeping or live heap. Spare buckets/control bytes, path/key/source/version
text, parser temporary text, diagnostic capacity and standard allocator OOM
retain existing exclusions. `FrozenMap`/box allocation can still abort on system
OOM after logical admission. The following slice admits composition ownership/
default lookup tables, validation scratch and parsed reference containers;
graph construction and value provenance remain separate work.

## Composition and parsed-reference admission

The fifteenth slice admits the logical entries in `Origins` source-ownership,
converted-default and optional-type-default maps before insertion. Updating an
existing key does not charge another entry; default conversion and copied type
trees retain their own admission. Duplicate-attribute validation admits its set
entries. Singleton and Terraform-settings checks use fixed inline flags. The
Terraform-settings merge walks stable outer file/block indices directly, so it
needs no position vector. Arena item movement retains existing arena admission.

Reference-edge and lexical-binding vectors reserve requested capacity before
growth, including iterator bindings whose body contains no references. The edge
slot reserves before copying its owned symbol names. Binding cleanup restores
the outer scope on both success and refusal; template, comprehension and dynamic
iterator names retain their previous meaning. Completed reference storage moves
directly into the definition's shared vector. Warm definitions share that vector
without paying again.

If composition or reference collection refuses storage, the module exposes no
partial declarations, indexes or reference edges. Already observed syntax or
composition errors survive, and the scan retains its terminal storage diagnostic.
An incomplete dependency list cannot masquerade as complete knowledge. Override
spans continue to identify their original source files. Loaded definitions remain
immutable and drop before their arenas.

Tests sweep every reference-container byte and a small composition's every-byte
boundary; broader sampled cases cover HCL/JSON defaults, multiple Terraform
settings bodies, overrides, source ownership and warm cache reuse. Scan checks
reject partial reference models with retention both enabled and disabled, keeping
earlier errors. A one-million-byte symbol is refused before copying its text with
less than 4 KiB allocated during the measured operation, excluding the fixture.

Hash-table spare capacity/control bytes, container headers, diagnostic storage,
and symbol/key text retain the earlier exclusions. The reference slot protects
the new edge allocation; the symbol's text length still needs text admission.
Composition and reference traversal work remain outside the work counter.
Existing parser-guarded recursive walks still need explicit traversal stacks.
Graph solver/dependency construction and evaluator value provenance are separate
from these cached, parsed reference records.

## Remaining scope

Input, arena, evaluator text, builtin, expression, semantic conversion, analyzer
model and parsed-definition metadata admission do not bound line indexes,
parser scratch strings, paths, remaining value containers and source-table metadata,
plan models, graph/provenance allocations, findings, diagnostics, output
serialization, or Python argument/result conversion. Retained models and active
workers still need memory admission. Native rules and Python callbacks charge
hook admission; native Checkov predicates, graph solver internals, structural
module composition, and many builtin internals remain outside counted work.
Standalone parser/JSON arenas now have admission; their scratch collections,
error lists and decoded temporary strings still need the complete storage contract.
This is not a process-wide CPU or memory sandbox.

Those gaps remain in [Phase 2/3 of the TigerStyle plan](plans/TIGERSTYLE_PLAN.md).
The temporary depth guards still need replacement with explicit traversal
stacks, including runtime conversion's descent through validated type/default
trees. The completed directory walkers do not close that broader recursion work.

## Default measurement

On 2026-10-21 the work probe scanned all 504 discovered roots in the
pinned 17-repository corpus, with `whole_files=true`, one thread, a shared
module/file cache, and each completed model dropped. It loaded 2,199 files.

| Measurement | Observed |
| --- | --- |
| Total successful steps | 624,739 |
| Median root | 205 |
| 95th percentile root (floor rank) | 5,595 |
| Largest root | 26,223 |
| Roots exhausting the default | 0 |
| Release median elapsed time (CPU 0, five runs) | 1.067 s |
| Release median peak RSS (same runs) | 73,604 KiB |

The largest root was
`terraform-aws-modules__terraform-aws-lambda/examples/build-package`.
The default gives about 38 times that root's observed work. These counts include
runtime input conversion; before that accounting was added, the probe reported
534,509 total steps and a 22,116-step maximum. The larger counts measure work
that was previously uncharged. These counts cover available source analysis,
including roots with unrelated coverage gaps; they do not prove complete
Terraform execution.

The first timing comparison against the saved pre-slice release probe crossed
the plan's 10% investigation threshold. Repeats alternated the two binaries,
measured child CPU time, and finally pinned both to CPU 0. Each series began
with one warmup per binary. All runs retained the same 504 roots and 2,199 files,
with no work exhaustion in either version; rules were not run.

| Series | Measured runs per binary | Before median elapsed | After median elapsed |
| --- | ---: | ---: | ---: |
| Initial, unpinned | 5 | 0.696 s | 0.784 s |
| Repeat, unpinned | 10 | 0.771 s | 0.824 s |
| Repeat, CPU 0 | 5 | 1.170 s | 1.067 s |

Median child CPU time was 0.738/0.704 s before/after in the unpinned repeat and
0.852/0.828 s in the pinned repeat. Individual elapsed times ranged from about
0.61 to 1.32 s. Pinned median peak RSS was 73,976/73,604 KiB before/after.
Decision: retain the accounting checks. The initial slowdown did not reproduce
consistently, and the repeats do not show increased median CPU time or peak RSS.
This noisy host comparison establishes neither a speedup nor a precise
regression cost. The full Phase 0 catalog/worker/retention matrix remains open.

The saved baseline executable was copied before this slice from
`target/release/examples/evaluation_budget` to
`/tmp/oxtf-input-budget-probe-before`; its SHA-256 was
`9d7fff8637d281571dde27e2b8bd95360bc0d3f2ca817e37ebb0a9964df0c9ed`.
Raw samples and the comparison script remain under `/tmp/oxtf-input-budget-*`.

The same run recorded zero loader steps: none of these roots exercised cached
override-default preparation. The loader default is therefore provisional;
this corpus cannot establish its production headroom. Synthetic modules with
one variable and an empty `override.tf` exercise the new counter:

| Default shape | 64 elements/fields | 256 | 1,024 |
| --- | ---: | ---: | ---: |
| `list(number)` with distinct integers | 845 | 3,341 | 13,325 |
| `set(number)` with distinct integers | 2,861 | 35,981 | 537,101 |
| Object of `optional(number, 1)` fields, default `{}` | 586 | 2,314 | 9,226 |

All nine preparations finish within the default. A 2,048-element distinct
number set stops after 999,789 successful steps when the next comparison
reservation would exceed 1,000,000. Set deduplication's quadratic comparisons
are intentionally visible in the charge. This evidence exercises the counter;
it is not a representative workload survey.

Reproduce with:

```sh
cargo build --release --offline --locked -p tf_linter --example evaluation_budget
/usr/bin/time -v target/release/examples/evaluation_budget corpus/repos
```

For the pinned timing series, prefix that command with `taskset -c 0`, warm up
each binary once, then alternate the saved baseline and current binary for five
measured runs each. Keep workload and affinity identical within a comparison.

Reproduce the synthetic shapes in temporary directories, then run the same
probe (the final directory also includes the intentionally exhausted set):

```python
from pathlib import Path

base = Path("/tmp/oxtf-loader-probe")
for size in [64, 256, 1024, 2048]:
    for kind in ["list", "set", "optional"]:
        if size == 2048 and kind != "set":
            continue
        root = base / f"{kind}-{size}"
        root.mkdir(parents=True, exist_ok=True)
        constraint = f"{kind}(number)"
        value = "[" + ",".join(map(str, range(size))) + "]"
        if kind == "optional":
            fields = ",".join(f"v{i}=optional(number, 1)" for i in range(size))
            constraint, value = "object({" + fields + "})", "{}"
        source = f'variable "value" {{\n type = {constraint}\n default = {value}\n}}\n'
        (root / "main.tf").write_text(source)
        (root / "override.tf").write_text("")
```

```sh
target/release/examples/evaluation_budget /tmp/oxtf-loader-probe/set-1024
target/release/examples/evaluation_budget /tmp/oxtf-loader-probe/set-2048
```

Machine: x86-64 Linux/WSL, Intel Core i9-12900HK, eight visible logical CPUs;
Rust 1.96.0. Measurement used the uncommitted TigerStyle budget implementation
on base `c6eb123bbb1753dabcaf32ea507018763269d08b`, including the existing local
source-function, signal, and earlier TigerStyle changes. Rules were not run.
Corpus revisions are pinned in [repos.lock.pinned](../corpus/repos.lock.pinned),
SHA-256 `abf2de706b57e2ace847b635fe31b00c4355235a72b46c4178507eaff17cf7d2`.

## Rule default measurement

The rule probe ran on the same machine and corpus on 2026-10-21. It resolved
each catalog, analyzed 504 roots serially using a shared file/module cache, ran
their rules, and dropped each model. `whole_files` follows the catalog's needs;
these catalogs loaded 2,195 files and analyzed 5,379 resource instances.
The probe raises only `rule_steps` to `u64::MAX` to avoid censoring its counts.

| Catalog | Total steps | Median root | p95 root (floor rank) | Maximum root | Findings | Rule errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Seed | 1,902 | 1 | 14 | 46 | 2 | 0 |
| Standard security | 455,669 | 14 | 3,328 | 68,146 | 510 | 14 |
| All shipped profiles | 505,862 | 60 | 3,691 | 68,146 | 1,582 | 14 |

The largest standard/all root was
`terraform-aws-modules__terraform-aws-iam/examples/iam-role-for-service-accounts`.
The 10,000,000 default gives approximately 147 times its measured work. It equals
50 interpreter-attempt ceilings; dispatch and other charges draw from the same pool.
This headroom accommodates larger roots and multiple alternative runs while
placing a finite ceiling on their accumulated counted work. Every observed
root fits below the default. The 14 ordinary rule errors, source coverage gaps,
and unmetered backend work limit what these measurements establish; they are
not evidence of complete catalog execution or a physical resource bound.

```sh
cargo build --release --offline --locked -p tf_scan --example rule_budget
target/release/examples/rule_budget corpus/repos seed
target/release/examples/rule_budget corpus/repos standard
target/release/examples/rule_budget corpus/repos all
```

Raw probe logs are `/tmp/oxtf-rule-budget-corpus-{seed,standard,all}.log`.
Their timings overlapped builds and other probes and are not performance
comparisons. The Phase 0 catalog/worker/retention timing matrix remains open.

## Input and cache measurements

On 2026-10-21 the release scan matrix ran on the same machine and corpus as
above, pinned to CPUs 0–3. Each cell had one warmup and three measured runs;
values below are medians of end-to-end process time and process peak RSS.
Builds and tests were finished before measuring. Raw samples, commands, binary
and source-tree hashes, toolchain, and corpus hash are in
[`bench/results/tigerstyle-inputs.json`](../bench/results/tigerstyle-inputs.json).
This is a new matrix anchor, not a paired comparison to an invented earlier
matrix. The smaller preserved rule-probe comparison is recorded separately.

| Catalog | Workers | Keep models | Elapsed (s) | Peak RSS (KiB) |
| --- | ---: | --- | ---: | ---: |
| seed | 1 | false | 0.64 | 83,812 |
| seed | 1 | true | 0.67 | 165,420 |
| seed | 4 | false | 0.24 | 90,864 |
| seed | 4 | true | 0.30 | 168,656 |
| standard | 1 | false | 1.04 | 126,132 |
| standard | 1 | true | 1.10 | 216,100 |
| standard | 4 | false | 0.33 | 136,236 |
| standard | 4 | true | 0.40 | 218,880 |

All cells discovered 504 roots and loaded 2,195 files, covering 1,498 module
instances and 5,379 resources. Successful source admission was identical:
20,207,589 payload bytes, 6,568 representations, 8,517 directory entries, and
504 root admissions. The largest loaded source text was 103,061 bytes. No
input allowance was exhausted. These give approximately 163× per-input, 13×
aggregate-byte, 2.5× representation-count, 31× directory-entry, and 8× root
headroom. The defaults are provisional for this corpus; representation count
has the narrowest observed headroom. They do not establish production-plan
sizes or a memory bound.

The seed scans retained 2 findings and no rule errors; standard scans retained
507 findings and 14 existing rule errors after skip processing. Every cell's
status was `failed` because this corpus contains analysis failures; absence of
budget exhaustion is not evidence of complete analysis. With `keep_models`
false/true, retained models were 0/504. The roughly doubled RSS with retained
models is evidence for the remaining model-memory admission work.

The Rego work probe used the unmodified Conftest HCL fixture over the same 504
roots on CPU 0. It produced 1,849 findings, no rule errors, and no exhaustion.
Adapter work totaled 839,276 steps (median 293, p95 6,884, maximum 36,190).
Admitted engine time totaled 184,230 µs (median 107 µs, p95 1,594 µs, maximum
5,768 µs). The 10,000-ms default is about 1,733 times this measured maximum;
this one policy family is not a worst-case policy benchmark. Whole-file
analysis loaded 2,199 files in this probe. Elapsed time was 1.70 s and peak RSS
103,512 KiB. The direct rule probe has its own discovery/catalog tables, so its
input counters must not be substituted for the shared scan-matrix counters.

A separate persistent-thread probe rebuilt and ran the RDS Rego catalog for
1,000 plan scans with `keep_models=false`, producing one finding each time.
RSS was 11,648 KiB at iteration 1, 11,844 at 100, and 11,868 at 1,000; iterations
700–1,000 were flat at 11,868 KiB. This supports the lifetime regression that
proves the working engine releases its captured input table when the root
budget drops. It does not prove zero allocator retention or a general RSS cap.

The preserved pre-slice release rule-probe binary and the current probe were
also compared on CPU 0, one warmup each followed by three alternating measured
runs per catalog. Both drop each model after its root. This narrower comparison
has identical raw finding/error/work counts before and after: seed 2/0/1,902,
standard 510/14/455,669. Unlike the scan matrix, this direct linter probe does
not apply skip processing. Median process time was 0.56→0.59 s for seed and
0.97→0.96 s for standard. Median peak RSS was 75,840→83,040 KiB and
116,488→123,748 KiB, respectively. Retaining raw snapshots alongside text adds
source payload; the approximately 7 MiB RSS increase is consistent with that
change. These three-run samples do not establish a general speedup or slowdown.
Binary hashes and all samples are in
[`tigerstyle-rule-comparison.json`](../bench/results/tigerstyle-rule-comparison.json);
the Rego/persistent-plan outputs are in
[`tigerstyle-backends.json`](../bench/results/tigerstyle-backends.json).
The old binary is preserved in this session at `/tmp/oxtf-rule-budget-before-storage`;
it was built from the earlier uncommitted tree, not the base Git revision alone.

Reproduce after builds and tests have finished:

```sh
cargo build --release --offline --locked -p tf_scan --examples
python3 bench/input_limits.py
/usr/bin/time -f 'elapsed=%e peak_rss_kib=%M' taskset -c 0 \
  target/release/examples/rule_budget corpus/repos rego \
  fixtures/rego/foreign/conftest_hcl2_deny.rego
taskset -c 0-3 target/release/examples/scan_limits plan \
  fixtures/plans/aws-rds-unencrypted/fail_explicit_false.json \
  fixtures/rego/ports/rds.rego 1000
```

## Arena measurements and contention investigation

The release corpus matrix admits 51,000,896 arena payload bytes and 770,642
construction reservations, identically for seed/standard catalogs, one/four
workers, and models discarded/retained. The 256-MiB and 4,000,000 defaults give
approximately 5.26× and 5.19× headroom over this scan of the pinned corpus.
These finite defaults leave room for larger inputs than those measured; they
are not evidence of worst-case Terraform memory use or complete analysis.

The initial implementation held the scan input mutex for every arena operation.
The five-pair matrix recorded 15–33% slower medians in three four-worker cases,
crossing the plan's investigation threshold. Ranked hypotheses were mutex
contention, vector-layout/check overhead, and host timing variance. A separate
seven-pair experiment compared the pre-slice, locked-arena, and optimized
executables at one and four workers. Atomic construction reservation and a
no-growth path reduced the four-worker seed median from 0.28 to 0.23 seconds
(pre-slice: 0.22), while both arena implementations took 0.65 seconds at one
worker (pre-slice: 0.61). Chunk growth still acquires exclusive admission and
sets the backing allocator's ceiling before allocating. Boundary/concurrency
regressions verify that this change cannot overbook either allowance.

Futex tracing also observed 13,702 calls before this slice versus 16,713 with
per-operation locking. Tracing perturbs scheduling; those traced runs are not
the acceptance timings. The controlled change and paired timing experiment
support mutex contention as the dominant parallel regression. No timing
assertion was added to ordinary tests: the representative seam is the pinned
corpus comparison, while deterministic tests enforce the allocation invariants.

Raw initial samples and the investigation are preserved in
[`tigerstyle-arenas-initial.json`](../bench/results/tigerstyle-arenas-initial.json)
and [`tigerstyle-arena-lock-comparison.json`](../bench/results/tigerstyle-arena-lock-comparison.json).
The final matrix, source/binary hashes, toolchain, commands, and raw samples are
in [`tigerstyle-arenas.json`](../bench/results/tigerstyle-arenas.json). It uses one
warmup per executable/case followed by five alternating paired runs, pinned to
CPUs 0–3 after builds and tests. The pre-slice executable's SHA-256 matches the
previous input matrix; its recorded source metadata includes the earlier
uncommitted tree. Git revisions alone do not reproduce either implementation.

<!-- arena-comparison-table -->
| Catalog | Workers | Keep models | Before → after elapsed (s) | Before → after peak RSS (KiB) |
| --- | ---: | --- | ---: | ---: |
| seed | 1 | false | 0.60 → 0.63 | 83,700 → 85,060 |
| seed | 1 | true | 0.67 → 0.69 | 165,488 → 166,660 |
| seed | 4 | false | 0.23 → 0.24 | 90,680 → 92,548 |
| seed | 4 | true | 0.30 → 0.29 | 168,876 → 168,212 |
| standard | 1 | false | 1.03 → 1.02 | 126,436 → 127,508 |
| standard | 1 | true | 1.10 → 1.13 | 216,072 → 217,416 |
| standard | 4 | false | 0.34 → 0.33 | 137,104 → 137,704 |
| standard | 4 | true | 0.41 → 0.43 | 219,056 → 219,496 |

Final median elapsed-time increases are at most 5.0%, with peak RSS
increases at most 2.1%. Both are below the 10% investigation threshold.
Timings are rounded to 0.01 seconds; these samples do not establish a general
speedup. The earlier optimized matrix is retained in
[`tigerstyle-arenas-atomic.json`](../bench/results/tigerstyle-arenas-atomic.json).
The only intervening Rust source change was parser API documentation.
<!-- /arena-comparison-table -->

The matrix preserves all source counters and corpus outcomes: 504 roots, 2,195
files, 1,498 module instances, 5,379 resources, and 0/504 retained models. Seed
has 2 findings and no rule errors; standard has 507 findings and 14 existing
rule errors. Every cell remains `failed` because of pre-existing analysis
failures, with no admission exhaustion. Matching those outcomes does not prove
complete corpus analysis. Cumulative arena payload is not process peak RSS;
model retention and other unaccounted structures remain visible in the latter.

Reproduce after building the release `tf_scan` example and preserving the
matching pre-slice executable:

```sh
cargo build --release --offline --locked -p tf_scan --example scan_limits
python3 bench/arena_limits.py --before /tmp/oxtf-scan-before-arena --repeats 5
```


### Evaluator text measurements

`bench/results/tigerstyle-text.json` compares the preserved eighth-slice release
probe with the text-admission implementation. Every case uses one warmup per
binary and five alternating before/after pairs, pinned to CPUs 0–3, without
concurrent builds or test suites. Corpus, catalogs, worker counts, model
retention, outcomes, input/arena counters, and executable/source hashes are
recorded. The raw first run is retained in `tigerstyle-text-initial.json`.

| Catalog | Workers | Keep models | Before → after elapsed median (s) | Before → after peak RSS median (KiB) |
| --- | ---: | :---: | ---: | ---: |
| seed | 1 | false | 0.49 → 0.51 | 84,832 → 85,056 |
| seed | 1 | true | 0.70 → 0.72 | 166,524 → 166,672 |
| seed | 4 | false | 0.23 → 0.23 | 89,796 → 90,496 |
| seed | 4 | true | 0.29 → 0.31 | 167,912 → 167,780 |
| standard | 1 | false | 1.03 → 1.04 | 127,604 → 127,752 |
| standard | 1 | true | 1.08 → 0.87 | 217,400 → 217,508 |
| standard | 4 | false | 0.29 → 0.37 | 136,804 → 136,008 |
| standard | 4 | true | 0.34 → 0.35 | 220,388 → 219,784 |

All cases admitted **7,539,771 text bytes**, about **35.6×** below the 256 MiB
default. This is construction cost, not live text or memory. Outcomes match:
504 roots, 2,195 files, 1,498 module instances, 5,379 resources; seed has 2 findings
and no rule errors, standard has 507 findings and 14 rule errors. These scans
still report `failed` from existing corpus analysis failures; no budget was
exhausted. This does not establish complete corpus analysis.

The first standard/four-worker/discarded-model case crossed the 10% investigation
gate (0.29 → 0.37 s). Timing variance, shared-counter contention, and extra text
work were ranked before running another experiment. Eleven matched alternating
pairs with one and four workers, changing no code, did not reproduce a slowdown:
medians were 0.88 → 0.87 s and 0.36 → 0.30 s. The raw values vary substantially;
no speedup is claimed. The accepted decision is to retain the implementation and
record the initial outlier, rather than attribute the noisy difference to a
code regression. Peak RSS medians differ by less than 1% in every first-run case.

The repeat, predictions, and decision are in
`bench/results/tigerstyle-text-repeat.json`. Reproduce it with:

```sh
python bench/text_limits.py --before /tmp/oxtf-scan-before-values \
  --catalog standard --keep-models false --repeats 11 \
  --output bench/results/tigerstyle-text-repeat.json
```

The corpus timing matrix is the performance regression seam. No flaky unit-test
wall-clock threshold was added. Deterministic tests enforce the storage bounds.


### Builtin collection measurements

The tenth-slice probe admits **486,768 collection bytes** across the same 504
corpus roots in every catalog/worker/retention configuration. The 256 MiB default
provides 551.5 times that observed allowance. On this build it permits up to
8,388,608 32-byte Value slots; the generous provisional default leaves room for
larger builtin workloads than the corpus exercises. Collection headers, B-tree
overhead and the remaining builders are excluded, so this is not a heap bound.
The standalone `jsondecode("{}")` probe admits 528 bytes, confirming the 264-byte
per-input-byte JSON reservation on this build.

The matched matrix uses the preserved ninth-slice executable, one warmup per
binary/case, and five alternating pairs on CPUs 0–3. Builds and tests had
finished. Rust source/manifest hashes, executable hashes, corpus pin, toolchain,
commands, and raw samples are in
[`tigerstyle-collections.json`](../bench/results/tigerstyle-collections.json).
The table uses monotonic subprocess duration, including launch and teardown;
the probe's separate `Instant` duration ends before result destruction.

| Catalog | Workers | Keep models | Before → after process median (s) | Before → after peak RSS median (KiB) |
| --- | ---: | :---: | ---: | ---: |
| seed | 1 | false | 0.690 → 0.678 | 84,864 → 85,004 |
| seed | 1 | true | 0.760 → 0.731 | 166,660 → 166,540 |
| seed | 4 | false | 0.209 → 0.213 | 92,412 → 93,096 |
| seed | 4 | true | 0.254 → 0.280 | 169,960 → 167,688 |
| standard | 1 | false | 1.066 → 1.097 | 127,648 → 127,392 |
| standard | 1 | true | 0.898 → 0.914 | 217,356 → 217,396 |
| standard | 4 | false | 0.389 → 0.376 | 136,484 → 137,600 |
| standard | 4 | true | 0.441 → 0.436 | 219,732 → 220,180 |

The first matrix had a 34.6% four-worker seed timing increase without retained
models. Its raw samples are preserved in
[`tigerstyle-collections-initial.json`](../bench/results/tigerstyle-collections-initial.json).
That matrix also contained a negative GNU `time` elapsed value (-1.92 seconds),
so the collection harness now uses `perf_counter_ns` for process duration and
records CPU time as well. Raw wall-clock values remain available; they are not
the final timing measure. Internal monotonic scan time also showed the initial
seed outlier, so the timer problem alone does not explain it.

Ranked predictions considered transient host scheduling/load, shared-counter
contention, and extra construction work. With unchanged executables, eleven
alternating pairs for the original case measured process medians of 240 → 238 ms,
internal scan medians of 227 → 226 ms, and identical CPU medians (0.64 s user,
0.11 s system). The full monotonic matrix then measured +2.0% for that case.

A different matrix case, four-worker seed with retained models, crossed the
10% investigation gate by 0.2 percentage points. Eleven separate alternating
pairs measured process medians of 335 → 351 ms (+4.8%), identical internal scan
medians of 256 ms, identical CPU medians (0.69 s user, 0.18 s system), and +0.3%
peak RSS. Both repeat sets and ranked predictions are retained in
[`tigerstyle-collections-repeat.json`](../bench/results/tigerstyle-collections-repeat.json),
[`tigerstyle-collections-retained-repeat.json`](../bench/results/tigerstyle-collections-retained-repeat.json),
and the main artifact's investigation record. No scanner code changed during
this investigation. Neither above-threshold slowdown persisted in the repeat
sets. The measurements are consistent with transient load, without establishing
its cause, and do not establish a speedup. No timing assertion was added to unit
tests; the paired corpus harness exercises the actual scan workload.

The final matrix's other process-time increases are at most 3.0%, and all peak
RSS increases are below 1%. Every row preserves the previous input/arena/text
counters and outcomes: 504 roots, 2,195 files, 1,498 module instances, 5,379
resources, 0/504 retained models, and 2/507 seed/standard findings. The standard
catalog retains 14 ordinary rule errors. Status remains `failed` from existing
analysis failures, with no storage exhaustion. This does not establish complete
analysis of the corpus.

### Expression collection measurements

The eleventh-slice comparison uses the preserved tenth-slice executable
`/tmp/oxtf-scan-before-expressions` (SHA-256
`9e1f57e43ddcc3109951c0e6d9d71b78f7a63a8a0c27e95b872bae76d6309918`),
the pinned corpus, CPUs 0–3, one warmup per executable/configuration, and five
alternating measured pairs. [The full evidence](../bench/results/tigerstyle-expressions.json)
records source/executable identities, commands, machine/build metadata, all
samples, the allocation regression, and the investigation.

Every configuration admits **7,233,000 collection bytes**, compared with 486,768
for builtin-only admission. The unchanged **256 MiB** default gives **37.1×**
observed headroom. These cumulative logical reservations include temporary
expression buffers; they are not live memory or RSS. Outcomes and all existing
input/arena/text counters match. Both executables retain the corpus's existing
`failed` status; this is not a complete-analysis baseline.

Initial matrix medians:

| Catalog | Workers | Keep models | Before (s) | After (s) | Time change | RSS change |
| --- | ---: | :---: | ---: | ---: | ---: | ---: |
| seed | 1 | false | 0.852 | 0.867 | +1.76% | +0.19% |
| seed | 1 | true | 0.932 | 1.026 | +10.04% | -0.09% |
| seed | 4 | false | 0.427 | 0.522 | +22.20% | +0.26% |
| seed | 4 | true | 0.381 | 0.377 | -1.05% | +0.17% |
| standard | 1 | false | 1.380 | 1.273 | -7.77% | +0.12% |
| standard | 1 | true | 1.229 | 1.220 | -0.75% | +0.08% |
| standard | 4 | false | 0.386 | 0.400 | +3.71% | +0.17% |
| standard | 4 | true | 0.466 | 0.470 | +0.82% | +0.22% |

The seed/one-worker/retained and seed/four-worker/not-retained timing medians
crossed the 10% investigation gate. The ranked, falsifiable hypotheses were
transient host variation, systematic reservation overhead, and contention on
shared collection counters. Each affected configuration then ran one warmup
and eleven alternating pairs with unchanged sources, executable fingerprints,
corpus, CPU affinity and settings. Builds and tests did not overlap timing.

The retained repeat measured 0.770 → 0.811 seconds (**+5.33%**) and
166,624 → 166,768 KiB peak RSS (**+0.09%**). The parallel repeat measured
0.309 → 0.316 seconds (**+2.28%**) and 90,536 → 93,016 KiB peak RSS (**+2.74%**).
Median total process CPU time increased 5.56% and 8.24%, respectively. The
large initial wall-time gap is consistent with transient host variation,
without uniquely identifying its cause; modest admission overhead remains.

Accept the slice: neither eleven-pair repeat reproduces an above-threshold
elapsed/RSS regression, outcomes match, and no scanner code changed during the
investigation. No speedup is claimed. Preserve the
[initial matrix](../bench/results/tigerstyle-expressions-initial.json),
[retained repeat](../bench/results/tigerstyle-expressions-retained-repeat.json),
and [parallel repeat](../bench/results/tigerstyle-expressions-parallel-repeat.json).
The final evidence retains the original matrix and records the repeats separately;
it does not replace unfavorable samples.

## Semantic conversion collection measurements

The twelfth-slice comparison uses the preserved final expression-slice executable
and the same pinned corpus, catalogs, CPU affinity and retention modes. Each case
has one warmup per binary and five measured pairs with alternating order. All
matched outcome fields and input/arena/text counters agree, including the
corpus's existing `failed` status; this is not a clean-corpus claim.

| Catalog | Workers | Keep models | Before ms | After ms | Elapsed change | Peak RSS change |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| seed | 1 | false | 719.16 | 725.40 | +0.87% | -0.06% |
| seed | 1 | true | 780.37 | 787.80 | +0.95% | -0.00% |
| seed | 4 | false | 281.73 | 282.64 | +0.32% | +1.01% |
| seed | 4 | true | 331.21 | 333.13 | +0.58% | +0.00% |
| standard | 1 | false | 1196.08 | 1164.77 | -2.62% | -0.01% |
| standard | 1 | true | 1200.10 | 1192.95 | -0.60% | +0.02% |
| standard | 4 | false | 367.64 | 360.97 | -1.81% | -1.04% |
| standard | 4 | true | 472.95 | 456.22 | -3.54% | +0.00% |

All per-case median elapsed and RSS regressions stay below the 10% investigation
gate. These five-pair measurements support acceptance of the admission overhead;
small negative timing changes are not a speedup claim. The complete samples,
source/executable/corpus fingerprints, validation and acceptance decision are in
[`tigerstyle-semantic.json`](../bench/results/tigerstyle-semantic.json).

Every configuration admits 8,350,520 collection bytes, up from 7,233,000. The
added 1,117,520 bytes cover newly admitted semantic conversion/default containers
and type payloads. The 256 MiB default has 32.1× observed logical-payload headroom.
Text admission remains 7,539,771 bytes. These cumulative counters do not measure
live heap or close the documented model, metadata and output exclusions.

## Analyzer model collection measurements

The thirteenth-slice comparison uses the preserved twelfth-slice executable,
the pinned 504-root corpus, CPU affinity 0–3, both catalogs, one/four workers and
both retention modes. Each case runs one warmup per binary and five alternating
measurement pairs, separately from builds and tests. All outcome fields and
input/arena/text counters match, including the corpus's existing `failed` status.

| Catalog | Workers | Keep models | Before ms | After ms | Elapsed change | Peak RSS change |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| seed | 1 | false | 691.07 | 701.88 | +1.56% | -0.14% |
| seed | 1 | true | 753.88 | 791.79 | +5.03% | -1.91% |
| seed | 4 | false | 259.66 | 276.91 | +6.64% | -1.21% |
| seed | 4 | true | 325.47 | 344.50 | +5.85% | -1.90% |
| standard | 1 | false | 1128.83 | 1155.01 | +2.32% | -0.09% |
| standard | 1 | true | 1196.12 | 1212.49 | +1.37% | -1.57% |
| standard | 4 | false | 449.91 | 447.44 | -0.55% | -0.74% |
| standard | 4 | true | 507.41 | 474.41 | -6.50% | -1.61% |

All eight per-case elapsed/RSS medians remain below the 10% investigation gate.
Accept the slice without repeated measurements. These samples support acceptance
of the admission overhead; negative timing changes are not a speedup claim.
Raw samples, source/executable/corpus fingerprints, validation and acceptance are
in [`tigerstyle-models.json`](../bench/results/tigerstyle-models.json).

Every configuration admits 42,055,016 collection bytes, up from
8,350,520. The added 33,704,496 logical bytes cover analyzer model, instance,
expansion, cache and projection payloads newly admitted in this slice. The
256 MiB default has 6.38× observed logical-payload headroom. Text remains
7,539,771 bytes. These are cumulative reservations, not live memory or RSS;
parsed metadata, graph/provenance, plan models and output exclusions remain.

## Parsed-definition metadata measurements

The fourteenth-slice comparison uses the preserved thirteenth-slice executable,
the pinned 504-root corpus, CPU affinity 0–3, both catalogs, one/four workers and
both model-retention modes. Each case runs one warmup per binary and five
alternating measurement pairs, separately from builds and tests. All outcomes
and existing input/arena/text counters match, including the corpus's existing
`failed` status; this is not a clean-corpus claim.

| Catalog | Workers | Keep models | Before ms | After ms | Elapsed change | Peak RSS change |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| seed | 1 | false | 707.90 | 709.86 | +0.28% | +0.15% |
| seed | 1 | true | 758.58 | 771.61 | +1.72% | -0.04% |
| seed | 4 | false | 273.41 | 269.95 | -1.27% | -1.18% |
| seed | 4 | true | 344.71 | 342.42 | -0.67% | -0.13% |
| standard | 1 | false | 1149.22 | 1144.07 | -0.45% | -0.18% |
| standard | 1 | true | 1057.70 | 1163.03 | +9.96% | -0.04% |
| standard | 4 | false | 377.24 | 379.62 | +0.63% | +0.99% |
| standard | 4 | true | 464.49 | 459.34 | -1.11% | +0.48% |

All eight per-case elapsed/RSS medians remain below the 10% investigation gate.
Accept this slice without repeated measurements. Negative timing changes are
not a speedup claim. Raw samples, source/executable/corpus fingerprints,
validation and acceptance are retained in
[`tigerstyle-metadata.json`](../bench/results/tigerstyle-metadata.json).

Every configuration admits 44,359,328 collection bytes, up from
42,055,016. The added 2,304,312 logical bytes cover newly admitted parsed
file staging/references, declaration/provider indexes and cache metadata in this
corpus. The default 256 MiB allowance has 6.05× observed logical-payload headroom.
Text remains 7,539,771 bytes. These counters measure cumulative reservations,
not live heap or RSS; composition, graph/provenance, plan and output exclusions
remain open.

## Composition and parsed-reference measurements

The fifteenth-slice comparison uses the preserved fourteenth-slice executable,
the pinned 504-root corpus, CPU affinity 0–3, both catalogs, one/four workers and
both model-retention modes. Each case runs one warmup per binary and five
alternating measurement pairs, separately from builds and tests. All outcomes
and existing input/arena/text counters match, including the corpus's existing
`failed` status; this is not a clean-corpus claim.

| Catalog | Workers | Keep models | Before ms | After ms | Elapsed change | Peak RSS change |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| seed | 1 | false | 719.69 | 731.84 | +1.69% | +1.15% |
| seed | 1 | true | 792.32 | 797.46 | +0.65% | +0.57% |
| seed | 4 | false | 275.11 | 279.56 | +1.62% | +7.02% |
| seed | 4 | true | 339.35 | 345.05 | +1.68% | +0.86% |
| standard | 1 | false | 1165.43 | 1185.52 | +1.72% | +0.85% |
| standard | 1 | true | 1237.63 | 1241.10 | +0.28% | +0.39% |
| standard | 4 | false | 406.08 | 402.06 | -0.99% | +0.66% |
| standard | 4 | true | 493.35 | 481.09 | -2.49% | +1.25% |

All eight per-case elapsed/RSS medians remain below the 10% investigation gate.
Accept this slice without repeated measurements. Negative timing changes are
not a speedup claim. Raw samples, source/executable/corpus fingerprints,
validation and acceptance are retained in
[`tigerstyle-composition.json`](../bench/results/tigerstyle-composition.json).

Every configuration admits 52,557,488 collection bytes, up from
44,359,328. The added 8,198,160 logical bytes cover newly admitted composition
maps, validation sets and parsed-reference edge/binding vectors in this corpus.
The default 256 MiB allowance has 5.11× observed logical-payload headroom.
Text remains 7,539,771 bytes. These counters measure cumulative reservations,
not live heap or RSS; graph/value provenance, plan models, remaining metadata/text,
results/output and live memory admission remain open.

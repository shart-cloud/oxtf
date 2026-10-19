# Bundled catalog follow-ups: speed, duplicates, the untranslated checks

Status: planned 2026-10-19. Builds on the bundled Checkov catalog
(FIRST_CLASS_RULES_PLAN.md, "Bundled catalog"; commit 638afcb).

Three steps, one commit each, in this order:

1. **Speed**: give back the one-file latency the catalog cost.
2. **Duplicates**: one finding per issue when a seed rule and a Checkov
   rule judge the same thing.
3. **Classification**: sort the 388 untranslated Checkov checks by what
   their Python does. This is analysis only; no operators are built
   until the results have been reviewed.

## 1. Speed: build a bundled rule only when a scan can use it

### Where the time goes now

| Build | Corpus | One file |
|---|---:|---:|
| Seed only (before 638afcb) | 111 ms | 5.4 ms |
| Bundled (638afcb) | 132 ms | 11.5 ms |

The ~6 ms added to every scan is a fixed startup cost:
`Catalog::resolve` parses all of `rules.json` (958 KB) into `RuleSpec`s
(~2.5–4 ms) and then compiles all 693 rules (~1.5 ms). It does this
before reading any input. A file with two resource types uses perhaps a
dozen of those rules.

### Design

**Lazy bundled rules.** `tf_rule_ir::bundled` returns
`Vec<Box<dyn DynRule>>` of `LazyRule`s:

```rust
struct LazyRule {
    info: RuleInfo,           // built from a precomputed header, no spec parse
    needs_graph: bool,        // also precomputed
    spec: &'static str,       // this rule's JSON
    compiled: OnceLock<Result<CompiledRule, String>>,
}
```

- `info()` and `needs_graph()` read the header and never compile.
- `judge_resource` and `judge_graph` parse and compile the rule on first
  use. A compile error becomes a `RuleFailure`, which the scan reports as
  a rule error. `tests/bundled.rs` already compiles every bundled rule, so
  that path should never run.
- The existing dispatch then skips unused rules by itself:
  - `Linter::run_with` calls `judge_resource` only for types in
    `by_type`, and does so per resource that exists;
  - graph rules are already filtered by present types (`engine.rs:121`).
- `rules` / `rules_info` listings use only `info()`, so they compile
  nothing.

**The header.** `bundle_checkov` generates it, because only there is the
compiler available to work out `needs_graph`. `BundledRule` gains a
`needs_graph: bool` field. The drift test (`bundled_catalog_is_current`)
covers it like any other byte of the file.

**Avoiding the 958 KB parse.** Two options; the measurement in step 1a
decides:

- **(a) `serde_json::value::RawValue`:** parse the bundle with each
  `rule` kept as raw JSON and only the header fields typed. This is one
  validating pass over the file with no allocation per field, and needs
  no build script. Use it if the parse comes in under ~0.5 ms.
- **(b) `build.rs`:** read `data/checkov/rules.json` at build time and
  emit `OUT_DIR/bundled.rs`, a static table of headers plus each rule's
  minified JSON as a `&'static str`. There is no JSON work at startup
  beyond the rules actually used. It costs a build script and a
  `serde_json` build-dependency.

### Steps

- **1a.** Measure, using the profiling setup in memory (Python
  `perf_counter` medians, no perf on WSL2). Time the one-file scan split
  into four parts: bundle parse, compile, `Linter::new`, and the scan
  itself. Then time a `RawValue` parse of `rules.json` on its own. Choose
  option (a) or (b).
- **1b.** Add `needs_graph` to `BundledRule` and `generate()`, then
  regenerate `data/checkov/` with the scratch Checkov venv.
- **1c.** Add `LazyRule` and switch `bundled::checkov()` (or a new
  `bundled::rules()`) to it. `Catalog::resolve` adds lazy rules instead
  of `compile_specs(specs)`.
  - Shadowing is unchanged, since it works on `info().name`.
  - `bundled::checkov() -> Vec<RuleSpec>` stays for the tests and the
    generator.
- **1d.** `Linter::new` builds `by_type` for all 698 rules. If 1a shows
  this matters, check it; it is probably negligible.

### Gate

- Corpus JSON output is byte-identical to 638afcb (default flags, and
  with `--no-bundled`).
- One file at or under **6.5 ms** (seed-only was 5.4 ms); corpus at or
  under **120 ms**. Report medians.
- All Rust tests, clippy and pytest pass. The value and graph
  differential harnesses run unchanged; they pass `--no-bundled`, so this
  is a sanity check only.
- New test: a scan of a one-resource fixture compiles only that type's
  rules. A test-only counter on `LazyRule` compiles is enough.

### Result (implemented 2026-10-19)

**What was built**
- Option (b), the `build.rs` table. A `RawValue`-style skip-parse of
  `rules.json` measured 0.97 ms, over the 0.5 ms cutoff.
- The header comes straight from the rule JSON: resource types in clause
  order, and `needs_graph` is any clause with `op: checkov_graph`. So
  `rules.json` and the generator are unchanged and nothing needed
  regenerating.
- `lazy_rules_match_their_compiled_rules` (in `tf_rule_ir/tests/bundled.rs`)
  checks every header against the compiled rule.
- `tf_scan/tests/bundled.rs` checks that a one-resource scan compiles
  exactly the bundled rules of that type, and that listing compiles none.

**Checks**
- Corpus JSON is identical to 638afcb, with and without `--no-bundled`,
  apart from `elapsed_ms`.
- 233 Rust tests pass; clippy is clean; 50 pytest pass, 1 skipped; the
  drift test passes against a fresh 3.2.328 export.

**Timings.** Medians from interleaved runs; this machine was noisier than
on 2026-10-17, so compare the rows with each other.

| Build | `null_resource` file | `aws_s3_bucket` file | Corpus |
|---|---:|---:|---:|
| Seed only | 4.8 ms | 6.0 ms | 99 ms |
| 638afcb (eager) | 13.6 ms | 15.3 ms | 148 ms |
| Lazy | 6.7 ms | 8.4 ms | 134 ms |

**Gate**
- The bundled catalog's fixed cost per scan fell from ~8.8 ms to
  ~1.9 ms.
- What remains is building metadata for 693 rules, the `Linter` index
  and freeing both: ~0.9 ms cold in-process, mostly allocation. Cutting
  it further would mean letting `RuleInfo` borrow `&'static str`, an
  API-wide change.
- The `aws_s3_bucket` file's extra ~0.8 ms is real work: 12 graph rules
  run on it, so the resource graph is built.
- **Corpus gate (120 ms) missed.** The corpus cost is rule evaluation
  (974 findings), not startup. A single-thread profile shows graph rules
  at ~11% of CPU. Most of that goes to rebuilding a resource's
  Checkov-shaped configuration (`checkov::configuration` /
  `graph_configuration`) once per rule × resource, then dropping it.
- **Follow-up:** cache that configuration per resource per root (the
  `ResourceGraph` is shared by all graph rules of a root). Expected: most
  of that 11%.

## 2. Duplicates: one finding per issue

### The overlap

Seed rules that a translated Checkov rule also covers, so both fire
today:

| Seed rule | Checkov rule | Checkov kind |
|---|---|---|
| `aws-rds-unencrypted` | `CKV_AWS_16` (RDSEncryption) | value |
| `gcp-storage-uniform-access` | `CKV_GCP_29` (GoogleStorageBucketUniformAccess) | value |
| `aws-s3-public-access-block` | `CKV2_AWS_6` (S3BucketHasPublicAccessBlock) | graph |

Two more are not translated yet, so they will become duplicates only
after step 3:

| Seed rule | Checkov rule(s) |
|---|---|
| `aws-sg-open-ssh` | `CKV_AWS_24` |
| `aws-iam-wildcard-policy` | `CKV_AWS_62` / `CKV_AWS_63` / `CKV_AWS_355` |

The IAM one is not a one-to-one match: the seed rule flags Action `*`
*and* Resource `*`, while the Checkov checks split that differently.

### Design

The rule is: declare an equivalence only where it has been proven, and
keep one rule.

- **Declaring it.** Seed rules can declare
  `const CHECKOV: &[&str] = &["CKV_AWS_16"];` (default empty). It is
  exposed through `RuleInfo` as `aliases: Vec<Arc<str>>`.
- **Which rule survives.** When both rules are in the catalog, the
  **Checkov rule is canonical**:
  - its ID is the one users and `checkov:skip` comments already know;
  - it was proven against Checkov by the harness;
  - the seed name becomes an alias.

  `Catalog::resolve` drops a seed rule whose aliases are all present.
  With `--no-bundled`, the seed rule runs as today.
- **Keeping what the seed rule did better.** Before dropping a seed
  rule, compare its message, severity and fix hint with the Checkov
  rule's. Wherever the seed rule's is better, carry it onto the Checkov
  rule as a bundled override in `tf_rule_ir/data/` (a small
  `overrides.json` keyed by ID, applied in `bundled::*`). Do not edit
  the generated `rules.json`. This also starts the mechanism the
  "severity_defaulted" problem needs later.
- **Selecting rules.** `--rule aws-rds-unencrypted` and
  `rules=[...]` select the canonical rule through the alias, so existing
  invocations keep working. Findings carry the canonical ID. Check
  whether oxtf honours inline skip comments by rule ID; if so, a skip
  naming either ID must suppress the finding.

### Proving equivalence (per pair, before declaring it)

- Run both rules alone on the 17-repo corpus plus the seed rule's test
  fixtures, and compare the flagged addresses. Also compare definite
  versus conditional where they differ.
- Run the seed rule against Checkov's own test fixtures for that check
  (the value-check harness already has these cases).
- If the sets differ, the rules are not duplicates: record how they
  differ in this doc and keep both. A known candidate is
  `aws-s3-public-access-block` versus `CKV2_AWS_6`, which may differ on
  which of the four flags it requires.

### Gate

- Corpus: findings drop by exactly the number of duplicate pairs. No
  address loses its last finding for an issue.
- CLI and Python tests cover:
  - default (the Checkov ID is reported once);
  - `--no-bundled` (the seed ID is reported);
  - `--no-builtin` (unchanged);
  - selecting by the seed ID under the default catalog.
- `rules` listing: the dropped seed rules no longer count, so the total
  is 5 + 693 − *n*, and they show as aliases on their canonical rules.
  Update the counts in the CLI test.

### Result (implemented 2026-10-19)

**Method.** Each pair was compared on four sets of cases, with real
Checkov 3.2.328 as the reference:
- the corpus;
- the seed rule's fixtures;
- hand-written edge cases;
- for the GCP pair, also the harness's generated cases for that check.

| Pair | Outcome |
|---|---|
| `gcp-storage-uniform-access` / `CKV_GCP_29` | **Equivalent → aliased** |
| `aws-rds-unencrypted` / `CKV_AWS_16` | Not equivalent: kept both |
| `aws-s3-public-access-block` / `CKV2_AWS_6` | Not equivalent: kept both |

**GCP pair: equivalent, and aliased.**
- They agree on the corpus, all five seed fixtures, and eight edge cases:
  string `"true"`, `"True"` and `"false"`, `"true"` through an untyped
  variable, a typed variable and a local, `null`, and a dynamic `count`.
- They also agree on all but one of Checkov's 14 generated cases. The
  exception is `= 1`, which Checkov passes only because Python treats
  `1 == True`; Terraform rejects a number for this boolean.
- Getting there exposed a conformance bug in the bundled catalog. Checkov
  reads string booleans as booleans and our translation did not; fixed
  in 514d960, which also made both harnesses test that case.

**RDS pair: not equivalent.** The seed rule skips read replicas, which
inherit encryption from their source. Checkov flags them: 1 corpus
resource (`replica-postgres`). The seed behaviour is the better one, but
`CKV_AWS_16` must match Checkov, so both run.

**S3 pair: not equivalent.**
- `CKV2_AWS_6` requires only `block_public_acls` and
  `block_public_policy`; the seed rule requires all four protections.
- The seed rule also looks for the access block only in the bucket's own
  module. A block in the root that refers to `module.m.id` is a seed
  false positive; Checkov follows the connection.
- **Follow-up:** make the seed rule follow cross-module references (the
  resource graph has them).

**Design change from the plan: the seed rule survives.** The plan said
the Checkov rule would be canonical, with the seed rule's better output
carried over as an override. Comparing findings showed the seed rule's
output is computed, not static:
- a specific message (`uniform_bucket_level_access is not set (provider
  default: false)`);
- the deciding attribute;
- a fix hint.

The Checkov rule has only its title, with no attribute and no fix hint.
Static JSON can't carry any of that, so the seed rule is canonical:
- `RuleMeta::ALIASES` names the bundled IDs it replaces, exposed as
  `RuleInfo::aliases`.
- An alias shadows like a name in `Catalog::resolve`, which drops
  `CKV_GCP_29` when the seed rules are on.
- Either ID selects the rule (`--rule`, `select=`).
- A `checkov:skip` of either ID suppresses it.
- `oxtf rules` and `tfscan.rules()` list the aliases.

**Gate**
- Corpus findings unchanged (974). No corpus resource had both GCP
  findings, so nothing dropped there.
- `rules` lists 5 + 693 − 1 = 697.
- New tests cover replacement, selection by alias, the bundled rule
  without seeds, `checkov:skip` by alias (`tf_scan/tests/aliases.rs`),
  and the Python listing and selection.

## 3. Classify the 388 untranslated checks

| Reason in `manifest.json` | Checks |
|---|---:|
| custom Python `scan_resource_conf` | 343 |
| overridden `scan_resource_conf`; metadata alone is insufficient | 45 |
| expected/forbidden values are not a list | 9 |
| meta-argument is not retained in the rule model | 4 |
| predicate compares unevaluated expression text | 1 |
| **Total resource checks** | **402** |

The first two rows are the 388. The remaining 14 are small IR gaps and
can be handled one by one alongside step 3.

### Method

**`scripts/classify_checkov.py`**, run in the pinned Checkov 3.2.328
venv with `python -I`. For every unsupported check, it:

1. **Finds the code.** It imports the check class, locates
   `scan_resource_conf` (and any methods it calls on `self`, the base
   class chain and imported checkov helpers), and parses that source
   with `ast`.
2. **Extracts a feature signature** from the AST:
   - attribute paths read (`conf.get("x")`, `conf["x"][0]["y"]`);
   - iteration over lists or blocks (`for … in`, `any`, `all`);
   - comparisons: equality, membership, ordering on ints or versions,
     `len`;
   - string operations: `startswith`, `in`, `re`, `.lower()`;
   - JSON and policy parsing (`json.loads`, `policy_document`, IAM
     statement helpers);
   - networking: ports, port ranges, CIDRs (`ipaddress`, `0.0.0.0/0`,
     `::/0`);
   - helper calls: `force_list`, `find_in_dict`, `extract_policy_dict`,
     and so on;
   - result paths: early returns of PASSED / FAILED / UNKNOWN, and what
     triggers each;
   - whether the check reads anything outside `conf` (other resources,
     the environment, files). That makes a check untranslatable as a
     value check.
3. **Clusters** the checks by signature. Then each cluster is labelled
   by hand with a *shape*, meaning one IR operator or combinator that
   would express it. Expected shapes, to be confirmed:
   - "any or all element of block list X satisfies P";
   - port-range coverage;
   - CIDR is open to the world;
   - the IAM policy document has a statement with Effect/Action/Resource
     matching P;
   - version or number comparison;
   - an attribute is absent or present depending on another attribute;
   - string prefix or suffix or regex on a nested value.
4. **Labels a check "won't translate"** when its result depends on
   anything that is not the resource's own evaluated configuration.

### Deliverables

- `bench/checkov/python_checks.json`: one record per check with its ID,
  file, signature, cluster, shape, and translatable yes/no plus a reason.
  It is regenerable and pinned to 3.2.328.
- A section appended to this doc: shapes ranked by **checks unlocked
  per unit of IR work**. For each shape:
  - proposed operator syntax in rule IR;
  - semantics notes where Python's behaviour is subtle (`None` versus
    missing, list wrapping by `force_list`, `[0]` indexing into
    single-element blocks);
  - the count of checks it unlocks;
  - a rough effort estimate.
- Spot-check by reading **at least 3 checks per cluster** by hand, to
  make sure the clustering did not merge different logic.

### Gate: stop and review

Step 3 ends with the ranked table. The plan for building operators
(IR version bump, importer changes, harness cases) is written only after
it has been reviewed. The value-check harness (`bench/checkov/compare.py`)
is the correctness gate for every operator that follows, as it was for
the existing 508.

### Result (done 2026-10-19): one interpreter, not one operator per shape

**How it was done**
- `scripts/classify_checkov.py` reads each check's *deciding code*:
  - the methods of its class and its helper bases (`Abs*` classes and
    similar), stopping at Checkov's generic bases;
  - the module-level helpers of the checks they call;
  - type annotations stripped.
- It records two labels for each check in
  `bench/checkov/python_checks.json` (388 rows):
  - a *shape*: what the check is about;
  - a *tier*: the smallest restricted-Python subset its code stays
    within.
- About 25 checks were read by hand, at least 3 per tier and from the
  two largest shape buckets. Three classifier bugs found that way were
  fixed:
  - Checkov's shared utilities were treated as inlined helpers;
  - type annotations were counted as names;
  - `super().scan_resource_conf` was rejected, though it is Checkov's
    generic value check.

**Why tiers, not shapes.** Reading the code changed the plan's premise.
The shapes are not the useful axis:
- 212 of the 388 (`multi-attribute` 127, `quantified-block` 85) are
  small decision trees over the Checkov-shaped `conf`. They test whether
  a key is present, compare `conf[k][0] ==` a literal, test `in` a list,
  `is None` and `isinstance`, and combine those with `and`/`or` and
  early `return CheckResult.X`.
- The domain-looking shapes (`open-ingress`, `named-setting`,
  `version-compare`) are the same code plus loops and string or number
  operations.
- So the leverage is in one native interpreter for a restricted Python
  subset, run over the Checkov-shaped configuration the value checks
  already build (`checkov::configuration`). Per-shape operators would
  each cover a few dozen checks.

**Tiers.** Each tier adds constructs to the one before; the cumulative
column counts the checks covered up to that tier.

| Tier | Constructs it adds | Checks | Cumulative |
|---|---|---:|---:|
| decision-tree | `if`/`return`, `get`/`[k]`/`[0]`, `in`, `==`, `is None`, `isinstance`, `and`/`or`/`not`, locals, instance and module constants, `force_list`, `super()` value check | 162 | 162 (42%) |
| loops | `for`, comprehensions, `any`/`all`, `len`, `enumerate`, `sort` with a key lambda, `break`/`continue` | 116 | 278 (72%) |
| string-number-ops | `lower`/`startswith`/`split`/`replace`/..., `int`/`float`/`force_int`, arithmetic, `fnmatch`, version tuples | 52 | 330 (85%) |
| regex | `re.match`/`search`/`findall`, compiled patterns (`tf_rule_ir::pyre` already translates Python regex) | 11 | 341 (88%) |
| exceptions | `try`/`except` as a fallback result when a lookup fails | 17 | 358 (92%) |
| domain-helper | see below | 27 | 385 (99%) |
| outside-subset | 2 read Checkov's resource graph (`self.graph`), 1 depends on the current date (`datetime.now`) | 3 | 388 |

**Domain helpers (27):**
- IAM/resource policy parsing: `extract_policy_dict`,
  `ResourcePolicyDocument`, `json.loads`/`yaml`. 12 checks.
- cloudsplaining: needs policy_sentry's IAM action database. 6 checks.
- `find_in_dict`/`dpath` path search over a nested dict. 5 checks.
- `string_has_secrets`: Checkov's secret regexes. 3 checks.
- `ipaddress`. 1 check.

**Shape × tier**, for reference:

| shape | decision | loops | string/num | regex | except | domain | outside |
|---|---:|---:|---:|---:|---:|---:|---:|
| multi-attribute | 115 | 4 | 1 | 0 | 0 | 7 | 0 |
| quantified-block | 0 | 82 | 2 | 0 | 0 | 1 | 0 |
| open-ingress | 2 | 5 | 18 | 3 | 12 | 0 | 0 |
| single-attribute | 31 | 0 | 0 | 0 | 0 | 0 | 0 |
| number-compare | 11 | 3 | 13 | 1 | 0 | 0 | 1 |
| named-setting | 1 | 20 | 3 | 0 | 0 | 0 | 0 |
| policy-document | 1 | 0 | 0 | 0 | 2 | 15 | 2 |
| string-match | 0 | 0 | 12 | 6 | 1 | 0 | 0 |
| version-compare | 1 | 0 | 3 | 1 | 2 | 0 | 0 |
| secret-scan | 0 | 0 | 0 | 0 | 0 | 3 | 0 |
| cidr | 0 | 2 | 0 | 0 | 0 | 1 | 0 |

**Recommended next plan.** To be written only after review.

*A `checkov_python` clause.* The importer serializes each check's
deciding code as a normalized AST, with instance and module constants
folded in, into rule IR. `tf_rule_ir` then interprets it natively over
`checkov::configuration` (the same conf shape, with string booleans
already normalized as of 514d960). The order:
1. **decision-tree + loops: 278 checks (72%).** The interpreter core:
   Python values (dict, list, str, number, bool, None) and the subset's
   semantics. The semantics to match exactly:
   - truthiness: `[False]` is true;
   - `in` on a string is a substring test, on a list membership;
   - `['x'] == 'x'` is false;
   - `dict.get` defaults;
   - `KeyError`/`IndexError` (abort with no result unless caught);
   - in-place `sort` mutates only the check's copy.
2. **string/number ops, regex, exceptions: +80 → 358 checks (92%).**
   Mostly library surface on the same core. Regex reuses `pyre`.
3. **Domain helpers, each a native function: up to +27.**
   - Policy parsing (12) first.
   - `find_in_dict`/`dpath` (5) and `ipaddress` (1) are small.
   - Secrets (3) needs Checkov's patterns vendored.
   - cloudsplaining (6) needs policy_sentry's action database. Defer,
     or bundle it as data.
4. **Outside (3):** the two `self.graph` checks are candidates for the
   graph engine. Skip `datetime.now`.

*Abstract values.* A branch on a value that is not known follows the
existing lattice:
- Unknown makes the result Unknown (no finding);
- Tainted makes it conditional;
- OneOf evaluates each alternative and joins the results.

`self.evaluated_keys`, which Checkov sets for its own reporting, gives
the deciding attribute path for findings, which the value checks lack
today.

*Conformance.* The value harness needs richer generators: nested blocks
and lists built from the keys each check reads (`signature.keys`), with
the existing value variants at each leaf. Better still, Checkov's own
per-check test fixtures (`tests/terraform/checks/resource/**`, not in
the PyPI package; needs the 3.2.328 git tag) as a second corpus. The
gate stays 0 disagreements.

*Alternative considered.* Transpiling the Python to existing IR
expressions. Rejected: the IR has no statements, early return or loops
with exits, so most of the 278 would not fit without growing it into
the same interpreter.

## 4. The `checkov_python` interpreter (implemented 2026-10-19)

Built after the step 3 review, which chose the interpreter.

### What was built

**Export** (`tfscan/checkov_python.py`, called by the importer for every
check that is not a plain value check). The exported program holds:
- `scan_resource_conf`;
- every method and helper function it calls: the check's own classes,
  the helper methods of Checkov's generic bases, and Checkov's utility
  functions, all inlined as their own Python;
- every constant it reads, folded in: module globals, instance
  attributes, enum members, compiled patterns;
- the result as a normalized JSON AST in a `checkov_python` clause (IR
  version 4).

Some calls are not inlined:
- `super().scan_resource_conf` becomes the native `checkov_value` node;
- `is_terraform_variable_dependent` runs natively;
- whatever falls outside the subset makes the check unsupported, with
  the reason.

**Interpreter** (`tf_rule_ir::checkov_python`). It runs Python semantics
over the Checkov-shaped configuration:
- values: None, bool, int, float, str, list, tuple, set, dict, range,
  `CheckResult`, types, patterns, matches, lambdas, function references;
- operations: truthiness, `==`/`in`/ordering across types, `is`,
  indexing and slicing, arithmetic, f-strings;
- the `dict`/`list`/`str`/`set` methods the checks use;
- builtins (`len`, `isinstance`, `any`/`all` lazily over generators,
  `sorted`, `map`, `enumerate`, `int`, `str`, `json.loads`/`dumps`, ...);
- Checkov helpers (`force_list`, `force_int`, ...);
- `re` (through `pyre`), `fnmatch`, `try`/`except` with the exception
  hierarchy, in-place mutation of the check's own copy.

How a run ends:
- An `Unknown`/`Tainted` leaf decides the run only when the code inspects
  it.
- A `OneOf` forks the run per alternative, and the results are joined as
  `truth::combine_one_of`.
- `FAILED` is a finding, located by the check's own `evaluated_keys`.
- An escaping exception, an operation outside the subset, or the step
  budget (200,000) means no result, as Checkov reports none for a check
  that raises.
- `OXTF_DEBUG_PYTHON=1|2` logs failures or every outcome.

**Coverage.** 367 of the 388 Python checks. The catalog grows from 693 to
1,060 rules (875 resource checks + 186 graph policies, after merging
shared IDs). `rules.json` is written one compact rule per line, 1.8 MB.

Unsupported, with reasons in the manifest:
- policy_sentry policy documents: 10;
- secrets regexes: 3;
- `yaml`: 2;
- `dpath`: 2;
- `itertools`, `ipaddress`, a date-dependent check and a custom
  exclusion predicate: 1 each;
- plus the 14 value checks the importer already rejected.

### Runner rendering: a Checkov behaviour the harnesses had missed

Comparing against Checkov's runner, not its check code alone, showed
that resource checks see a configuration the runner has *rendered*.
`checkov::configuration` (and so the value checks) now reproduces it:
- **List order.** Lists put their strings, sorted, after their other
  elements (`clean_parser_types`).
- **Top-level strings.** A top-level string that evaluates (as a Python
  literal, else strict JSON) to a list or dict becomes it. This is what
  turns a heredoc JSON policy into a dict, so policy checks can read it.
- **List elements.** The elements of a list attribute, and the values of
  objects inside it, are evaluated: `["22", "-1"]` becomes `[-1, 22]`,
  `[{protocol = "-1"}]` becomes `[{protocol: -1}]`.
- **Left as written.** Block attributes, map values and top-level
  scalars.

`tf_rule_ir::pyliteral` reads exactly the Python literal syntax that
`eval` accepts. It does not read arithmetic or calls, and those strings
stay strings.

Graph policies see Checkov's *vertex* attributes, which are rendered
differently (every string is evaluated). That view is not modelled yet:
`jsonpath` and the graph attribute checks use the parsed configuration,
and the graph harness builds its vertices the same way.

### Gates

The value harness (`compare.py`) now uses Checkov's runner as its
reference: it writes the corpus and runs `Runner` over it, instead of
calling each check on `hcl2` output. Before that change it could not see
runner rendering at all.

| Harness | Cases | Disagreements |
|---|---:|---:|
| `compare.py` (value checks, against Checkov's runner) | 8,869 | 0 |
| `graph_compare.py` | 41,208 | 0 |
| `python_compare.py` (Checkov's 747 fixture files, 367 checks) | 17,918 results | 0 |

The Python harness classifies everything else it finds; nothing
unexplained is counted:
- **Unresolved inputs: 96.** Checkov fails on a reference oxtf leaves
  abstract, almost all an undeclared `var.test_var`. oxtf reports no
  finding by design.
- **Documented divergences: 20.** Each one is either invalid Terraform
  that Checkov's lenient parser accepts, or a case where Checkov reads
  unevaluated expression text:
  - a heredoc closing marker followed by spaces;
  - a list assigned to a string attribute;
  - an attribute that is also a block;
  - `base64encode(...)` matched as text;
  - a `jsonencode()` that Checkov failed to render.

Other gates:
- **Rust tests:** 245 passed.
- **New tests:** `tests/checkov_python.rs` covers list wrapping,
  truthiness and `in`, abstract values, OneOf forking, exceptions, runner
  rendering and the step budget. `pyliteral` has unit tests against
  CPython's `eval` behaviour.
- **pytest:** 51 passed, 1 skipped.
- **Known failure:** `checkov_policy`'s ignored
  `pinned_catalog_matches_python_importer` fails. It did so before this
  change and against the old pack too: it expects a pack with graph
  rules.

### Real-world comparison: the 17-repo corpus

`python_compare.py --fixtures corpus/repos` runs Checkov's runner over the
corpus once (27 minutes) and compares it with oxtf.

- **Agree:** 4,099 of 4,282 results (95.7%).
- **Not created, 131:** resources Terraform does not create
  (`count = var.create ? 1 : 0` with `create = false`, wrappers whose
  `for_each` defaults to `{}`). Checkov evaluates these anyway; oxtf has
  no such instance.
- **Remaining: 52 disagreements and 10 findings Checkov does not report,
  in 20 checks.** Every group spot-checked traces to Checkov rendering
  module inputs only partially:
  - **`CKV_AWS_173`** (23): `kms_key_arn` stays the text `var.kms_key_arn`,
    and a `dynamic "environment"` block is kept although its `for_each`
    is empty.
  - **`CKV_GCP_66`** (7): unrendered dynamic content becomes Checkov's
    `[True]` placeholder, which the check accepts.
  - **`CKV_AWS_79`:** Checkov does not render the variable the example
    module passes in.

  oxtf evaluates these as Terraform would.

**Decided (2026-10-19): stay faithful to Terraform.**
- **Evaluation:** oxtf evaluates a configuration as Terraform does
  (variables, module inputs, `count`/`for_each`, dynamic blocks,
  functions) and does not copy where Checkov's rendering falls short.
  Divergences of that kind are expected, and the corpus comparison is
  read with that in mind.
- **Shape:** what is reproduced is the *shape* Checkov's checks are
  written against: list wrapping, string booleans, sorted lists, a JSON
  policy as a dict, literal list elements. Without it a check's own
  code would misread a correctly evaluated value.

Unlike the fixtures, this comparison is not a gate.

### Cost and effect

Medians from interleaved runs; same machine and session.

| Build | Corpus | One `aws_s3_bucket` file | One `null_resource` file |
|---|---:|---:|---:|
| Lazy catalog, 693 rules (e2d4c7f) | 144 ms | 7.7 ms | 6.1 ms |
| With the interpreter, 1,060 rules | 184 ms | 9.9 ms | 6.6 ms |

- **Findings.** Corpus findings go from 974 to 1,495, with 0 rule errors.
- **Where the time goes.** Each Python check converts the resource's
  Checkov-shaped configuration to Python values on every run. Caching the
  rendered configuration (and its conversion) per resource is the same
  follow-up as caching the graph rules' configuration per root (step 1).

## 5. Speed and domain helpers (2026-10-19)

**Caching (b619b4d).** Each resource now computes its Checkov views once
and shares them across rules (`tf_semantic::Resource::derived`): the
rendered configuration, the graph configuration and the JSONPath vertex.
- Corpus output is unchanged.
- Single-thread corpus CPU: 581 → 538 ms, against 439 ms with the
  693-rule catalog. Wall time: 189 → 183 ms.
- What remains is interpretation itself: about 7.5% of single-thread
  CPU.

**Domain helpers.**
- **Classes (5337971).** The interpreter now supports objects of
  inlined classes (cloudsplaining, policy_sentry, Checkov). That
  translates the four `ResourcePolicyDocument` checks.
- **Native helpers (5343e15):** `yaml.safe_load`, `dpath`, `ipaddress`,
  `itertools.chain`, `hasattr`, `*args`, compiled-pattern methods,
  `re.DOTALL`/`re.MULTILINE`, and a boundary lookaround form. Together
  they translate nine more checks.
- **Result:** 380 of 388 Python checks; 1,073 bundled rules.
- **Gates:** fixtures, 0 unexplained disagreements; value harness, 0.
- **Licences (f3e55f4):** cloudsplaining (BSD-3-Clause) and
  policy_sentry (MIT) now ship next to Checkov's.

**Left: 8 Python checks.**
- The six cloudsplaining IAM checks (`CKV_AWS_286`–`290`, `355`) need
  policy_sentry's IAM database. It has 17,752 actions across 409
  services: about 1.1 MB as compact JSON, 150 KB gzipped. They also need
  native versions of its queries: wildcard expansion, actions matching an
  ARN, access-level filters. **Open decision:** whether to bundle that
  data.
- `CKV_AWS_380` depends on the current date.
- `CKV_GCP_36` uses a custom exclusion predicate.

## Branching

These commits stack on `feat/checkov-native-policies` (638afcb, not
pushed) as `feat/catalog-followups`. Alternatively, merge 638afcb first
and branch from `main`.

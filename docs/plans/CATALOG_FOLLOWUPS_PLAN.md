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

## Branching

These commits stack on `feat/checkov-native-policies` (638afcb, not
pushed) as `feat/catalog-followups`. Alternatively, merge 638afcb first
and branch from `main`.

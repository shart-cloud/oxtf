# Plan: deepen the oxtf modules before adding rule backends

Oct 14, 2026 · follows the architecture review of the same date · supersedes the sequencing in
[`RULE_ENGINES_PLAN.md`](RULE_ENGINES_PLAN.md) (its R1–R7 workstreams resume after Phase 4 here).

## Product goal this plan serves

oxtf is a fast way for agents to surface bad Terraform, and the first tool in a chain that gets
it patched. That goal decides what "well thought out" means here:

- **An agent is the primary reader of a finding.** A finding must carry enough structure to act
  on without re-parsing: which resource instance, which attribute path, the configured value,
  the effective value after defaults, where to edit, and why the tool is certain or not. Prose
  messages are secondary.
- **Certainty must never be inflated.** Definite versus Conditional, and "no finding" on
  Unknown, is the property that lets a patch tool act unattended. Every backend (native, rule
  IR, Rego, Python) must reach a finding through the same certainty logic.
- **Errors are outcomes, not passes.** A rule that failed to run must show up in the output as
  a failed rule, so a downstream tool never reads silence as clean.
- **Speed is a feature, not a benchmark.** The 0.5 s corpus scan is the budget. Every phase
  below has a performance guard; none may regress it beyond noise.

Vocabulary: domain terms from [`CONTEXT.md`](../../CONTEXT.md); architecture terms (module,
interface, seam, adapter, depth, locality, leverage) from the review.

## Current state the plan starts from

- Six friction points were identified (see the review): the truth lattice re-implemented seven
  times; verdict fused with finding construction; two front ends building the model by hand;
  scan orchestration with no single owner; six finding projections with drifting fields; and
  disk-only analysis.
- The working tree holds about 40 uncommitted files spanning five separate changes.
- `crates/tf_rego` now ports all five seed rules to Rego. Each port has bespoke projection code
  in Rust (`ssh.rs`, `iam.rs`, `s3.rs`) and its own copy of the four-valued lattice in Rego.
  These ports prove parity; they add no coverage. **Rule: no further Rego rules or projections
  land until Phase 2 is complete.** Each one added now is rewritten then.

## Phases

Dependencies run downward. Phases 1 and 3 are independent and can run in parallel.

| Phase | Candidate | Depends on | Size |
| --- | --- | --- | --- |
| 0 | Land the working tree as separate commits | — | ½ day |
| 1 | Split verdict from finding construction | 0 | 1 day |
| 2 | One truth lattice; Rego receives lifted atoms | 1 | 2 days |
| 3 | Address type and Resource constructor | 0 | 1 day |
| 4 | Finding record: the agent-facing contract | 1, 3 | 2 days |
| 5 | Scan request: one orchestration module | 2, 4 | 1½ days |
| 6 | In-memory analysis (optional) | 3 | 1 day |

### Guardrails that apply to every phase

1. `fixtures/baseline/native.json` is the behaviour oracle. A phase that changes it must explain
   every changed line in the commit message. Phases 1, 2, 3 and 5 must leave it byte-identical.
   Phase 4 changes its shape once, deliberately, and regenerates it.
2. `cargo test --workspace` and `cargo clippy --workspace --all-targets` clean at every commit.
3. Performance guard: `oxtf scan --recursive --format json corpus/repos`, release build, min of 5
   runs, before and after each phase. Record both numbers in the commit. A regression above
   10 % blocks the merge until explained.
4. One phase per branch. No phase touches a crate outside its file list without a note.

### Phase 0 — land the working tree

Split the current tree into these commits, in this order, each passing the suite:

1. **Rule selection rejects unknown IDs.** `engine.rs`, `scan.rs`, `tfscan_py/src/lib.rs`,
   `tests/selection.rs`, the CLI test. This is a security-tool bug fix and should land first.
2. **Resource reference matching replaces provenance-as-identity.** `references.rs` and its
   tests, the S3 rule, the `prov.rs` doc change, `CONTEXT.md`.
3. **Native baseline snapshot.** `native_baseline.rs`, `fixtures/baseline/`, the `.gitignore` line.
4. **Checkov parity harness and uncertainty experiment.** `bench/parity`, `bench/uncertainty`,
   `bench/results/*.json`, `fixtures/parity`, `fixtures/uncertainty`, the plan doc additions.
   Confirm `bench/uncertainty/target/` is not staged.
5. **Rego slice.** `crates/tf_rego`, `fixtures/rego`, `rego_native.rs`, the CLI flags, and the
   three public `report` functions on native rules. Mark the flags experimental in the help text.

Exit: `git status` clean, five commits, suite green.

### Phase 1 — split verdict from finding construction

**Files.** `crates/tf_linter/src/rule.rs`, `rules/*.rs`, `engine.rs`, `crates/tf_rego/src/lib.rs`,
`crates/tf_rule_ir/src/lib.rs`, `crates/tfscan_py/src/lib.rs` (callback rule), `bench/uncertainty/src/main.rs`.

**Shape.** Rules stop pushing findings. A rule answers two questions and nothing else:

```rust
pub trait Rule: RuleMeta + Send + Sync {
    /// Verdict for one resource instance, or None when the rule does not apply.
    fn verdict(&self, r: &Resource, m: &Module) -> Option<Verdict> { None }
    /// Verdicts for cross-resource rules, keyed by the resource instance they are about.
    fn module_verdicts(&self, m: &Module) -> Vec<(ResourceId, Verdict)> { vec![] }
    /// Wording. Receives the resource so rules stop re-reading it inside a closure.
    fn message(&self, r: &Resource, v: &Verdict) -> String;
}
```

One pure function owns everything `RuleContext::report` does today:

```rust
impl Finding {
    /// Existence gate, Truth → Severity, primary span, message suffix. Returns None
    /// when the verdict or the resource's existence yields no finding.
    pub fn from_verdict(info: &RuleInfo, r: &Resource, v: &Verdict, message: &str, root: &Path) -> Option<Finding>;
}
```

The engine is the only caller. `RuleContext` is deleted. The three `pub fn report` side doors on
native rules are deleted; `tf_rego` and `tf_rule_ir` call `Finding::from_verdict` through the
engine like everyone else. `DynRule` keeps the object-safe mirror of the trait and caches
`RuleInfo` once instead of allocating per call.

**Tests that survive.** All fixture tests, the baseline snapshot (byte-identical), rule IR
equivalence, Rego equivalence. **Tests added.** Unit tests for `from_verdict`: each cell of the
Truth × existence table, primary-span choice with and without a resource step, each message
suffix. `review_regressions.rs` moves off the temp directory onto `from_verdict`. The SSH test in
`tf_rego/src/ssh.rs` that re-implements the native rule calls `AwsSgOpenSsh.verdict` instead.

**Exit.** Baseline identical; `grep -r "fn report" crates/tf_linter/src/rules` returns nothing;
`bench/uncertainty` no longer wraps a fake rule to observe gating.

### Phase 2 — one truth lattice, Rego receives lifted atoms

**Files.** `crates/tf_eval/src/truth.rs`, `value.rs`, `crates/tf_semantic/src/analyze.rs`
(existence classification), `crates/tf_rule_ir/src/lib.rs`, `crates/tf_linter/src/rules/mod.rs`,
all of `crates/tf_rego/src`, `bench/uncertainty/policy.rego`.

**Shape, Rust side.** `tf_eval::truth` becomes the only lattice:

- `pub fn combine_one_of(verdicts, tainted) -> Verdict` (currently private).
- `Verdict::negate`, `truth::forall` (today spelled `negate(exists(negate))` in the rule IR).
- `Truth::rank() -> u8` and `Truth::from_rank(u8) -> Option<Truth>`, replacing the two hand
  copies in `tf_rego` and `bench/uncertainty`.
- `truth::classify_existence(&Value) -> Truth` replacing the three hand-rolled classifiers in
  `analyze.rs`. The count classifier currently ignores tainted alternatives; this is a behaviour
  fix and must be covered by a fixture before the change so the baseline diff is explained.
- `Value::field_or_null(name)` replacing the four `field()` copies.

**Shape, Rego side.** This is the design decision of the plan. The owner's goal (decided
2026-10-14) is that people **bring policies they already have**: Rego written for Conftest or
OPA against plan JSON, KICS queries, Trivy checks, and later other engines. Those policies will
not be rewritten against an oxtf-specific input. So the seam is a **projection**: the evaluated
model rendered into the input shape a policy family expects, with the policy run unchanged.

Two tiers, kept distinct in the output:

- **Foreign policies** (the product). The adapter projects each resource instance into the
  policy family's input shape. Only **Known** values are projected; every Unknown, Tainted or
  OneOf value is projected as absent and recorded on a per-resource **abstraction list** with
  its attribute path and kind. Rego never sees an abstract value, so it cannot mishandle one.
  A violation the policy reports on a resource is then classified by the adapter, never by the
  policy:
  - abstraction list empty → **Definite**;
  - list contains a Tainted value → **Conditional**, naming the variables;
  - list contains only Unknown values → **Indeterminate**, a third certainty level that says
    "the policy fired but an input it may depend on is provider-computed". Not Definite, not
    dropped. A patch tool must treat it as needs-a-human.
  This loses expression structure (the uncertainty experiment's 12/17 strategy) but it never
  inflates: a finding is Definite only when every projected input was Known. That is the
  property the patch chain needs. Finer classification (per-path dependency, bounded
  enumeration of OneOf) is a later optimisation behind the same interface.
- **Native policies** (the five seed rules, and any policy written for oxtf on purpose). The
  adapter lifts in Rust: the policy declares the attribute paths it reads, the adapter evaluates
  them with the native lattice and hands Rego **only Known leaves** plus an evidence handle per
  leaf, enumerating OneOf alternatives and combining with `combine_one_of`. The policy returns
  `{violates, evidence}`. Full native certainty, because the adapter did the lattice work.

The first projection adapter is **plan JSON shape**, because that is what the largest body of
existing Terraform Rego targets, and `tf_plan` already defines the mapping in the other
direction. KICS shape is the second adapter. Two adapters make the projection a real seam.

In both tiers, no lattice lives in Rego. `boolean.rego`, the lattice sections of `ssh.rego`, and
the per-rule `Shape` projections in `ssh.rs`, `iam.rs`, `s3.rs` are deleted. The five seed
policies become native-tier policies and shrink to the security predicate.

**Shape, output side.** `Severity` gains `Indeterminate`. `Finding::from_verdict` (Phase 1) is
unchanged for native rules; foreign findings reach it through a `Verdict` the adapter builds
from the abstraction list (`True` / `Tainted` / `Unknown`), so the existence gate, primary
span and suffix logic are shared. The finding record (Phase 4) carries the abstraction list and
the policy family, so a reader can tell a foreign finding from a native one.

**Tests that survive.** Rego-versus-native equivalence per fixture (now in-process; see Phase 5),
`verdict_and_witness_match_native_lattice` becomes a test of `combine_one_of` alone. **Tests
added.** Property test: for random lattice values, `test`, `map`, `exists`, `forall` agree with a
brute-force enumeration over OneOf alternatives. Unit tests for `classify_existence`.

**Exit.** `grep -rl "one_of" crates/tf_rego/src/*.rego bench/uncertainty/*.rego` returns nothing.
Seed policy total line count below 100. One unmodified Conftest-style policy from a public repo
(pinned by commit) runs over the plan-shape projection and produces findings on a fixture with
the expected certainty in each of the three classes. Performance guard passes with the Rego
backend on.

### Phase 3 — Address type and Resource constructor

**Files.** `crates/tf_semantic/src/model.rs`, `analyze.rs`, `references.rs`,
`crates/tf_plan/src/lib.rs`, `refs.rs`.

**Shape.**

```rust
/// Identity of a resource instance. CONTEXT.md: base address alone is not an identity.
pub struct Address { pub module: ModulePath, pub mode: Mode, pub ty: Arc<str>, pub name: Arc<str>, pub key: Option<InstanceKey> }
impl Address {
    pub fn parse(s: &str) -> Result<Address, AddressError>;
    pub fn base(&self) -> Address;              // key dropped
    pub fn local(&self) -> String;              // "data.T.N" or "T.N"
    pub fn to_string(&self) -> String;          // one quoting rule for keys
}
impl Resource { pub fn new(addr: Address, ty_schema: ..., attrs: ..., existence: Truth) -> Resource; }
impl Origin { pub fn computed(addr: &Address, attr: &str) -> Origin; }
```

Both front ends construct resources and computed origins through these. `match_resource_reference`
compares `Address` values, not strings. `DefaultValue → Value` becomes one function in `model.rs`.
The plan front end's `origin_from_refs` keeps its logic but builds through `Origin::computed`.
Dead `Resource::local_address` is deleted.

**Key quoting.** HCL uses Debug quoting, plan JSON is verbatim. Pick Terraform's own formatting
(`["key"]` with HCL string escaping) and add a fixture with a key that needs escaping to the
baseline before the change, so the diff shows the fix.

**Tests that survive.** All fixture and plan fixture tests. **Tests added.** `Address` round-trip
and quoting unit tests. `references.rs` tests build a `Resource` with `Resource::new` instead of
analysing a fixture directory.

**Exit.** Baseline identical except the new escaping fixture; `grep -rn 'format!("data.'` returns
one site.

### Phase 4 — the finding record: the agent-facing contract

**Files.** New `crates/tf_linter/src/record.rs`; `render.rs`; `crates/tf_cli/src/main.rs`;
`crates/tfscan_py/src/{lib,arrow}.rs`; `tests/native_baseline.rs`; `fixtures/baseline/`.

**Shape.** One owned, fully resolved record that every output renders from:

```rust
pub struct FindingRecord {
    pub schema: u32,                       // 1; bumped on any breaking change
    pub rule: RuleRef,                     // id, category, level, description
    pub severity: Severity,                // definite | conditional
    pub resource: Address,                 // structured, Phase 3
    pub root: PathBuf,
    pub attribute: Option<AttrPath>,       // typed path segments to the deciding value
    pub configured: Option<ValueRecord>,   // what the author wrote (absent, null, value)
    pub effective: Option<ValueRecord>,    // after defaults overlay
    pub location: Location,               // file, line, col, start, end
    pub provenance: Vec<StepRecord>,       // kind, label, location, resource address
    pub message: String,
    pub fix_hint: Option<FixHint>,         // see below
    pub fingerprint: String,               // stable across scans; see below
    pub abstractions: Vec<Abstraction>,    // foreign findings: paths that were not Known, with kind
}
pub struct ScanRecord {
    pub schema: u32,
    pub findings: Vec<FindingRecord>,
    pub diagnostics: Vec<DiagnosticRecord>, // same Location type as findings
    pub rule_errors: Vec<RuleError>,        // rule id, resource, message; never silent
    pub stats: ScanStats,
}
```

`fingerprint` is the identity a backlog tool keys on. It hashes rule id, root-relative
resource address, and attribute path. It deliberately excludes line numbers, message text and
severity, so a finding survives unrelated edits and a certainty change updates the existing
issue rather than filing a new one. Indeterminate findings carry their abstraction list so the
issue can say exactly which provider-computed inputs a human has to check.

`FixHint` is the hook for the patch tool: the attribute path, the span of the attribute if
present or the span of the block to insert into, and the desired value when the rule knows it
(`storage_encrypted = true`). Rules supply it through `Rule::fix_hint` with a default of `None`;
the first five rules get one each.

JSON serializes the record directly with serde. Arrow, the Python getters and the text renderer
read from the record. The four location formatters collapse to `Location::display`. The two
test normalisers collapse to one helper in `tf_linter::record::test_support`.

This is the one phase that changes the baseline shape. Regenerate it once, review the diff field
by field, and from then on it is the contract snapshot. Document the schema in
`docs/FINDING_SCHEMA.md` with a worked example an agent can pattern-match against.

**Tests that survive.** Everything, with the baseline regenerated. **Tests added.** Serde
round-trip of `ScanRecord`; a schema-stability test that fails if a field is added or removed
without bumping `schema`; one test per renderer that it covers every record field or lists the
ones it drops.

**Exit.** `grep -rn "elapsed_s\b" crates` returns nothing; Python, Arrow and JSON expose the same
field set; `rule_errors` appears in JSON output when a Rego policy fails.

### Phase 5 — scan request: one orchestration module

**Files.** `crates/tf_linter/src/scan.rs`, `engine.rs`, `crates/tf_cli/src/main.rs`,
`crates/tfscan_py/src/lib.rs`, `crates/tf_plan/src/lib.rs`, `crates/tf_rego/src/lib.rs`,
`crates/tf_cli/tests/*.rs`.

**Shape.**

```rust
pub struct ScanRequest {
    pub input: ScanInput,                  // Dirs { paths, recursive } | Plan { plan, source }
    pub catalog: Catalog,                  // builtin + rule files + python callbacks + rego policies
    pub selection: Option<Vec<String>>,    // one meaning: applied to the whole catalog
    pub backend: Backend,                  // Native | Rego
    pub var_files: Vec<PathBuf>,
    pub threads: Option<usize>,
}
pub fn scan(req: &ScanRequest) -> Result<ScanOutput, ScanError>;   // ScanOutput = ScanRecord + analyses
```

- `tf_rego` exposes `catalog(kinds) -> Result<Vec<Box<dyn DynRule>>, PolicyError>` and nothing
  else; the closure-wrapping API and the mutex error channel are deleted. Rule hooks return
  `Result`, and the engine collects failures into `rule_errors`.
- `ScanStats::from_findings` is the one stats fold; `tf_plan::scan_plan` uses it.
- `discover_roots` and the `is_dir` check live once, in `scan`.
- CLI and Python become argument adapters. Python gains plan scanning and the Rego backend for
  free. The CLI's `--rego-rds` flag is deleted; `--backend rego` remains.
- `CONTEXT.md`'s note that Python's `builtin` selection differs from CLI selection is resolved:
  selection applies to the whole catalog everywhere. Update the glossary entry.

**Tests that survive.** All, but moved in-process: `rego_native.rs` and `native_baseline.rs`
call `scan` instead of spawning the binary (74 spawns become 0). `cli.rs` keeps argument
parsing, exit codes and one smoke scan.

**Exit.** `grep -rn "discover_roots" crates/tf_cli crates/tfscan_py` returns nothing; Python test
scans a plan; suite wall time drops (record before and after).

### Phase 6 — in-memory analysis (optional)

Only if stdin scanning or editor integration becomes a goal. `FileTable` becomes the seam with a
disk adapter and an in-memory adapter; `analyze_sources(&[(PathBuf, String)], opts)` is the entry.
Phase 3 already removes the test pain that motivated this candidate.

## After this plan

Resume `RULE_ENGINES_PLAN.md` R2–R7 on top of the new seams. Every foreign engine is one more
projection adapter plus, where the engine is not Rego, one more execution adapter: Checkov
value checks translate to rule IR (full native certainty, because the IR runs on the lattice);
Checkov Python checks run through the callback path over the same Known-only projection and
abstraction-list classification as foreign Rego. The classification rule is the same for every
foreign family, so it is written once.

## Open decisions for the owner

1. ~~Is Rego a coverage bet or a validation harness?~~ **Decided 2026-10-14:** the point is
   letting people bring existing policies, Rego first. Phase 2 is shaped accordingly.
2. ~~Is a third certainty level acceptable?~~ **Decided 2026-10-14:** yes. Every Indeterminate
   finding becomes an issue in the backlog for a human. Consequence for Phase 4: a finding needs
   a **stable fingerprint** so a second scan does not file a second issue (see Phase 4).
3. ~~What does the patch tool need from `FixHint`?~~ **Decided 2026-10-14:** the patch tool
   is agent skills, with oxtf supplying deterministic primitives where a fix is mechanical. See
   *Patch chain* below. The fix hint is shaped for that split.
4. ~~Does Python stay a first-class consumer?~~ **Decided 2026-10-14:** yes; agent tooling will
   be built in Python. Phase 4 exposes the complete finding record in Python and Arrow, and
   Phase 5 gives Python every scan capability the CLI has.

## Patch chain: what oxtf provides, what skills do

The judgment in a fix is usually not *what* value to write but *where*. A finding's explanation
provenance already shows the choice: `storage_encrypted` is false because of a default in
`variables.tf`, overridden by `terraform.tfvars`, read through a local. Editing the resource
line, the variable default or the tfvars line are three different fixes with different blast
radius, and picking one is the agent's call. oxtf's job is to make that call well informed and
the chosen edit mechanical.

oxtf provides, in Python and the CLI:

- **Candidate edit sites.** The fix hint lists every step in the provenance chain as a
  candidate site with its file, span, the expression text there, and what kind of step it is
  (resource attribute, local, variable default, tfvars value, module argument). The agent picks.
- **A deterministic apply for the mechanical class.** "Set scalar attribute to literal" and
  "add missing attribute with literal" cover the five seed rules and most Checkov value checks.
  These are done in code, span-exact, through a lossless edit so formatting and comments survive.
  The spike ruled out an owned lossless tree (W1 non-goal); `hcl-edit` is already a dependency
  and is lossless, so the apply primitive uses it on the one file being edited. Anything else
  (rewriting a policy document, restructuring a block, changing a module interface) is left to
  the agent with the span as its anchor.
- **Verify.** Re-scan and report whether the finding's fingerprint is gone, and list any new
  findings the edit introduced. The skill loops on this.

Skills orchestrate: read finding record → choose site → apply (primitive or hand edit) → verify
→ file or update the backlog issue by fingerprint. Indeterminate findings skip apply and go
straight to the backlog with their abstraction list.

This is a later workstream, after Phase 4 defines the record and Phase 5 gives Python the scan
entry. It is listed here so the fix hint and fingerprint are shaped for it now.

## Glossary additions (proposed for CONTEXT.md)

- **Verdict**: a four-valued truth plus the witness value that decided it. Rules produce verdicts;
  they never produce findings.
- **Finding construction**: the single step that turns a verdict into a finding by applying the
  existence gate, certainty mapping, primary location and message suffix.
- **Finding record**: the resolved, versioned, agent-facing form of a finding; every output
  format is a projection of it.
- **Fix hint**: the part of a finding record that tells a patch tool where to edit and what value
  to write, when the rule knows it.
- **Rule catalog**: the complete set of rules available to one scan, from every backend. Rule
  selection applies to the whole catalog.
- **Scan request**: the one input to a scan: input kind, catalog, selection, backend, options.
- **Projection**: the evaluated model rendered into the input shape a foreign policy family
  expects. Only Known values are projected; abstract values become absent and are listed.
- **Abstraction list**: for one projected resource instance, the attribute paths whose values
  were Unknown, Tainted or OneOf and so did not reach the foreign policy. It decides the
  certainty of any foreign finding on that resource.
- **Indeterminate**: the certainty of a foreign finding on a resource whose abstraction list
  holds only provider-computed values. Neither Definite nor Conditional; needs a human.

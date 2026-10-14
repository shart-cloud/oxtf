# Spike: Rust Terraform Security Analyzer

Oct 14, 2026 · @Jared Gore

## Summary

This spike proves or kills one idea: a Rust Terraform security analyzer, built the way oxc builds its JavaScript tooling, with a Python package on top the way polars ships. The output is a working prototype plus a written findings report with a go/no-go recommendation, not a product.

The thesis: today's scanners run Rego over flattened JSON (Trivy, KICS) or Python over a resource graph (Checkov). None generate their resource model from provider schemas, none explain *why* a value is insecure (the chain from attribute to variable to tfvars line), and none are fast. A Rust engine with schema codegen, an abstract-value evaluator with provenance, and a shared rule engine across source and plan input would be meaningfully different.

Suggested timebox: about five agent-days, split across the workstreams below. Cut scope rather than extend the timebox, and record every cut in the report.

## Goals and non-goals

**Goals**

- An arena-allocated HCL AST and an error-recovering parser that handles real-world Terraform.
- Code generation from `terraform providers schema -json` for the latest major of each target provider: AWS 6.x, AzureRM 5.x, Google 8.x (changed from 7.x on 2026-10-14 to track the latest major).
- A Terraform semantic layer (module tree, symbols, reference graph) and a partial evaluator that tracks where each value came from.
- Five seed rules that exercise the hard cases: variable indirection, `dynamic` blocks, `jsonencode` policies, and cross-resource joins.
- A Python package (PyO3 + maturin) with a polars-style rule expression API, a callback escape hatch, and Arrow export.
- Measured answers to the open questions at the end of this doc.

**Non-goals**

- Rule coverage. Five good rules beat fifty shallow ones here.
- Older provider majors, HCL v1, or Terraform below 1.x.
- Remote module fetching, private registries, or Terraform Cloud integration. Treat remote module outputs as unknown.
- Autofix, LSP, editor integration, SARIF polish.
- A Checkov compatibility shim. Note feasibility in the report; don't build it.

## Workstreams

Run W1 and W2 in parallel first; W3 needs both; W4 needs W3; W6 needs W4. W5 is a stretch goal.

### W1. Parser and AST

Model the AST on oxc: `bumpalo` arena, `Box<'a, T>` / `Vec<'a, T>` / `Atom<'a>`, `u32` spans, enums of boxed variants, comments stored on the side.

- [ ] `tf_span` and `tf_allocator` crates.
- [ ] AST types: `File`, `Body`, `BodyItem`, `Attribute`, `Block`, `BlockLabel`, and `Expression` covering literals, templates and heredocs (including `%{ if }` / `%{ for }` directives), traversals with splats, function calls, tuples, objects, `for` expressions, conditionals, unary and binary ops.
- [ ] Hand-written lexer and recursive-descent parser with a Pratt loop for operators. It must recover from errors and still return a tree.
- [ ] Generated `Visit`, `VisitMut` and `AstKind`, via a build-time codegen crate or proc macros. Record which you chose and why.
- [ ] Size test asserting `size_of::<Expression>() == 16`.
- [ ] Accept unknown top-level blocks (`moved`, `import`, `removed`, `check`) without error.

**Exit:** parses every `.tf` file in the test corpus; differential test against `hcl-edit` shows no structural divergence (trivia excluded); snapshot tests with `insta`.

### W2. Provider schema codegen

- [ ] Pin AWS 6.x, AzureRM 5.x and Google 7.x in a `required_providers` file; run `terraform providers schema -json`; commit the JSON snapshots.
- [ ] Generator emits a compact schema IR (postcard or rkyv blob, `phf` index) covering every resource and data source: type, required/optional/computed, sensitive, deprecated, nesting mode, min/max items.
- [ ] Generator emits zero-cost typed views (`AwsSecurityGroup<'a>` over a resource node) only for resources listed in an allowlist.
- [ ] A hand-written defaults overlay (`defaults/aws.toml` etc.). The schema protocol does not carry default values, so absent-attribute checks depend on this file.
- [ ] A schema-diff script that reports new resources with no rules and breaks the build when a typed view references a removed attribute.

**Exit:** report the blob size, generated line count, and the clean-build and incremental compile-time cost of the generated code.

### W3. Semantic layer and evaluator

- [ ] Module assembly (all `.tf` in a directory), local module sources followed, remote sources marked opaque.
- [ ] Symbol table for `variable`, `local`, `resource`, `data`, `module`, `output`, with reference edges from every traversal root; implicit scopes for `count.index`, `each.*`, `self`, `path.*`, and `dynamic` iterators.
- [ ] Resource index by `(type, name)` for cross-resource joins.
- [ ] Use the schema IR to tell nested blocks from object-typed attributes, mark computed attributes unknown, and enforce AWS 6.x strict booleans.
- [ ] Abstract value lattice: `Known`, `Unknown { origin }`, `OneOf`, `Tainted`, each carrying a provenance chain of spans.
- [ ] Variable resolution from defaults and `.tfvars`; `dynamic` block expansion when `for_each` is known.
- [ ] Built-in functions: at least `jsonencode`, `concat`, `merge`, `lookup`, `format`, `toset`, `cidrsubnet`.

**Exit:** a test fixture where an open CIDR flows `tfvars` to variable to local to attribute, and the evaluator returns the full chain.

### W4. Rule engine and seed rules

oxc-linter shape: rules are small structs with `run_on_resource` and `run_on_module` hooks, dispatched by resource kind, run per module in parallel with rayon, diagnostics rendered with miette.

Seed rules (each needs positive and negative fixtures, including one via variable indirection and one via a `dynamic` block where it applies):

1. Security group ingress open to `0.0.0.0/0` on port 22, both inline `ingress` blocks and `aws_vpc_security_group_ingress_rule`.
2. `aws_s3_bucket` with no matching or a permissive `aws_s3_bucket_public_access_block` (cross-resource join).
3. IAM policy built with `jsonencode` granting `Action: "*"` on `Resource: "*"`.
4. `aws_db_instance` with storage encryption off or absent (exercises the defaults overlay).
5. One non-AWS rule, for example `google_storage_bucket` without uniform bucket-level access.

**Exit:** all fixtures pass; findings print the provenance chain; a findings severity distinguishes "definitely insecure" from "insecure depending on an unconstrained variable".

### W5. Plan JSON front end (stretch)

- [ ] Read `terraform show -json` output into the same resource model, values as `Known`.
- [ ] Use the plan's `configuration` section to map findings back to source spans.
- [ ] Run the W4 rules unchanged.

**Exit:** the same five rules fire on plan input for the W4 fixtures.

### W6. Python bindings

- [ ] PyO3 + maturin package (working name `tfscan`), abi3 wheel for Python 3.10+.
- [ ] Owned handles across the boundary: arena held in a `self_cell` owner behind `Arc`, Python objects hold the `Arc` plus a `NodeId`. No `'a` borrows cross into Python.
- [ ] Release the GIL for parse, analyze and scan (`allow_threads` or `detach`, depending on the PyO3 version pinned).
- [ ] Expression API that compiles to a Rust rule and runs without the GIL, plus a decorator callback API that only sees resources passing a Rust-side type filter.
- [ ] `.pyi` stubs generated from the same schema codegen as W2.
- [ ] `to_arrow()` on resources and findings.

**Exit:** seed rule 1 rewritten in the Python expression API produces identical findings; a benchmark comparing the expression path and the callback path on the corpus.

## Prior art

Read these before writing W3 and W4; Checkov's evaluator is the correctness bar, oxc is the architecture bar.

| Project | Status | Approach | What to take |
| --- | --- | --- | --- |
| [oxc](https://github.com/oxc-project/oxc) | Active | Rust; arena AST, codegen'd visitors, separate semantic crate, linter rules as structs | The whole crate layout, `AstKind`, node size tests, `oxc_linter` rule trait and context |
| [Trivy](https://trivy.dev/latest/community/contribute/checks/service-support) (absorbed [tfsec](https://appsecsanta.com/iac-security-tools/tfsec-vs-trivy) in Feb 2023) | Active | Go; hand-written adapters map Terraform into typed per-service structs whose values carry source metadata; checks in Rego | The typed model with per-value metadata; note that hand-writing adapters per service is the bottleneck W2 removes |
| [Checkov](https://www.paloaltonetworks.com/blog/?p=307181) | Active | Python; in-memory resource graph, variable rendering, for\_each and dynamic resolution, module fetching, plan plus source deep analysis | Edge cases in `checkov/terraform/graph_builder/variable_rendering`; graph (cross-resource) checks; plan plus source merging |
| [KICS](https://github.com/Checkmarx/kics/blob/master/docs/architecture.md) | Active | Go; parses to normalized JSON, runs Rego queries over it; 2,400+ queries | Rule catalog as a coverage checklist only |
| [Terrascan](https://appsecsanta.com/terrascan) | Archived Nov 2025 | Go; OPA/Rego policies | What not to do: it rejected `moved` blocks ([issue #1302](https://github.com/tenable/terrascan/issues/1302)) |
| [hcl-edit](https://docs.rs/crate/hcl-edit/latest) / [hcl-rs](https://docs.rs/crate/hcl-rs/latest/source/README.md) | Active, pre-1.0 | Rust; winnow parser, owned trees, trivia preserved; hcl-rs adds expression and template evaluation | Differential-test oracle for W1; reference for HCL grammar corners |
| `terraform providers schema -json` ([docs](https://developer.hashicorp.com/terraform/cli/commands/providers/schema)) | Stable format | Provider, resource and data source schemas as blocks of attributes and nested block types | The W2 codegen input |

## Open questions

The report must answer each of these with evidence (a number, a test, or a short code sample), not opinion.

1. **Hand-written parser or `hcl-edit`?** Compare effort, error recovery quality, and throughput on the corpus. Is owning the parser worth it?
2. **Visitor codegen: build-time crate or proc macros?** Which keeps compile times and iteration speed acceptable as the AST changes?
3. **Schema IR cost.** Blob size, compile time, and startup time for three providers. Does embedding all three in one binary stay reasonable, or should schemas load at runtime?
4. **Typed views: all resources or an allowlist?** Measure the compile-time cost of generating views for every AWS resource versus only those with rules.
5. **How much of the defaults overlay can be derived** from provider docs or source rather than written by hand?
6. **Evaluator depth.** Which Terraform functions and expression forms appear in the corpus's security-relevant attributes? Rank by frequency so later work targets the long tail correctly.
7. **Arena lifetime across PyO3.** Does the `self_cell` + `Arc` + `NodeId` pattern hold up ergonomically, or does it force an owned "export" model instead?
8. **Rule portability.** Can a Python expression rule serialize to a rule IR that the Rust CLI runs with no Python runtime?
9. **Speed versus incumbents.** Wall time on the corpus versus `trivy config` and `checkov -d`, same machine. Treat this as directional, since rule counts differ.

## Deliverables and success criteria

The spike succeeds if it produces a clear go/no-go backed by measurements, even if the answer is no-go.

**Deliverables**

- A Cargo workspace with the crates in the architecture section, plus the `tfscan` Python package.
- Committed provider schema snapshots and the generator that consumes them.
- A test corpus: a few popular open-source Terraform module repos (for example the `terraform-aws-modules` family) plus hand-written fixtures per seed rule.
- `SPIKE_REPORT.md` at the repo root: answers to every open question, benchmark tables, the list of scope cuts, and a go/no-go recommendation with the riskiest unknowns for a real build.

**Success criteria**

- [ ] Parser handles 100% of corpus files, and the `hcl-edit` differential test is clean.
- [ ] `Expression` size test passes at 16 bytes.
- [ ] All five seed rules pass their fixtures, including the variable-indirection and `dynamic` cases.
- [ ] At least one finding shows a full provenance chain from attribute back to a `.tfvars` line.
- [ ] A Python user can `pip install` the wheel, scan a directory, write a rule in the expression API, and get findings as an Arrow table.
- [ ] Benchmarks against Trivy and Checkov are recorded with machine specs and exact commands.

## Instructions for the executing agent

Work in the order below, commit small, and keep `SPIKE_REPORT.md` current as you go rather than writing it at the end.

1. **Check the environment first.** You need stable Rust, Python 3.10+, maturin, and network access to crates.io, PyPI, GitHub, and the Terraform registry (to download Terraform and the three providers for the schema dump). If the registry is unreachable, stop W2 and say so in the report; the owner will supply the schema JSON files. Do not work around a blocked network.
2. **Verify versions before pinning.** Look up the current latest release of each provider major (AWS 6.x, AzureRM 5.x, Google 7.x) and of PyO3, and record the exact versions used.
3. **Start W1 and W2 in parallel.** Use subagents if available. Neither depends on the other.
4. **Then W3, W4, W6, in that order.** Only start W5 if everything else meets its exit criteria with time left.
5. **Cut scope, not quality.** If a workstream runs long, drop items from its checklist and log each cut with the reason. A smaller prototype with honest numbers beats a broader one with guesses.
6. **No invented numbers.** Every benchmark in the report comes from a command you ran; include the command, machine specs, and raw output in an appendix.
7. **Independent check before finishing.** Have a separate subagent that has not seen the work read `SPIKE_REPORT.md` against this doc and confirm every open question is answered with evidence and every success criterion is marked met or not met.
8. **Finish** with the report, the go/no-go recommendation, and a short list of what a real build would need next.

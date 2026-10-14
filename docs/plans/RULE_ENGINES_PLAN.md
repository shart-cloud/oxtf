# Plan: Checkov and Rego (regorus) rule engines for oxtf

Oct 14, 2026 · follows [`SPIKE_REPORT.md`](../../SPIKE_REPORT.md) (recommendation: go)

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
2. **Results map back through paths.** KICS results carry `searchLine` paths like `["resource", "aws_security_group", "web", "ingress"]`; Checkov reports the resource and `evaluated_keys`. The resolver walks that path in the model to find the value, which yields span, provenance and taint.
3. **Four-valued semantics over a two-valued engine.** Rego and Checkov are true/false. The projection renders Unknown values the way each tool does for unresolved expressions (KICS: the raw `${...}` string), so foreign rules behave as they do natively on unknowns. A finding whose resolved path depends on a Tainted value becomes Conditional. Whether that's sound enough, or whether a second "pessimistic" evaluation is needed, is open question 3.
4. **One compile, many evaluations.** Policies are parsed and compiled once per scan; each root module is an independent regorus evaluation, run in parallel with rayon, which needs per-thread `Engine` clones (open question 4).

## Workstreams

R1 and R3 can run in parallel first; R2 needs R1; R4 needs R1 and R3; R6 needs R2 and R3. R5 and R7 are stretch.

### R1. Backend abstraction and native Rego

- [ ] Pin regorus. The smoke test used 0.13.0, released the day this plan was written; pin the newest release that is at least two weeks old when work starts (0.12.0 if started before 2026-10-28) and re-run the smoke test on it. Record features enabled (`full-opa` vs a minimal set) and the binary-size cost.
- [ ] `RuleBackend` trait in `tf_linter` (or a new `tf_rules` crate): `prepare(&Rules) -> Compiled`, `run(&Compiled, &Analysis) -> Vec<RawResult>`, `resolve(RawResult) -> Finding`. Port the native and rule-IR rules onto it without changing their findings (the 34 fixtures must stay green).
- [ ] **oxtf native input schema** for Rego (`input.resources[]` with `address`, `type`, `name`, `module`, `values`, `known`, `tainted_paths`, plus `input.variables`, `input.outputs`), documented as JSON Schema and generated `.pyi`/docs. Values are the evaluated values; unknowns are `null` with an entry in `unknown_paths`.
- [ ] Result contract: a policy's `deny` / `warn` rules return `{address, path, msg}`; the resolver maps `path` to span and provenance.
- [ ] `oxtf scan --policy DIR` and `tfscan.scan(..., policies=[...])`.
- [ ] Port seed rules 1–5 to Rego, including rule 2 (cross-resource join), which rule IR v1 couldn't express; they must produce identical findings to the native rules on all fixtures.

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

# Spike Report: Rust Terraform Security Analyzer (`oxtf`)

Status: **in progress** (W1–W4, W6 done; benchmark, W5 and go/no-go pending). This file is kept current as work lands. Plan: [`docs/SPIKE_PLAN.md`](docs/SPIKE_PLAN.md).

## Environment and pinned versions

Machine: cloud container, 4 vCPU, 15 GiB RAM, Linux 6.18 x86_64. Exact `lscpu` output is in Appendix A.

| Component | Version | How it was chosen |
| --- | --- | --- |
| Rust | 1.97.0 (stable) | Preinstalled |
| Python | 3.13.16 | Preinstalled |
| maturin | 1.15.0 | Latest on PyPI, 2026-10-14 |
| PyO3 | 0.29.3 | Latest stable on crates.io, 2026-10-14 |
| Terraform CLI | 1.16.6 | `checkpoint-api.hashicorp.com` current version, SHA256-verified |
| hashicorp/aws | 6.68.0 | Latest 6.x on registry.terraform.io |
| hashicorp/azurerm | 5.9.0 | Latest 5.x |
| cloudflare/cloudflare | 5.28.0 | Latest overall; added at the owner's request 2026-10-14 (not in the original plan) |
| hashicorp/kubernetes | 3.3.0 | Latest overall; added at the owner's request |
| integrations/github | 6.13.0 | Latest overall; added at the owner's request |
| hashicorp/google | 8.7.0 | Latest overall. **Deviation from plan:** the plan says 7.x; the owner asked on 2026-10-14 to target the latest major instead (7.46.1 was used briefly first) |

Network check (step 1): crates.io, PyPI, the Terraform registry and releases.hashicorp.com were all reachable; GitHub is reachable over git (`codeload` tarballs return 403, so the corpus is fetched with `git clone`).

### Provider schema snapshots

`schemas/providers/{aws,azurerm,google}.json`, produced by `schemas/providers/dump.sh` (`terraform providers schema -json`, split per provider).

| Provider | Resources | Data sources | JSON size |
| --- | ---: | ---: | ---: |
| aws 6.68.0 | 1730 | 685 | 19.7 MB |
| azurerm 5.9.0 | 1106 | 396 | 3.2 MB |
| google 8.7.0 | 1375 | 471 | 9.7 MB |
| cloudflare 5.28.0 | 272 | 468 | 3.2 MB |
| kubernetes 3.3.0 | 81 | 27 | 3.1 MB |
| github 6.13.0 | 88 | 75 | 0.2 MB |

Cloudflare 5.x is built on terraform-plugin-framework and uses nested attributes (`nested_type`) 2,997 times; kubernetes 16 times; the original three providers never. This exercises a schema shape the first three providers didn't.

Google 7.46.1 → 8.7.0 removed 16 resource types (e.g. `google_notebooks_*`, `google_iap_brand`, `google_beyondcorp_app_*`) and added 45. `google_storage_bucket.uniform_bucket_level_access` is `optional + computed` in 8.7.0, so an absent value is not provably `false` from the schema alone (relevant to the defaults overlay and seed rule 5).

`terraform init` took 30.3 s and the schema dump took 11.8 s (wall time, cached provider downloads not used).

### Corpus

`corpus/repos.txt` lists 17 module repos (12 terraform-aws-modules, 3 terraform-google-modules, 2 Azure). Commits are pinned in `corpus/repos.lock.pinned`; `corpus/fetch.sh` reproduces the checkout. Total: **2171 `.tf` files, 12 MB**.

## Open questions

_Answers are filled in as each workstream produces evidence._

1. **Hand-written parser or `hcl-edit`? Own it.** Evidence ([W1 findings](docs/findings/W1.md)):
   - *Throughput* on the corpus (single thread, `--release`, 3 runs × 10 passes): `tf_parser` median 207–231 MB/s vs `hcl-edit` 29–32 MB/s, **6.5–7.4× faster**. Memory: 4.22 arena bytes per source byte.
   - *Error recovery* on 12 broken inputs: `tf_parser` returns a tree 12/12 and keeps 24/24 valid attributes; `hcl-edit` returns no tree 0/12 (it has no recovery). First error at the ideal position: 10/12 vs 6/12.
   - *Effort:* lexer + parser are 1,826 LOC (written in one agent session). The `hcl-edit` → our-AST walker in the differential test is 279 LOC, so adopting `hcl-edit` would be cheaper up front but gives up recovery and ~7× throughput, and keeps an owned-tree dependency that can't use the arena.
   - *Correctness:* 2,192/2,192 corpus files parse with 0 errors and are structurally identical to `hcl-edit` after normalisation. Known deviations (pinned by tests): duplicate object keys are kept (hcl-edit keeps one entry per key), `<<-` dedent inside `%{}` directives follows Go HCL, and a literal newline in a quoted string is an error as in Terraform.
2. **Visitor codegen: build-time crate.** A proc-macro version was built and measured, then removed (commits `daba104`, `a8fc883`). Cold build of `tf_ast`: 1.2–1.7 s (codegen) vs 5.0–5.9 s (proc macro); with a 10× AST, 3.3–3.7 s vs 7.9–8.5 s. Incremental rebuild after adding a node type is the same either way (~0.4–0.7 s). Dependency count of `tf_ast`: 4 crates vs 10 (proc macro puts `syn` under every downstream crate). A freshness test (`crates/tf_ast_codegen/tests/fresh.rs`) fails when committed output is stale. Timings were noisy (W2 compiling concurrently); each is min/max of 3 runs.
3. **Schema IR cost: embed all three providers.** ([W2 findings](docs/findings/W2.md)) All 5,763 resource and data-source schemas (aws 6.68.0, azurerm 5.9.0, google 8.7.0) fit in a 1,453,065 B postcard blob plus a 499,872 B shared-symbol table (interning cut 5.3 MB → 1.95 MB; xz would give 358 KB, not applied). Embedding grows a tiny stripped binary from 344,848 B to 3,517,272 B (+3.0 MiB). Generated code is 17,518 lines. `tf_schema` clean release build is 2.04 s with the generated code vs 0.75 s without (incremental 1.86 s vs 0.78 s). Startup: per-resource lazy decode; first lookup 0.9–1.2 ms, a typical cold lookup 21–42 µs, warm lookup ~0.5 µs, the largest schema (`aws_wafv2_web_acl_rule`) 3.3–4.6 ms; decoding everything eagerly would cost 22.5–33.6 ms. Nothing here argues for runtime loading.
   *Six-provider addendum* ([W2-providers](docs/findings/W2-providers.md)): adding cloudflare 5.28.0, kubernetes 3.3.0 and github 6.13.0 (6,774 schemas total) grows blob + symbol table from 1,952,937 B to 2,153,555 B (+10.3%), the stripped tiny binary from 3,517,288 B to 3,908,152 B (+0.37 MiB), the `tf_schema` clean release build from 1.99 s to 2.33 s, and first lookup from 0.93 ms to 1.05 ms (before/after re-measured interleaved, min of ≥3, concurrent-load caveat). Cloudflare's 740 schemas cost 85 KB of blob despite 2,997 nested attributes. Still embed.
4. **Typed views: allowlist only.** Allowlist (11 types): 4,022 lines, 0.36 s clean release build, 118 MB peak rustc RSS, 0.76 MB rlib. All AWS except 6 giants (1,724 types): 461k lines, 49.6 s, 2.3 GB, 108 MB rlib. All 1,730 AWS types: 2.87M lines and **rustc OOM at 7.46 GB** (10 GB cap); the 3 `wafv2` and 3 `quicksight` resources alone are 2.41M lines because of deeply recursive nested blocks. Generating views for every resource is not viable; generate for resources that have rules. Even a single allowlisted resource can be expensive: the full `kubernetes_pod_v1` view is 8,737 lines (+0.57 s per release build), so the generator gained `prune = true`, which emits sub-views only along the paths the rules use (342 lines).
5. **Defaults overlay: mostly derivable for a draft, not for rule-critical entries.** Extraction from provider docs (`Defaults to ...` phrases) and Go source (`Default:` in schema definitions) recovers 1,927 (resource, path) defaults on 590 AWS resources and 1,000 on 375 Google resources. Where both sources yield a value they agree 641/648 (AWS) and 151/155 (Google); a hand-checked sample was 59/60 correct. 18 of the 22 hand-written overlay entries are recovered. The misses are exactly the security-relevant kind: API-side defaults not in source (`aws_db_instance.storage_encrypted`) and "absent means none" semantics (`aws_security_group.ingress`). Recommendation: generate a draft overlay automatically and require hand review for anything a rule reads.
6. **Evaluator depth: the long tail is provider-computed values and remote modules, not functions.** ([W3 findings](docs/findings/W3.md), `cargo run -p tf_semantic --release --example q6_eval_depth -- corpus/repos`) Across 504 root modules, 1,039 security-relevant attribute locations and 4,353 evaluations: **77.3% wholly Known**, 6.7% partially Known, 15.8% Unknown, 0.2% Tainted. The first run was 60.3% Known; four measurement-driven fixes (`optional()` type defaults, `nullable`, `setproduct`/`base64*`, rendering `data.aws_iam_policy_document`) raised it. Function ranking over all 11,727 corpus call sites: `try` 30.1%, `lookup` 24.3%, `length` 6.4%, `merge` 6.2%, `keys` 4.4%, `coalesce` 3.0%; the top 10 cover 81.0%, and the 77 implemented functions cover 99.1%. Unimplemented are `regex`/`regexall`, `file`/`templatefile`, hash and time functions. Unknown origins: computed by provider 13.3% (plus data-source attributes such as `.partition` 3.1%, `.arn` 1.3%), remote module outputs 2.5%, unexpanded `count.index` 1.1%, unsupported functions 3 evaluations of 4,353. Next investments: more deterministic data sources, optional resolution of registry modules from a local cache, per-instance `count` expansion.
7. **Arena lifetime across PyO3: the pattern works, but the owned model is the right boundary.** ([W6 findings](docs/findings/W6.md)) A `self_cell` + `Arc` + node-index prototype (`tfscan.parse`, `crates/tfscan_py/src/ast.rs`) compiles and costs nothing measurable: 1.88–1.91 ns per node access in Rust vs 1.82–1.85 ns for a plain owned vector; ~90–120 ns from Python, the same as the owned-model handles (79–135 ns), i.e. PyO3 call overhead. But it needs two `unsafe impl Send/Sync` (bumpalo's arena isn't `Sync`; pyclasses must be, and releasing the GIL needs `Send`) whose soundness argument rests on bumpalo internals, and it forces closure-only access (`#[not_covariant]`, because the arena `Box` makes the AST invariant; `#[covariant]` doesn't compile). Since rules need *evaluated* values and the W3 model is already owned and `Send + Sync`, the shipped boundary is `Arc<ScanData>` + indices with no `unsafe`. Expose the arena AST only as a read-only syntax API.
8. **Rule portability: yes, for expression rules.** A rule built in Python with `rule()/col()` serializes to a JSON rule IR (`crates/tf_rule_ir`), saved with `tfscan.save_rules`, and runs under `env -i oxtf scan --rule-file rules.json` with no Python runtime. Findings are identical to the Python run, including message, primary file:line and full provenance: 7 on the fixtures, 0 on the corpus, 577 and 4,309 on two generated corpora. Callback rules don't port (`save_rules` raises `TypeError`); unknown IR operators are rejected (exit 2). IR v1 limits: no string/CIDR functions, cross-resource joins, module rules or JSON-document traversal, so seed rules 1, 4 and 5 are expressible and match the built-ins, while rules 2 (join) and 3 (policy JSON) are not.
9. **Speed versus incumbents: oxtf is 3–4 orders of magnitude faster, with far fewer rules (directional).** Per-repo wall time, minimum of 3 runs (1 run when a run exceeded 300 s), each tool scanning each corpus repo recursively, on an otherwise idle 4-vCPU machine; full table and commands in the [benchmark section](#benchmark-q9). Totals across all 17 repos: **oxtf 0.51 s**, **Checkov 887 s**, **Trivy 1,588 s**. Without the two repos where Trivy's module evaluator blows up (Azure AVM storage, Google GKE): oxtf 0.42 s, Trivy 125 s, Checkov 741 s. Peak RSS: oxtf 34 MB, Checkov 409 MB, Trivy 1.4 GB. Caveat: oxtf runs 5 rules; Checkov ships 1,144 Terraform checks and Trivy fired 88 distinct check IDs on this corpus, so this measures architecture headroom, not a like-for-like product comparison. Parse + analysis (not rules) dominates oxtf's time (W6 measured rule evaluation at 0.5–0.7 ms of a ~0.3–0.5 s corpus scan), so adding rules should not change the order of magnitude.

## Success criteria

| Criterion | Status |
| --- | --- |
| Parser handles 100% of corpus files; `hcl-edit` differential clean | **met**: 2,192/2,192 files, 0 errors, 0 divergences |
| `Expression` size test passes at 16 bytes | **met**: `tf_ast` `size_tests::expression_is_16_bytes` |
| All five seed rules pass fixtures incl. variable-indirection and `dynamic` | **met**: 31/31 cases (29 original + 2 added for `aws_iam_policy_document`), `cargo test -p tf_linter --test fixtures` |
| A finding shows a full provenance chain back to a `.tfvars` line | **met**: `oxtf scan fixtures/rules/aws-sg-open-ssh/fail_tfvars_through_local` shows `terraform.tfvars:1` → `variables.tf:1` → `locals.tf:2` → `main.tf:6`; also asserted by `tf_semantic/tests/exit.rs` |
| Python: pip install wheel, scan, expression rule, Arrow findings | **met**: `maturin build --release` → `tfscan-0.0.1-cp310-abi3-manylinux_2_34_x86_64.whl` (1.9 MB); installed in a fresh venv, scan + expression rule + `findings_arrow()` (pyarrow `Table`) work; pytest 38 passed, 1 skipped (mypy not installed) in my re-run, 39/39 in the agent's |
| Benchmarks vs Trivy and Checkov recorded with specs and commands | **met**: [benchmark section](#benchmark-q9), `bench/compare.sh`, raw rows in `bench/results/compare.tsv` |

## Scope cuts

- W6: rule IR v1 has no string/CIDR functions, joins, module rules or JSON traversal; callbacks clone the resource per call and their values carry no file/line; wheel is manylinux_2_34 x86_64 only, no sdist tested, abi3 can't target free-threaded CPython; `oxtf rules` doesn't list `--rule-file` rules; arena AST prototype is read-only and not linked to resources.

- W3: `.tf.json`, `override.tf` merging and `terraform.tfvars.json` not handled; `count > 1` evaluated as one instance with `count.index` Unknown; `for_each` expansion capped at 64 keys; `regex`, `regexall`, `file`, `templatefile`, hash and time functions unimplemented; references into another resource's nested blocks, `self` and `terraform.workspace` are Unknown.
- W4: IAM rule ignores `NotAction`/`NotResource` and partial wildcards (`s3:*`); S3 rule ignores account-level public access blocks and bucket policies; remote module outputs never produce findings; no `--fail-on` exit code; a module called by several roots is analysed once per root (findings carry their `root`).

- W2 (six providers): `tf_semantic` does not yet use the nested-attribute child schema (`Member::inner()`), so children of framework nested attributes (e.g. `cloudflare_ruleset.rules[*].action`) get no computed/sensitive marking; no defaults for kubernetes workload pod templates (deployment, daemonset, statefulset); defaults extractor not run on the new providers; no typed sub-views for nested-attribute children. No rules target the new providers (441 resources, 570 data sources uncovered).
- W2: no azurerm defaults file (no seed rule targets azurerm); derived defaults measured but not merged into the runtime overlay; "all views" measured in a throwaway crate rather than a feature flag; defaults are scalars only (no list/map/object values); descriptions are not stored in the runtime IR.
- W1: diagnostics are plain structs (miette rendering moved to W4); no lossless/trivia tree (autofix and formatting are non-goals); the proc-macro visitor prototype was deleted after measuring.

## W3/W4 results in brief

- Crates: `tf_eval` (value lattice, provenance, 77 built-ins, four-valued truth; no module or schema knowledge) and `tf_semantic` (module assembly, symbols and reference edges, `count`/`for_each`/`dynamic` expansion, schema-aware evaluation, owned model); `tf_linter` (rule trait, rayon per root module, miette/JSON output); `tf_cli` (`oxtf`).
- Value lattice: `Known`, `Unknown { origin }`, `OneOf`, `Tainted`. **Tainted** = derived from an unconstrained input (root variable with no default and no tfvars value). Rules map a Tainted-dependent violation to **Conditional** severity; a verdict that depends on `Unknown` (provider-computed, remote module) produces no finding.
- Provenance: an `Arc`'d linked list of steps (8 bytes per value), each with kind, file span, label, and resource address when applicable.
- Corpus run, `oxtf scan --recursive corpus/repos`: 504 root modules, 1,498 module instances, 2,176 files, 5,227 resources, no panics, **2 findings** (both `aws-rds-unencrypted`, both true positives: examples set `storage_encrypted = false`). 0.33–0.57 s wall (4 threads), 0.86–0.98 s (1 thread), release; concurrent load caveat, final numbers in the benchmark section. 10 spot-checked non-findings were correct. The low count reflects secure-by-default modules and five narrow rules, not silent evaluator failure (see `crates/tf_linter/examples/audit.rs` in [W4 findings](docs/findings/W4.md)).

## W6 results in brief

- `tfscan` (PyO3 0.29.3, abi3-py310). GIL released with `Python::detach` (0.29's name for `allow_threads`) for scan, parse and Arrow building; a Python thread keeps 0.92–0.98× of its idle speed during a scan (0.008–0.009× when the GIL is forcibly held).
- **Exit: seed rule 1 in the expression API gives identical findings** to the built-in rule (address, root, severity, message; primary span and provenance on fixtures): 7 on the sg fixtures, 0 on the corpus (no SSH findings there, so weak evidence), and 577 / 625 / 575 / 4,309 on four seeded generated corpora that exercise every resolution path (about half conditional). Callback rule matches too.
- **Exit: expression vs callback benchmark** (rule evaluation only, single thread, min–median of 7, two full runs): real corpus built-in 0.5–0.7 ms, expression 0.5 ms, callback 3.6–5.6 ms; 3,000-root generated corpus 28.2–29.1 / 27.0–27.1 / 149.1–157.2 ms. Expression rules cost the same as compiled Rust; callbacks ~15 µs per resource. Callback scans get *slower* with threads (767 → 1,173 ms, 1 → 4 threads) from GIL contention, expression scans faster (349 → 174 ms).
- Arrow: arrow-rs 60 columns handed over via the PyCapsule stream interface; 46–70 ms for 5,227 corpus resources, dominated by attribute-to-JSON (~40 ms). The `attributes` column is a JSON string, not typed structs.
- `.pyi` stubs (`crates/tfscan_stubgen`) generated from the tf_schema allowlist: `Literal` attribute names, `TypedDict`s and typed `col_of` overloads; mypy rejects a misspelled attribute.

## Benchmark (Q9)

Command: `bench/compare.sh` (commit `24560f0`; hardened afterwards in `63d976a` with a per-run kill limit and preflight checks, which don't change the measurement). Machine: Appendix A (4 vCPU Intel Xeon @ 2.80 GHz, 15 GiB), otherwise idle (no compiles running). Tools: oxtf release build at commit `df0183d`, `oxtf scan --recursive --format json <repo>`; Trivy 0.76.0, `trivy config --quiet --skip-check-update --misconfig-scanners terraform --format json <repo>`; Checkov 3.3.29, `checkov -d <repo> --framework terraform --quiet --compact -o json --skip-download --download-external-modules false`. No tool fetched remote modules (oxtf treats them as opaque, Checkov flag above, Trivy observed not to download; see `bench/NOTES.md`). Timing: `bench/timeit.py` (wall clock plus `getrusage` of the child). One untimed warm-up of each tool first. Raw rows: `bench/results/compare.tsv`; log: `bench/results/compare.log`. Checkov exits 1 whenever checks fail; that is expected.

| Repo | oxtf (s) | Trivy (s) | Checkov (s) |
| --- | ---: | ---: | ---: |
| terraform-azurerm-aks | 0.02 | 27.75 | 107.68 |
| terraform-azurerm-avm-res-storage-storageaccount | 0.05 | 1212.42 ✗ (failed, rc=1, empty output; 1 run) | 87.06 |
| terraform-aws-alb | 0.01 | 7.21 | 9.65 |
| terraform-aws-autoscaling | 0.02 | 4.48 | 43.09 |
| terraform-aws-cloudfront | 0.01 | 2.39 | 9.36 |
| terraform-aws-ec2-instance | 0.02 | 3.94 | 21.32 |
| terraform-aws-eks | 0.04 | 13.74 | 113.21 |
| terraform-aws-iam | 0.03 | 3.65 | 29.21 |
| terraform-aws-lambda | 0.06 | 9.01 | 93.47 |
| terraform-aws-rds | 0.04 | 13.58 | 43.66 |
| terraform-aws-rds-aurora | 0.02 | 6.97 | 17.05 |
| terraform-aws-s3-bucket | 0.03 | 5.46 | 85.45 |
| terraform-aws-security-group | 0.03 | 3.38 | 43.91 |
| terraform-aws-vpc | 0.05 | 10.10 | 103.05 |
| terraform-google-cloud-storage | 0.01 | 4.27 | 4.30 |
| terraform-google-kubernetes-engine | 0.04 | 249.67 | 59.08 |
| terraform-google-network | 0.03 | 9.49 | 16.76 |
| **Total, 17 repos** | **0.51** | **1,587.51** | **887.31** |
| **Total, without AVM storage and GKE** | **0.42** | **125.42** | **741.17** |

CPU time (user + sys, summed over the same best runs): oxtf 1.13 s, Trivy 2,666.56 s, Checkov 880.51 s. Findings reported in run 1 (for scale, not quality): oxtf 2, Trivy 978 (16 of 17 repos; AVM failed), Checkov 1,671 failed checks.

Trivy's two outliers are not network: a 60 s `--debug` run on GKE logged 79,008 evaluator "Starting iteration" lines and no downloads; its fixpoint evaluator re-iterates nested local modules (see `bench/NOTES.md`). On the Azure AVM storage repo Trivy ran 1,212 s and then exited 1 with no output.

## Go / no-go

Pending.

## Appendix A: machine specs

```
Architecture:                            x86_64
CPU op-mode(s):                          32-bit, 64-bit
Address sizes:                           46 bits physical, 48 bits virtual
Byte Order:                              Little Endian
CPU(s):                                  4
On-line CPU(s) list:                     0-3
Vendor ID:                               GenuineIntel
Model name:                              Intel(R) Xeon(R) Processor @ 2.80GHz
CPU family:                              6
Model:                                   85
Thread(s) per core:                      1
Core(s) per socket:                      4
Socket(s):                               1
Stepping:                                7
BogoMIPS:                                5599.99
Flags:                                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault ssbd ibrs ibpb stibp ibrs_enhanced fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves arat umip avx512_vnni md_clear arch_capabilities
Hypervisor vendor:                       KVM
Virtualization type:                     full
L1d cache:                               128 KiB (4 instances)
L1i cache:                               128 KiB (4 instances)
L2 cache:                                4 MiB (4 instances)
L3 cache:                                33 MiB (1 instance)
NUMA node(s):                            1
NUMA node0 CPU(s):                       0-3
Vulnerability Gather data sampling:      Not affected
Vulnerability Ghostwrite:                Not affected
Vulnerability Indirect target selection: Mitigation; Aligned branch/return thunks
Vulnerability Itlb multihit:             Not affected
Vulnerability L1tf:                      Not affected
Vulnerability Mds:                       Not affected
Vulnerability Meltdown:                  Not affected
Vulnerability Mmio stale data:           Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown
Vulnerability Old microcode:             Not affected
Vulnerability Reg file data sampling:    Not affected
Vulnerability Retbleed:                  Mitigation; Enhanced IBRS
Vulnerability Spec rstack overflow:      Not affected
Vulnerability Spec store bypass:         Mitigation; Speculative Store Bypass disabled via prctl
Vulnerability Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
Vulnerability Spectre v2:                Mitigation; Enhanced / Automatic IBRS; IBPB conditional; PBRSB-eIBRS SW sequence; BHI Vulnerable
Vulnerability Srbds:                     Not affected
Vulnerability Tsa:                       Not affected
Vulnerability Tsx async abort:           Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown
Vulnerability Vmscape:                   Not affected
```

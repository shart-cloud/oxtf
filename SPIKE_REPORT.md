# Spike Report: Rust Terraform Security Analyzer (`oxtf`)

Status: **in progress**. This file is kept current as work lands. Plan: [`docs/SPIKE_PLAN.md`](docs/SPIKE_PLAN.md).

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
| hashicorp/google | 8.7.0 | Latest overall. **Deviation from plan:** the plan says 7.x; the owner asked on 2026-10-14 to target the latest major instead (7.46.1 was used briefly first) |

Network check (step 1): crates.io, PyPI, the Terraform registry and releases.hashicorp.com were all reachable; GitHub is reachable over git (`codeload` tarballs return 403, so the corpus is fetched with `git clone`).

### Provider schema snapshots

`schemas/providers/{aws,azurerm,google}.json`, produced by `schemas/providers/dump.sh` (`terraform providers schema -json`, split per provider).

| Provider | Resources | Data sources | JSON size |
| --- | ---: | ---: | ---: |
| aws 6.68.0 | 1730 | 685 | 19.7 MB |
| azurerm 5.9.0 | 1106 | 396 | 3.2 MB |
| google 8.7.0 | 1375 | 471 | 9.7 MB |

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
4. **Typed views: allowlist only.** Allowlist (11 types): 4,022 lines, 0.36 s clean release build, 118 MB peak rustc RSS, 0.76 MB rlib. All AWS except 6 giants (1,724 types): 461k lines, 49.6 s, 2.3 GB, 108 MB rlib. All 1,730 AWS types: 2.87M lines and **rustc OOM at 7.46 GB** (10 GB cap); the 3 `wafv2` and 3 `quicksight` resources alone are 2.41M lines because of deeply recursive nested blocks. Generating views for every resource is not viable; generate for resources that have rules.
5. **Defaults overlay: mostly derivable for a draft, not for rule-critical entries.** Extraction from provider docs (`Defaults to ...` phrases) and Go source (`Default:` in schema definitions) recovers 1,927 (resource, path) defaults on 590 AWS resources and 1,000 on 375 Google resources. Where both sources yield a value they agree 641/648 (AWS) and 151/155 (Google); a hand-checked sample was 59/60 correct. 18 of the 22 hand-written overlay entries are recovered. The misses are exactly the security-relevant kind: API-side defaults not in source (`aws_db_instance.storage_encrypted`) and "absent means none" semantics (`aws_security_group.ingress`). Recommendation: generate a draft overlay automatically and require hand review for anything a rule reads.
6. Evaluator depth — pending (W3)
7. Arena lifetime across PyO3 — pending (W6)
8. Rule portability — pending (W6)
9. Speed versus incumbents — pending

## Success criteria

| Criterion | Status |
| --- | --- |
| Parser handles 100% of corpus files; `hcl-edit` differential clean | **met**: 2,192/2,192 files, 0 errors, 0 divergences |
| `Expression` size test passes at 16 bytes | **met**: `tf_ast` `size_tests::expression_is_16_bytes` |
| All five seed rules pass fixtures incl. variable-indirection and `dynamic` | pending |
| A finding shows a full provenance chain back to a `.tfvars` line | pending |
| Python: pip install wheel, scan, expression rule, Arrow findings | pending |
| Benchmarks vs Trivy and Checkov recorded with specs and commands | pending |

## Scope cuts

- W2: no azurerm defaults file (no seed rule targets azurerm); derived defaults measured but not merged into the runtime overlay; "all views" measured in a throwaway crate rather than a feature flag; defaults are scalars only (no list/map/object values); descriptions are not stored in the runtime IR.
- W1: diagnostics are plain structs (miette rendering moved to W4); no lossless/trivia tree (autofix and formatting are non-goals); the proc-macro visitor prototype was deleted after measuring.

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

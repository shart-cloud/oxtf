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

1. Hand-written parser or `hcl-edit`? — pending (W1)
2. Visitor codegen: build-time crate or proc macros? — pending (W1)
3. Schema IR cost — pending (W2)
4. Typed views: all resources or allowlist? — pending (W2)
5. How much of the defaults overlay can be derived? — pending (W2)
6. Evaluator depth — pending (W3)
7. Arena lifetime across PyO3 — pending (W6)
8. Rule portability — pending (W6)
9. Speed versus incumbents — pending

## Success criteria

| Criterion | Status |
| --- | --- |
| Parser handles 100% of corpus files; `hcl-edit` differential clean | pending |
| `Expression` size test passes at 16 bytes | pending |
| All five seed rules pass fixtures incl. variable-indirection and `dynamic` | pending |
| A finding shows a full provenance chain back to a `.tfvars` line | pending |
| Python: pip install wheel, scan, expression rule, Arrow findings | pending |
| Benchmarks vs Trivy and Checkov recorded with specs and commands | pending |

## Scope cuts

_None yet._

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

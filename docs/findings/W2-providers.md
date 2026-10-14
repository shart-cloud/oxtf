# W2 addendum: six providers and nested attributes

Status: done. The generator now covers six providers:

- aws, azurerm, google (unchanged)
- **cloudflare/cloudflare 5.28.0**: 272 resources, 468 data sources
- **hashicorp/kubernetes 3.3.0**: 81 resources, 27 data sources
- **integrations/github 6.13.0**: 88 resources, 75 data sources

Protocol-6 nested attributes now have an API and real-data tests. Five views and 15 default entries were added. Q3 and Q4 were re-measured. This file supplements `docs/findings/W2.md`, which is unchanged.

Commits on `claude/gifted-hypatia-v3im2o`:

| Commit | Change |
|---|---|
| `c09382b` | providers + nested-attribute API + views + regenerated blob |
| `467ec46` | defaults overlay |
| `b0d47fe` | allowlist `prune`, applied to the pod view; bench additions |
| `5878e3d` | coverage column width |

Machine: 4 vCPU Intel Xeon @ 2.80GHz, 15 GiB RAM, rustc 1.97.0.

**Caveat on timings:** the W3/W4 agent was compiling and testing in the same checkout while these timings ran. Two cargo/rustc processes were already running when the final build-time run started, and load average was 1.2–3.4 during the runs.

To reduce bias, every comparison was **re-measured now, interleaved**:

- `base` is the 3-provider tree (`git archive 232a763`, i.e. what W2.md measured).
- `new` is the 6-provider tree (`git archive` of HEAD after `b0d47fe`).
- Each tree has its own `CARGO_TARGET_DIR`, and runs alternated base/new.

Each figure is the minimum of ≥3 runs. W2.md's original numbers are shown alongside for reference.

## What changed

### Provider list (data-driven)

The provider list was hardcoded in four places:

- the `Provider` enum and `Provider::ALL`
- `provider_ident` in the generator
- `load_all`
- `read_defaults`

It is now a single table in `crates/tf_schema/src/ir.rs`: the `Provider` enum plus `name()` and the new `source()`. All the generator code above derives from `Provider::ALL`, and `provider_ident` uses `Debug`.

- **Registry address check.** A snapshot's registry address must equal `registry.terraform.io/<Provider::source()>`. This handles `cloudflare/…` and `integrations/…`, and also means a `hashicorp/github` file would be rejected.
- **Unknown snapshots.** `load_all` fails if `schemas/providers/` holds a `*.json` with no `Provider` variant (tested), so a new snapshot cannot be silently ignored.
- **Adding a provider** takes one variant, two match arms and the JSON file.
- **Why the enum is not generated:** the generator itself depends on `tf_schema::ir`, and W3 already uses `Provider::Aws`.

### Nested attributes: how they are represented

The IR already had `CtyType::Nested(NestingMode, Box<Block>)`. It was lossless, but no real data had ever exercised it. Now real data does: cloudflare has 2,997 nested attributes, nested up to 8 levels deep, and kubernetes has 16.

The test `nested_attribute_counts` walks the embedded IR and finds exactly 2,997 and 16. These match `grep -o '"nested_type"' | wc -l` on the snapshots. No IR or blob format change was needed.

**The semantics W3 needs:**

- **It is an attribute.** `Block::member(name)` returns `Member::Attribute`, and `block_type(name)` is `None`. `Attribute::accepts_block_syntax()` is **false**. Configuration writes it as:
  - `rules = [{ ... }]` (list or set)
  - `x = { ... }` (single)
  - `x = { k = { ... } }` (map)

  It is never written as `rules { ... }`.
- **Structure.** `Attribute::nested()` returns `(NestingMode, &Block)`, where the `Block` holds the child attributes and never has `block_types`.
  - Each child carries its own required, optional, computed, sensitive, deprecated and write-only flags.
  - The nested attribute itself has its own flags, e.g. `rules` is optional and computed.
  - Sensitivity is per child: `cloudflare_hyperdrive_config.origin` is not sensitive, but `origin.password` is.
- **Nesting mode** is `Single`, `List`, `Set` or `Map`. All four occur in cloudflare (single 2,166, list 665, map 102, set 64). 94 nested attributes have no `attributes` key and decode to an empty `Block`.

**API additions** (all additive; nothing was removed or renamed):

```rust
Attribute::is_nested() -> bool
Attribute::nested() -> Option<(NestingMode, &Block)>      // None for object(...)-typed attrs too
Attribute::nested_block() -> Option<&Block>
CtyType::nested() -> Option<(NestingMode, &Block)>
Member::{name(), is_attribute(), inner() -> Option<&Block> /* nested block body or nested attr children */, nesting()}
Block::member_at(&[&str]) -> Option<Member>   // walks nested blocks AND nested attributes
Block::descend(&[&str])                        // now ALSO walks nested attributes (was: blocks only)
Block::descend_blocks(&[&str])                 // the old block-only walk
Provider::{Cloudflare, Kubernetes, Github}, Provider::source(), Provider::from_name()
AllowEntry::prune (generator)
```

`Block::descend` changed behaviour, but only for paths through nested attributes. Before this change such paths could not exist, and nothing in the workspace calls `descend` (grep). `Provider::ALL` changed type from `[Provider; 3]` to `[Provider; 6]`; no downstream code names the type. `Provider` gained variants; no downstream code matches on it exhaustively (only `== Provider::Aws` in `tf_semantic`). `Member` gained **no** variant, so the existing exhaustive matches in `tf_semantic` still compile. `cargo check --workspace --all-targets` and `cargo test -p tf_semantic -p tf_linter` pass.

**Example walk** (real output from a scratch example against the committed blob; appendix B4):

```
member("rules"): is_attribute=true nesting=Some(List) block_type("rules")=None
rules: ty=nested(List) flags=optional+computed is_nested=true accepts_block_syntax=false
  rules.action                     string           required
  rules.action_parameters          nested(Single)   optional+computed
  rules.enabled                    bool             optional+computed
  rules.expression                 string           required
  rules.id                         string           computed
  ...
member_at(["rules", "action_parameters", "headers"]) = attribute headers nested(Map) optional
member_at(["rules", "action_parameters", "headers", "operation"]) = attribute operation string required
descend([rules, action_parameters]) attrs=80
descend_blocks([rules]) = None
vap member_at(["spec"]): attribute nesting=Some(Single)        # kubernetes_validating_admission_policy_v1
vap member_at(["timeouts"]): block nesting=Some(Single)        # same resource mixes both
vap member_at(["spec", "match_constraints", "resource_rules"]): attribute nesting=Some(List)
```

**Generator side:**

- Allowlist `uses` paths and defaults paths already resolved through `Nested`; this is now tested.
- `diff` now recurses into nested attributes and reports e.g. `rules.expression: string [required] -> string [optional]`.
- A default of `[]` (`Empty`) is accepted on nested list, set and map attributes.

**Tests:**

- `crates/tf_schema/tests/nested.rs` covers:
  - `cloudflare_ruleset` (list, three levels down to a map)
  - `cloudflare_account_member` (set)
  - `cloudflare_hyperdrive_config` (single, sensitive child)
  - `cloudflare_pages_project` (map three deep, empty nested_type)
  - `kubernetes_validating_admission_policy_v1` (nested attributes and a block in one resource)
  - `kubernetes_pod_v1` (SDKv2 blocks)
- `crates/tf_schema_codegen/tests/codegen.rs` covers `uses`, defaults and diff through nested attributes, and provider-address resolution.

### Typed views

Five views were added; there are now 16 allowlisted views.

| View | Generated lines | Notes |
|---|---|---|
| `CloudflareRuleset` | 83 | `rules()` is a nested list |
| `CloudflareZoneSetting` | 73 | `value` is `dynamic` |
| `KubernetesPodV1` | 342 | `prune = true`; 8,737 lines unpruned |
| `GithubRepository` | 658 | |
| `GithubBranchProtection` | 254 | |

**What a view returns for a nested attribute:** the whole value, `Option<N::Value>`, like any attribute. No child view struct is generated, because the value is written with `=` and `ResourceNode::blocks` never yields it. A rule that needs `rules[*].action` reads it from the evaluator's value.

The accessor's doc comment states the mode, the syntax and the children with their flags, for example:

```
`rules`: nested attribute, list of objects (optional, computed). Attribute syntax `rules = [{ ... }]`, not a block; ...
Children: `action` string (required), `action_parameters` nested Single (optional, computed), ...
```

This also makes framework views cheap: `cloudflare_ruleset` has 116 nested attributes but its view is 83 lines.

**New allowlist option `prune = true`.** The kubernetes pod spec is SDKv2 with deep nested blocks, so a full view generates one struct per nesting path: 8,737 lines for one resource, more than twice the whole previous `views.rs`. That one view cost about +0.57 s per clean release build of `tf_schema` (table below). With `prune`:

- child view structs are generated only along `uses` paths;
- every attribute accessor of the structs that are generated is kept;
- skipped blocks get a `// pruned block "volume"` comment.

The pod view drops to 342 lines. This is tested in `prune_limits_child_views_to_uses_paths`.

### Defaults overlay

There are 15 new entries, for 37 in total. Each was verified by reading source or docs at the pinned tag (shallow clones; commit SHAs in the toml headers and appendix B6). Each entry's `note` cites file and line.

| Resource | Path | Value | Source at tag |
|---|---|---|---|
| github_repository | visibility | "public" | `resource_github_repository.go:523` `calculateVisibility` returns "public" when neither `visibility` nor `private` is set (optional+computed, so only when `private` is absent too) |
| github_repository | private | false | docs `repository.md.tmpl:37` "Repositories are created as public ... by default" |
| github_branch_protection | enforce_admins, allows_force_pushes, allows_deletions, require_signed_commits | false | `resource_github_branch_protection.go:31-53` `Default: false` |
| kubernetes_pod_v1 | spec.container.security_context.privileged | false | `schema_container.go:797-802` `Default: false` |
| kubernetes_pod_v1 | spec.container.security_context.allow_privilege_escalation | **true** | `schema_container.go:766-771` `Default: true` |
| kubernetes_pod_v1 | spec.host_network, spec.host_pid, spec.host_ipc | false | `schema_pod_spec.go:173-196` `conditionalDefault(!isComputed, false)`; pod_v1 uses `podSpecFields(false, false)` |
| kubernetes_pod_v1 | spec.automount_service_account_token | true | `schema_pod_spec.go:35-40` `Default: true` |
| cloudflare_dns_record | proxied | false | `dns_record/schema.go:352-357` `booldefault.StaticBool(false)` |
| cloudflare_ruleset | rules | [] (Empty) | `ruleset/schema.go:131-135` `listdefault.StaticValue(empty)` |
| cloudflare_ruleset | rules.enabled | true | `ruleset/schema.go:2252-2257` `booldefault.StaticBool(true)`. This default sits **inside a nested attribute** |

Three of these need careful handling by W3:

- **Defaults inside nested blocks apply only when the parent block is present.** With no `security_context` block, the kubernetes provider sends no security context at all. This is the same semantics as `google_storage_bucket.versioning.enabled` in W2.
- **Some security-relevant defaults are `true`.** In kubernetes 3.3.0, `allow_privilege_escalation` and `automount_service_account_token` both default to `true`.
- **`cloudflare_ruleset.rules.enabled` applies per element** of `rules`.

## Q3 / Q4 before and after

"W2.md" is the published 3-provider figure. "base" and "new" were measured interleaved in this session (appendix B1–B3).

| Metric | W2.md (3 providers) | base, now (3) | **new (6)** | Delta new − base |
|---|---|---|---|---|
| Schemas | 5,763 | 5,763 | **6,774** | +1,011 |
| schema.postcard | 1,453,065 B | same | **1,618,178 B** | +165,113 (+11.4%) |
| symbols.postcard (names) | 499,872 B (25,893) | same | **535,377 B (28,094)** | +35,505 |
| Blob + symbols | 1,952,937 B | same | **2,153,555 B** (2.05 MiB) | +200,618 (+10.3%) |
| gzip -9 schema + symbols | 276,278 + 164,448 | same | 313,740 + 178,265 | +51,279 |
| xz -9 of both files concatenated | 358,488 | same | 397,752 | +39,264 |
| Generated lines: index / views / defaults | 13,479 / 4,022 / 17 | same | **15,838 / 5,419 / 24** | +2,359 / +1,397 / +7 |
| Generated lines total | 17,518 | same | **21,281** (29,676 with unpruned pod view) | +3,763 |
| Generator `check`, release | 0.65–0.80 s | 620–810 ms | 711–932 ms | ≈ +0.1–0.2 s |
| `tf_schema` clean release (deps prebuilt) | 2.04 s | 1.99 s | **2.33 s** (unpruned pod view: 2.90 s) | **+0.34 s** |
| … `--no-default-features` (no generated code) | 0.75 s | 0.79 s | 0.88 s | noise |
| `tf_schema` incremental release (touch lib.rs) | 1.86 s | 2.00 s | **2.28 s** (unpruned: 3.00 s) | **+0.28 s** |
| `tf_schema` clean debug / incremental debug | 1.79 / 0.50 s | 1.92 / 0.52 s | 2.17 / 0.67 s | +0.25 / +0.15 s |
| `tf_schema` from scratch incl. deps, release | 8.58 s | 8.86 s | 9.17 s | +0.31 s |
| Tiny bin (stripped), linking `tf_schema` | 3,517,272 B | 3,517,288 B | **3,908,152 B** | **+390,864 B (+0.37 MiB)** |
| … vs the same bin without `tf_schema` (344,848 B) | +3,172,424 | +3,172,440 | **+3,563,304 (+3.4 MiB)** | |
| Tiny bin, gzip -9 | 753,031 B | 753,026 B | 825,507 B | +72,481 |
| First lookup (symbol table + 1 schema) | 0.90–1.24 ms | 0.93–1.16 ms | **1.05–1.36 ms** | ≈ +0.1 ms |
| Second lookup (aws_db_instance) | 21–42 µs (one 234 µs) | 28–75 µs | 29.6–47 µs | — |
| Largest schema, first lookup (aws_wafv2_web_acl_rule) | 3.3–4.6 ms | 3.76–4.70 ms | 3.50–6.26 ms | — |
| **Largest new-provider schema, first lookup** | – | – | **kubernetes_stateful_set_v1 (3,744 B): 86–217 µs**; cloudflare_zero_trust_access_application (1,800 B): 49–111 µs | |
| Decode all remaining schemas, cold | 22.5–33.6 ms | 27.8–38.7 ms | 28.1–47.8 ms | — |
| Cached lookup of all + `attribute("id")` | 2.7–3.7 ms | 3.30–3.83 ms (5,763) | 3.62–7.83 ms (6,774) | ≈ +0.3 ms at min |

**Per-provider share of schema.postcard (new):**

| Provider | Bytes | Schemas | Median record |
|---|---|---|---|
| aws | 1,054,965 B | 2,415 | – |
| azurerm | 160,359 B | 1,502 | – |
| google | 240,916 B | 1,846 | – |
| cloudflare | 84,997 B | 740 | 58 B |
| kubernetes | 69,422 B | 108 | 93 B |
| github | 7,519 B | 163 | 29 B |

AWS grew by 2,718 B with no schema change. Adding 2,201 symbols re-ranks the frequency-ordered ids, so some AWS names now need longer varints.

**Largest records in the new providers:**

- kubernetes_stateful_set_v1 and kubernetes_stateful_set: 3,744 B each
- kubernetes_cron_job_v1: 3,720 B
- cloudflare_zero_trust_access_applications (data source): 1,805 B
- cloudflare_zero_trust_access_application: 1,804 B (data source) and 1,800 B (resource)
- github_organization_ruleset: 511 B

The overall top records are still AWS (aws_wafv2_web_acl_rule is 221,918 B).

**Q3 conclusion is unchanged: embed.** The three new providers cost:

- **+0.20 MB** of data
- **+0.39 MB** of stripped binary
- about **+0.3 s** per clean or incremental `tf_schema` release build
- about +0.1 ms on the first lookup

Cloudflare's 740 schemas take only 85 KB despite 2,997 nested attributes, because names are interned (one or two bytes each). Per-type lookup cost stays in the tens to hundreds of microseconds.

**Q4 conclusion is unchanged: allowlist, with one new data point.** View cost is driven by nested-*block* depth, not by schema size:

- A single SDKv2 kubernetes pod view, unpruned, adds 8,737 lines and about +0.57 s per `tf_schema` release build (2.90 s vs 2.33 s clean; 3.00 s vs 2.28 s incremental).
- Framework nested attributes cost nothing extra in views, because they are values, not structs.

The new `prune` option keeps deep SDKv2 resources affordable in the allowlist.

## Coverage (schema-diff tool `coverage`)

No rule targets any of the new providers. `rule_targets.txt` is unchanged and holds 11 targets, all aws or google.

| Provider | Resources without rules | Data sources without rules |
|---|---|---|
| cloudflare | **272 / 272** | **468 / 468** |
| kubernetes | **81 / 81** | **27 / 27** |
| github | **88 / 88** | **75 / 75** |
| New providers, total | **441 resources** | **570 data sources** |

## Scope cuts

| Cut | Why |
|---|---|
| No typed sub-views for nested-attribute children | The value is an evaluator value written with `=`. A struct over `N::Block` would never be populated by `ResourceNode::blocks`. Children are documented on the accessor and walkable via `member_at`. |
| Defaults: only 15 entries on 5 resources | The task asked for minimal and security-relevant. Not covered: `kubernetes_deployment_v1`, daemonset and statefulset pod templates (same `podSpecFields` and `securityContextSchema`, so the same values apply, but they were not added), legacy unversioned `kubernetes_pod`, and other cloudflare `*_setting` resources. |
| Q5 extractor (`extract_defaults.py`) not run on the new providers | It knows the aws and google repo layouts only. Cloudflare's `internal/services/*/schema.go` uses framework `booldefault`, which the regexes already match, but resource attribution would need a new rule. |
| `views-all` Q4 experiment not re-run per new provider | The pod data point above answers the question. Cloudflare views are flat. |
| `Provider` not made `#[non_exhaustive]` | It would be a (theoretical) breaking change. Downstream crates should avoid exhaustive matches on it. |
| No old-vs-new `diff` demo for the new providers | There is only one snapshot of each. Nested-attribute diffing is covered by a test that edits the ruleset schema. |
| `CtyType` `Display` for nested is still `nested(List)` | Children are listed by `diff` (recursive) and by view docs. Changing the type's string form gained nothing. |

## Known gaps / notes for W3

- `tf_semantic::analyze::nested_schema()` maps every `Member::Attribute` to `(None, true)`. For a nested attribute it should descend with `member.inner()` (or `attr.nested_block()`). Without that, `cloudflare_ruleset.rules[*].action` gets no schema, so computed or sensitive children are not marked. That code belongs to W3 and was not touched.
- Computed-only nested attributes are common: 2,073 of cloudflare's 2,997 nested attributes are `computed` only, mostly in data sources. `is_computed_only()` applies to the nested attribute as a whole.
- `default_for` paths through nested attributes (`rules.enabled`) apply per element. Paths through nested blocks apply only when the block is present.
- `kubernetes_pod_v1` is pruned: only `spec`, `spec.container` and `spec.container.security_context` have child views. Rules on other pod blocks must add their path to `uses`, or use the dynamic API.

## Appendix: commands and raw output

### B1. Generation and sizes
```
$ cargo run -q -p tf_schema_codegen --release -- check        # (in /tmp/claude-0/w2p/new, OXTF_ROOT set)
schema.postcard     1618178 bytes        - lines
symbols.postcard     535377 bytes        - lines
index.rs             924461 bytes    15838 lines
views.rs             191062 bytes     5419 lines
defaults.rs            5319 bytes       24 lines
6774 schemas, 37 defaults, 710.82ms
$ (same, base tree)
schema.postcard     1453065 bytes        - lines
symbols.postcard     499872 bytes        - lines
index.rs             782466 bytes    13479 lines
views.rs             135105 bytes     4022 lines
defaults.rs            2808 bytes       17 lines
5763 schemas, 22 defaults, 620.13ms
$ for i in 1 2 3; do for t in base new; do OXTF_ROOT=/tmp/claude-0/w2p/$t target-$t/release/tf_schema_codegen check | tail -1; done; done
base: 5763 schemas, 22 defaults, 666.52ms
new: 6774 schemas, 37 defaults, 858.67ms
base: 5763 schemas, 22 defaults, 760.44ms
new: 6774 schemas, 37 defaults, 917.42ms
base: 5763 schemas, 22 defaults, 809.67ms
new: 6774 schemas, 37 defaults, 931.84ms
```
Before `prune` (first `generate` with the five new views): `views.rs 515224 bytes 13814 lines` (`kubernetes_pod_v1` module: 8,737 lines, counted with `awk '/^pub mod /{...}' views.rs`).
```
$ for f in schema.postcard symbols.postcard; do echo "$f raw $(wc -c <$f) gzip9 $(gzip -9 -c $f|wc -c) xz9 $(xz -9 -c $f|wc -c)"; done; cat schema.postcard symbols.postcard | xz -9 | wc -c
schema.postcard raw 1618178 gzip9 313740 xz9 243600
symbols.postcard raw 535377 gzip9 178265 xz9 154272
397752
$ python3 -I symcount.py base/.../symbols.postcard new/.../symbols.postcard     # postcard Vec<&str> decoder
base/crates/tf_schema/src/generated/symbols.postcard symbols 25893 one-byte ids 128
new/crates/tf_schema/src/generated/symbols.postcard symbols 28094 one-byte ids 128
```
Per-provider share and largest records (inline Python over the `e(name, kind, provider, start, end)` rows of `index.rs`):
```
entries 6774 total 1618178
Aws           1054965 B   2415 schemas
Azurerm        160359 B   1502 schemas
Google         240916 B   1846 schemas
Cloudflare      84997 B    740 schemas
Kubernetes      69422 B    108 schemas
Github           7519 B    163 schemas
top overall [(221918, 'aws_wafv2_web_acl_rule', 'Aws', 'Resource'), (106787, 'aws_wafv2_web_acl', 'Aws', 'Resource'), (102377, 'aws_quicksight_dashboard', 'Aws', 'Resource')]
Cloudflare top3 [(1805, 'cloudflare_zero_trust_access_applications', 'Cloudflare', 'DataSource'), (1804, 'cloudflare_zero_trust_access_application', 'Cloudflare', 'DataSource'), (1800, 'cloudflare_zero_trust_access_application', 'Cloudflare', 'Resource')] median 58.0
Kubernetes top3 [(3744, 'kubernetes_stateful_set_v1', 'Kubernetes', 'Resource'), (3744, 'kubernetes_stateful_set', 'Kubernetes', 'Resource'), (3720, 'kubernetes_cron_job_v1', 'Kubernetes', 'Resource')] median 93.0
Github top3 [(511, 'github_organization_ruleset', 'Github', 'Resource'), (474, 'github_repository_ruleset', 'Github', 'Resource'), (338, 'github_repository', 'Github', 'Resource')] median 29
median all 56.0
```
View lines per module (new):
```
1239 aws_s3_bucket / 1018 google_storage_bucket / 739 aws_db_instance / 658 github_repository / 342 kubernetes_pod_v1 /
291 aws_security_group / 267 data_aws_iam_policy_document / 254 github_branch_protection / 108 aws_vpc_security_group_ingress_rule /
93 aws_iam_policy / 83 cloudflare_ruleset / 73 cloudflare_zone_setting / 73 aws_s3_bucket_public_access_block / 58 x3 aws_iam_*_policy
```

### B2. `tf_schema` build time (`/tmp/claude-0/w2p/time_build2.sh`)
Setup: trees `base` = `git archive 232a763`, `new` = `git archive b0d47fe` (+ bench example), `unpruned` = `new` before `prune` (`c09382b` + defaults + bench). Each tree has `CARGO_TARGET_DIR=/tmp/claude-0/w2p/target-<tree>` with deps prebuilt. clean = `cargo clean -p tf_schema; cargo build -p tf_schema`. incr = `touch crates/tf_schema/src/lib.rs; cargo build -p tf_schema`. Trees alternate within each round.
```
concurrent rustc/cargo procs: 2
 18:45:08 up  1:30,  0 user,  load average: 1.57, 1.93, 1.93
base clean release  : 2.269434984
new clean release  : 2.326030709
unpruned clean release  : 3.169628053
base clean release  : 2.086639849
new clean release  : 2.499490593
unpruned clean release  : 2.895466123
base clean release  : 1.986677149
new clean release  : 2.570114496
unpruned clean release  : 3.174250499
base incr  release  : 1.999078638
new incr  release  : 2.277282772
unpruned incr  release  : 3.000940097
base incr  release  : 2.342383296
new incr  release  : 2.288651742
unpruned incr  release  : 3.004488354
base incr  release  : 2.087712642
new incr  release  : 2.917642389
unpruned incr  release  : 3.295263479
 18:45:56 up  1:30,  0 user,  load average: 1.27, 1.80, 1.88
base clean release --no-default-features : .811573776
new clean release --no-default-features : .884798968
base clean release --no-default-features : .986581628
new clean release --no-default-features : .890784559
base clean release --no-default-features : .793274102
new clean release --no-default-features : 1.008969496
base incr  release --no-default-features : .853608946
new incr  release --no-default-features : .832954038
base incr  release --no-default-features : .948521309
new incr  release --no-default-features : .823404808
base incr  release --no-default-features : .975010211
new incr  release --no-default-features : 1.140789278
 18:46:20 up  1:31,  0 user,  load average: 1.63, 1.83, 1.89
base clean dev  : 2.080390539
new clean dev  : 2.310141516
base clean dev  : 2.117142060
new clean dev  : 2.433304240
base clean dev  : 1.923952891
new clean dev  : 2.172972584
base incr  dev  : .639720579
new incr  dev  : .676179723
base incr  dev  : .527927795
new incr  dev  : .719031187
base incr  dev  : .524185705
new incr  dev  : .674831199
base clean dev --no-default-features : .827846952
new clean dev --no-default-features : .863391408
base clean dev --no-default-features : .838071943
new clean dev --no-default-features : .816987018
base clean dev --no-default-features : .789953271
new clean dev --no-default-features : .905528828
base incr  dev --no-default-features : .277746917
new incr  dev --no-default-features : .256026407
base incr  dev --no-default-features : .263521161
new incr  dev --no-default-features : .320146069
base incr  dev --no-default-features : .312374469
new incr  dev --no-default-features : .272702718
 18:46:47 up  1:31,  0 user,  load average: 1.92, 1.89, 1.91
concurrent rustc/cargo procs: 2
```
Earlier run, before `prune`, where "new" was the unpruned tree (consistent with the above):
```
 18:40:50 up  1:25,  0 user,  load average: 3.41, 2.37, 2.03
base clean release  : 2.129609354 / 2.267899201 / 2.086420340
new clean release  : 3.030022944 / 3.158889245 / 3.276792275
base incr  release  : 2.282383200 / 2.306818166 / 2.268082351
new incr  release  : 3.102011390 / 3.327843229 / 2.989020803
```
Attribution run (`nopod` = unpruned tree with the pod view removed from the allowlist):
```
base clean release  : 2.263472636 / 1.994806203 / 1.990772315
nopod clean release  : 2.340180040 / 2.221970176 / 2.377180289
new clean release  : 2.883709013 / 2.908806038 / 3.373260996      (unpruned)
base incr  release  : 2.145224880 / 1.944822145 / 1.974366359
nopod incr  release  : 2.324540247 / 2.427000583 / 2.228742765
new incr  release  : 3.259619913 / 2.947601107 / 3.163882201      (unpruned)
```
From scratch (`rm -rf $CARGO_TARGET_DIR; cargo build -q --release -p tf_schema`):
```
base from-scratch release : 9.061168306
new from-scratch release : 9.737789756
base from-scratch release : 11.725103479
new from-scratch release : 9.166731281
base from-scratch release : 8.859871579
new from-scratch release : 9.301342571
 18:47:50 up  1:32,  0 user,  load average: 2.44, 2.02, 1.95
```

### B3. Startup (`target-<tree>/release/examples/bench_lookup`, same example source in both trees, 5 alternating runs)
The example gained two lookups that print only when the type exists (kubernetes_stateful_set_v1 and cloudflare_zero_trust_access_application). "All cold" therefore excludes the schemas already loaded earlier in the run.
```
 18:47:59 up  1:32,  0 user,  load average: 2.15, 1.97, 1.94
== base run 1
blob bytes: schema 1453065 + symbols 499872 = 1952937
first lookup (symbol table + 1 schema): 996.026µs
second lookup (1 schema): 43.682µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 3.758032ms
lookup+decode all 5763 schemas (cold): 38.667542ms (57158 top-level attributes)
lookup all 5763 schemas again (cached) + attribute("id"): 3.833076ms (5415 have id)
== new run 1
blob bytes: schema 1618178 + symbols 535377 = 2153555
first lookup (symbol table + 1 schema): 1.325424ms
second lookup (1 schema): 37.571µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 5.378756ms
kubernetes_stateful_set_v1 first lookup: 122.082µs (2 top-level attributes)
cloudflare_zero_trust_access_application first lookup: 62.154µs (42 top-level attributes)
lookup+decode all 6774 schemas (cold): 35.87244ms (65272 top-level attributes)
lookup all 6774 schemas again (cached) + attribute("id"): 3.623844ms (6164 have id)
== base run 2
first lookup (symbol table + 1 schema): 1.155546ms
second lookup (1 schema): 33.093µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 4.322007ms
lookup+decode all 5763 schemas (cold): 27.863027ms (57158 top-level attributes)
lookup all 5763 schemas again (cached) + attribute("id"): 3.450795ms (5415 have id)
== new run 2
first lookup (symbol table + 1 schema): 1.196112ms
second lookup (1 schema): 32.083µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 4.161025ms
kubernetes_stateful_set_v1 first lookup: 114.241µs (2 top-level attributes)
cloudflare_zero_trust_access_application first lookup: 62.489µs (42 top-level attributes)
lookup+decode all 6774 schemas (cold): 28.132354ms (65272 top-level attributes)
lookup all 6774 schemas again (cached) + attribute("id"): 3.67968ms (6164 have id)
== base run 3
first lookup (symbol table + 1 schema): 1.03706ms
second lookup (1 schema): 28.169µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 3.804197ms
lookup+decode all 5763 schemas (cold): 32.741751ms (57158 top-level attributes)
lookup all 5763 schemas again (cached) + attribute("id"): 3.304956ms (5415 have id)
== new run 3
first lookup (symbol table + 1 schema): 1.051231ms
second lookup (1 schema): 29.619µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 3.55872ms
kubernetes_stateful_set_v1 first lookup: 86.061µs (2 top-level attributes)
cloudflare_zero_trust_access_application first lookup: 51.84µs (42 top-level attributes)
lookup+decode all 6774 schemas (cold): 30.010951ms (65272 top-level attributes)
lookup all 6774 schemas again (cached) + attribute("id"): 3.811526ms (6164 have id)
== base run 4
first lookup (symbol table + 1 schema): 927.527µs
second lookup (1 schema): 28.716µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 4.698293ms
lookup+decode all 5763 schemas (cold): 28.306748ms (57158 top-level attributes)
lookup all 5763 schemas again (cached) + attribute("id"): 3.316727ms (5415 have id)
== new run 4
first lookup (symbol table + 1 schema): 1.10614ms
second lookup (1 schema): 32.547µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 3.496677ms
kubernetes_stateful_set_v1 first lookup: 86.59µs (2 top-level attributes)
cloudflare_zero_trust_access_application first lookup: 48.885µs (42 top-level attributes)
lookup+decode all 6774 schemas (cold): 29.183243ms (65272 top-level attributes)
lookup all 6774 schemas again (cached) + attribute("id"): 7.827358ms (6164 have id)
== base run 5
first lookup (symbol table + 1 schema): 1.02051ms
second lookup (1 schema): 75.097µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 4.552267ms
lookup+decode all 5763 schemas (cold): 27.801209ms (57158 top-level attributes)
lookup all 5763 schemas again (cached) + attribute("id"): 3.763704ms (5415 have id)
== new run 5
first lookup (symbol table + 1 schema): 1.360773ms
second lookup (1 schema): 47.295µs
largest schema (aws_wafv2_web_acl_rule) first lookup: 6.260177ms
kubernetes_stateful_set_v1 first lookup: 216.701µs (2 top-level attributes)
cloudflare_zero_trust_access_application first lookup: 110.571µs (42 top-level attributes)
lookup+decode all 6774 schemas (cold): 47.798711ms (65272 top-level attributes)
lookup all 6774 schemas again (cached) + attribute("id"): 4.464271ms (6164 have id)
```
(The "blob bytes" line repeats identically in every run and is omitted after run 1.)

### B4. Tiny binary (`/tmp/claude-0/w2p/bin`, three standalone crates with the same `main.rs` as W2.md A4; `bin_base` depends on the base tree's `tf_schema`, `bin_new` on the new one; default release profile; postcard 1.1.3, serde 1.0.229, phf 0.14.0 in both lockfiles)
```
3629376 bin_base/target/release/bin_base
4020240 bin_new/target/release/bin_new
448456 bin_without/target/release/bin_without
$ strip -o <b>.stripped ...
3517288 bin_base.stripped
3908152 bin_new.stripped
344848 bin_without.stripped
bin_base gzip9 753026
bin_new gzip9 825507
bin_without gzip9 168130
$ ./bin_new cloudflare_ruleset; ./bin_new github_repository; ./bin_base cloudflare_ruleset; ./bin_new aws_db_instance
cloudflare_ruleset attributes: 10
github_repository attributes: 46
no such resource: cloudflare_ruleset
aws_db_instance attributes: 84
```
Nested-attribute walk (scratch `examples/walk.rs` in the new tree, not committed; output shown in "Example walk" above, plus):
```
  rules.description                string           optional+computed
  rules.exposed_credential_check   nested(Single)   optional
  rules.logging                    nested(Single)   optional+computed
  rules.ratelimit                  nested(Single)   optional
  rules.ref                        string           optional+computed
vap member_at(["spec", "match_constraints", "resource_rules", "operations"]): attribute nesting=None
```

### B5. Coverage and nested_type counts
```
$ cargo run -q -p tf_schema_codegen --release -- coverage
aws        resource  total  1730  with rules   9  without  1721
aws        data      total   685  with rules   1  without   684
azurerm    resource  total  1106  with rules   0  without  1106
azurerm    data      total   396  with rules   0  without   396
google     resource  total  1375  with rules   1  without  1374
google     data      total   471  with rules   0  without   471
cloudflare resource  total   272  with rules   0  without   272
cloudflare data      total   468  with rules   0  without   468
kubernetes resource  total    81  with rules   0  without    81
kubernetes data      total    27  with rules   0  without    27
github     resource  total    88  with rules   0  without    88
github     data      total    75  with rules   0  without    75
$ for p in cloudflare kubernetes github; do echo "$p $(grep -o '"nested_type"' schemas/providers/$p.json | wc -l)"; done
cloudflare 2997
kubernetes 16
github 0
```
Snapshot survey (inline Python over the JSON):
```
cloudflare registry.terraform.io/cloudflare/cloudflare 272 468
 nested_type keys {'attributes': 2903, 'nesting_mode': 2997} modes {'single': 2166, 'set': 64, 'list': 665, 'map': 102}
kubernetes registry.terraform.io/hashicorp/kubernetes 81 27
 nested_type keys {'attributes': 16, 'nesting_mode': 16} modes {'single': 7, 'list': 9}
 all {'kubernetes_validating_admission_policy_v1': 15, 'kubernetes_namespace_v1': 1}     # the latter is the data source
github registry.terraform.io/integrations/github 88 75
 nested_type keys {} modes {}
cloudflare: both type+nested_type 0, nested_type without attributes 94, max nesting depth 8, top-level block_types 0
 flags of nested attrs: computed-only 2073, optional 704, optional+computed 129, required 91
```

### B6. Provider sources for the defaults
```
$ git clone -q --depth 1 --branch v5.28.0 https://github.com/cloudflare/terraform-provider-cloudflare cf      -> fa63ebaea80e153d0d9325f818adc36187a8e12a
$ git clone -q --depth 1 --branch v3.3.0  https://github.com/hashicorp/terraform-provider-kubernetes k8s      -> a612b9cfce0fd1321cf2d25084b07b8fccd79737
$ git clone -q --depth 1 --branch v6.13.0 https://github.com/integrations/terraform-provider-github gh        -> 20728bb30c112287ac3e8243cdb0307a45c6a0a0
```
Excerpts read for the overlay (each is the line range cited in the toml note):
```
gh  github/resource_github_branch_protection.go:43   PROTECTION_IS_ADMIN_ENFORCED: { Type: schema.TypeBool, Optional: true, Default: false, ...
gh  github/resource_github_repository.go:523-537     func calculateVisibility(...) { if visibility set -> it; if private set -> "private"/"public"; return "public" }
gh  templates/resources/repository.md.tmpl:37        `private` - (Optional) ... Repositories are created as public (e.g. open source) by default.
k8s kubernetes/schema_container.go:766-771           "allow_privilege_escalation": { Type: schema.TypeBool, Optional: true, Default: true, ...
k8s kubernetes/schema_container.go:797-802           "privileged": { Type: schema.TypeBool, Optional: true, ForceNew: !isUpdatable, Default: false, ...
k8s kubernetes/schema_pod_spec.go:35-40              "automount_service_account_token": { ... Optional: true, Default: true, ...
k8s kubernetes/schema_pod_spec.go:173-196            host_ipc / host_network / host_pid: Default: conditionalDefault(!isComputed, false)
k8s kubernetes/resource_kubernetes_pod_v1.go:60      Schema: podSpecFields(false, false),
cf  internal/services/dns_record/schema.go:352-356   "proxied": schema.BoolAttribute{ Computed: true, Optional: true, Default: booldefault.StaticBool(false) }
cf  internal/services/ruleset/schema.go:131-135      "rules": schema.ListNestedAttribute{ Computed: true, Optional: true, Default: listdefault.StaticValue(...[]RulesetRulesModel{}...) }
cf  internal/services/ruleset/schema.go:2252-2257    "enabled": schema.BoolAttribute{ Computed: true, Optional: true, Default: booldefault.StaticBool(true) }
```

### B7. Checks run before each commit
```
$ cargo fmt -p tf_schema -p tf_schema_codegen --check
$ cargo clippy -q -p tf_schema -p tf_schema_codegen --all-targets       # no output
$ cargo test -q -p tf_schema -p tf_schema_codegen
test result: ok. 6 passed (nested.rs) / 5 passed (schema.rs) / 9 passed (codegen.rs, incl. generated_files_are_fresh)
$ cargo check -q --workspace --all-targets                                # no output (after c09382b)
$ cargo test -q -p tf_semantic -p tf_linter                               # all ok (after 467ec46)
$ cargo doc -p tf_schema --no-deps 2>&1 | grep -c '^warning'              # 0 (generated view modules allow rustdoc::bare_urls/invalid_html_tags)
```

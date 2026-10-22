# Signal plan: output an agent can act on

oxtf is fast enough (corpus 0.2 s; one root ~10 ms). What limits it as the
first step of an agent's patch chain is the output: most of it repeated,
little of it pointing at what to change, none of it rankable. This plan
fixes that. Status per workstream is at the end of each.

## Where we started (2026-10-19, main at a099f88)

Corpus scan, release build, 17 repositories:

| | |
| --- | --- |
| Findings | 1,535 |
| Distinct (rule, file, offset) | 554 — 981 (64 %) were copies from overlapping roots |
| JSON | 2.6 MB, ~1.3 KB per finding, rule metadata repeated in each |
| With the deciding `attribute` | 181 (12 %) |
| With a `fix_hint` | 2 |
| `level` | 1,533 medium, 2 high |
| `guideline` | 0 |
| Exit code with findings | 0 |

Where the copies come from: 1,072 findings came from `examples/` roots,
209 from `modules/` roots, 169 from test roots. One declaration was
reported 57 times. No group of copies disagreed on certainty.

Why the attribute is missing, over the 554 distinct findings:

| Rule kind | Findings | Without attribute |
| --- | --- | --- |
| Checkov Python checks | 304 | 292 |
| `checkov_value` | 155 | 118 |
| `checkov_graph` | 94 | 86 |

A value check whose attribute is absent returns `Verdict::new(True, None)`
(`checkov.rs`, `ValueCheck::missing`); a Python check without
`evaluated_keys` is witnessed by the whole configuration. Either way the
finding falls back to the resource header.

The firing rules are concentrated: 190 rules fire; the top 20 account for
284 of the 554, the top 40 for 378 (68 %). About 116 of the 554 look like
hygiene (logging, labels, replication, notifications) by name alone.

## Decisions

Made with the user on 2026-10-19:

- **A finding is one rule on one resource declaration's attribute**;
  roots and instances are its occurrences. The fingerprint hashes exactly
  that identity, so it is the same from every root and working directory.
- **Default catalog**: a plain `oxtf scan` will run the `security` profile
  only, with hygiene rules behind `--profile all` (workstream D). Rules not
  yet curated default to on.
- **Exit codes**: 0 no finding at or above `--fail-on` (default
  `definite`), 1 some finding is, 2 the scan could not run, 3 a rule failed
  on some resource. 3 wins over 1.

## A. Group by finding identity — done

Grouping lives in the record (`tf_linter::record::group`), not the engine:
the engine, `Finding`, Python and Arrow stay per occurrence. Group key:
rule, primary file, local identity (local address; a file subject's
message), attribute — what the fingerprint hashes.

- Representative: most certain, then shallowest module instance, then
  shortest root. Its provenance is the finding's.
- `occurrences: [{root, address, certainty, location?}]`, `location` only
  when it differs (alternative `dynamic` blocks setting one attribute).
- Fingerprint: rule + repository-relative file (outermost `.git`
  ancestor, so nested clones and submodules stay inside their checkout) +
  local identity + attribute.
- Text output: one report per finding, then "also reached as ..." with up
  to three other occurrences.

Known limit: occurrences reached through different values (a `for_each`
over a map whose entries differ) share the representative's provenance in
the record. An agent fixing one entry sees the finding persist through the
remaining occurrence, which is correct but not explained. A later step can
add per-occurrence origin locations when provenance diverges.

## B. Compact record (schema 3) and agent formats — done

- `rules` table keyed by ID; a finding carries `rule` (ID) and `level`.
- `severity` → `certainty` everywhere (Rust `Certainty`, Python
  `Finding.certainty`, Arrow column). Diagnostics keep `severity`: theirs is
  one.
- `subject` carries the structured resource reference; `resource` and the
  per-finding `schema` are gone.
- `--format ndjson` (finding lines, rule errors, diagnostics, a summary
  line) and `--format sarif` (2.1.0; fingerprint as
  `partialFingerprints["oxtf/v1"]`, provenance as related locations).
- `--fail-on` and the exit codes above.

## C. Name the deciding attribute in every evaluator — done (connection checks excepted)

The engine was already right: `Finding::build` takes the attribute and the
location from the witness's provenance. What was missing was witnesses.

- **Absence is a witness.** `Resource::absent(path)` is a null with one
  `absent` provenance step at the resource header naming the attribute.
  Checkov value checks (`ValueCheck::missing`) and graph attribute checks
  return it when the attribute is not set, so the finding names it and its
  fix hint inserts it.
- **Value-check fixes.** A positive value check of a top-level attribute
  against one literal implies `set attribute = literal`
  (`ValueCheck::fix`, through `derive_fix`): 198 bundled rules.
  Nested paths (119 rules) wait for block-aware fix actions.
- **Python checks: `evaluated_keys` resolved properly.** A reported path
  that is not set used to fall back to the whole configuration (no
  attribute); it is now an absent witness, and a set value without
  provenance of its own (a rendered view) gets a step naming the attribute
  (`Resource::mentioned`). Bare `0` indices are dropped like `[0]`.
- **Python checks: read tracing.** For checks that report no
  `evaluated_keys`, the interpreter records every lookup (subscript,
  `.get`, `in`) on the configuration's dicts, identified by pointer with
  their paths recorded at conversion. The witness is what a delegated
  native value check located, else the last key read, found or absent.
  Measured against the checks that do report `evaluated_keys`
  (`OXTF_DEBUG_PYTHON=trace`): 330 of 433 failing judgements agree exactly,
  75 name the parent or child of the same attribute (a missing block vs its
  leaf), 28 differ (no reads traced, falling back to the header, or a
  conjunction where either attribute is a fair answer).
- Verdicts are untouched: the corpus has the same 1,535 occurrences with
  the same certainties. One pair of findings merged (CKV_AWS_34 had pointed
  at the header in one root and the attribute in another).

Still header-only, rightly: graph **connection** checks ("network has no
firewall", "security group is attached to nothing"), about 70 findings.
Their fix is a new resource, not an attribute. They could later name the
missing connection (`connected_resource_types`) in the record.

Found along the way, for later:

- ~~`tf_scan::apply_fix` has no CLI or Python surface.~~ Done: `oxtf fix
  FINGERPRINT [scan options] [--write] [-f diff|json]` and
  `tfscan.fix(fingerprint, path, ...)` (`tf_scan::fix`) apply the hint in
  memory, rescan with the edit as an overlay, and report the diff and
  whether the finding is gone; `--write` writes only a verified edit.
- ~~A fix hint's `site` replaces `x = var.x` with a literal.~~ Done (F):
  the hint carries `default_site`, and `oxtf fix` writes the default
  first.
- `configured` / `effective` hold the whole top-level attribute, so an IAM
  finding embeds its full policy (15 KB). For nested attribute paths the
  deciding sub-value would be enough.

## D. Curate the catalog — done for every rule a default corpus scan reports; in review

Current priority: improve the accuracy and usefulness of existing findings
before expanding the catalog. New rule work should include a reviewed impact
level with rationale, actionable remediation, authoritative documentation,
and representative pass/fail/uncertain cases. A pinned implementation link
alone does not satisfy remediation guidance. Existing `unreviewed` rules remain
identified as such; this pass does not claim the entire catalog is curated.

- `crates/tf_rule_ir/data/checkov/curation.toml`, hand-maintained and never
  regenerated: per Checkov ID a `level`, optional `category`, a `profile`
  (`security` / `audit` / `hygiene`) and a one-line `why`. `build.rs`
  applies it to the static header table and to `bundled::checkov()`'s
  specs, and fails on an unknown ID, field or value.
- `audit` is a third profile beside the two agreed: logging, flow logs and
  retention are neither exposure nor noise, and an agent "fixing" them
  creates log sinks and cost. It is off by default with `hygiene`.
- `tf_linter::Profile` on `RuleInfo` and in the record's `rules` table;
  `Catalog::profiles` (`--profile security,audit,hygiene,all`; Python
  `profiles=`). The default is `security`, which includes `unreviewed`. Only
  shipped rules are filtered; an explicit selection reaches every profile;
  `oxtf rules` lists every profile with a column for it.
- A bundled rule without reviewed remediation retains its Checkov source at
  the pinned tag as a fallback guideline.
- First curation: the 45 most frequent rules on the corpus plus 22
  well-known critical checks the module corpus rarely exercises (public S3
  ACLs and policies, world-open SSH/RDP/all ports, public RDS and Cloud
  SQL, hard-coded secrets, admin IAM). 67 rules: 10 critical, 23 high, 9
  medium-or-other security calls, 16 hygiene, 3 audit. **Needs the
  user's review** — every entry has its reason inline.

Effect on the corpus: a default scan reports 374 findings instead of 552
(the 178 audit and hygiene findings move behind `--profile`), and 26.7 %
of them have a level other than medium (from 0.2 %): 4 critical, 60 high.

Second curation (2026-10-20): the 139 unreviewed rules behind the 154
default findings that were left. They fire once or twice each, so they
were reviewed together under principles written at the top of the file:
exposure and over-grants are `security`, levelled by blast radius;
logging and retention are `audit`; backups, availability, deletion
protection, cost and operational style are `hygiene`; a customer-managed
key where the provider already encrypts the data is `low` `hygiene`
(CKV_AWS_158 moved there, for consistency with CKV_GCP_38). 206 rules are
curated; a default corpus scan now reports no unreviewed rule: 289
findings, 49 % not medium (4 critical, 76 high, 147 medium, 62 low).

### Severity and remediation review (2026-10-20)

Reviewed 40 existing bundled rules and all five native rules against their
actual predicates and provider documentation. Seven previously unreviewed
bundled rules now have curated metadata (213 total); 40 have remediation text
and provider documentation. No rules or predicates were added. Curation `why`
is exported as `rationale`; `remediation` and a supporting HTTPS `guideline`
are validated together. Corrected descriptions also update finding messages.

The reviewed families cover AWS security-group ingress, public database and
storage settings, S3 public-access guardrails, broad IAM grants and account
trust, RDS/EBS/SQS/SNS encryption, S3/CloudWatch key-control requirements, GCP
firewall defaults and storage access, GKE endpoint/identity settings, and Azure
Storage network and anonymous-access controls.

Key decisions:

- Public RDS endpoints and all-port security-group rules are `high`, with
  reachability prerequisites documented. A public endpoint does not establish
  data access. Azure's permission to enable public containers is a `medium`
  guardrail gap, not a confirmed public container.
- Account-principal IAM trust (`CKV_AWS_61`) and resource scoping
  (`CKV_AWS_355`) are `medium`; neither check proves administrative access.
  Explicit administrative grants remain `critical`, with effective-permission
  limits explained.
- RDS at-rest encryption and explicit S3 public-access guardrails are `medium`
  in both native and corresponding bundled metadata. RDS remediation explains
  snapshot-copy/restore and cutover rather than implying an in-place migration.
- S3 and CloudWatch KMS requirements remain `low`/`hygiene`, since baseline
  encryption already exists. SQS guidance distinguishes explicit disablement
  from relying on service defaults; no blanket assertion of unencrypted data
  is made from omitted attributes.
- The presence-only GCP firewall check (`CKV2_GCP_18`) moves to `low`/`hygiene`.
  GCP has implied deny-ingress rules: adding an allow rule merely to pass this
  check could weaken the configuration.

Primary references are stored per rule. Examples include
[RDS encryption and migration](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html),
[IAM principal semantics](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html),
[S3 encryption defaults](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html),
[Azure anonymous-access controls](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent),
and [GCP firewall defaults](https://docs.cloud.google.com/firewall/docs/firewalls).

Severity is a reviewed potential-impact classification, not a CVSS score or a
proof of effective cloud access. Remaining curation should prioritize frequent
rules without remediation and ambiguous default/guardrail checks. Catalog
growth is secondary to that work.

## F. Fixes for nested attributes and variable defaults — done

- **Nested paths.** A fix hint's `attribute` is a path of block names and
  an attribute. Checkov value checks against one literal derive one at any
  depth (index segments dropped), and so do graph attribute checks with
  dotted paths; fixes are per resource type, so a rule whose clauses use
  different paths per type (CKV_AZURE_15) still gets one.
  `FixHint::set_path` builds the hint per resource against the provider
  schema: each block on the path is written at most once and not by
  `dynamic`, and a block to create needs no other required attribute or
  block. Otherwise there is no hint.
- **Edits keep the file's layout.** A replaced value keeps the text up to
  its `=`. An inserted attribute aligns with the one-line attributes above
  it, re-padding them only when the new name is the longest, as `terraform
  fmt` does. One-line blocks (`master_auth {}`) are opened up. New blocks
  are indented from the enclosing brace. Every corpus edit passes
  `terraform fmt -check`.
- **Variable defaults.** When the attribute is written as exactly
  `var.<name>` and the value's provenance is that variable's default, the
  hint carries `default_site`. `oxtf fix` writes the default first, which
  keeps the module's interface, and falls back to the attribute when a
  caller passes its own value. `--at default|attribute` (Python `at=`)
  picks one.
- **Target resolution is per declaration.** The target is resolved when the rule no
  longer fails on the declaration (rule, module directory, local address)
  from any root, so a finding that moves to another attribute is not
  reported as fixed. The current fix contract additionally requires complete
  scans and no new findings or affected occurrences before reporting `verified`;
  see `docs/FINDING_SCHEMA.md` for the before/after delta.
- **Bug fixed along the way.** `apply_fix` looked up the hint's resource
  address in every root; two examples that each declare `aws_instance.this`
  got the first one's file edited. It now looks only in the finding's
  root.
- **Python read tracing.** `"k" in conf.keys()`, a common Checkov idiom,
  is now traced like `"k" in conf`: CKV_GCP_69 and CKV_GCP_39 name their
  attribute (19 corpus findings).

Corpus: every one of the 56 fix hints applies and verifies (38 at the
attribute, 18 at a variable default). Hints: 8.3 % → 10.1 % of all
findings.

## E. Signal gate — in place

`bench/signal.py` measures the corpus scan over every shipped rule
(`--profile all`, so moving a rule between profiles is not a regression)
and reports the default profile's numbers beside it: findings, occurrences, JSON and
NDJSON bytes per finding, % with attribute, % with fix hint, % header-only,
level distribution, coverage of severity rationale and remediation, and scan
completion. Severity distribution is reported but never a quality gate:
changing a correct `medium` to `high` must not count as progress. Metadata
coverage is checked across all profiles and the default profile. `--write`
stores `bench/results/signal.json` only for complete scans; `--check` fails for
incomplete analysis or a judged metric moving the wrong way. Run it beside the perf
guard on every change to the output or the catalog.

The current corpus has pre-existing missing remote modules, evaluation coverage
gaps, and 14 Checkov rule execution errors (`CKV_GCP_24` and `CKV_GCP_22`). The
metadata review reports observed measurements without replacing the historical
trusted baseline or claiming the signal gate passes. Fixing these gaps and
recording a complete baseline is required before the new corpus coverage floors
can be established. Focused metadata and output tests run independently.

Observed before/after measurements on the same current checkout (partial
scans, not a new baseline): all-profile findings and occurrences stay at
568 / 1,576; default findings decrease from 304 to 262 because the 42
presence-only GCP firewall findings move to hygiene. The default profile's
high findings change from 89 to 58 and critical findings from 4 to 3;
these are classification corrections, not resolved infrastructure issues.
Reviewed rationale reaches 99.2% of observed default findings and actionable
remediation reaches 37.4%. The remaining 62.6% is explicit guidance debt.
NDJSON now carries rule metadata once in the summary; together with existing
coverage diagnostics this exceeds the historical byte budget. The old
fix-hint percentage floor also fails (9.9% versus 10.1%). Those gate failures
remain visible rather than being waived or written over.

The subsequent [completion follow-up](SIGNAL_COMPLETION.md) adds file/template
evaluation and guidance for 11 more existing rules. The latest failed
observation is `bench/results/signal-observed.json`: default remediation
coverage is 68.3%, with unchanged finding counts. It includes a ranked guidance
backlog and byte/cause inventories. The follow-up records the upstream Checkov
defects, dependency preparation and evaluation work still blocking a complete
baseline; the measurements above are the earlier checkpoint.

## Results so far

| | main | after A + B | after C | after D + F |
| --- | --- | --- | --- | --- |
| Findings | 1,535 | 553 (1,535 occurrences) | 552 (1,535 occurrences) | 552; 289 in the default profile |
| Distinct fingerprints | 959 for 554 distinct problems (one backlog issue per module path) | 553, one per finding | 552 | 552 |
| With the deciding attribute | 12 % | 10 % | 79 % | 83 % |
| With a fix hint | 0.1 % | 0.2 % | 8.3 % | 10.1 %, all verified |
| Level other than medium | 0.2 % | 0.2 % | 0.2 % | 73 %; 49 % in the default profile |
| JSON | 2.6 MB | 1.15 MB (2,078 B per finding) | 1.6 MB (2,888 B; the added bytes are provenance) | — |
| NDJSON | — | 231 KB (418 B per finding) | 247 KB (448 B) | 450 B per finding |
| Exit code with definite findings | 0 | 1 | 1 | 1 |
| Corpus wall time, JSON, min of 5 | 0.21 s | 0.22 s | 0.21 s | 0.22 s |

`fixtures/baseline/native.json` was regenerated for the new shape; every
case expands back to exactly the old judgements, with the representative's
fields unchanged (2 `for_each` pairs merged).

# Remote modules and configuration coverage plan

Status: milestones 1 through 6 implemented 2026-10-20. Validation results and
remaining coverage gaps are recorded below.

Extend oxtf's source analysis to JSON variable files, installed remote modules,
JSON configuration, override files, and concrete `count` instances. Add explicit
dependency fetching after offline module resolution is established.

Implementation proceeded in three batches: installed modules and JSON variables,
JSON configuration and overrides, then bounded evaluation and dependency fetching.
Build on the completion, sensitivity, and fix-verification guarantees described
in [VALIDATION.md](../VALIDATION.md).

## Architecture

Keep the existing evaluated model shared by the rule engines. Most changes belong
in [module loading](../../crates/tf_semantic/src/module.rs),
[the parsed module store](../../crates/tf_semantic/src/store.rs), and
[analysis](../../crates/tf_semantic/src/analyze.rs).

Introduce two boundaries as the milestones need them:

- A module resolver that maps a source and module-call path to an installed
  package, keeping resolution specific to the scanned root.
- Configuration loading and composition that preserve each effective value's
  original source location.

Expose new options through [ScanRequest](../../crates/tf_scan/src/lib.rs) so the
CLI and Python API use the same behavior. Keep package resolution separate from
the cache of parsed module directories.

## 1 JSON variable files

Implemented in `tf_parser::parse_json_vars`, the standalone-file store, and
the analyzer's variable-file discovery. The original JSON supplies all spans;
strings and object keys remain literal. Tests cover overlays, explicit files,
mixed precedence, root comments, malformed or duplicate values, and sensitivity.

Support `terraform.tfvars.json`, `*.auto.tfvars.json`, and explicitly supplied
JSON variable files. Preserve literal strings, nested values, sensitivity, and
diagnostic locations.

Apply variable files in this order, with later assignments taking precedence:

1. `terraform.tfvars`.
2. `terraform.tfvars.json`.
3. Both auto-file formats together in lexical filename order.
4. Explicit variable files in argument order.

This follows [Terraform's variable precedence](https://developer.hashicorp.com/terraform/language/values/variables#assign-values-to-variables)
for file inputs. JSON variable values are literal; strings containing template
syntax must remain literal.

Acceptance criteria:

- Equivalent HCL and JSON variable files produce the same evaluated values and
  findings.
- Tests cover mixed-file precedence, nested values, literal template strings,
  malformed inputs, and sensitive values.
- Automatically discovered files, explicit files, and in-memory overlays use
  the same loading behavior.

## 2 Installed remote modules

Implemented in `tf_semantic::installed`, shared scan options, and the CLI/Python
adapters. Use `--data-dir DIR` or `data_dir=...` for a custom data directory.
The option also reaches plan source mapping and fix verification. The scan does
not implicitly read `TF_DATA_DIR`; pass it explicitly for reproducible requests.

The resolver validates the full static call path, including local ancestors,
and supports exact source matches plus default registry-host and GitHub shorthand
normalization. Missing installations, stale entries, unrecognized source
spellings, and nonliteral source/version expressions remain coverage gaps.
Registry version checks cover Terraform's comparison and pessimistic operators.
Installed findings carry package metadata and caller locations; their identity
uses source, recorded version, and package-relative file. Cache files are
protected both when generating fix hints and when applying edits.

Add offline resolution using `.terraform/modules/modules.json`, with an explicit
data-directory option. Resolve by scanned root and static module-call path,
checking the recorded source and installed version against the configuration.
Follow nested modules through the existing analyzer.

Terraform's manifest records the module-call key, source, version, and installed
directory. Isolate its reader behind an adapter because it belongs to Terraform's
internal implementation. See the
[manifest implementation](https://github.com/hashicorp/terraform/blob/main/internal/modsdir/manifest.go)
and [installer checks](https://github.com/hashicorp/terraform/blob/main/internal/initwd/module_install.go).

Missing or stale installations must remain explicitly incomplete. Report the
installed package metadata without treating the manifest as proof of an immutable
Git revision. Findings need stable package identities and caller locations.
Exclude managed module-cache files from automatic fixes.

Acceptance criteria:

- Installed registry and Git modules behave like equivalent local modules,
  including outputs, dependencies, and sensitive values.
- Repeated calls with different inputs produce the correct module instances.
- Tests cover nested modules, package subdirectories, custom data directories,
  multiple roots, missing directories, and source or version mismatches.
- Scanning requires no network access or module installation.
- Findings remain identifiable when the installation directory changes.

## 3 JSON configuration

Implemented in the shared configuration loader and `tf_semantic::json_config`,
using an ordered literal JSON tree and the native expression/template parser.
The generated mutable AST visitor maps every decoded expression span back to
original bytes, including Unicode escapes and surrogate pairs. Standalone
variable-file loading remains explicitly literal. Source and plan findings
suppress JSON edit hints, including cross-resource and insertion targets.
Provider configuration schemas are generated from the checked-in snapshots;
local provider names resolve through effective `required_providers` settings
across ordinary files and overrides before JSON block mapping.

Add a frontend for `.tf.json` that feeds the existing semantic model. Support
mixed HCL and JSON files within a module.

Implement templates, single-interpolation values that retain their result type,
literal-only fields, provider references, and schema-aware nested blocks.
Terraform assigns different meanings to JSON strings depending on their
configuration context; use its
[JSON mapping](https://developer.hashicorp.com/terraform/language/syntax/json)
as the compatibility reference.

Preserve property order, duplicate block properties, and original byte locations.
A plain JSON object map would discard information required by the
[HCL JSON specification](https://github.com/hashicorp/hcl/blob/main/json/spec.md).
Embedded expression diagnostics must map back to the original JSON, including
escaped strings.

Acceptance criteria:

- Paired HCL and JSON fixtures produce equivalent resources, dependency graphs,
  and findings.
- Tests cover literal and expression contexts, repeated nested blocks, mixed
  formats, escaped strings, and malformed configuration.
- Discovery and plan-to-source mapping recognize JSON configuration.
- Diagnostics and sensitivity masking refer to the original source.
- JSON fix generation uses a format-aware implementation. Until that exists,
  JSON findings do not receive HCL edits.

## 4 Override composition

Implemented in `tf_semantic::compose`. Composition moves arena-owned nodes
before indexing; an origin table retains each effective attribute, expression,
and body file. The parsed-module cache owns both the effective AST and its
source metadata. Evaluation, references, sensitivity, whole-file policies,
and fixes use those origins. Defaults are converted through successive type
overrides, including common element types for dynamic collections. Invalid
type constraints and duplicate settings in an override file remain errors,
as do ordinary duplicate declarations.

Compose ordinary configuration files and ordered overrides before indexing
declarations. Support HCL and JSON base files and overrides.

Implement attribute replacement, nested-block replacement, and the special rules
for lifecycle, variables, locals, and Terraform settings. These semantics require
more than a generic recursive merge. Follow
[Terraform's override semantics](https://developer.hashicorp.com/terraform/language/files/override).

Each effective attribute must retain its originating file. Declarations currently
associate an entire block with one file, so adjust this representation before
enabling override diagnostics or fixes.

Acceptance criteria:

- HCL and JSON combinations match fixtures checked against a pinned Terraform
  version.
- Tests cover override ordering, nested-block replacement, lifecycle merging,
  variable type and default interactions, and invalid overrides.
- Findings identify the effective value's actual source.
- Fixes target the effective assignment and pass complete before-and-after
  analysis.

## 5 Bounded evaluation gaps

Implemented concrete numeric instance keys throughout expansion, memoization,
resource and module references, outputs, splats, and dependency provenance.
Known zero counts produce empty collections; invalid known counts produce
errors. Both indexed attributes and whole-object references select the correct
instance, including references carried through conditional objects. Direct
dependencies do not acquire unrelated instances or transitive edges.

`AnalyzeOptions.max_expand` defaults to 64 per declaration, and the new
`max_instances` defaults to 16,384 resources and child modules combined per
root. Exceeded budgets retain coverage diagnostics and unknown collection
contents instead of reporting omitted instances as empty. Unknown counts
continue abstract evaluation.

Corpus measurements selected `regex` and regex-mode `replace`: 40 diagnostics
disappeared after their implementation. Capture results, replacement expansion,
sensitivity, and RE2 ASCII character classes are covered by tests, including
pinned Terraform comparisons. Pattern size, input/output size, compiled regex
size, and match count are bounded. The corpus finding records did not change
from this function support; the additional findings came from count expansion.

Expand known `count` values into concrete resource and module instances within
the existing expansion budget. Evaluate `count.index`, indexed references, and
module outputs for each instance.

Keep explicit coverage diagnostics when expansion exceeds the budget. Unknown
counts continue to use abstract evaluation.

After count expansion, rerun the corpus and prioritize unsupported functions by
their effect on findings. Add functions based on measured coverage gaps.

Acceptance criteria:

- Instance-specific values, addresses, outputs, and dependencies are correct.
- Tests cover zero, one, and multiple instances; unknown counts; and expansion
  limits.
- Runtime and memory remain bounded.
- Corpus results identify the next function work with concrete examples of the
  findings it would improve.

## 6 Explicit dependency fetching

Implemented in the separate `tf_fetch` crate, re-exported through `tf_scan`,
with `oxtf fetch` and `tfscan.fetch(...)` adapters. Fetching uses the shared
composed configuration loader and the installed resolver's source/version
normalization. It resolves nested registry and Git modules, static package
subdirectories, private registry tokens, and Git credential helpers.

Packages are staged, validated, hashed, and installed as read-only snapshots
under `modules/oxtf-packages`. The manifest records Git commit IDs or extracted
content SHA-256 revisions. Fetch verifies existing snapshots before offline
reuse; explicit refresh resolves versions and refs again. A failed operation
preserves the previous manifest, and refresh retains old snapshots. Ordinary
scans remain offline and read recorded revisions without rehashing contents.
Findings include the revision in package metadata and identity, and existing
cache edit protection applies.

HTTP metadata, redirects, downloads, archive entries, extracted size, Git
staging size, dependency count/depth, and process/network time have bounds.
Unix Git commands also receive a file-size limit and process-group cancellation.
Extraction rejects traversal, links, special files, and reserved paths; nested
local calls cannot leave their fetched package. Registry tokens stay on their
original origin, and credentials are excluded from reports and cache metadata.

Supported downloads are Git, TAR, gzip-compressed TAR, and ZIP. Unsupported
getter transports, Git submodules, and Git query parameters other than `ref`
are rejected. Package subdirectories are supported in module source addresses
and Git download addresses; HTTP archive download URLs do not implement
go-getter's `//subdirectory` or wrapper-directory conventions. See
[README](../../README.md) for public options and limits.

Build a separate fetch operation using the resolver from milestone 2. Start with
registry modules and Git sources. Support version constraints, package
subdirectories, private credentials, immutable cached contents, and recorded
resolved revisions.

Ordinary scanning remains offline by default. Fetching resolves and stores
dependencies for subsequent scans, with explicit refresh behavior.

Acceptance criteria:

- Fetching once enables repeatable offline scans.
- Tests cover nested dependencies, unavailable sources, changed revisions, and
  version selection.
- Credentials are excluded from reports and cache metadata.
- Downloads and extraction have bounded resource usage and validate package
  paths.
- Normal tests use deterministic local fixtures instead of public network
  services.

## Dependencies and delivery

- Milestones 1 and 2 can be delivered independently as the first batch.
- Milestone 3 can reuse JSON source-location handling introduced in milestone 1.
- Milestone 4 follows milestone 3 so override composition covers both formats.
- Milestone 5 is technically independent; the proposed sequence measures its
  impact after source coverage improves.
- Milestone 6 depends on milestone 2 and should follow JSON and override support
  so fetched packages use the same configuration pipeline.

## Validation and compatibility

Every milestone must preserve accurate completion status, sensitivity masking,
and the requirement that both scans complete before a fix is verified.
Unsupported cases retain coverage diagnostics until their support is tested.

Pin Terraform and HCL versions in compatibility fixtures. Define the supported
language baseline explicitly, including the boundary for newer features such as
constant-expression module sources and versions.

Use paired HCL and JSON fixtures and Terraform reference results for configuration
semantics. Exercise each public entry point through the shared scan request, and
run the relevant Rust, Python, formatting, Clippy, and conformance checks described
in [VALIDATION.md](../VALIDATION.md). Compare corpus findings and performance
before and after each milestone, explaining expected coverage changes.

### Milestones 1 and 2 validation — 2026-10-20

- `OXTF_REQUIRE_CORPUS=1 cargo test --workspace --locked`: 306 passed, no
  failures, and two existing opt-in reference-pack tests ignored.
- Python suite with `OXTF_REQUIRE_TERRAFORM=1`: 172 passed. The pinned
  Terraform 1.16.1 reference test checks mixed variable-file precedence and
  literal JSON values, a real local Git installation with a package
  subdirectory and nested local module, and eleven registry-version cases.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo fmt --all --check`, and the release CLI build pass.
- The 76-case native finding baseline passes. New coverage includes installed
  module outputs and inferred graph edges, sensitivity, repeated calls,
  multiple roots, stale manifests, cache relocation, custom data directories,
  and cache edit protection.

Local release benchmarks scanned 504 roots and 5,224 resources. Each number
below is the median of five measured runs after one warmup, with the two
binaries run alternately and JSON output included.

| Rules | Prior release artifact | Current implementation | Findings |
| --- | ---: | ---: | ---: |
| Seed rules (`--no-bundled`) | 112.29 ms | 122.04 ms | 1 |
| Bundled catalog | 241.59 ms | 256.60 ms | 289 |

Finding fingerprint sets and resource counts match in both modes. The prior
release artifact predates some of the earlier trust and sensitivity work, so
this comparison does not isolate the performance cost of these two milestones.
Seed finding records match; catalog records differ in 53 message fields and
nine provenance fields. These measurements describe this local corpus and
machine, not a general performance guarantee.

CI now requires the pinned Terraform reference test; the checks above were run
locally. This subsection records the first implementation batch.

### Milestones 3 and 4 validation — 2026-10-20

The pre-change baseline includes the uncommitted trust work and milestones 1–2.
Its release binary, source snapshot, and corpus records are retained locally at
`/tmp/oxtf-m3-m4-baseline`. The JSON-only release checkpoint is
`/tmp/oxtf-m3-validation`. Both scan 504 roots and 5,224 resources, with matching
finding fingerprints (one seed finding and 289 bundled-catalog findings).

Compatibility fixtures pin Terraform 1.16.1 / HCL 2.24.0. They exercise local
modules and built-in resources, with no public provider/module downloads.
The existing boundary for constant-expression module source/version fields
remains unchanged. Known multiple-count expansion and explicit fetching are
still milestones 5 and 6.

Completed local validation:

- `OXTF_REQUIRE_CORPUS=1 cargo test --workspace --locked`: 327 passed, no
  failures, two opt-in reference-pack tests ignored in the workspace run.
  Both opt-in tests also passed with newly generated pinned reference packs.
  This includes the 76-case native baseline, parser corpus, and generated
  provider-schema freshness checks.
- Python suite with `OXTF_REQUIRE_TERRAFORM=1`: 198 passed, including 29
  source-coverage cases. The source cases were rerun against the final native
  extension after the last conversion refinements.
- Formatting, Clippy with warnings denied, AST generation checks, and the
  release CLI build passed.
- Checkov 3.2.328: 8,857 comparable cases, zero disagreements or reference
  errors; 12 cases remained unresolved by the reference runner.
- OPA 1.17.0: all 120 evaluations agreed across the three local policy sets,
  with no rule errors.
- Independent standards review found no violations. The specification review
  identified dynamic default conversion, provider JSON block mapping, and
  duplicate override settings; all were fixed and rechecked. Provider mapping
  also covers custom local names and requirements changed by another file.

Release timings below include JSON output. Each is the median of five measured
runs after one warmup, rotating the three binaries with no concurrent build.
Artifacts and full records are in `/tmp/oxtf-m3-m4-validation`.

| Rules | Pre-change baseline | Initial JSON checkpoint | JSON and overrides |
| --- | ---: | ---: | ---: |
| Seed rules (`--no-bundled`) | 127.04 ms | 112.87 ms | 121.68 ms |
| Bundled catalog | 254.10 ms | 245.25 ms | 251.02 ms |

All three binaries scan 504 roots and 5,224 resources. Complete finding records
and fingerprints match: one seed finding (two occurrences), 289 catalog
findings (525 occurrences). The existing 1,115 coverage diagnostics are also
unchanged: 600 unavailable remote modules, 473 evaluation gaps, and 42 count
gaps. Seed scans therefore remain incomplete. Catalog scans retain the same
14 rule execution errors and report failed status. These are corpus limitations,
not successful full-corpus analysis, and were present in the saved baseline.

These are local measurements, not a general performance guarantee or a remote
CI result. Milestones 5 and 6 remain outside this implementation batch.

### Milestones 5 and 6 validation — 2026-10-20

The starting snapshot includes all uncommitted remediation and milestones 1–4,
including untracked files. It is retained locally at
`/tmp/oxtf-m5-m6-baseline`; the count checkpoint is `/tmp/oxtf-m5-count`, and
final corpus records and measurements are in `/tmp/oxtf-m5-m6-validation`.
Earlier working-tree changes were preserved.

Completed local validation:

- `OXTF_REQUIRE_CORPUS=1 cargo test --workspace --locked`: 340 passed, no
  failures, two opt-in reference-pack tests ignored in the workspace run.
  Both opt-in tests also passed against the pinned reference packs from the
  preceding batch. This includes the native baseline, parser corpus, and
  generated provider-schema freshness checks.
- Rebuilt Python extension with `OXTF_REQUIRE_TERRAFORM=1`: 214 tests passed.
  The 45 targeted source-coverage/fetch cases also passed separately.
  Terraform 1.16.1 comparisons cover counted module addresses and values,
  overridden HCL/JSON counts, splats, regex results, and invalid counts.
- Deterministic Git and loopback HTTP fixtures cover nested modules, private
  registry authentication, cross-origin token isolation, signed download URLs,
  version selection, package subdirectories, offline reuse after sources are
  removed, refresh and revision changes, damaged cache detection, failed
  refresh preservation, TAR/ZIP extraction, and unsafe archive rejection.
- Formatting, Clippy with warnings denied, AST generation checks, and the
  release CLI build passed.
- Checkov 3.2.328: 8,857 comparable cases, zero disagreements or reference
  errors; 12 cases remained unresolved by the reference runner.
- OPA 1.17.0: all 120 evaluations agreed across three local policy sets, with
  no rule errors.
- Independent standards and specification reviews were completed. Findings
  concerning whole-object and conditional dependency provenance, skipped
  expansions, snapshot permissions, damaged-cache recovery guidance, and
  Git process cancellation were fixed and rechecked with no open findings.

All three release checkpoints scan 504 roots and 1,498 module instances.

| Corpus result | Milestones 1–4 baseline | Count checkpoint | Final |
| --- | ---: | ---: | ---: |
| Resources | 5,224 | 5,379 | 5,379 |
| Seed findings / occurrences | 1 / 2 | 1 / 2 | 1 / 2 |
| Catalog findings / occurrences | 289 / 525 | 304 / 568 | 304 / 568 |
| Count coverage gaps | 42 | 0 | 0 |
| Evaluation coverage gaps | 473 | 485 | 445 |
| Unavailable remote modules | 600 | 600 | 600 |
| Catalog rule execution errors | 14 | 14 | 14 |

Count expansion adds 15 catalog fingerprints and removes none. It also exposes
12 additional unsupported `templatefile` evaluations in newly expanded
resources. Regex support removes 37 regex-replacement and three regex-matching
diagnostics; complete finding records match the count checkpoint. Remaining
coverage diagnostics total 1,045. Seed scans remain incomplete, and catalog
scans remain failed because of the existing 14 rule execution errors.
Fetching was validated with local fixtures; the corpus comparison did not
download the 600 unavailable modules.

Timings include JSON output and are medians of five runs after one warmup,
rotating the three binaries with no concurrent build. Peak resident memory is
from a separate single run per binary and mode.

| Rules | Baseline time | Count time | Final time |
| --- | ---: | ---: | ---: |
| Seed rules (`--no-bundled`) | 117.47 ms | 107.66 ms | 130.34 ms |
| Bundled catalog | 250.19 ms | 218.71 ms | 219.51 ms |

| Rules | Baseline peak RSS | Count peak RSS | Final peak RSS |
| --- | ---: | ---: | ---: |
| Seed rules (`--no-bundled`) | 238,388 KiB | 234,100 KiB | 223,012 KiB |
| Bundled catalog | 290,176 KiB | 290,140 KiB | 308,940 KiB |

These are local measurements, not a general performance guarantee or remote
CI result. Expansion budgets bound instance growth; Git staging and archive
limits do not constitute a process memory limit.

The remaining function priorities follow observed evaluation gaps:

1. `templatefile` accounts for 214 diagnostics. In the EKS managed and
   self-managed node-group modules, rendered user data flows into
   `aws_launch_template.user_data`. Supporting it would let the shipped
   `CKV_AWS_46` hard-coded-secret check inspect those scripts. This identifies
   a concrete policy evaluation opportunity, not a confirmed additional
   vulnerability in the corpus.
2. `file` accounts for 114 diagnostics, including CloudFront function code
   and IAM SAML metadata. File evaluation needs to preserve source ownership,
   sensitivity, overlays, and fetched-package containment.
3. `filesha256` (50), `filebase64sha256` (38), and the less frequent hashes and
   date functions are smaller follow-ups. Many observed uses are deployment
   identifiers; no finding gain from implementing them has been measured.

The implemented regex cases include Lambda IAM statement-ID sanitization in
`terraform-aws-lambda/iam.tf` and Google network project extraction in
`terraform-google-network/modules/foundation/network/ncc.tf`. These were
measured coverage improvements without a claim of new security findings.

### All-milestone review fixes — 2026-10-20

The six findings from the subsequent all-milestone review are fixed:

- Git packages retain committed files and literal contents even when
  `.gitattributes` specifies `export-ignore` or `export-subst`.
- Sensitive resource/module selectors mark selected values, errors, source
  snippets, Arrow exports, and verified fix diffs. Sensitive locals remain
  masked after an edit removes their consumers.
- Override composition retains the original declaration's optional defaults
  separately from the effective type. Inherited and replacement defaults,
  tfvars, and module arguments follow the Terraform reference.
- Concrete collection types survive successive overrides, including nested
  values, typed nulls, empty collections, and intermediate `any` constraints.
  Incompatible conversions report failure.
- Whole-resource objects retain nested block fields as unknown when their
  values cannot be resolved, so `can`/`try` do not treat them as absent.
- Count indices accept numeric strings such as `"1.0"` and `"1e0"` while
  rejecting fractional, negative, non-finite, and out-of-range values.

Validation also exposed a Git monitor race: renaming a lockfile between
directory enumeration and metadata lookup falsely triggered the download
limit. The monitor now tolerates disappeared entries while retaining its
other error and limit checks. Forty consecutive traced fetches passed after
the fix; an oversized-package regression verifies rejection without manifest
publication.

Completed local gates: 350 Rust tests passed with the pinned parser corpus;
the two opt-in reference-pack tests also passed separately. The rebuilt Python
extension passed all 277 tests with Terraform 1.16.1 required. Formatting,
Clippy with warnings denied, AST generation checks, and the release build
passed. Checkov agreed on 8,857 comparable cases (12 reference-unresolved);
OPA agreed on all 120 evaluations. Both follow-up review axes have no open
findings; the specification reviewer independently rechecked 19 saved
Terraform differential probes.

The release corpus comparison preserves all finding records and fingerprints:
504 roots, 1,498 module instances, 5,379 resources, one seed finding with two
occurrences, and 304 catalog findings with 568 occurrences. The existing 600
unavailable-module diagnostics, 445 evaluation diagnostics, and 14 catalog
rule errors are unchanged. Seed scans remain incomplete and catalog scans
remain failed; these fixes do not remove those existing coverage limitations.

Five measured runs after warmup, rotating the before/after binaries without
concurrent builds, gave median seed times of 122.85/125.61 ms and catalog
times of 229.31/219.84 ms. These local measurements are not performance
guarantees. The pre-fix working tree is preserved at
`/tmp/oxtf-review-fixes-baseline`; final release, comparison records, and
reference reports are in `/tmp/oxtf-review-fixes-validation`. Changes remain
uncommitted and no remote CI result is claimed.

# Signal completion follow-up — 2026-10-20

This follows the severity/remediation review in `SIGNAL_PLAN.md`. It improves
existing findings and evaluation coverage. It adds no rules and does not
replace the historical signal baseline with partial evidence.

## Implemented

- Added source-context evaluation for `file`, `filebase64`, `templatefile`,
  `abspath`, file MD5/SHA-1/SHA-256/SHA-512, and base64 SHA-256/SHA-512 hashes.
  Corresponding string hashes are supported too. Hash algorithms reproduce
  Terraform functions; their implementation is not a cryptographic recommendation.
- File functions share overlays and cache raw bytes. UTF-8 is required for
  text/templates, while hashes and base64 accept binary data. File provenance,
  sensitivity, unknown values and alternatives survive evaluation. Templates
  preserve single-interpolation types, bind supplied variables and iterators,
  check free variables even in unused branches, and reject recursive calls.
  Fetch manifests carrying `OxtfPackageRoot` bound file reads to that package,
  including local descendants; an outside read remains a coverage limit.
- Corrected relative `path.module` resolution for sibling modules. Unhandled
  expression errors now produce `evaluation-error` diagnostics and failed status.
  Diagnostics omit value-bearing error details; explicit value APIs retain the
  underlying reason. Caught `try`/`can` errors do not fail the scan.
- Reviewed 11 additional existing bundled rules: `CKV_GCP_12`, `22`, `25`,
  `32`, `39`, `40`, `41`, `49`, `64`, `66`, and `68`. There are now 51 bundled
  rules with remediation/documentation, plus all five native rules. The number
  of curated bundled entries remains 213. Predicates and profile membership
  did not change in this batch.
- Added signal-report inventories: guidance debt ranked by finding frequency,
  grouped rule errors and coverage gaps, and NDJSON bytes split into findings,
  diagnostics, rule errors, rule metadata, and summary overhead.

The function contract follows HashiCorp's
[templatefile documentation](https://developer.hashicorp.com/terraform/language/functions/templatefile)
and [binary file hash semantics](https://developer.hashicorp.com/terraform/language/functions/filemd5).
Provider references live beside each reviewed rule in
`crates/tf_rule_ir/data/checkov/curation.toml`.

## Metadata decisions that affect interpretation

The private-cluster checks `CKV_GCP_25` and `64` only test for a block; they can
pass with private nodes explicitly disabled. Their descriptions and guidance
now say what the predicate establishes. Both are medium. `CKV_GCP_40` is also
medium: an external IPv4 configuration alone does not establish reachable
services, and the check only inspects the first interface.

`CKV_GCP_49` becomes medium because its broad role-name list includes legitimate
service-agent grants and does not inspect the principal or conditions.
`CKV_GCP_41` remains high, with the distinction between attaching a service
account and minting its credentials explained. Remediation preserves necessary
service-agent grants and warns about authoritative IAM binding replacement.

Binary Authorization's cluster switch does not prove a restrictive admission
policy; its default policy allows images. Network-policy guidance distinguishes
enforcement from actual NetworkPolicy objects and documents the pinned check's
Dataplane V2 limitation. SSH-key guidance accounts for OS Login. Shielded VM and
node-image guidance distinguishes defaults, hardening, compatibility, and
version-specific legacy predicates. These are interpretation corrections,
not infrastructure fixes or claims that predicate limitations have been removed.

## Same-scope observed results

The durable observation is `bench/results/signal-observed.json`. Both profiles
scan the same 504 roots and 5,379 resource instances from the pinned corpus.
All-profile results remain 568 findings / 1,576 occurrences; the default remains
262 / 507. Default remediation coverage increases from 37.4% to 68.3%; rationale
coverage remains 99.2%. All-profile remediation coverage increases from 27.5%
to 41.7%. High findings decrease from 58 to 47 through classification changes;
this is not evidence that resources were fixed.
Comparing full-record fingerprints with the pre-curation snapshot adds none
and removes none.

Coverage-evaluation diagnostics decrease from 445 to 19. Evaluating previously
unsupported expressions exposes other limits, including six `fileset` calls.
There are also 109 now-visible expression-error diagnostics and the unchanged
600 missing-module diagnostics, for 728 total. Fourteen rule errors remain.
The scan status is **failed**.

NDJSON decreases from about 1,348 to 1,229 bytes per all-profile finding despite
the additional guidance. The current byte breakdown is approximately 263 KB
of findings, 329 KB of diagnostics, 103 KB of rule metadata, and 3 KB of rule
errors/summary. Finding lines alone are about 464 bytes per finding. The total
is the judged metric: diagnostics and guidance have not been dropped to meet
the old 457-byte floor. Fix-hint coverage remains 9.9%; there are 56 hints on
568 findings, versus the historical 10.1% on a smaller denominator. No synthetic
hints were added to raise that percentage.

## Remaining blockers and exact next work

1. **Pinned upstream rule defects.** `CKV_GCP_24` raises `AttributeError` for
   `min_master_version = null` (13 observed errors); `CKV_GCP_22` does the same
   for `version = null` (one). Calling the original Checkov 3.2.328 classes
   directly and its runner reproduces the defect. The interpreter is faithful.
   Rust/Python regressions preserve the failed status. Resolving this requires
   a reviewed checker replacement or upstream-version update with compatibility
   evidence; globally swallowing exceptions or removing nulls would change
   other checks and conceal failures.
2. **Dependency preparation.** The 600 diagnostics refer to missing manifests
   in 214 roots, including examples reached through several local modules.
   Explicit fetching was exercised successfully for the GKE `simple_regional`
   example with an isolated data directory; it resolved version 44.3.0 at Git
   revision `521f499b5d12c032bdf977cddd3fb21f78b4b3c3`. This is a preparation probe,
   not a lock for all corpus dependencies. Prepare every root using the existing
   fetch workflow, retain manifests and content revisions, and scan with the
   same data-directory convention. Do not treat an arbitrary latest resolution
   or a smaller corpus as a comparable baseline.
3. **Evaluation gaps.** Remaining coverage causes are `fileset` (6), `timeadd`
   (4), `formatdate` (1), `uuid` (1), merge-alternative limits (5), and filter-
   alternative limits (2). Implement deterministic functions with Terraform
   comparisons; runtime-generated values need an explicit unknown-value model,
   not fabricated values. Preserve expansion limits unless a sounder bounded
   abstraction replaces them.
4. **Expression errors.** Investigate the now-visible failures independently.
   Model inspection finds repeated missing fields (`module_source`,
   `module_version`, `result`, `subscription_id`, `tenant_id`, `id`, `hex`),
   unsupported ephemeral-resource references, invalid template interpolations,
   and empty coalesce/coalescelist inputs. These include provider-computed-field
   modeling gaps; a failed status does not prove the Terraform configuration is
   invalid. Do not make error values disappear merely to complete scans.
5. **Baseline and guidance debt.** Keep `bench/results/signal.json` unchanged
   until comparable scans complete. Then review byte/hint budgets and establish
   metadata coverage floors. The observed report ranks the next default-profile
   guidance work: Azure Key Vault private endpoints, AKS encryption at host,
   secret expiration, KMS rotation, and other lower-frequency rules. There is no
   requirement to add rules to complete that work.

## Reproduction and validation

```sh
cargo build --locked --release -p tf_cli
python bench/signal.py --output /tmp/oxtf-signal-observed.json --check
python -m unittest discover -s bench -p test_signal.py
cargo test --locked -p tf_scan --test file_functions --test completion --test guidance
```

The signal check intentionally exits 1 while the above failures persist.
`--write` continues to reject incomplete/failed scans. `--output` cannot target
the trusted baseline path.

The Rust workspace suite passed with `OXTF_REQUIRE_CORPUS=1`. All 285 Python
tests passed with `OXTF_REQUIRE_TERRAFORM=1`, including the new Terraform 1.16.1
file/template/hash comparison. Fresh Checkov export matches the checked-in
catalog, and 8,857 comparable generated predicate cases had zero disagreements
(12 further cases were unresolved in the reference). Clippy and formatting
checks pass. Focused regressions cover the final function and metadata changes;
see `docs/VALIDATION.md` for the standard commands and reference prerequisites.
The six signal-script tests also run in the Rust CI job.

A local release scan over the full pinned corpus, all profiles, JSON output,
and one worker took a median 853.48 ms across five runs after one warmup, with
176,084 KiB peak child RSS. These timings measure the failed/partial scan above;
they do not establish complete-analysis performance or a speedup over an older
binary. No performance budget was changed.

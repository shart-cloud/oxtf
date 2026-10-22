---
name: oxtf
description: >
  Find and fix Terraform security misconfigurations with the oxtf scanner, verifying every
  fix by rescanning. Use when asked to scan, audit, harden or fix Terraform (.tf/.tf.json)
  for security issues, to check Terraform against Checkov rules, or to fix a specific
  finding. Requires the `oxtf` CLI 0.1.0 or later.
---

# oxtf: scan and fix Terraform

oxtf evaluates Terraform the way Terraform does (variable defaults, `count`/`for_each`,
locals, modules) and runs Checkov's Terraform checks plus native rules. Every finding has a
stable `fingerprint`. Many carry a `fix_hint` that `oxtf fix` applies and verifies by
rescanning. Work from JSON output (`-f json`), never the text.

## 1. Scan

```sh
oxtf --version                          # confirm it is installed (0.1.0 or later)
oxtf scan -r PATH -f json > scan.json   # every directory with .tf files is a root
```

Add `--fetch` only when the user agrees to network access and writing `.terraform/`: it
installs remote modules for the roots that need them, as `terraform init` would.

Exit codes: 0 means no finding at or above `--fail-on` (default `definite`, so conditional
findings alone exit 0), 1 means some are, 2 means the scan could not run, and 3 means it was
incomplete or failed (read `status` to tell which). Errors (for example from `oxtf fix`) are
printed to stderr as text, even with `-f json`. `oxtf --help` prints every option.

Before reporting anything, read:

- `status`: `complete`, `incomplete` or `failed`. Only `complete` means every check ran on
  everything. Findings from an incomplete scan are real, but a missing finding then proves
  nothing. Say so.
- `roots`: each root module's own `path` and `status`. `incomplete` means some
  configuration was not evaluated, for example an uninstalled module, so its findings are
  real but partial. `failed` means an expression failed to evaluate. Resources depending on
  it were not checked, and the root may report few or no findings. Neither status is clean.
- `diagnostics`: `code`, `message` and a `location`, but no root. A diagnostic in a shared
  module file can repeat once per root that reaches it. To attribute one to a root, rescan
  that root alone (`oxtf scan ROOT -f json`).
  - `coverage-module-not-installed`: remote modules are missing. Use `--fetch` or
    `terraform init`.
  - `evaluation-error`: an expression failed to evaluate. The message names the builtin
    when one failed. Common causes: a reusable module scanned on its own with defaults
    that Terraform also rejects, or a value from a module that is not installed. Check the
    same root's other diagnostics before concluding which.
  - `coverage-evaluation` with "analysis limit": a safety allowance stopped evaluation.
    `--limits FILE` raises allowances, from a JSON object such as
    `{"evaluation_steps": 5000000}`.
  - Other `coverage-*` codes: something oxtf could not evaluate.
- `rule_errors`: rules that failed to run. Never present one of these as a pass.

## 2. Choose findings

Each finding has:

- `rule`, `level` (`critical`, `high`, `medium`, `low`), `certainty`, `message` and
  `location`;
- `occurrences`: each `root` and `address` that reaches the declaration;
- `fix_hint`, when a mechanical fix exists.

`rules[rule]` holds `description`, `rationale`, `remediation` and `guideline`. If
`remediation` is missing, work from the description and the guideline link.

- `definite`: the rule's condition holds as configured, with defaults and tfvars. Read the
  `rationale`: some rules flag a missing guardrail, which is not proof of exposure.
- `conditional`: it holds for some value of a variable nobody set; the `message` names the
  variable. Read the rule's `description` to work out which values are bad. Check what the
  repository's callers actually pass. oxtf does not use `validation` or `precondition`
  blocks to narrow variables. If one rules out the bad values, report the finding as
  mitigated and cite the guard. If none does, recommend a `validation` block, which oxtf
  cannot verify, and ask before adding it.

Order the work by `level`, then `definite` before `conditional`. Weight a finding by what
reaches it: one reached only from a reusable module scanned on its own, or only from
`examples/` or `tests/`, matters less than one reached from a deployed root. Before changing
anything, read the rule's `rationale` and `remediation`: some fixes have migration costs,
such as irreversible settings or authoritative IAM bindings.

To accept a finding deliberately, add `# checkov:skip=RULE_ID:reason` inside the resource
block. oxtf honours Checkov's skip comments and lists the result under `suppressed`, never
silently.

## 3. Fix with a hint, verified

Dry-run first. Pass the roots in the finding's `occurrences`, not the whole repository:
verification needs complete scans before and after, and an unrelated incomplete root
elsewhere blocks it.

```sh
oxtf fix FINGERPRINT ROOT [ROOT...] -f json   # dry run: nothing is written
```

The fix writes the literal in one of three places, reported as `site`:

- `input`: the value is passed in by a caller's module argument or a tfvars entry
  (`fix_hint.input_site`). It is fixed there, and only there, because rewriting the
  module's attribute would override that input for every caller. oxtf refuses
  `--at attribute` in this case.
- `default`: the attribute is `var.x` and the value comes from that variable's default
  (`fix_hint.default_site`). Fixing the default keeps the module's interface.
- `attribute`: the value is written in the resource itself, or the attribute is missing
  and gets inserted.

`--at input|default|attribute` picks a site explicitly.

Exit codes: 0 verified, 1 not verified, 2 no such finding, no fix hint, or a scan that
could not run.

Read the result:

- `verified`: true only when both scans were complete, `target_resolved` (the rule no
  longer fails on that declaration from any root) and `no_new_findings` both hold.
  `verified` covers the scanner's rules only. It does not check that the provider or cloud
  API accepts the result, for example `BucketOwnerEnforced` next to an `acl` argument.
  Read the whole block around the edit, and the code's purpose, before writing: an example
  that exists to demonstrate a setting should keep it, with a `checkov:skip`.
- `diff`: the exact edit. Show it to the user.
- `finding_delta`: findings `added`, `removed` and `changed`.
- `verification_errors`: why the scans were incomplete. When it is empty but
  `target_resolved` is false, other occurrences of the finding remain (see below).

When `verified` is true and the user wants the change, rerun with `--write`. oxtf writes
only verified edits; `--write` on an unverified one writes nothing.

When it is not verified because other occurrences remain (`finding_delta.changed` with
`removed_occurrences`), the declaration is reached with bad values from several places,
such as two callers, or a caller plus an insecure default. One edit cannot fix them all.
Fix each place by hand (section 4), then rescan.

## 4. Fix without a hint, or across several places

Edit by hand, following `rules[rule].remediation`. Never replace `var.x` in a reusable
module with a literal when callers set `x`: fix the callers, or the default.

To test edits before writing them, write each edited file to a scratch location and
rescan the same roots with `--overlay PATH=FILE` (repeatable). PATH is spelled the way
oxtf prints file paths for that scan:

```sh
oxtf scan -r repo/examples/app -f json \
  --overlay repo/examples/app/main.tf=/tmp/edit/main.tf > after.json
```

Then compare fingerprints with the earlier record: the target must be gone, and no
fingerprint may be new.

If those roots cannot scan `complete` (modules not installed, and `--fetch` not allowed),
the evidence is partial. Present the edit as unverified, show what the overlay scan
showed, and ask before writing it.

## 5. Report

List:

- what was fixed: fingerprint, rule, file, and whether it was verified;
- what remains, and why;
- what could not be checked: incomplete or failed roots, rule errors, unverified edits.

Do not call a repository clean unless the final scan's `status` is `complete` and it has
no findings.

## Python

The `tfscan` package exposes the same operations.

- `tfscan.scan(path, recursive=True, fetch=False)` returns `status`, `roots`, `findings`,
  `diagnostics` and `rule_errors`.
- `tfscan.fix(fingerprint, roots, at=None)` returns the same dictionary as
  `oxtf fix -f json`, plus `text`, the edited file. It never writes: write `text` to
  `file` yourself, and only when `verified` is true.

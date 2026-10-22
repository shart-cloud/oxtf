# Proof-of-value plan

Status: proposed, 2026-10-22. Follows the completed
[TigerStyle migration](TIGERSTYLE_PLAN.md). Relates to the open items in
[signal completion](SIGNAL_COMPLETION.md).

Goal: put oxtf in front of a team or design partner as a faster, more
trustworthy replacement for Checkov in agent and CI workflows. The product
goal is unchanged: a fast agent-facing scanner and the first step of a patch
chain. This plan covers what blocks a credible first run, not new rules.

## Starting point

One real repository, `terraform-aws-modules/terraform-aws-eks` from the pinned
corpus, scanned recursively without `terraform init`, on the development machine:

| Tool | Elapsed | Peak RSS | Result |
| --- | ---: | ---: | --- |
| oxtf (release) | 0.12 s | 118 MB | 16 findings (39 occurrences); 35 diagnostics; `analysis failed`, exit 3 |
| Checkov 3.2 | 168 s | 514 MB | 98 failed checks |
| Trivy config | 18.8 s | — | — |

Speed is the headline: about 1,400× faster than Checkov while running Checkov's
own rules. The first run still looks broken:

- 30 of the 35 diagnostics say the same thing, `cannot read installed module
  manifest`, once per module call.
- One `evaluation-error` in `modules/capability/main.tf:28` makes the whole
  summary say `analysis failed`, although the other 18 roots completed.
- oxtf reports 39 occurrences where Checkov reports 98, and nothing explains
  the difference.

A prospect stops at that screen, so the order below starts there.

## Work items

### 1. First-run experience

Make a scan of an uninitialized repository read as useful and honest.

- **Summarize missing installs.** Group missing-manifest diagnostics into one
  line per scan, for example `14 remote modules not installed: run oxtf fetch .
  or terraform init`. Keep per-module detail in JSON output. Consider a
  `--fetch` flag that runs the existing fetch workflow first.
- **Scope failure to its root.** The text summary should say which roots could
  not be fully evaluated and that findings elsewhere are complete, for example
  `1 of 19 roots could not be fully evaluated (modules/capability/main.tf:28)`.
  Status and exit codes keep their current meaning for CI; only presentation
  changes. Per-root status in JSON makes this machine-readable.
- **Investigate the observed `evaluation-error`.** It belongs to the expression-
  error item in signal completion. Fix the evaluator only if Terraform accepts
  the expression; never make errors disappear to complete a scan.

Done when: the EKS scan above shows one install hint, names the incomplete root,
and every remaining diagnostic is one a user can act on.

### 2. Reconciliation against Checkov

Answer "why fewer findings?" before anyone asks.

- Scan 5–6 public repositories from the corpus with both tools, using the same
  rule set (bundled catalog, `--profile all` and the default security profile).
- Classify every difference: same finding; Checkov false positive that oxtf
  rules out (unset variables, conditionals, resources that may not exist);
  outside the selected profile; uncurated or not-bundled rule; installed-module
  coverage; or a genuine oxtf gap.
- Publish the result as `docs/RECONCILIATION.md` with reproducible commands and
  pinned repository revisions. Store the raw comparison under `bench/results/`.
- Feed every genuine gap into item 5 or a follow-up, ranked by frequency.

Done when: every Checkov result on those repositories has a category, and
genuine gaps are listed with counts.

### 3. Installation

A POV cannot start with "install Rust and build it".

- Tagged GitHub releases with prebuilt `oxtf` binaries for Linux x86-64/arm64
  and macOS arm64, with checksums.
- A `tfscan` wheel built by maturin in CI (abi3), published to PyPI or attached
  to the release.
- One install line in the README, and a version command that reports the
  bundled Checkov catalog version.

Done when: a clean machine goes from nothing to a first scan with one command.

### 4. Agent patch loop

Show the differentiator end to end: scan, choose a finding, apply its fix,
verify by fingerprint.

- Package the loop for agents: an agent skill wrapping the CLI or Python
  binding, or a small MCP server with `scan`, `explain` and `fix` tools. Pick
  whichever needs less new surface; reuse `oxtf fix` and the finding record
  schema rather than adding a parallel format.
- Script one recorded demonstration on a public repository, including a fix
  that verification rejects, so the safety story is visible.

Done when: Claude Code or Codex can fix a real finding from a cold start using
only the packaged skill or server.

### 5. Common-repository failures

Remove failures that make clean repositories report `failed`, in the order
the reconciliation ranks them. Known candidates from signal completion:

- `CKV_GCP_24` and `CKV_GCP_22` raise on `version = null` in the pinned Checkov
  classes (13 corpus errors). Needs a reviewed checker replacement; do not
  swallow exceptions globally.
- Missing deterministic functions: `fileset` (6 roots), `timeadd` (4),
  `formatdate` (1). Implement against Terraform comparisons. Runtime-generated
  values such as `uuid` stay unknown.

Done when: the reconciliation repositories scan without rule errors caused by
these defects.

## Sequencing

| Session | Items | Why together |
| --- | --- | --- |
| 1 | 1 and 2 | The reconciliation shows which first-run problems matter most. |
| 2 | 3 and 4 | Together they make the POV installable and demonstrable. |
| Alongside | 5 | Ordered by the reconciliation's gap list. |

Keep the existing gates on every change: workspace tests with the corpus
required, Clippy with the function-length lint, the stack and work-meter
tests, and the 0.5 s corpus budget. The standard catalog currently scans the
corpus in about 0.4–0.47 s with four workers; profile before adding rules.

## Open question

Which audience leads: CI users (Checkov parity and installation first) or
agent workflows (patch loop and packaging first)? The answer may swap the
order of items 3 and 4.

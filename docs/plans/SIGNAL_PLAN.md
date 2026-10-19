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

## C. Name the deciding attribute in every evaluator — next

- **Value checks**: on a missing attribute, emit an "absent at `path`"
  witness so `attribute` is set. Derive a fix hint when the check expects a
  single literal (`private_cluster_enabled = true`): 62 of the 155 value
  findings, with no curation.
- **Python and graph checks**: trace the configuration keys the
  interpreter reads (subscripts, `.get`, `in`). On FAILED, the attribute is
  the last read that decided a branch, absence tests first; the witness is
  that sub-value or an absent marker. This reaches the 292 + 86 findings
  that metadata cannot.
- **Engine contract**: a judgement without an attribute path becomes an
  explicit header-only case, counted in stats, so the gap cannot regrow
  silently.

## D. Curate the catalog — after C

- `crates/tf_rule_ir/data/checkov/curation.toml`, hand-maintained and never
  touched by regeneration: per Checkov ID, `level`, `category`, `profile`
  (`security` / `hygiene` / `reliability`) and an optional fix template
  (attribute, value, block shape).
- Curate by corpus frequency: the top 40 rules cover 68 % of findings.
  The tail stays `medium` and unreviewed.
- Guideline: the Checkov source at the pinned tag, from `source`, for
  every bundled rule.
- `--profile security|all`; `security` is the default.

## E. Signal gate — started

`bench/signal.py` measures the corpus scan: findings, occurrences, JSON and
NDJSON bytes per finding, % with attribute, % with fix hint, % header-only,
level distribution. `--write` stores `bench/results/signal.json`; `--check`
fails when a judged metric moves the wrong way. Run it beside the perf
guard on every change to the output or the catalog.

## Results so far

| | main | after A + B |
| --- | --- | --- |
| Findings | 1,535 | 553 (1,535 occurrences) |
| Distinct fingerprints | 959 for 554 distinct problems (one backlog issue per module path) | 553, one per finding |
| JSON | 2.6 MB | 1.15 MB (2,078 B per finding) |
| NDJSON | — | 231 KB (418 B per finding) |
| Exit code with definite findings | 0 | 1 |
| Corpus wall time, JSON, min of 5 | 0.21 s | 0.22 s |

`fixtures/baseline/native.json` was regenerated for the new shape; every
case expands back to exactly the old judgements, with the representative's
fields unchanged (2 `for_each` pairs merged).

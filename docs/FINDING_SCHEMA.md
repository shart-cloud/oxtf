# Finding record (schema 3)

The finding record is the machine-readable form of a scan. Every output of
oxtf is a projection of it: `oxtf scan --format json` prints it verbatim,
`--format ndjson` and `--format sarif` are built from it alone
(`tf_linter::formats`), the Python `Finding` getters and `to_dict()` read
from it, the Arrow table carries its columns plus the record as JSON, and
the text renderer shows a subset for humans. It is produced by
`tf_linter::record`.

The shape is versioned by the top-level `schema` field. Any change that
removes or renames a field, or changes a field's meaning, bumps it. Adding
an optional field does not.

`status` is independent of findings: `complete`, `incomplete` (a known
coverage gap), or `failed` (an error diagnostic or rule execution error).
It is included in JSON and the NDJSON summary. A complete scan may still
contain unknown values; provider-computed and unconstrained inputs are
part of the abstract evaluation model, not execution failures.

## What a finding is

A **finding** is one rule failing on one attribute (or the whole) of one
resource declaration: the rule, the declaration's file, its local address
(`aws_s3_bucket.this`, no module path, no instance key) and the deciding
attribute. That is also what its fingerprint hashes.

The engine judges resource *instances* in each *root*. When the same
declaration is judged in several places — a module scanned as its own root
and again from each example that calls it, or the instances of a
`for_each` — each judgement is an **occurrence** of one finding, not a
finding of its own. On the 17-repo corpus this turns 1,535 judgements into
553 findings.

A finding's fields describe its **representative** occurrence: the most
certain one, then the one in the shallowest module instance (the module
scanned as its own root), then the shortest root path. `occurrences` lists
them all.

Installed module findings and their occurrences optionally include `package`:
`source` (normalized source address), `version` (the installed version recorded
in the manifest, or `null`), `file` (relative to the selected module directory),
and `calls` (source locations from the root through the module-call chain).
Packages installed by explicit fetching also include optional `revision`: a
resolved Git commit or `sha256:` of extracted package contents. Older Terraform
manifests omit this field.
Local descendants retain the package origin; their relative files can contain
`..` when a package subdirectory calls a sibling.

For installed source, the fingerprint uses source address, installed version,
and package-relative filename in place of the physical cache path. Separate
installations of the same source and version therefore group together. These
fields describe the scanned installation. When present, the fetched revision is
also part of its fingerprint identity, so different fetched revisions remain
distinct. It records the fetch result; ordinary scans do not rehash the package.
Each occurrence retains its own caller locations. Managed cache files
have no automatic fix hints and are also rejected by the edit API.

## Changes from schema 2

- Findings are grouped: `occurrences` added; `stats.findings` and the
  certainty counts count findings, `stats.occurrences` counts judgements.
- `severity` is renamed `certainty` (it always meant certainty; `level` is
  the rule's severity).
- Rule metadata moves to a top-level `rules` table keyed by ID; a finding's
  `rule` is the ID, and it keeps `level` so it can be ranked alone. The
  table adds `aliases`.
- `resource` is gone; `subject` carries the structured resource reference
  (`{"kind": "resource", "address", "base_address", "module", "mode",
  "type", "name", "key"}`) or the file.
- The per-finding `schema` is gone.
- The fingerprint hashes the repository-relative file and the local address
  instead of the full address, so it is the same from every root and every
  working directory.
- The CLI's exit code reflects findings (see below).

## Worked example

`oxtf scan --no-bundled --format json fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default`:

```json
{
  "schema": 3,
  "status": "complete",
  "rules": {
    "aws-rds-unencrypted": {
      "category": "encryption",
      "level": "high",
      "description": "RDS instance storage is not encrypted",
      "guideline": null,
      "source": {
        "engine": "builtin",
        "file": null,
        "line": null
      },
      "aliases": []
    }
  },
  "findings": [
    {
      "fingerprint": "96482caeecf7176c",
      "rule": "aws-rds-unencrypted",
      "level": "high",
      "certainty": "definite",
      "subject": {
        "kind": "resource",
        "address": "aws_db_instance.db",
        "base_address": "aws_db_instance.db",
        "module": "",
        "mode": "managed",
        "type": "aws_db_instance",
        "name": "db",
        "key": null
      },
      "root": "fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default",
      "attribute": "storage_encrypted",
      "configured": null,
      "effective": {
        "kind": "known",
        "value": false,
        "display": "false"
      },
      "location": {
        "file": "fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default/main.tf",
        "line": 1,
        "column": 1,
        "start": 0,
        "end": 31
      },
      "provenance": [
        {
          "kind": "default",
          "label": "aws_db_instance.db storage_encrypted not set: provider default false (defaults overlay; docs: 'The default is `false` if not specified.' (no Default: in source; AWS API default))",
          "resource": "aws_db_instance.db",
          "attribute": "storage_encrypted",
          "location": {
            "file": "fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default/main.tf",
            "line": 1,
            "column": 1,
            "start": 0,
            "end": 31
          }
        }
      ],
      "message": "storage_encrypted is not set (provider default: false)",
      "hidden": [],
      "fix_hint": {
        "resource": {
          "address": "aws_db_instance.db",
          "base_address": "aws_db_instance.db",
          "module": "",
          "mode": "managed",
          "type": "aws_db_instance",
          "name": "db",
          "key": null
        },
        "attribute": "storage_encrypted",
        "action": "set",
        "value": true,
        "site": null
      },
      "occurrences": [
        {
          "root": "fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default",
          "address": "aws_db_instance.db",
          "certainty": "definite"
        }
      ]
    }
  ],
  "diagnostics": [],
  "rule_errors": [],
  "stats": {
    "roots": 1,
    "module_instances": 1,
    "files": 1,
    "resources": 1,
    "findings": 1,
    "occurrences": 1,
    "definite": 1,
    "conditional": 0,
    "indeterminate": 0,
    "findings_by_rule": {
      "aws-rds-unencrypted": 1
    },
    "elapsed_ms": 1.2
  },
  "suppressed": [],
  "roots": [{ "path": "infra", "status": "complete" }]
}
```

## Scan

| Field | Meaning |
| --- | --- |
| `schema` | Record version (3). |
| `status` | `complete`, `incomplete`, or `failed`; independent of findings. |
| `rules` | Metadata of every rule a finding names, by ID: `category` (`network`, `storage`, `iam`, `encryption`, `other`), `level` (`low`, `medium`, `high`, `critical`: potential impact, independent of certainty), `description`, optional `rationale` (why that severity fits the check's evidence and limits), optional `remediation` (actionable steps and material migration constraints), `guideline` (documentation URL, or `null`), `source` (`engine`: `builtin`, `ir`, `checkov`, `rego`, `conftest`, `python`; the rule's `file` and `line`, `null` for built-in rules), `aliases` and `profile` (`security`, `audit`, `hygiene`, or `unreviewed`; see `--profile`). Reviewed guidance links to provider documentation; other bundled rules retain their pinned Checkov source URL. A source link alone is not remediation guidance. |
| `findings` | One record per finding, below, ordered by file, position and rule. |
| `diagnostics` | Parse errors, warnings and notes: `severity` (`error`, `warning`, `info`), `code`, `message`, `location` or `null`. A `rule-skipped` warning (listed first, `location` `null`) names a file in a `--rule-file` directory that did not load; its message gives the file and each reason with its line and column. The rules in that file did not run. `coverage-module-not-installed` marks a remote module call with no installed-module manifest (install with `--fetch`, `oxtf fetch` or `terraform init`); other unresolved remote sources keep `coverage-remote-module`. `coverage-fetch` names a root whose modules `--fetch` could not install. An `evaluation-error` names the failing builtin when there is one (for example `expression evaluation failed in coalesce()`), never the values involved. |
| `rule_errors` | Rules that failed to run or returned an unresolved foreign result: `rule`, `resource` (or `null`), `message`. An empty list means no execution errors were recorded for selected, applicable rules; it does not establish coverage of unsupported rules or prove that native Unknown outcomes passed. A reader must never take silence from a rule listed here as a pass. |
| `stats` | `roots`, `module_instances`, `files`, `resources`; `findings` (findings) and `occurrences` (judgements); `definite`, `conditional`, `indeterminate` and `findings_by_rule`, counting findings; `elapsed_ms`. |
| `roots` | Each scanned root module in scan order: `path` and its own `status`. A root is `failed` or `incomplete` by its own diagnostics and rule errors; scan-wide limits (`coverage-storage`, `coverage-results`) affect only the scan `status`, so a complete root can sit inside an incomplete scan. Records without this field (older readers) default to an empty list. |
| `suppressed` | Judgements of Checkov-sourced rules that a `checkov:skip=ID:reason` line suppressed, as Checkov applies them (in the resource's block or an enclosing `module` block): `rule`, `resource`, `comment` (Checkov's `No comment provided` when there is none) and the `location` of that line. Not findings, but never dropped silently. |

## Finding

| Field | Meaning |
| --- | --- |
| `fingerprint` | Stable identity across scans: FNV-1a 64 of `rule`, the file's path relative to its repository (the outermost ancestor holding `.git`; the path as given outside any repository), the subject's local identity (the local address for a resource, the message for a file subject) and `attribute`. It excludes locations, module paths, instance keys, roots and certainty on purpose: unrelated edits, new callers and certainty changes keep the identity. Installed source substitutes the package identity described above for the repository path. Every occurrence of a finding has it. |
| `rule` | The rule's ID; metadata in `rules`. |
| `level` | The rule's level, repeated from `rules`. |
| `certainty` | The most certain occurrence's. `definite`: insecure as written. `conditional`: insecure for some value of an unconstrained variable. `indeterminate`: a foreign policy fired on the Known values, but an input it may depend on is provider-computed; needs a human. Native rules never produce `indeterminate`. |
| `subject` | What the representative occurrence is about: `{"kind": "resource", "address", "base_address", "module", "mode", "type", "name", "key"}` (`address` full, `base_address` without key, `module` `""` for the root, `mode` `managed` or `data`, `key` a number for `count`, a string for `for_each`, or `null`), or `{"kind": "file", "file", "module"}` for a whole-file policy result that no single resource reproduces. |
| `root` | Root module directory of the representative occurrence. |
| `attribute` | Path of the deciding value within the resource (`storage_encrypted`, `ingress.cidr_blocks`), also when it is not set (the provenance then ends in an `absent` step at the resource header), or `null` when the deciding value is on another resource (the S3 join, graph connection checks) or the rule points at the header. |
| `configured` | The deciding top-level attribute as written, or `null` when it is not set. |
| `effective` | The same after the defaults overlay. |
| `location` | Where to point: the deciding attribute, else the resource header (the file's start for a file subject). |
| `provenance` | Origin-first explanation of the representative's deciding value: each step has `kind` (`tfvars`, `variable`, `variable_default`, `module_argument`, `local`, `output`, `attribute`, `iteration`, `default`, `absent`, `other`), `label`, `resource` (base address of the resource whose attribute the step reads, if any), `attribute` (path within it, if any) and `location`. |
| `message` | Human wording, with a certainty suffix for conditional findings. |
| `hidden` | For foreign policies: configured values the policy did not see, each with `path` and `kind` (`tainted` or `unknown`). Empty for native rules. |
| `fix_hint` | A mechanical fix when the rule knows one, else `null`. |
| `occurrences` | Every judgement that is this finding, ordered by root and address: `root`, `address`, `certainty`, and `location` only when it differs from the finding's (a resource that sets the attribute in alternative `dynamic` blocks). Occurrences that reach the declaration through different values (instances of a `for_each` over a map) may have different provenance; only the representative's is in the record. Installed occurrences also carry their own `package` metadata and call locations. |

### Values

`configured` and `effective` are value records: `kind` (`known`, `unknown`,
`tainted`, `one_of`), `value` (the JSON value when wholly known, else
`null`), `display` (a human rendering; abstract values are described).

### Locations

`file`, 1-based `line` and `column`, and byte offsets `start` and `end`
into the file. Paths are as given on the command line.

### Fix hint

`resource` (the instance to edit; for the S3 rule this is the public-access
block, not the bucket), `attribute` (the path to set: nested block names,
then the attribute, as in `metadata_options.http_tokens`), `action`
(`set`), `value` (the literal to write), `site`: the location of the
attribute as written today, or `null` meaning insert it into the resource
block, creating the blocks on its path that are not written, and, only
when the attribute is written as exactly `var.<name>` and its value comes
from that variable's default, `default_site`: the location of the
`default`, the other place the literal can go.

A hint is only built when the edit is valid configuration: each block on
the path is written at most once and not by `dynamic`, and a block that
has to be created needs no other required attribute or block in the
provider schema (an EKS `vpc_config` needs `subnet_ids`, so a missing one
gets no hint). The hint says what a mechanical edit would do; whether to
make it is the caller's judgement.

After override composition, locations and edit sites identify the effective
assignment's original file. Insertions use the originating body. JSON findings
and JSON edit targets do not receive HCL edits. If an HCL assignment references
a default in JSON, only the HCL assignment is offered as an edit site.

`oxtf fix FINGERPRINT` (and `tfscan.fix`) applies a hint and rescans to
verify it. Both the original scan and the rescan must have `complete`
status. `target_resolved` means the rule no longer fails on the
declaration from any root, whatever attribute would decide it next.
`no_new_findings` means the edit adds no finding or affected occurrence
anywhere in the request's selected rules and roots. Existing unrelated
findings may remain. `verified` requires both checks; `--write` writes only
a verified edit, and an unverified edit returns exit code 1. With a
`default_site` it writes the default first, which keeps a module's
interface, and falls back to the attribute when the default edit leaves the
target unresolved or introduces other findings. `--at default|attribute`
picks the site. Edits keep the file's
layout: a replaced value keeps the text up to its `=`, and an inserted
attribute is aligned with the attributes above it as `terraform fmt`
aligns them.

The Rust outcome, CLI JSON and Python dict include `finding_delta`:

- `before` and `after`: grouped finding counts, using the scan record's identity.
- `added`: new finding records, with evidence from the rescan.
- `removed`: disappeared finding records, with evidence from the original scan.
- `changed`: persistent findings that gained or lost occurrences. Each entry
  includes `before` and `after` finding records plus `added_occurrences` and
  `removed_occurrences`. An added occurrence is a regression even if that
  grouped finding already existed and the total finding count decreased.
- `unchanged`: the number of persistent findings with the same occurrence
  identities; their values, certainty, and source positions may differ.

Findings match by fingerprint; occurrences match by root and address, with
multiplicity preserved. Line and byte offsets are ignored when matching so
an insertion does not make later findings appear new. Delta records use the
same sensitive-value masking as scan records. Suppressed findings are excluded.

`verification_errors` explains analysis failures or coverage gaps before and
after the edit. If either scan is incomplete or failed, `target_resolved`,
`no_new_findings`, and `verified` are all false; the delta still reports what
was observed, without claiming the comparison is complete. An empty error
list alone does not mean verified: the target may remain or new findings may
appear. Verification covers only the request's selected scan; it does not run
Terraform validation or check unselected policies.

## Sensitive evidence

Terraform `sensitive = true` variables and outputs, `sensitive()`, provider
schema sensitive attributes, and plan sensitivity flags mark values.
The mark propagates through expressions, containers, transformations, and
module boundaries. Rules evaluate the real values. `nonsensitive()`
explicitly removes the value mark.

A sensitive `configured` or `effective` value adds `sensitive: true`, has
`value: null`, and displays `(sensitive)`. Provenance labels and source
snippets are masked. Container marking is conservative: a container with
a sensitive member is redacted as a whole. Custom/foreign policy messages
and error details are redacted when the policy's input scope contains
sensitive values, since arbitrary message strings have no dependency trace.
Python resource JSON/Arrow exports use `{"$sensitive": true}`.

The fix `diff` masks sensitive source context. Its `original` and `text`
fields (Rust `original` and `edit.text`) remain raw so callers can apply
edits without corrupting secrets. Explicit evaluator accessors such as
Python `Value.to_str()` and Rust `value::to_json()` also remain raw for rule
authors; these are not presentation APIs. Debug policy traces contain raw
inputs. Sensitive values must be marked: this is not a secret detector.

## NDJSON

`--format ndjson` prints one JSON object per line, each with a `type`:

- `finding`, one per finding in record order: `fingerprint`, `rule`,
  `level`, `certainty`, `file`, `line`, `column`, `address`, `attribute`,
  `message`, `occurrences` (a count) and, when there is one, `fix_hint`
  (`resource` as an address, `attribute`, `action`, `value`, `site` and,
  when there is one, `default_site` as `file`/`line`/`column`);
- `rule_error`: `rule`, `resource`, `message`;
- `diagnostic`: `severity`, `code`, `message`, `file`, `line`;
- `summary`, always last: `schema`, `findings`, `occurrences`, `definite`,
  `conditional`, `indeterminate`, `rule_errors`, `diagnostics`,
  `suppressed`, `roots`, `resources`, `elapsed_ms`, `status`, and `rules`
  (the full rule metadata table, including guidance, sent once per scan).

Provenance, values and the occurrence list are only in the full JSON record.
Rule guidance is shared in the summary rather than repeated on each finding.

## SARIF

`--format sarif` prints SARIF 2.1.0 with one run. `tool.driver.rules` is the
record's `rules` table (`shortDescription`, `helpUri` from `guideline`,
`help.text` from `remediation`, `defaultConfiguration.level`, and `category`,
`level`, `engine`, and optional `rationale` as properties). Each result has
`ruleId` and `ruleIndex`, `level` (`error` for
high and critical rules, `warning` for medium, `note` for low rules and
indeterminate findings), the message, the location with the subject as a
logical location, `partialFingerprints["oxtf/v1"]` (the fingerprint), the
provenance chain as `relatedLocations`, and `certainty`, `occurrences`,
`attribute` and `fix_hint` as properties. Rule errors are
`invocations[0].toolExecutionNotifications`, along with analysis diagnostics.
`executionSuccessful` is true only for a complete scan.

## Exit codes

`oxtf scan` exits 0 when no finding is at least as certain as `--fail-on`
(`definite` by default; `conditional`, `indeterminate`, or `never`), 1 when
some finding is, 2 when the scan could not run, and 3 when analysis is
incomplete or failed. 3 wins over 1 and is not disabled by `--fail-on never`
or `--no-diagnostics`. The output is printed in every case but 2.

## What each output keeps

| Output | Keeps |
| --- | --- |
| JSON | Everything. |
| NDJSON | Per finding: identity, rule, level, certainty, location, address, attribute, message, occurrence count, fix hint. Rule errors, diagnostics, a summary. |
| SARIF | Per finding: rule (with metadata), level, message, location, fingerprint, provenance locations, certainty, occurrence count, attribute, fix hint. |
| Python `Finding` | One judgement (occurrence), not a grouped finding: flat getters for scalars (`certainty`, `fingerprint`, ...; `resource_type` is `None` for a file subject), dicts for `subject`, `configured`, `effective`, `fix_hint`, `hidden`, and `to_dict()` for its record (a finding with one occurrence). `provenance` dicts carry `kind`, `label`, `file`, `line`, `column`, `resource`, `attribute`. `ScanResult.to_json()` is the grouped record. |
| Arrow | One row per judgement: columns `fingerprint`, `rule`, `category`, `level`, `certainty`, `address` (the file's path for a file subject), `resource_type` (null for a file subject), `module`, `message`, `root`, `attribute`, `file`, `line`, `column`, `provenance` (structs with `kind`, `label`, `file`, `line`, `column`, `resource`, `attribute`) and `record` (the judgement's record as JSON). Group by `fingerprint` for findings. |
| Text | One report per finding (its representative: rule, certainty, address, message, location, provenance chain) and the other occurrences' addresses and roots. No fingerprint, values or fix hint. |

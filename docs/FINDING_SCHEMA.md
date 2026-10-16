# Finding record (schema 1)

The finding record is the machine-readable form of a scan. Every output of
oxtf is a projection of it: `oxtf scan --format json` prints it verbatim,
the Python `Finding` getters and `to_dict()` read from it, the Arrow table
carries its columns plus the whole record as JSON, and the text renderer
shows a subset for humans. It is produced by `tf_linter::record`.

The shape is versioned by the top-level `schema` field (and repeated on each
finding). Any change that removes or renames a field, or changes a field's
meaning, bumps it. Adding an optional field does not.

## Worked example

`oxtf scan --format json fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default`:

```json
{
  "diagnostics": [],
  "findings": [
    {
      "attribute": "storage_encrypted",
      "configured": null,
      "effective": {
        "display": "false",
        "kind": "known",
        "value": false
      },
      "fingerprint": "a01a60e3c54ec070",
      "fix_hint": {
        "action": "set",
        "attribute": "storage_encrypted",
        "resource": {
          "address": "aws_db_instance.db",
          "base_address": "aws_db_instance.db",
          "key": null,
          "mode": "managed",
          "module": "",
          "name": "db",
          "type": "aws_db_instance"
        },
        "site": null,
        "value": true
      },
      "hidden": [],
      "location": {
        "column": 1,
        "end": 31,
        "file": "fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default/main.tf",
        "line": 1,
        "start": 0
      },
      "message": "storage_encrypted is not set (provider default: false)",
      "provenance": [
        {
          "attribute": "storage_encrypted",
          "kind": "default",
          "label": "aws_db_instance.db storage_encrypted not set: provider default false (defaults overlay; docs: 'The default is `false` if not specified.' (no Default: in source; AWS API default))",
          "location": {
            "column": 1,
            "end": 31,
            "file": "fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default/main.tf",
            "line": 1,
            "start": 0
          },
          "resource": "aws_db_instance.db"
        }
      ],
      "resource": {
        "address": "aws_db_instance.db",
        "base_address": "aws_db_instance.db",
        "key": null,
        "mode": "managed",
        "module": "",
        "name": "db",
        "type": "aws_db_instance"
      },
      "root": "fixtures/rules/aws-rds-unencrypted/fail_absent_uses_default",
      "rule": {
        "category": "encryption",
        "description": "RDS instance storage is not encrypted",
        "id": "aws-rds-unencrypted",
        "level": "high"
      },
      "schema": 1,
      "severity": "definite"
    }
  ],
  "rule_errors": [],
  "schema": 1,
  "stats": {
    "conditional": 0,
    "definite": 1,
    "elapsed_ms": 1.2,
    "files": 1,
    "findings": 1,
    "findings_by_rule": {
      "aws-rds-unencrypted": 1
    },
    "indeterminate": 0,
    "module_instances": 1,
    "resources": 1,
    "roots": 1
  }
}
```

## Scan

| Field | Meaning |
| --- | --- |
| `schema` | Record version. |
| `findings` | One record per finding, below. |
| `diagnostics` | Parse errors, warnings and notes: `severity` (`error`, `warning`, `info`), `code`, `message`, `location` or `null`. A `rule-skipped` warning (listed first, `location` `null`) names a file in a `--rule-file` directory that did not load; its message gives the file and each reason with its line and column. The rules in that file did not run. |
| `rule_errors` | Rules that failed to run or returned an unresolved foreign result: `rule`, `resource` (or `null`), `message`. An empty list means no execution errors were recorded for selected, applicable rules; it does not establish coverage of unsupported rules or prove that native Unknown outcomes passed. A reader must never take silence from a rule listed here as a pass. The CLI still prints the record and exits 1 when this list is non-empty (2 means the scan could not run at all). |
| `stats` | Counts: `roots`, `module_instances`, `files`, `resources`, `findings`, `definite`, `conditional`, `indeterminate`, `findings_by_rule`, `elapsed_ms`. |

## Finding

| Field | Meaning |
| --- | --- |
| `fingerprint` | Stable identity across scans: a hash of `rule.id`, `resource.address` and `attribute`. It excludes locations, message and severity on purpose, so unrelated edits keep the identity and a certainty change updates an existing issue instead of filing a new one. |
| `rule` | `id`, `category` (`network`, `storage`, `iam`, `encryption`, `other`), `level` (`low`, `medium`, `high`, `critical`: impact, independent of certainty), `description`. |
| `severity` | Certainty. `definite`: insecure as written. `conditional`: insecure for some value of an unconstrained variable. `indeterminate`: a foreign policy fired on the Known values, but an input it may depend on is provider-computed; needs a human. Native rules never produce `indeterminate`. |
| `resource` | The resource instance: `address` (full), `base_address` (no key), `module` (`""` for the root), `mode` (`managed` or `data`), `type`, `name`, `key` (a number for `count`, a string for `for_each`, or `null`). |
| `root` | Root module directory the finding was produced in. |
| `attribute` | Path of the deciding value within the resource (`storage_encrypted`, `ingress.cidr_blocks`), or `null` when the deciding value is on another resource (the S3 join) or the rule points at the header. |
| `configured` | The deciding top-level attribute as written, or `null` when it is not set. |
| `effective` | The same after the defaults overlay. |
| `location` | Where to point: the deciding attribute, else the resource header. |
| `provenance` | Origin-first explanation of the deciding value: each step has `kind`, `label`, `resource` (base address of the resource whose attribute the step reads, if any), `attribute` (path within it, if any) and `location`. |
| `message` | Human wording, with a certainty suffix for conditional findings. |
| `hidden` | For foreign policies: configured values the policy did not see, each with `path` and `kind` (`tainted` or `unknown`). Empty for native rules. |
| `fix_hint` | A mechanical fix when the rule knows one, else `null`. |

### Values

`configured` and `effective` are value records: `kind` (`known`, `unknown`,
`tainted`, `one_of`), `value` (the JSON value when wholly known, else
`null`), `display` (a human rendering; abstract values are described).

### Locations

`file`, 1-based `line` and `column`, and byte offsets `start` and `end`
into the file. Paths are as given on the command line.

### Fix hint

`resource` (the instance to edit; for the S3 rule this is the public-access
block, not the bucket), `attribute` (top-level path to set), `action`
(`set`), `value` (the literal to write), and `site`: the location of the
attribute as written today, or `null` meaning insert the attribute into the
resource block at the finding's `location`. The hint says what a mechanical
edit would do; whether to make it, and where in a provenance chain to make
it instead, is the caller's judgement.

Provenance steps are the candidate edit sites: a value that reaches the
resource through a variable default or a tfvars line can be fixed at any
step, with different blast radius.

## What each output keeps

| Output | Keeps |
| --- | --- |
| JSON | Everything. |
| Python `Finding` | Everything: flat getters for scalars, dicts for `resource`, `configured`, `effective`, `fix_hint`, `hidden`, and `to_dict()` for the whole record. `provenance` dicts carry `kind`, `label`, `file`, `line`, `column`, `resource`, `attribute`. |
| Arrow | Columns `fingerprint`, `rule`, `category`, `level`, `severity`, `address`, `resource_type`, `module`, `message`, `root`, `attribute`, `file`, `line`, `column`, `provenance` (structs with `kind`, `label`, `file`, `line`, `column`, `resource`, `attribute`) and `record` (the whole record as JSON). `configured`, `effective`, `fix_hint`, `hidden` and the structured `resource` are only in `record`. |
| Text | Rule, severity, address, message, the primary location and the provenance chain. No fingerprint, values or fix hint. |

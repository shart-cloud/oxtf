# Bundled Checkov catalog

Generated from [Checkov](https://github.com/bridgecrewio/checkov) 3.2.328
(Apache License 2.0, `LICENSE.checkov`). This is a derived work: Checkov's
Terraform resource value checks, graph policies and Python resource checks
are translated into oxtf rule IR. The Python checks are included as
translations of their source (syntax trees of `scan_resource_conf` and the
helpers it calls), interpreted natively; Checkov itself is not run.
Upstream IDs, names and categories are kept, and each rule records the
upstream file it came from.

Some Python checks call into libraries Checkov depends on, and their
programs carry translations of that code too:

- [cloudsplaining](https://github.com/salesforce/cloudsplaining) 0.7.0
  (`ResourcePolicyDocument`), BSD 3-Clause, `LICENSE.cloudsplaining`;
- [policy_sentry](https://github.com/salesforce/policy_sentry) 0.13.2
  (the `ARN` parser), MIT, `LICENSE.policy_sentry`.

- `iam.ndjson`: policy_sentry 0.13.2's IAM database (the AWS Service
  Authorization Reference, as policy_sentry ships it), reduced to what the
  cloudsplaining checks query: per service, each action's access level and
  resource types (with their dependent actions) and each resource type's
  ARN. One service per line, after a header line, so a scan parses only
  the services its policies name. MIT, `LICENSE.policy_sentry`.

The two licence files and `curation.toml` are kept by hand: the generator
writes `rules.json`, `manifest.json`, `iam.ndjson` and `LICENSE.checkov`.

- `curation.toml`: oxtf's own metadata for bundled rules, applied by
  `build.rs` over the translated rules: a level (Checkov's open-source
  checks have none, so every rule is `medium` until curated), optionally a
  category, a profile (`security`, `audit`, `hygiene`; uncurated rules are
  `unreviewed` and run with `security`) and a one-line reason. The build
  fails on an ID that is not bundled or a value it does not know. Every
  bundled rule's guideline is its Checkov source at the pinned tag.

- `rules.json`: the rules compiled into oxtf (`tf_rule_ir::bundled`).
  `build.rs` turns it into a static table at build time, so a scan reads
  no JSON at startup and compiles a rule only when it first judges a
  resource.
- `manifest.json`: every upstream Terraform check, `translated` or
  `unsupported` with the reason. A check whose `scan_resource_conf` is
  Python of its own is translated as a `checkov_python` program (its
  code, as a restricted-Python AST, interpreted natively) when the code
  stays within the interpreted subset; the reason names what does not.

Do not edit these files by hand. Regenerate them with a Checkov 3.2.328
install:

```sh
"$CHECKOV_PYTHON" -I scripts/import_checkov.py --output /tmp/pack
cargo run -p tf_rule_ir --example bundle_checkov -- /tmp/pack \
  "$("$CHECKOV_PYTHON" -c 'import checkov,os;print(os.path.dirname(checkov.__file__))')/terraform/checks/graph_checks"
```

`tests/bundled.rs` checks that they are current (run it with
`CHECKOV_PACK` and `CHECKOV_GRAPH_CHECKS` set). The differential harnesses
in `bench/checkov/` compare the same rules with Checkov itself.

Upstream oddity: `CKV_NCP_22` names both a resource check (NKS control
plane logging) and a graph policy (route table and public subnet). Checkov
runs both under the one ID, so the bundled rule has both sets of clauses
and the resource check's title.

# Bundled Checkov catalog

Generated from [Checkov](https://github.com/bridgecrewio/checkov) 3.2.328
(Apache License 2.0, `LICENSE.checkov`). This is a derived work: Checkov's
Terraform resource value checks, graph policies and Python resource checks
are translated into oxtf rule IR. The Python checks are included as
translations of their source (syntax trees of `scan_resource_conf` and the
helpers it calls), interpreted natively; Checkov itself is not run.
Upstream IDs, names and categories are kept, and each rule records the
upstream file it came from.

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

#!/usr/bin/env python3
"""Write Checkov's per-provider resource-type table for `resource_types: all`.

Checkov expands `all` (and a missing `resource_types`) from this table, keyed
by the policy's lowercased `scope.provider`. Run with the pinned Checkov:

    "$CHECKOV_PYTHON" -I scripts/gen_checkov_resource_types.py \
        crates/tf_rule_ir/data/checkov_resource_types.json
"""
import importlib.metadata
import json
import sys

from checkov.common.checks_infra.resources_types import resources_types

out = {
    "source": "checkov/common/checks_infra/resources_types.py",
    "checkov": importlib.metadata.version("checkov"),
    "license": "Apache-2.0 (Checkov); generated data, see LICENSE.checkov in the Checkov distribution",
    "providers": {k: list(v) for k, v in sorted(resources_types.items())},
}
with open(sys.argv[1], "w") as f:
    json.dump(out, f, indent=0, sort_keys=True)
    f.write("\n")

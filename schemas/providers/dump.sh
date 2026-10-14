#!/usr/bin/env bash
# Regenerate provider schema snapshots. Requires terraform >= 1.x on PATH and
# network access to registry.terraform.io.
set -euo pipefail
cd "$(dirname "$0")"
terraform init -input=false -no-color >/dev/null
terraform providers schema -json > schema.json
python3 - <<'PY'
import json
d = json.load(open("schema.json"))
for k, v in d["provider_schemas"].items():
    name = k.rsplit("/", 1)[1]
    json.dump({"format_version": d["format_version"], "provider_schemas": {k: v}},
              open(f"{name}.json", "w"), separators=(",", ":"), sort_keys=True)
PY
rm schema.json

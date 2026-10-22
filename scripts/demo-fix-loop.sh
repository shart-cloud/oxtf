#!/usr/bin/env bash
# The agent fix loop on public modules, as skills/oxtf/SKILL.md describes it:
# scan, choose a finding with a fix hint, dry-run the fix, write it only when
# verified, and rescan to confirm. Then show a fix oxtf refuses to verify.
#
# Needs the pinned corpus (bash corpus/fetch.sh) and an oxtf binary:
#   scripts/demo-fix-loop.sh [path/to/oxtf]
set -euo pipefail

oxtf=${1:-target/release/oxtf}
work=$(mktemp -d)
trap 'chmod -R u+w "$work"; rm -rf "$work"' EXIT
json() { python3 -I -c "import json, sys; d = json.load(sys.stdin); print($1)"; }
step() { printf '\n== %s\n' "$*"; }

# Copies, so --write never touches the corpus.
cp -r corpus/repos/Azure__terraform-azurerm-aks "$work/aks"
cp -r corpus/repos/terraform-aws-modules__terraform-aws-eks "$work/eks"

step "Scan"
"$oxtf" scan -r "$work/aks" -f json > "$work/scan.json" || true
json '"status:", d["status"], "| findings:", len(d["findings"]),
      "| with fix hints:", sum(1 for f in d["findings"] if f["fix_hint"])' < "$work/scan.json"

step "Choose a definite finding with a fix hint in a complete root"
read -r fingerprint rule roots < <(json '" ".join(next(
    [f["fingerprint"], f["rule"], ",".join(sorted({o["root"] for o in f["occurrences"]}))]
    for f in d["findings"]
    if f["fix_hint"] and f["certainty"] == "definite"
    and all(r["status"] == "complete" for r in d["roots"]
            if r["path"] in {o["root"] for o in f["occurrences"]})))' < "$work/scan.json")
echo "$fingerprint $rule in ${roots//,/ }"

step "Dry run: nothing is written"
IFS=, read -r -a root_list <<< "$roots"
"$oxtf" fix "$fingerprint" "${root_list[@]}" -f json > "$work/fix.json" || true
json '"verified:", d["verified"], "| site:", d["site"], "\n" + d["diff"]' < "$work/fix.json"

step "Write the verified edit and rescan"
"$oxtf" fix "$fingerprint" "${root_list[@]}" --write > /dev/null
"$oxtf" scan "${root_list[@]}" -f json > "$work/after.json" || true
json '"still reported:", any(f["fingerprint"] == "'"$fingerprint"'" for f in d["findings"])' \
  < "$work/after.json"

step "A fix oxtf will not verify: the root has modules that are not installed"
"$oxtf" scan "$work/eks/examples/karpenter" -f json > "$work/eks.json" || true
fingerprint=$(json 'next(f["fingerprint"] for f in d["findings"] if f["fix_hint"])' \
  < "$work/eks.json")
"$oxtf" fix "$fingerprint" "$work/eks/examples/karpenter" -f json > "$work/refused.json" || true
json '"verified:", d["verified"], "| written:", d["written"],
      "\n" + "\n".join(d["verification_errors"][:2])' < "$work/refused.json"

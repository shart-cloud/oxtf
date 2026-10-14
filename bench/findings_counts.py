#!/usr/bin/env python3
"""Count findings per tool in bench/results/out/*.1.json (run 1 of compare.sh).

The per-run JSON outputs are ~300 MB and gitignored; this script's output is
committed as bench/results/findings_counts.txt.
"""
import glob, json, os

def count(tool, path):
    try:
        d = json.load(open(path))
    except Exception:
        return None, set()
    if tool == "oxtf":
        return len(d["findings"]), set()
    if tool == "trivy":
        ms = [m for r in d.get("Results", []) for m in (r.get("Misconfigurations") or [])]
        return len(ms), {m["ID"] for m in ms}
    d = d if isinstance(d, list) else [d]
    return sum(x["summary"]["failed"] for x in d), set()

os.chdir(os.path.join(os.path.dirname(__file__), ".."))
for tool in ("oxtf", "trivy", "checkov"):
    total, ids, bad = 0, set(), []
    for f in sorted(glob.glob(f"bench/results/out/*.{tool}.1.json")):
        n, i = count(tool, f)
        if n is None:
            bad.append(os.path.basename(f))
        else:
            total += n; ids |= i
    extra = f", {len(ids)} distinct check IDs" if tool == "trivy" else ""
    print(f"{tool}: {total} findings{extra}; unreadable outputs: {bad or 'none'}")

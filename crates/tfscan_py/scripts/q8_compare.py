"""Q8: compare `oxtf scan --rule-file rules.json --format json` output (no
Python involved) with the same rule run from Python.

    python q8_compare.py rules.json oxtf_output.json SCAN_DIR [--recursive]
"""

import json
import sys

import tfscan

rules_path, cli_out, scan_dir = sys.argv[1:4]
recursive = "--recursive" in sys.argv
rules = tfscan.load_rules(rules_path)
py = tfscan.scan(scan_dir, recursive=recursive, builtin=False, rules=rules)
with open(cli_out) as f:
    cli = json.load(f)


def key(rule, address, root, severity, message, file, line, prov):
    return (rule, address, root, severity, message, file, line, prov)


py_set = {
    key(f.rule, f.address, f.root, f.certainty, f.message, f.file, f.line,
        tuple((p["kind"], p["label"], p["file"], p["line"]) for p in f.provenance))
    for f in py.findings
}
cli_set = {
    key(f["rule"], f["address"], f["root"], f["severity"], f["message"], f["location"]["file"],
        f["location"]["line"], tuple((p["kind"], p["label"], p["file"], p["line"]) for p in f["provenance"]))
    for f in cli["findings"]
}
print(f"python findings: {len(py.findings)}, CLI findings: {len(cli['findings'])}")
print(f"identical (rule, address, root, severity, message, primary file:line, provenance chain): {py_set == cli_set}")
if py_set != cli_set:
    print("only python:", sorted(py_set - cli_set)[:5])
    print("only cli:", sorted(cli_set - py_set)[:5])

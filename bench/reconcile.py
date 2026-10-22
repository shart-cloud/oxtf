"""Reconcile oxtf findings with Checkov's on the same repositories.

Both tools scan each repository without installed remote modules. Results are
compared per (check id, file, resource block): Checkov reports a failed check
once per declaration, and oxtf groups its occurrences under one finding per
declaration. Native oxtf rules count under their Checkov aliases.

Every difference gets a category; `review` marks what needs a person:

  matched          both tools report it
  not-bundled      Checkov check that oxtf does not ship
  coverage         oxtf could not fully evaluate the file's root
  checkov-only     shipped, evaluated, and oxtf reports nothing: review
  oxtf-only        oxtf reports it and Checkov does not: review; `checkov_passed`
                   says whether Checkov evaluated the check and passed it

Usage:
  python3 bench/reconcile.py --checkov-dir bench/results/reconcile/checkov \\
      --out bench/results/reconcile [--oxtf target/release/oxtf] REPO_DIR...
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys


def checkov_results(path, repo):
    """Failed and passed (check id, repo-relative file, resource block) sets."""
    with open(path) as f:
        reports = json.load(f)
    reports = reports if isinstance(reports, list) else [reports]
    failed, passed = set(), set()
    for report in reports:
        if report.get("check_type") != "terraform":
            continue
        for kind, keys in (("failed_checks", failed), ("passed_checks", passed)):
            for check in report["results"][kind]:
                file = os.path.relpath(check["file_abs_path"], repo)
                keys.add((check["check_id"], file, block(check["resource"])))
    return failed, passed


def block(resource):
    """`module.a.aws_x.y["k"]` -> `aws_x.y`; data sources keep their prefix."""
    parts = re.sub(r"\[[^\]]*\]", "", resource).split(".")
    while len(parts) > 2 and parts[0] == "module":
        parts = parts[2:]
    if parts[0] == "data":
        return ".".join(parts[:3])
    return ".".join(parts[-2:])


def oxtf_scan(oxtf, repo, profile):
    out = subprocess.run(
        [oxtf, "scan", "-r", "--profile", profile, "-f", "json", repo],
        capture_output=True,
        text=True,
    )
    if out.returncode not in (0, 1, 3):
        sys.exit(f"oxtf failed on {repo}: {out.stderr}")
    return json.loads(out.stdout)


def oxtf_findings(record, repo):
    """Keys like Checkov's, plus each key's certainty."""
    keys = {}
    for finding in record["findings"]:
        subject = finding["subject"]
        if subject.get("kind") != "resource":
            continue
        name = f"{subject['type']}.{subject['name']}"
        if subject.get("mode") == "data":
            name = "data." + name
        file = os.path.relpath(finding["location"]["file"], repo)
        rule = record["rules"][finding["rule"]]
        for check in [finding["rule"], *rule.get("aliases", [])]:
            keys[(check, file, name)] = finding["certainty"]
    return keys


def unevaluated_dirs(record, repo):
    """Root directories oxtf could not fully evaluate, repo-relative."""
    return {
        os.path.relpath(r["path"], repo)
        for r in record.get("roots", [])
        if r["status"] != "complete"
    }


def classify(repo, checkov, passed, record, catalog):
    oxtf = oxtf_findings(record, repo)
    partial = unevaluated_dirs(record, repo)
    rows = []
    for key in sorted(checkov | oxtf.keys()):
        check, file, _ = key
        if key in checkov and key in oxtf:
            category = "matched"
        elif key in oxtf:
            category = "oxtf-only"
        elif check not in catalog:
            category = "not-bundled"
        elif (os.path.dirname(file) or ".") in partial:
            category = "coverage"
        else:
            category = "checkov-only"
        rows.append({
            "check": check,
            "file": file,
            "resource": key[2],
            "category": category,
            "certainty": oxtf.get(key),
            "profile": catalog.get(check),
            "checkov_passed": key in passed,
        })
    return rows


def catalog_profiles(oxtf):
    out = subprocess.run([oxtf, "rules", "-f", "json"], capture_output=True, text=True, check=True)
    profiles = {}
    for rule in json.loads(out.stdout):
        for check in [rule["id"], *rule.get("aliases", [])]:
            profiles[check] = rule["profile"]
    return profiles


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("repos", nargs="+")
    parser.add_argument("--checkov-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--oxtf", default="target/release/oxtf")
    args = parser.parse_args()
    catalog = catalog_profiles(args.oxtf)
    rows = []
    for repo in args.repos:
        name = os.path.basename(os.path.normpath(repo))
        record = oxtf_scan(args.oxtf, repo, "all")
        with open(os.path.join(args.out, f"oxtf-{name}.json"), "w") as f:
            json.dump(record, f, indent=1)
        path = os.path.join(args.checkov_dir, f"{name}.json")
        checkov, passed = checkov_results(path, repo)
        for row in classify(repo, checkov, passed, record, catalog):
            rows.append({"repo": name, **row})
    with open(os.path.join(args.out, "rows.json"), "w") as f:
        json.dump(rows, f, indent=1)
    table = collections.Counter((r["repo"], r["category"]) for r in rows)
    categories = ["matched", "checkov-only", "oxtf-only", "coverage", "not-bundled"]
    print("| Repository | " + " | ".join(categories) + " |")
    print("| --- |" + " ---: |" * len(categories))
    for repo in sorted({r["repo"] for r in rows}):
        print(f"| {repo} | " + " | ".join(str(table[(repo, c)]) for c in categories) + " |")
    totals = collections.Counter(r["category"] for r in rows)
    print("| total | " + " | ".join(str(totals[c]) for c in categories) + " |")


if __name__ == "__main__":
    main()

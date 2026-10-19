#!/usr/bin/env python3
"""Differential conformance of the ``checkov_python`` rules against Checkov.

Run with the pinned Checkov interpreter. The reference is Checkov's own
runner (parser, variable rendering, the original check code) over real
Terraform: Checkov's per-check test fixtures from the 3.2.328 source tree
(``tests/terraform/checks/resource``, not in the PyPI package) and, with
``--corpus``, any other directories. oxtf scans the same directories with
the exported rules. Every (check, file, resource) Checkov reports PASSED or
FAILED is compared with oxtf: FAILED must be a definite finding, PASSED no
finding. A definite finding Checkov did not report at all is also counted.

    "$CHECKOV_PYTHON" -I bench/checkov/python_compare.py --pack PACK \\
        --fixtures checkov-3.2.328/tests/terraform/checks/resource \\
        --native target/release/oxtf --output OUT
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import re
import time

# Fixture cases where oxtf deliberately differs from Checkov: (check, the
# fixture's directory name, resource) -> why. Each is invalid Terraform that
# Checkov's lenient parser accepts, or Checkov reading unevaluated text.
DOCUMENTED = {
    **{(c, "example_S3AllowsAnyPrincipal" if r == "json" else "example_S3SecureDataTransport",
        f"aws_s3_bucket_policy.{r}"):
       "Checkov leaves a jsonencode() with an unresolved reference unrendered (mangled text) and reports "
       "nothing; oxtf evaluates the policy, which allows any principal"
       for c in ("CKV_AWS_70",) for r in ("json", "fail2", "pass_policy2")},
    **{(c, "dynamic_blocks_map_brackets", "aws_network_acl.network_acl"):
       "a list assigned to cidr_block (a string attribute): Checkov unwraps it, Terraform rejects it"
       for c in ("CKV_AWS_229", "CKV_AWS_230", "CKV_AWS_232")},
    ("CKV_K8S_27", "example_DockerSocketVolume", "kubernetes_pod_v1.fail"):
        "volume is both an attribute and a block: Checkov merges them, Terraform rejects it",
    ("CKV_TC_13", "example_CVMUserData", "tencentcloud_instance.negative1"):
        "Checkov matches the text of an unevaluated base64encode(...); oxtf evaluates it",
}
# Fixture directories oxtf does not parse, for every check.
DOCUMENTED_DIRS = {
    "example_KMSKeyWildcardPrincipal":
        "heredoc closing marker followed by spaces: not a terminator in HCL (Terraform rejects the file)",
}


def python_rules(pack):
    rules = json.loads((pack / "rules.json").read_text())
    keep = [r for r in rules if any(c["condition"]["op"] == "checkov_python" for c in r["clauses"])]
    return keep


def checkov_results(root, ids):
    from checkov.runner_filter import RunnerFilter
    from checkov.terraform.runner import Runner

    report = Runner().run(root_folder=str(root), runner_filter=RunnerFilter(checks=ids, framework=["terraform"]))
    rows = {}
    for label, records in (("PASSED", report.passed_checks), ("FAILED", report.failed_checks)):
        for r in records:
            path = (Path(root) / r.file_path.lstrip("/")).resolve()
            rows[(r.check_id, str(path), r.resource)] = label
    return rows, len(report.parsing_errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, action="append", default=[])
    parser.add_argument("--native", type=Path, default=Path("target/release/oxtf"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--only", help="comma-separated check IDs")
    args = parser.parse_args()

    rules = python_rules(args.pack)
    if args.only:
        wanted = set(args.only.split(","))
        rules = [r for r in rules if r["name"] in wanted]
    ids = sorted(r["name"] for r in rules)
    args.output.mkdir(parents=True, exist_ok=False)
    rules_file = args.output / "python-rules.json"
    rules_file.write_text(json.dumps(rules))

    reference, parse_errors = {}, 0
    start = time.perf_counter()
    for root in args.fixtures:
        rows, errors = checkov_results(root.resolve(), ids)
        reference.update(rows)
        parse_errors += errors
    checkov_seconds = time.perf_counter() - start

    findings = {}
    # Every (program entry, resource address) oxtf evaluated, with outcomes.
    evaluated = collections.defaultdict(set)
    native_seconds = 0.0
    for root in args.fixtures:
        command = [str(args.native.resolve()), "scan", str(root.resolve()), "--recursive", "--format", "json",
                   "--no-bundled", "--no-builtin", "--rule-file", str(rules_file)]
        start = time.perf_counter()
        native = subprocess.run(command, capture_output=True, text=True, timeout=600,
                                env={**os.environ, "OXTF_DEBUG_PYTHON": "2"})
        native_seconds += time.perf_counter() - start
        (args.output / "native.stderr.txt").open("a").write(native.stderr)
        for line in native.stderr.splitlines():
            m = re.match(r"checkov_python (\S+): (.+): (\S+)", line)
            if m:
                evaluated[(m.group(1), m.group(2))].add(m.group(3))
        if native.returncode not in (0, 1):
            raise RuntimeError(f"oxtf exited {native.returncode}: {native.stderr[-2000:]}")
        result = json.loads(native.stdout)
        for f in result["findings"]:
            if f["resource"] is None:
                continue
            path = str(Path(f["location"]["file"]).resolve()) if f.get("location") else None
            key = (f["rule"]["id"] if isinstance(f["rule"], dict) else f["rule"], path, f["resource"]["address"])
            # A module's resources are also found when its directory is a root:
            # keep the strongest result per key.
            if findings.get(key) != "definite":
                findings[key] = f["severity"]

    rows, disagreements = [], []
    counts = collections.Counter()
    # A resource with a conditional `count` (`count = var.create ? 1 : 0`)
    # is one instance in oxtf, with conditional existence, and `this[0]`
    # in Checkov.
    def lookup(check, path, address):
        if (check, path, address) in findings:
            return findings[(check, path, address)]
        if address.endswith("[0]"):
            return findings.get((check, path, address[:-3]), "no_finding")
        return "no_finding"

    seen_keys = set()
    for (check, path, address), label in sorted(reference.items()):
        got = lookup(check, path, address)
        seen_keys.add((check, path, address))
        seen_keys.add((check, path, address[:-3] if address.endswith("[0]") else address))
        agree = (label == "FAILED") == (got == "definite")
        kind = "agree" if agree else ("missed" if label == "FAILED" else "extra")
        if got == "conditional":
            kind += "_conditional"
        counts[kind] += 1
        row = {"check": check, "file": path, "resource": address, "checkov": label, "oxtf": got}
        rows.append(row)
        if not agree:
            disagreements.append(row)
    # Why oxtf decided each disagreement, from the interpreter's outcome log
    # (by address: a module's resource can be reached from several roots).
    entries = {r["name"]: r["clauses"][0]["condition"]["program"]["entry"] for r in rules}
    for row in disagreements:
        why = DOCUMENTED.get((row["check"], Path(row["file"]).parent.name, row["resource"])) \
            or DOCUMENTED_DIRS.get(Path(row["file"]).parent.name)
        if why:
            row["documented"] = why
            continue
        names = (row["resource"], row["resource"].removesuffix("[0]"))
        # The file's own directory as a root first (exact for a fixture),
        # else every root the scan evaluated it from (a module's resource).
        out = subprocess.run([str(args.native.resolve()), "scan", str(Path(row["file"]).parent), "-q",
                              "--no-bundled", "--no-builtin", "--rule-file", str(rules_file), "--rule", row["check"]],
                             capture_output=True, text=True, timeout=120, env={**os.environ, "OXTF_DEBUG_PYTHON": "2"})
        prefixes = [f"checkov_python {entries[row['check']]}: {a}: " for a in names]
        outcomes = {l[len(p):] for l in out.stderr.splitlines() for p in prefixes if l.startswith(p)}
        if not outcomes:
            for a in names:
                outcomes |= evaluated.get((entries[row["check"]], a), set())
        row["outcome"] = ", ".join(sorted(outcomes)) or "not evaluated"
        if row["outcome"].startswith("abstract"):
            row["kind"] = "unresolved input"
            counts["unresolved_input"] += 1
        elif not outcomes:
            # oxtf has no such instance: Terraform creates none (count = 0,
            # an empty for_each), while Checkov evaluates the block anyway.
            row["kind"] = "not created"
            counts["not_created"] += 1
    unreported = [{"check": c, "file": p, "resource": a, "checkov": "not reported", "oxtf": s}
                  for (c, p, a), s in sorted(findings.items()) if s == "definite" and (c, p, a) not in seen_keys]
    unresolved = [d for d in disagreements if d.get("kind") == "unresolved input"]
    not_created = [d for d in disagreements if d.get("kind") == "not created"]
    documented = [d for d in disagreements if "documented" in d]
    disagreements = [d for d in disagreements if d.get("kind") is None and "documented" not in d]
    # A directory another fixture calls as a module is also scanned as a root
    # by `--recursive`; Checkov reports its resources only under the caller.
    called = set()
    for root in args.fixtures:
        for tf in root.resolve().rglob("*.tf"):
            for m in re.finditer(r'source\s*=\s*"(\.{1,2}/[^"]+)"', tf.read_text(errors="replace")):
                called.add(str((tf.parent / m.group(1)).resolve()))
    unreported = [u for u in unreported if str(Path(u["file"]).parent) not in called]
    for u in unreported:
        why = DOCUMENTED.get((u["check"], Path(u["file"]).parent.name, u["resource"]))
        if why:
            u["documented"] = why
            documented.append(u)
    unreported = [u for u in unreported if "documented" not in u]
    by_check = collections.Counter(d["check"] for d in disagreements + unreported)
    report = {
        "rules": len(ids), "rules_sha256": hashlib.sha256(rules_file.read_bytes()).hexdigest(),
        "compared": len(rows), "counts": dict(counts), "checks_with_results": len({r["check"] for r in rows}),
        "disagreements": disagreements, "unreported_findings": unreported,
        # Checkov failed on a value oxtf leaves abstract (an undeclared
        # variable, a computed attribute): oxtf reports no finding by design.
        "unresolved_inputs": unresolved,
        "not_created": not_created,
        "documented_divergences": documented,
        "disagreeing_checks": dict(by_check.most_common()), "checkov_parse_errors": parse_errors,
        "checkov_seconds": checkov_seconds, "native_seconds": native_seconds, "rows": rows,
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps({k: report[k] for k in ("rules", "compared", "counts", "checks_with_results",
                                              "checkov_parse_errors", "checkov_seconds", "native_seconds")}))
    print(f"disagreements: {len(disagreements)}, unreported definite findings: {len(unreported)}, "
          f"unresolved inputs (not counted): {len(unresolved)}, not created by Terraform (not counted): "
          f"{len(not_created)}, documented divergences: {len(documented)}, "
          f"checks involved: {len(by_check)}")
    raise SystemExit(1 if disagreements or unreported else 0)


if __name__ == "__main__":
    main()

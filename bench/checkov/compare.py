#!/usr/bin/env python3
"""Differential conformance of an exported value-check pack against Checkov.

Run with the pinned Checkov interpreter. Generates real HCL configurations,
uses Checkov's HCL parser and original check implementations as the reference,
then scans the entire generated corpus once with oxtf. Artifacts are retained.
"""
import argparse
import copy
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import subprocess
import time

import hcl2
from checkov.terraform import runner  # registers upstream checks
from checkov.terraform.checks.resource.registry import resource_registry


def graph_cases(rule, manifest, corpus):
    from checkov.common.checks_infra.checks_parser import GraphCheckParser
    from networkx import DiGraph

    package = Path(inspect.getfile(runner)).parent.parent
    source = next(x["source"] for x in manifest["checks"] if x["id"] == rule["name"] and x["kind"] == "graph")
    doc = json.loads((package / source).read_text())
    check = GraphCheckParser().parse_raw_check(doc)
    attributes = {}

    def leaves(node):
        if "attribute" in node:
            values = attributes.setdefault(node["attribute"], [None, False, True, 0, 1, "", "unexpected", [], {}])
            value = node.get("value")
            values.extend(value if isinstance(value, list) else [value])
        for key in ("and", "or"):
            for child in node.get(key, []):
                leaves(child)

    leaves(doc["definition"])
    cases = [{}]
    base = {key: values[-1] for key, values in attributes.items()}
    cases.append(base)
    for key, values in attributes.items():
        for value in values:
            cases.append({**base, key: value})
    cases = list({json.dumps(x, sort_keys=True): x for x in cases}.values())
    rows = []
    for ty in check.resource_types:
        root = corpus / f"{rule['name']}-{ty}"
        root.mkdir(parents=True)
        graph = DiGraph()
        blocks = []
        for i, values in enumerate(cases):
            contents = "\n".join(f"{k} = {json.dumps(v)}" for k, v in values.items())
            blocks.append(f'resource "{ty}" "case_{i}" {{\n{contents}\n}}\n')
            graph.add_node(i, **values, resource_type=ty, block_type_="resource", source_="terraform",
                           id_=i, __address__=f"{ty}.case_{i}", file_path_=str(root / "main.tf"))
        passed, failed, unknown = check.run(graph)
        outcomes = {n["__address__"]: label for nodes, label in ((passed,"PASSED"), (failed,"FAILED"), (unknown,"UNKNOWN")) for n in nodes}
        for i, values in enumerate(cases):
            address = f"{ty}.case_{i}"
            if address not in outcomes:
                raise RuntimeError(f"graph solver omitted {rule['name']} {address}")
            rows.append({"root":str(root), "rule":rule["name"], "address":address, "case":values, "checkov":outcomes[address]})
        (root / "main.tf").write_text("\n".join(blocks))
    return rows


def body(path, value):
    key, *rest = path
    if rest and (rest[0].startswith("[") or rest[0].isdigit()):
        rest = rest[1:]
        if not rest:
            value = [value]
    if rest:
        return f"{key} {{\n{body(rest, value)}\n}}"
    return f"{key} = {json.dumps(value)}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--native", type=Path, default=Path("target/debug/oxtf"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.pack / "manifest.json").read_text())
    assert importlib.metadata.version("checkov") == manifest["source_version"]
    rules_file = args.pack / "rules.json"
    payload = rules_file.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == manifest["rules_sha256"]
    rules = json.loads(payload)
    # Graph v3 has its own graph_compare.py harness. Isolate resource clauses
    # here, including IDs shared by both kinds, so these cases test the original
    # resource predicate rather than the merged catalog rule.
    rules = [{**r, "clauses": [c for c in r["clauses"] if c["condition"]["op"] != "checkov_graph"]} for r in rules]
    rules = [r for r in rules if r["clauses"]]
    checks = {c.id: c for registry in (resource_registry.checks, resource_registry.wildcard_checks)
              for group in registry.values() for c in group}
    args.output.mkdir(parents=True, exist_ok=False)
    rules_file = args.output / "predicate-rules.json"
    rules_file.write_text(json.dumps(rules))
    corpus = args.output / "corpus"
    rows = []
    for rule in rules:
        if rule["name"].startswith("CKV2_"):
            rows.extend(graph_cases(rule, manifest, corpus))
            continue
        for clause_idx, clause in enumerate(rule["clauses"]):
            condition = clause["condition"]
            if condition["op"] != "checkov_value":
                continue
            values = [None, False, True, 0, 1, "", "unexpected", [], ["unexpected", "other"], {}]
            values.extend(condition["values"])
            # Missing is separate from explicit null.
            values = ["__missing__", *{json.dumps(x, sort_keys=True): x for x in values}.values()]
            ty = clause["resource_types"][0]
            root = corpus / f"{rule['name']}-{clause_idx}"
            root.mkdir(parents=True)
            blocks = []
            for i, value in enumerate(values):
                contents = "" if value == "__missing__" else body(condition["path"], value)
                text = f'resource "{ty}" "case_{i}" {{\n{contents}\n}}\n'
                conf = hcl2.loads(text)["resource"][0][ty][f"case_{i}"]
                check = copy.deepcopy(checks[rule["name"]])
                try:
                    outcome = check.scan_entity_conf(conf, ty).value
                except Exception as exc:
                    outcome = f"ERROR: {type(exc).__name__}: {exc}"
                rows.append({"root": str(root), "rule": rule["name"], "address": f"{ty}.case_{i}",
                             "case": value, "checkov": outcome})
                blocks.append(text)
            (root / "main.tf").write_text("\n".join(blocks))
    command = [str(args.native.resolve()), "scan", str(corpus), "--recursive", "--format", "json", "--rule-file", str(rules_file)]
    start = time.perf_counter()
    native = subprocess.run(command, capture_output=True, text=True, timeout=120)
    elapsed = time.perf_counter() - start
    (args.output / "native.stdout.json").write_text(native.stdout)
    (args.output / "native.stderr.txt").write_text(native.stderr)
    if native.returncode:
        raise RuntimeError(f"oxtf exited {native.returncode}: {native.stderr}")
    result = json.loads(native.stdout)
    if result["rule_errors"] or any(d["severity"] == "error" for d in result["diagnostics"]):
        raise RuntimeError("oxtf reported execution or parse errors")
    findings = {(f["root"], f["rule"]["id"], f["resource"]["address"]): f for f in result["findings"]}
    disagreements, reference_errors, reference_unresolved = [], [], []
    for row in rows:
        finding = findings.get((row["root"], row["rule"], row["address"]))
        row["oxtf"] = finding["severity"] if finding else "no_finding"
        if row["checkov"].startswith("ERROR"):
            reference_errors.append(row)
        elif row["checkov"] not in {"PASSED", "FAILED"}:
            reference_unresolved.append(row)
            if finding:
                disagreements.append(row)
        elif (row["checkov"] == "FAILED") != (row["oxtf"] == "definite"):
            disagreements.append(row)
    report = {"source_version": manifest["source_version"], "rules_sha256": manifest["rules_sha256"],
              "native_sha256": hashlib.sha256(args.native.read_bytes()).hexdigest(), "command": command,
              "executed_rules_sha256": hashlib.sha256(rules_file.read_bytes()).hexdigest(),
              "cases": len(rows), "value_rules": sum(any(c["condition"]["op"] == "checkov_value" for c in r["clauses"]) for r in rules),
              "elapsed_seconds": elapsed, "disagreements": disagreements, "reference_errors": reference_errors,
              "comparable_cases": len(rows) - len(reference_errors) - len(reference_unresolved),
              "reference_unresolved": reference_unresolved,
              "rows": rows, "interpretation": "Generated known-value conformance, not full Terraform semantic or security accuracy."}
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cases":len(rows), "comparable_cases":report["comparable_cases"],
                      "disagreements":len(disagreements), "reference_errors":len(reference_errors),
                      "reference_unresolved":len(reference_unresolved), "elapsed_seconds":elapsed}))
    raise SystemExit(1 if disagreements or reference_errors else 0)


if __name__ == "__main__":
    main()

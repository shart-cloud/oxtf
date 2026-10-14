#!/usr/bin/env python3
"""Compare native findings with a pinned Checkov on an explicit pilot inventory.

No third-party Python dependencies. This measures agreement, not correctness.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]


def execute(command, timeout, cwd=REPO):
    started = time.monotonic()
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                timeout=timeout, env={**os.environ, "CHECKOV_ENABLE_VERSION_CHECK": "false"})
        return {"command": command, "exit_code": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr,
                "elapsed_seconds": time.monotonic() - started, "error": None}
    except subprocess.TimeoutExpired as exc:
        text = lambda v: v.decode(errors="replace") if isinstance(v, bytes) else (v or "")
        return {"command": command, "exit_code": None, "stdout": text(exc.stdout),
                "stderr": text(exc.stderr), "elapsed_seconds": time.monotonic() - started,
                "error": "timeout"}
    except OSError as exc:
        return {"command": command, "exit_code": None, "stdout": "", "stderr": str(exc),
                "elapsed_seconds": time.monotonic() - started, "error": "launch_error"}


def payload(run, allowed_codes):
    if run["error"]:
        raise ValueError(run["error"])
    if run["exit_code"] not in allowed_codes:
        raise ValueError(f"unexpected exit code {run['exit_code']}")
    return json.loads(run["stdout"])


def native_records(run, rule):
    doc = payload(run, {0})
    if not isinstance(doc.get("findings"), list) or not isinstance(doc.get("diagnostics"), list):
        raise ValueError("missing native findings or diagnostics")
    if doc["diagnostics"]:
        raise ValueError("native diagnostics: scan is not a clean comparison")
    records = defaultdict(list)
    for finding in doc["findings"]:
        if finding["rule"] != rule:
            raise ValueError(f"unexpected native rule {finding['rule']}")
        if finding["severity"] not in {"definite", "conditional"}:
            raise ValueError("unknown native certainty")
        address = finding["address"]
        if not isinstance(address, str) or not address:
            raise ValueError("missing native address")
        records[address].append(finding)
    return dict(records)


def checkov_records(run, rule, version):
    doc = payload(run, {0, 1})  # Checkov exits 1 for findings, not just execution errors.
    # Checkov emits a bare zero summary when no check records survive (for
    # example an unresolved input). Recognize it as absent coverage, not pass.
    if isinstance(doc, dict) and "check_type" not in doc and "checkov_version" in doc:
        if (doc["checkov_version"] == version and run["exit_code"] == 0
                and all(doc.get(k) == 0 for k in ("passed", "failed", "skipped", "parsing_errors", "resource_count"))):
            return {}
        raise ValueError("invalid or incomplete Checkov summary-only report")
    reports = doc if isinstance(doc, list) else [doc]
    reports = [r for r in reports if r.get("check_type") == "terraform"]
    if len(reports) != 1:
        raise ValueError("expected exactly one Terraform report")
    report = reports[0]
    results, summary = report["results"], report["summary"]
    if summary["checkov_version"] != version:
        raise ValueError("Checkov report version differs from manifest")
    if results["parsing_errors"] or summary["parsing_errors"]:
        raise ValueError("Checkov parsing errors: scan is incomplete")
    records = defaultdict(list)
    for group, state in [("passed", "PASSED"), ("failed", "FAILED"), ("skipped", "SKIPPED")]:
        checks = results[f"{group}_checks"]  # Reject quiet/truncated reports.
        if len(checks) != summary[group]:
            raise ValueError(f"Checkov {group} count differs from records")
        for check in checks:
            if check["check_id"] != rule:
                raise ValueError(f"unexpected Checkov rule {check['check_id']}")
            status = check["check_result"]["result"]
            if status not in {state, "UNKNOWN"}:
                raise ValueError(f"unexpected Checkov result {status}")
            # Prefer the full address where supplied; never remove module paths or keys.
            address = check.get("resource_address") or check["resource"]
            if not isinstance(address, str) or not address:
                raise ValueError("missing Checkov address")
            records[address].append({"status": status.lower(), "record": check})
    if run["exit_code"] == 1 and not summary["failed"]:
        raise ValueError("Checkov exit 1 without reported failures")
    return dict(records)


def compare(case, rule, native, checkov, errors):
    rows = []
    declared = set(case["resources"])
    for address in sorted(declared | native.keys() | checkov.keys()):
        ns, cs = native.get(address, []), checkov.get(address, [])
        nstate = "error" if "native" in errors else (
            ns[0]["severity"] if len(ns) == 1 else "multiple_findings" if ns else "no_finding")
        cstate = "error" if "checkov" in errors else (
            cs[0]["status"] if len(cs) == 1 else "multiple_records" if cs else "not_observed")
        reason = None
        if errors:
            outcome, reason = "error", errors
        elif address not in declared:
            outcome, reason = "unsupported", "resource outside declared pilot inventory"
        elif len(ns) > 1 or len(cs) > 1:
            outcome, reason = "unsupported", "ambiguous duplicate records; not deduplicated"
        elif cstate == "skipped":
            outcome, reason = "skipped", "Checkov suppression; not compared as pass"
        elif cstate in {"unknown", "not_observed"}:
            outcome, reason = "unsupported", "Checkov did not report a two-valued outcome"
        elif ns and cstate == "failed":
            outcome = "both_reported"
        elif ns:
            outcome = "native_only"
        elif cstate == "failed":
            outcome = "checkov_only"
        else:
            outcome = "neither_reported"
        rows.append({"root": case["root"], "check_id": rule, "address": address,
                     "native": nstate, "checkov": cstate, "outcome": outcome,
                     "reason": reason, "native_findings": ns, "checkov_records": cs})
    return rows


def portable(value):
    if isinstance(value, str):
        return value.replace(str(REPO) + "/", "")
    if isinstance(value, list):
        return [portable(v) for v in value]
    if isinstance(value, dict):
        return {k: portable(v) for k, v in value.items()}
    return value


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=REPO / "bench/parity/rds.json")
    parser.add_argument("--native", type=Path, default=REPO / "target/debug/oxtf")
    parser.add_argument("--checkov", default="checkov")
    parser.add_argument("--output", type=Path, required=True, help="new output directory (never overwritten)")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    manifest = json.loads(args.manifest.read_text())
    if manifest["version"] != 1:
        parser.error("unsupported manifest version")
    cases = manifest["cases"]
    if not cases or len({c["root"] for c in cases}) != len(cases):
        parser.error("manifest needs unique, nonempty roots")
    for case in cases:
        root = (REPO / case["root"]).resolve()
        if not root.is_relative_to(REPO) or not root.is_dir():
            parser.error(f"invalid root {case['root']}")
        if not case["resources"] or len(set(case["resources"])) != len(case["resources"]):
            parser.error("each root needs an explicit, unique resource inventory")
    native = args.native.resolve()
    checkov = shutil.which(args.checkov)
    if not native.is_file() or not checkov:
        parser.error("build the native CLI and install Checkov before running")
    args.output.mkdir(parents=True, exist_ok=False)
    version = execute([checkov, "--version"], args.timeout)
    (args.output / "version.json").write_text(json.dumps(version, indent=2) + "\n")
    if version["error"] or version["exit_code"] != 0 or version["stdout"].strip() != manifest["checkov_version"]:
        print(f"Checkov version must be {manifest['checkov_version']}; see {args.output}/version.json", file=sys.stderr)
        return 2
    all_rows, runs, inputs = [], [], {}
    for i, case in enumerate(cases):
        root = REPO / case["root"]
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix in {".tf", ".tfvars"}:
                inputs[str(path.relative_to(REPO))] = digest(path)
        commands = {
            "native": [str(native), "scan", str(root), "--format", "json", "--rule", manifest["native_rule"]],
            "checkov": [checkov, "-d", str(root), "--framework", "terraform", "--check", manifest["checkov_rule"],
                        "--compact", "-o", "json", "--skip-download", "--download-external-modules", "false"],
        }
        parsed, errors = {}, {}
        for tool, command in commands.items():
            result = execute(command, args.timeout)
            artifact = f"{i:02d}-{tool}.json"
            (args.output / artifact).write_text(json.dumps(result, indent=2) + "\n")
            try:
                parsed[tool] = (native_records(result, manifest["native_rule"]) if tool == "native" else
                                checkov_records(result, manifest["checkov_rule"], manifest["checkov_version"]))
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                errors[tool] = str(exc)
                parsed[tool] = {}
            runs.append({"root": case["root"], "tool": tool, "artifact": artifact,
                         "command": command, "exit_code": result["exit_code"], "error": errors.get(tool)})
        all_rows.extend(compare(case, manifest["checkov_rule"], parsed["native"], parsed["checkov"], errors))
        print(f"{i+1}/{len(cases)} {case['root']}", flush=True)
    summary = dict(sorted(Counter(row["outcome"] for row in all_rows).items()))
    report = portable({"version": 1, "manifest": manifest, "input_sha256": inputs,
                       "raw_artifact_directory": str(args.output.resolve()),
                       "native_binary_sha256": digest(native), "platform": platform.platform(),
                       "python": platform.python_version(), "rows": all_rows, "summary": summary, "runs": runs,
                       "interpretation": "Finding agreement only. no_finding is not proof of a native pass; Conditional is retained, not equated with Checkov certainty."})
    (args.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 2 if any(row["outcome"] == "error" for row in all_rows) else 0


if __name__ == "__main__":
    sys.exit(main())

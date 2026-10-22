#!/usr/bin/env python3
"""Signal metrics: how much of a corpus scan an agent can act on.

Measured over every shipped rule (`--profile all`), and again for the
default profile (`default_profile`, with guidance and completion checked).

The perf budget guards speed; this guards the output. It scans the corpus
with the release CLI and measures, per finding of the record:

- how many findings and occurrences there are (grouping),
- the size of the JSON and NDJSON outputs (what an agent reads),
- the share that name the deciding attribute, carry a fix hint, or point
  only at a resource header,
- the level distribution (reported, never rewarded for changing labels),
- coverage of reviewed severity rationale and actionable remediation,
- scan completion, so partial evidence is never recorded as a passing baseline.

    python3 bench/signal.py                  # print the metrics
    python3 bench/signal.py --write          # also store bench/results/signal.json
    python3 bench/signal.py --check          # fail when a metric got worse

`--check` compares against bench/results/signal.json: a metric fails when it
moves in its bad direction (more NDJSON bytes per finding beyond 10 %,
fewer attributes, ...).
Finding and occurrence counts are reported, not judged: catalog changes move
them legitimately.
"""

import argparse
import collections
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
RESULTS = REPO / "bench" / "results" / "signal.json"

# metric -> (+1 when larger is better, -1 when smaller is better, the
# relative change tolerated in the bad direction). NDJSON is what an agent
# reads, so its size is judged; the JSON record grows with every attribute
# and provenance chain a change adds, so its size is reported, not judged.
JUDGED = {
    "ndjson_bytes_per_finding": (-1, 0.10),
    "with_attribute_pct": (+1, 0.0),
    "with_fix_hint_pct": (+1, 0.0),
    "header_only_pct": (-1, 0.0),
    "with_rationale_pct": (+1, 0.0),
    "with_remediation_pct": (+1, 0.0),
}


def scan(fmt, corpus, profile, binary, data_dir=None):
    extra = ["--data-dir", str(data_dir)] if data_dir else []
    out = subprocess.run(
        [str(binary), "scan", "-r", str(corpus),
         "--format", fmt, "--fail-on", "never", "--threads", "1",
         "--profile", profile, *extra],
        capture_output=True, cwd=REPO,
    )
    # Incomplete/failed analysis still produces a useful record. Report its
    # measurements; --check and --write must reject it below.
    if out.returncode not in (0, 1, 2, 3) or not out.stdout:
        raise RuntimeError(out.stderr.decode(errors="replace"))
    return out.stdout


def metrics(corpus, binary, profile="all", data_dir=None):
    raw = scan("json", corpus, profile, binary, data_dir)
    record = json.loads(raw)
    ndjson = scan("ndjson", corpus, profile, binary, data_dir)
    result = measure(record, len(raw), len(ndjson))
    result["ndjson_breakdown"] = ndjson_breakdown(ndjson)
    result["analysis_inventory"] = inventory(record)
    return result


def ndjson_breakdown(raw):
    """Account for every byte without hiding diagnostics or guidance costs."""
    sizes = collections.Counter()
    for line in raw.splitlines(keepends=True):
        value = json.loads(line)
        kind = value["type"]
        if kind == "summary":
            rules = json.dumps(value["rules"], ensure_ascii=False, separators=(",", ":")).encode()
            sizes["rule_metadata"] += len(rules)
            sizes["summary"] += len(line) - len(rules)
        else:
            sizes[kind] += len(line)
    return dict(sorted(sizes.items()))


def inventory(record):
    counts = collections.Counter(f["rule"] for f in record["findings"])
    backlog = []
    for rule, count in counts.most_common():
        info = record["rules"][rule]
        if not all(isinstance(info.get(k), str) and info[k].strip()
                   for k in ("rationale", "remediation", "guideline")):
            backlog.append({"rule": rule, "findings": count,
                            "description": info.get("description", ""),
                            "level": info.get("level"), "profile": info.get("profile")})
    errors = collections.Counter((e["rule"], e["message"]) for e in record["rule_errors"])
    gaps = collections.Counter(d["message"] for d in record["diagnostics"]
                               if d["code"] == "coverage-evaluation")
    return {
        "diagnostics_by_code": dict(sorted(collections.Counter(d["code"] for d in record["diagnostics"]).items())),
        "evaluation_gaps": [{"reason": reason, "count": count} for reason, count in gaps.most_common()],
        "rule_errors": [{"rule": rule, "message": message, "count": count}
                        for (rule, message), count in errors.most_common()],
        "guidance_backlog": backlog,
    }


def measure(record, json_bytes, ndjson_bytes):
    findings = record["findings"]
    n = len(findings) or 1
    pct = lambda k: round(100.0 * k / n, 1)
    attribute = sum(1 for f in findings if f["attribute"])
    fix = sum(1 for f in findings if f["fix_hint"])
    levels = collections.Counter(f["level"] for f in findings)
    rule_info = [record["rules"][f["rule"]] for f in findings]
    has_text = lambda value: isinstance(value, str) and bool(value.strip())
    reviewed = sum(has_text(r.get("rationale")) for r in rule_info)
    actionable = sum(has_text(r.get("rationale"))
                     and has_text(r.get("remediation"))
                     and has_text(r.get("guideline")) for r in rule_info)
    return {
        "schema": record["schema"],
        "roots": record["stats"].get("roots"),
        "resources": record["stats"].get("resources"),
        "status": record["status"],
        "rule_errors": len(record["rule_errors"]),
        "diagnostics": len(record["diagnostics"]),
        "findings": len(findings),
        "occurrences": record["stats"]["occurrences"],
        "rules_firing": len(record["rules"]),
        "json_bytes": json_bytes,
        "json_bytes_per_finding": round(json_bytes / n),
        "ndjson_bytes": ndjson_bytes,
        "ndjson_bytes_per_finding": round(ndjson_bytes / n),
        "with_attribute_pct": pct(attribute),
        "with_fix_hint_pct": pct(fix),
        "header_only_pct": pct(len(findings) - attribute),
        "not_medium_pct": pct(len(findings) - levels.get("medium", 0)),
        "with_rationale_pct": pct(reviewed),
        "with_remediation_pct": pct(actionable),
        "levels": dict(sorted(levels.items())),
    }


def regressions(measured, baseline):
    problems = []
    for name, current, previous in [
        ("all", measured, baseline),
        ("default", measured["default_profile"], baseline.get("default_profile", {})),
    ]:
        if current["status"] != "complete":
            problems.append(f"{name}: analysis {current['status']} "
                            f"({current['rule_errors']} rule errors, {current['diagnostics']} diagnostics)")
        # Profile membership can legitimately change other per-finding metrics.
        judged = JUDGED if name == "all" else {
            k: v for k, v in JUDGED.items() if k in ("with_rationale_pct", "with_remediation_pct")
        }
        problems.extend(
            f"{name}.{k}: {previous[k]} -> {current[k]}"
            for k, (sign, tolerance) in judged.items()
            if k in previous and (current[k] - previous[k]) * sign < -abs(previous[k]) * tolerance
        )
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", default="corpus/repos")
    ap.add_argument("--binary", default="target/release/oxtf")
    ap.add_argument("--data-dir", help="installed module data directory, relative to each root unless absolute")
    ap.add_argument("--output", type=pathlib.Path, help="save observed metrics and inventory; does not replace the baseline")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    # Per-finding quality over every shipped rule, so moving a rule between
    # profiles does not read as a regression; the default profile's numbers
    # are what an agent sees by default.
    m = metrics(REPO / args.corpus, REPO / args.binary, data_dir=args.data_dir)
    m["default_profile"] = metrics(REPO / args.corpus, REPO / args.binary, "security", args.data_dir)
    if args.output:
        if args.output.resolve() == RESULTS.resolve():
            ap.error("use --write for the baseline; --output is for observed reports")
        args.output.write_text(json.dumps(m, indent=2) + "\n")
    print(json.dumps(m, indent=2))
    if args.check:
        base = json.loads(RESULTS.read_text())
        worse = regressions(m, base)
        if worse:
            print("signal regressed:\n  " + "\n  ".join(worse), file=sys.stderr)
            sys.exit(1)
    if args.write:
        if m["status"] != "complete" or m["default_profile"]["status"] != "complete":
            print("refusing to baseline incomplete analysis", file=sys.stderr)
            sys.exit(1)
        RESULTS.write_text(json.dumps(m, indent=2) + "\n")


if __name__ == "__main__":
    main()

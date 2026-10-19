#!/usr/bin/env python3
"""Signal metrics: how much of a corpus scan an agent can act on.

The perf budget guards speed; this guards the output. It scans the corpus
with the release CLI and measures, per finding of the record:

- how many findings and occurrences there are (grouping),
- the size of the JSON and NDJSON outputs (what an agent reads),
- the share that name the deciding attribute, carry a fix hint, or point
  only at a resource header,
- the level distribution (whether the output can be ranked).

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
    "not_medium_pct": (+1, 0.0),
}


def scan(fmt, corpus):
    out = subprocess.run(
        [str(REPO / "target/release/oxtf"), "scan", "-r", str(corpus),
         "--format", fmt, "--fail-on", "never", "--threads", "1"],
        check=True, capture_output=True, cwd=REPO,
    )
    return out.stdout


def metrics(corpus):
    raw = scan("json", corpus)
    record = json.loads(raw)
    ndjson = scan("ndjson", corpus)
    findings = record["findings"]
    n = len(findings) or 1
    pct = lambda k: round(100.0 * k / n, 1)
    attribute = sum(1 for f in findings if f["attribute"])
    fix = sum(1 for f in findings if f["fix_hint"])
    levels = collections.Counter(f["level"] for f in findings)
    return {
        "schema": record["schema"],
        "findings": len(findings),
        "occurrences": record["stats"]["occurrences"],
        "rules_firing": len(record["rules"]),
        "json_bytes": len(raw),
        "json_bytes_per_finding": round(len(raw) / n),
        "ndjson_bytes": len(ndjson),
        "ndjson_bytes_per_finding": round(len(ndjson) / n),
        "with_attribute_pct": pct(attribute),
        "with_fix_hint_pct": pct(fix),
        "header_only_pct": pct(len(findings) - attribute),
        "not_medium_pct": pct(len(findings) - levels.get("medium", 0)),
        "levels": dict(sorted(levels.items())),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", default="corpus/repos")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    m = metrics(REPO / args.corpus)
    print(json.dumps(m, indent=2))
    if args.check:
        base = json.loads(RESULTS.read_text())
        worse = [
            f"{k}: {base[k]} -> {m[k]}"
            for k, (sign, tolerance) in JUDGED.items()
            if k in base and (m[k] - base[k]) * sign < -abs(base[k]) * tolerance
        ]
        if worse:
            print("signal regressed:\n  " + "\n  ".join(worse), file=sys.stderr)
            sys.exit(1)
    if args.write:
        RESULTS.write_text(json.dumps(m, indent=2) + "\n")


if __name__ == "__main__":
    main()

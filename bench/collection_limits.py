#!/usr/bin/env python3
"""Compare a preserved collection-admission scan probe with the current release executable."""
import argparse
import itertools
import json
import subprocess
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from arena_limits import OUTCOMES
from input_limits import digest, metadata


def sample(args, catalog, workers, keep_models):
    command = ["taskset", "-c", args.cpus, args.binary, args.corpus,
               catalog, str(workers), str(keep_models).lower()]
    with tempfile.TemporaryDirectory(prefix="oxtf-collection-measure-") as tmp:
        timing = Path(tmp) / "time"
        started = time.perf_counter_ns()
        run = subprocess.run(
            ["/usr/bin/time", "-f", "%e %M %U %S", "-o", str(timing), *command],
            check=True, capture_output=True, text=True)
        elapsed_monotonic = (time.perf_counter_ns() - started) / 1e9
        elapsed, peak, user, system = timing.read_text().split()
    result = json.loads(run.stdout)
    result.update(elapsed_s=float(elapsed), elapsed_monotonic_s=elapsed_monotonic,
                  cpu_user_s=float(user), cpu_system_s=float(system),
                  peak_rss_kib=int(peak), command=command)
    assert not result["input_exhausted"], result
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True)
    parser.add_argument("--binary", default="target/release/examples/scan_limits")
    parser.add_argument("--corpus", default="corpus/repos")
    parser.add_argument("--cpus", default="0-3")
    parser.add_argument("--repeats", type=int, choices=range(5, 21), default=5)
    parser.add_argument("--output", default="bench/results/tigerstyle-collections.json")
    parser.add_argument("--baseline-record", default="bench/results/tigerstyle-text.json")
    parser.add_argument("--catalog", choices=["seed", "standard"])
    parser.add_argument("--workers", type=int, choices=[1, 4])
    parser.add_argument("--keep-models", choices=["false", "true"])
    args = parser.parse_args()
    previous = json.loads(Path(args.baseline_record).read_text())["metadata"]
    assert digest(args.before) == previous["binary_sha256"], "baseline does not match recorded probe"
    result = {"metadata": metadata(args.binary), "before_metadata": previous,
              "warmups_per_case_and_binary": 1, "samples": []}
    variants = {phase: SimpleNamespace(**{**vars(args), "binary": binary})
                for phase, binary in [("before", args.before), ("after", args.binary)]}
    outcomes = (*OUTCOMES, "arena_bytes", "ast_nodes", "text_bytes")
    catalogs = [args.catalog] if args.catalog else ["seed", "standard"]
    workers_list = [args.workers] if args.workers else [1, 4]
    retention = [args.keep_models == "true"] if args.keep_models else [False, True]
    for catalog, workers, keep in itertools.product(catalogs, workers_list, retention):
        for variant in variants.values():
            sample(variant, catalog, workers, keep)
        for repeat in range(args.repeats):
            rows = []
            for phase in (["before", "after"] if repeat % 2 == 0 else ["after", "before"]):
                row = sample(variants[phase], catalog, workers, keep)
                row.update(phase=phase, repeat=repeat + 1)
                result["samples"].append(row)
                rows.append(row)
            assert all(rows[0][field] == rows[1][field] for field in outcomes), rows
        print(f"{catalog} workers={workers} keep_models={keep}: {args.repeats} pairs", flush=True)
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare a preserved pre-text scan probe with the current release executable."""
import argparse
import itertools
import json
from pathlib import Path
from types import SimpleNamespace

from arena_limits import OUTCOMES
from input_limits import digest, metadata, sample


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True)
    parser.add_argument("--binary", default="target/release/examples/scan_limits")
    parser.add_argument("--corpus", default="corpus/repos")
    parser.add_argument("--cpus", default="0-3")
    parser.add_argument("--repeats", type=int, choices=range(5, 21), default=5)
    parser.add_argument("--output", default="bench/results/tigerstyle-text.json")
    parser.add_argument("--catalog", choices=["seed", "standard"])
    parser.add_argument("--workers", type=int, choices=[1, 4])
    parser.add_argument("--keep-models", choices=["false", "true"])
    args = parser.parse_args()
    previous = json.loads(Path("bench/results/tigerstyle-arenas.json").read_text())["metadata"]
    assert digest(args.before) == previous["binary_sha256"], "baseline does not match recorded probe"
    result = {"metadata": metadata(args.binary), "before_metadata": previous,
              "warmups_per_case_and_binary": 1, "samples": []}
    variants = {phase: SimpleNamespace(**{**vars(args), "binary": binary})
                for phase, binary in [("before", args.before), ("after", args.binary)]}
    outcomes = (*OUTCOMES, "arena_bytes", "ast_nodes")
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

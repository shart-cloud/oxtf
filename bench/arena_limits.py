#!/usr/bin/env python3
"""Compare a preserved pre-arena scan probe with the current release executable."""
import argparse
import itertools
import json
from pathlib import Path
from types import SimpleNamespace

from input_limits import digest, metadata, sample


OUTCOMES = (
    "status", "roots", "files", "resources", "module_instances", "retained_models",
    "findings", "errors", "source_bytes", "file_entries", "directory_entries", "roots_admitted",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True)
    parser.add_argument("--binary", default="target/release/examples/scan_limits")
    parser.add_argument("--corpus", default="corpus/repos")
    parser.add_argument("--cpus", default="0-3")
    parser.add_argument("--repeats", type=int, choices=range(1, 21), default=5)
    parser.add_argument("--output", default="bench/results/tigerstyle-arenas.json")
    args = parser.parse_args()
    previous = json.loads(Path("bench/results/tigerstyle-inputs.json").read_text())["metadata"]
    assert digest(args.before) == previous["binary_sha256"], "baseline does not match recorded probe"
    result = {"metadata": metadata(args.binary), "before_metadata": previous,
              "warmups_per_case_and_binary": 1, "samples": []}
    variants = [SimpleNamespace(**{**vars(args), "binary": binary})
                for binary in [args.before, args.binary]]
    for catalog, workers, keep in itertools.product(["seed", "standard"], [1, 4], [False, True]):
        for variant in variants:
            sample(variant, catalog, workers, keep)
        for repeat in range(args.repeats):
            rows = []
            for phase, variant in zip(["before", "after"], variants):
                row = sample(variant, catalog, workers, keep)
                row.update(phase=phase, repeat=repeat + 1)
                result["samples"].append(row)
                rows.append(row)
            assert all(rows[0][field] == rows[1][field] for field in OUTCOMES), rows
        print(f"{catalog} workers={workers} keep_models={keep}: {args.repeats} pairs", flush=True)
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()

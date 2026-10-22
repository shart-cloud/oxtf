#!/usr/bin/env python3
"""Record the input-limit scan matrix. Run after builds/tests have finished."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def metadata(binary):
    paths = subprocess.check_output(
        ["rg", "--files", "crates", "-g", "*.rs", "-g", "Cargo.toml"], text=True
    ).splitlines() + ["Cargo.toml", "Cargo.lock"]
    tree = hashlib.sha256()
    for path in sorted(paths):
        tree.update(path.encode() + b"\0" + Path(path).read_bytes() + b"\0")
    return {
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "rust_source_and_manifest_sha256": tree.hexdigest(),
        "corpus_lock_sha256": digest("corpus/repos.lock.pinned"),
        "binary_sha256": digest(binary),
        "platform": platform.platform(),
        "cpu_model": next(line.split(":", 1)[1].strip() for line in
                          Path("/proc/cpuinfo").read_text().splitlines()
                          if line.startswith("model name")),
        "available_cpus": sorted(os.sched_getaffinity(0)),
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
    }


def sample(args, catalog, workers, keep_models):
    command = ["taskset", "-c", args.cpus, args.binary, args.corpus,
               catalog, str(workers), str(keep_models).lower()]
    with tempfile.TemporaryDirectory(prefix="oxtf-input-measure-") as tmp:
        timing = Path(tmp) / "time"
        run = subprocess.run(["/usr/bin/time", "-f", "%e %M", "-o", str(timing), *command],
                             check=True, capture_output=True, text=True)
        elapsed, peak = timing.read_text().split()
    result = json.loads(run.stdout)
    result.update(elapsed_s=float(elapsed), peak_rss_kib=int(peak), command=command)
    assert not result["input_exhausted"], result
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/examples/scan_limits")
    parser.add_argument("--corpus", default="corpus/repos")
    parser.add_argument("--cpus", default="0-3")
    parser.add_argument("--repeats", type=int, choices=range(1, 21), default=3)
    parser.add_argument("--output", default="bench/results/tigerstyle-inputs.json")
    args = parser.parse_args()
    result = {"metadata": metadata(args.binary), "warmups_per_case": 1, "samples": []}
    for catalog, workers, keep in itertools.product(["seed", "standard"], [1, 4], [False, True]):
        sample(args, catalog, workers, keep)
        for repeat in range(args.repeats):
            row = sample(args, catalog, workers, keep)
            row["repeat"] = repeat + 1
            result["samples"].append(row)
        print(f"{catalog} workers={workers} keep_models={keep}: {args.repeats} runs", flush=True)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()

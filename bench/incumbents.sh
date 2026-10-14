#!/usr/bin/env bash
# Time trivy and checkov on the corpus (Q9). 1 warm-up run each, then 3 timed runs.
# Both tools run without fetching remote modules (trivy,
# checkov --download-external-modules false), matching oxtf, which treats them as opaque.
# Usage: bench/incumbents.sh [target-dir]   (default: corpus/repos)
set -uo pipefail
cd "$(dirname "$0")/.."
T=${1:-corpus/repos}
OUT=bench/results/incumbents; mkdir -p $OUT
echo "trivy: $(trivy --version | head -1)"; echo "checkov: $(/opt/checkov-venv/bin/checkov --version)"
run() { # name, cmd...
  local name=$1; shift
  "$@" > $OUT/$name.warmup.json 2>/dev/null
  for i in 1 2 3; do
    python3 bench/timeit.py "$name run$i" $OUT/$name.$i.json -- "$@"
  done
}
run trivy trivy config --quiet --skip-check-update --misconfig-scanners terraform --format json "$T"
run checkov /opt/checkov-venv/bin/checkov -d "$T" --framework terraform --quiet --compact -o json --skip-download --download-external-modules false

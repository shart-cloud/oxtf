#!/usr/bin/env bash
# Fetch exactly the reviewed corpus commits; never reset an existing checkout.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p repos
while read -r r sha; do
  [[ -z "$r" || "$r" == \#* ]] && continue
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid pin for $r" >&2; exit 1; }
  d="repos/${r//\//__}"
  if [ ! -d "$d" ]; then
    git init -q "$d"
    git -C "$d" fetch -q --depth 1 "https://github.com/$r" "$sha"
    git -C "$d" checkout -q FETCH_HEAD
  fi
  actual=$(git -C "$d" rev-parse HEAD)
  [[ "$actual" == "$sha" ]] || { echo "$d: expected $sha, found $actual" >&2; exit 1; }
  [[ -z "$(git -C "$d" status --porcelain)" ]] || { echo "$d: checkout is modified" >&2; exit 1; }
done < repos.lock.pinned

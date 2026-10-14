#!/usr/bin/env bash
# Shallow-clone the corpus repos into corpus/repos/ and record their commits.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p repos
: > repos.lock
grep -v '^#' repos.txt | while read -r r; do
  [ -z "$r" ] && continue
  d="repos/${r//\//__}"
  if [ ! -d "$d" ]; then
    if [ -f repos.lock.pinned ] && sha=$(grep "^$r " repos.lock.pinned | cut -d' ' -f2); then
      git init -q "$d" && git -C "$d" fetch -q --depth 1 "https://github.com/$r" "$sha" && git -C "$d" checkout -q FETCH_HEAD
    else
      git clone -q --depth 1 "https://github.com/$r" "$d"
    fi
  fi
  echo "$r $(git -C "$d" rev-parse HEAD)" >> repos.lock
done

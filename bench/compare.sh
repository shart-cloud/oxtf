#!/usr/bin/env bash
# Q9: per-repo wall time of oxtf vs trivy vs checkov on the corpus.
# Each tool scans each corpus repo directory recursively. 3 timed runs per
# (repo, tool) after one untimed warm-up of each tool on a small repo; if a
# single run exceeds 300 s it is not repeated (recorded as 1 run). Each run is
# killed (SIGKILL; trivy ignores SIGTERM) after $LIMIT seconds (default 1800).
# No tool fetches remote modules: oxtf treats them as opaque, checkov runs
# with --download-external-modules false, and trivy 0.76.0 was observed not
# to download (see bench/NOTES.md).
# Output: bench/results/compare.tsv (repo, tool, run, wall_s, user_s, sys_s, maxrss_bytes, rc)
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=bench/results; mkdir -p $OUT/out
TSV=$OUT/compare.tsv
echo -e "repo\ttool\trun\twall_s\tuser_s\tsys_s\tmaxrss_bytes\trc" > $TSV
OXTF=$PWD/target/release/oxtf
CHECKOV=/opt/checkov-venv/bin/checkov
LIMIT=${LIMIT:-1800}
for bin in "$OXTF" "$(command -v trivy)" "$CHECKOV"; do
  [ -x "$bin" ] || { echo "missing tool: ${bin:-trivy} (build oxtf with cargo build --release -p tf_cli)" >&2; exit 1; }
done
rm -f $OUT/out/*.json
cmd_for() { # tool repo
  case $1 in
    oxtf) echo "$OXTF scan --recursive --format json $2" ;;
    trivy) echo "trivy config --quiet --skip-check-update --misconfig-scanners terraform --format json $2" ;;
    checkov) echo "$CHECKOV -d $2 --framework terraform --quiet --compact -o json --skip-download --download-external-modules false" ;;
  esac
}
# warm-up (page cache, trivy check cache, python imports)
for t in oxtf trivy checkov; do $(cmd_for $t corpus/repos/terraform-aws-modules__terraform-aws-security-group) >/dev/null 2>&1; done
for repo in corpus/repos/*/; do
  r=$(basename $repo)
  for t in oxtf trivy checkov; do
    for i in 1 2 3; do
      line=$(python3 bench/timeit.py "$r $t $i" $OUT/out/$r.$t.$i.json -- timeout -s KILL $LIMIT $(cmd_for $t $repo))
      echo "$line"
      [[ $line =~ wall=[0-9.]+s\ user=[0-9.]+s\ sys=[0-9.]+s\ maxrss=[0-9]+B\ rc=-?[0-9]+$ ]] || { echo "unparseable timing line: $line" >&2; exit 1; }
      wall=$(sed -E 's/.*wall=([0-9.]+)s.*/\1/' <<<"$line"); user=$(sed -E 's/.*user=([0-9.]+)s.*/\1/' <<<"$line")
      sys=$(sed -E 's/.*sys=([0-9.]+)s.*/\1/' <<<"$line"); rss=$(sed -E 's/.*maxrss=([0-9]+)B.*/\1/' <<<"$line"); rc=$(sed -E 's/.*rc=(-?[0-9]+).*/\1/' <<<"$line")
      echo -e "$r\t$t\t$i\t$wall\t$user\t$sys\t$rss\t$rc" >> $TSV
      awk -v w=$wall 'BEGIN{exit !(w>300)}' && break
    done
  done
done

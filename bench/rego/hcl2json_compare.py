#!/usr/bin/env python3
"""oxtf's hcl2json rendering (`tf_rego::hcl2json::raw`) against
`conftest parse` on every .tf file under a directory.

    python3 bench/rego/hcl2json_compare.py --conftest PATH [--corpus DIR] --output OUT.json
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--conftest', required=True)
    p.add_argument('--native', type=Path, default=ROOT / 'target/release/examples/hcl2json')
    p.add_argument('--corpus', type=Path, default=ROOT / 'corpus/repos')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    files = sorted(str(f) for f in args.corpus.rglob('*.tf') if f.is_file())
    ours = {}
    for i in range(0, len(files), 200):
        out = subprocess.run([str(args.native), *files[i:i + 200]], capture_output=True, text=True, check=True)
        for line in out.stdout.splitlines():
            r = json.loads(line)
            ours[r['file']] = r

    def theirs(f):
        r = subprocess.run([args.conftest, 'parse', '--parser', 'hcl2', f], capture_output=True, text=True)
        if r.returncode:
            return f, {'error': r.stderr.strip()[:300]}
        return f, {'doc': json.loads(r.stdout)}

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        ref = dict(pool.map(theirs, files))
    rows = {'agree': 0, 'differ': 0, 'both_error': 0, 'oxtf_error': 0, 'conftest_error': 0}
    differences = []
    for f in files:
        a, b = ours[f], ref[f]
        if 'error' in a or 'error' in b:
            kind = 'both_error' if 'error' in a and 'error' in b else ('oxtf_error' if 'error' in a else 'conftest_error')
        else:
            kind = 'agree' if a['doc'] == b['doc'] else 'differ'
        rows[kind] += 1
        if kind not in ('agree', 'both_error'):
            differences.append({'file': f, 'kind': kind, 'oxtf': a, 'conftest': b})
    summary = {'files': len(files), **rows}
    args.output.write_text(json.dumps({'summary': summary, 'differences': differences}, indent=1))
    print(json.dumps(summary))


if __name__ == '__main__':
    main()

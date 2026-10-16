#!/usr/bin/env python3
"""oxtf's Conftest mode against `conftest test` on the corpus.

Conftest evaluates each .tf file on its own, with expressions as `${...}`
strings; oxtf evaluates the same file per module instance, with oxtf's
values (the semantic contract in FIRST_CLASS_RULES_PLAN.md). This harness
runs both and compares, per (rule, file), the set of violation messages:
Conftest's failures and warnings, and the whole-file evaluations oxtf
records under OXTF_POLICY_TRACE (the union over a file's module instances).

A difference is classified by whether the file holds any value oxtf could
not see (`hidden`) or any value Conftest saw only as a `${...}` expression
(`expressions`): those are where the two contracts are expected to part.

    python3 bench/rego/conftest_compare.py --conftest PATH --policy DIR --output OUT
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def has_expression(v):
    if isinstance(v, str):
        return '${' in v
    if isinstance(v, list):
        return any(has_expression(x) for x in v)
    if isinstance(v, dict):
        return any(has_expression(x) for x in v.values())
    return False


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--conftest', required=True)
    p.add_argument('--native', type=Path, default=ROOT / 'target/release/oxtf')
    p.add_argument('--corpus', type=Path, default=ROOT / 'corpus/repos')
    p.add_argument('--policy', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    version = subprocess.run([args.conftest, '--version'], capture_output=True, text=True).stdout.split()

    trace = args.output / 'trace.jsonl'
    scan = subprocess.run(
        [str(args.native), 'scan', str(args.corpus), '-r', '--format', 'json', '--no-diagnostics',
         '--policy', str(args.policy), '--all-namespaces'],
        capture_output=True, text=True, env={**os.environ, 'OXTF_POLICY_TRACE': str(trace)})
    if scan.returncode not in (0, 1):
        raise SystemExit(f'oxtf failed: {scan.stderr[:2000]}')
    record = json.loads(scan.stdout)
    ours, errors, hidden = {}, {}, {}
    for line in trace.read_text().splitlines():
        t = json.loads(line)
        if not t.get('whole_file'):
            continue
        f = os.path.normpath(t['file'])
        key = (t['entry'], f)
        if 'error' in t:
            errors.setdefault(key, t['error'])
            continue
        msgs = set()
        for item in t['result'] or []:
            if isinstance(item, str) and item:
                msgs.add(item)
            elif isinstance(item, dict) and isinstance(item.get('msg'), str) and item['msg']:
                msgs.add(item['msg'])
        ours.setdefault(key, set()).update(msgs)
    files = sorted({f for _, f in ours} | {f for _, f in errors})
    theirs = {}
    for i in range(0, len(files), 100):
        batch = files[i:i + 100]
        r = subprocess.run([args.conftest, 'test', '--all-namespaces', '--no-fail', '-o', 'json',
                            '--policy', str(args.policy), *batch], capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(f'conftest failed: {r.stderr[:2000]}')
        for res in json.loads(r.stdout):
            f = os.path.normpath(res['filename'])
            for kind in ('failures', 'warnings'):
                for x in res.get(kind) or []:
                    q = x.get('metadata', {}).get('query')
                    theirs.setdefault((q, f), set()).add(x['msg'])

    def parse(f):
        r = subprocess.run([args.conftest, 'parse', '--parser', 'hcl2', f], capture_output=True, text=True)
        return f, json.loads(r.stdout)

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        docs = dict(pool.map(parse, files))

    entries = sorted({e for e, _ in ours} | {e for e, _ in errors})
    counts = {'agree': 0, 'agree_with_violations': 0, 'differ_expressions': 0, 'differ_literal': 0, 'oxtf_error': 0}
    differences = []
    for e in entries:
        for f in files:
            key = (e, f)
            if key in errors:
                counts['oxtf_error'] += 1
                differences.append({'entry': e, 'file': f, 'kind': 'oxtf_error', 'error': errors[key][:300]})
                continue
            a, b = ours.get(key, set()), theirs.get(key, set())
            if a == b:
                counts['agree'] += 1
                counts['agree_with_violations'] += bool(a)
                continue
            kind = 'differ_expressions' if has_expression(docs[f]) else 'differ_literal'
            counts[kind] += 1
            differences.append({'entry': e, 'file': f, 'kind': kind,
                                'oxtf_only': sorted(a - b), 'conftest_only': sorted(b - a)})
    findings = [f for f in record['findings'] if f['rule']['id'].startswith('rego:')]
    summary = {
        'conftest': ' '.join(version), 'policy': str(args.policy), 'files': len(files),
        'rules': len(entries), 'comparisons': len(entries) * len(files), **counts,
        'findings': len(findings),
        'findings_on_resources': sum(f['subject']['kind'] == 'resource' for f in findings),
        'findings_on_files': sum(f['subject']['kind'] == 'file' for f in findings),
        'rule_errors': len(record['rule_errors']),
    }
    (args.output / 'report.json').write_text(json.dumps({'summary': summary, 'differences': differences}, indent=1))
    print(json.dumps(summary))


if __name__ == '__main__':
    main()

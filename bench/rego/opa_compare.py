#!/usr/bin/env python3
"""Conformance of oxtf's foreign Rego policies against `opa eval`.

For each policy set, oxtf scans the corpus with the set loaded and
`OXTF_POLICY_TRACE` recording every evaluation: the entry rule, the input
document oxtf projected, and regorus's result (or error). The same inputs
are then evaluated by `opa eval --strict-builtin-errors` with the same
policy files, and the two results are compared per (entry, input).

This checks the engine and the loader (bundle, data, entries), not the
projection: both engines see oxtf's input. Results are compared as sets of
canonical JSON values.

    python3 bench/rego/opa_compare.py --output OUT [--ext DIR]

`--ext` holds clones of the community policy repositories (see SETS).
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]

SEED = {'aws-iam-wildcard-policy', 'aws-rds-unencrypted', 'aws-s3-public-access-block', 'aws-sg-open-ssh',
        'gcp-storage-uniform-access'}
PORTS = ['rds', 'gcp_storage', 'sg_open_ssh', 'iam_wildcard', 's3_public_access_block']


def avm_entries(ext):
    names = set()
    for f in sorted((ext / 'policy-library-avm/policy/avmsec').glob('*.rego')):
        names.update(re.findall(r'^((?:deny|warn)_[A-Za-z0-9_]+)', f.read_text(), re.M))
    return [f'data.avmsec.{n}' for n in sorted(names)]


def sets(ext):
    out = [{
        'name': 'seed-ports',
        'sources': [ROOT / 'fixtures/rego/ports'],
        'entries': [f'data.ports.{p}.deny' for p in PORTS],
        'shape': 'plan',
    }, {
        'name': 'conftest-hcl2',
        'sources': [ROOT / 'fixtures/rego/foreign/conftest_hcl2_deny.rego'],
        'entries': ['data.main.deny'],
        'shape': 'hcl',
    }, {
        'name': 'rego-v0',
        'sources': [ROOT / 'fixtures/rego/foreign_v0'],
        'entries': ['data.main.deny'],
        'shape': 'plan',
        'v0': True,
    }]
    if ext:
        out.append({
            'name': 'azure-avm-sec',
            'sources': [ext / 'policy-library-avm/policy/avmsec', ext / 'policy-library-avm/policy/common'],
            'entries': avm_entries(ext),
            'shape': 'plan',
            'commit': git_head(ext / 'policy-library-avm'),
        })
    return out


def git_head(repo):
    return subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()


def stage(policy_set, into):
    """Copy the set's .rego files (only) into one directory per source."""
    paths = []
    for i, src in enumerate(policy_set['sources']):
        dst = into / f'{i}'
        if src.is_file():
            dst.mkdir(parents=True)
            shutil.copy(src, dst / src.name)
        else:
            for f in sorted(src.rglob('*.rego')):
                target = dst / f.relative_to(src)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(f, target)
        paths.append(dst)
    for name, old, new in policy_set.get('workarounds', []):
        hits = [f for p in paths for f in p.rglob(name)]
        for f in hits:
            text = f.read_text()
            if old not in text:
                raise SystemExit(f'{policy_set["name"]}: workaround does not apply to {f}')
            f.write_text(text.replace(old, new))
        if not hits:
            raise SystemExit(f'{policy_set["name"]}: no {name} for a workaround')
    return paths


def canon(value):
    """A result as a sorted list of canonical JSON strings (sets and
    arrays alike), or None when undefined."""
    if value is None:
        return None
    items = value if isinstance(value, list) else [value]
    return sorted(json.dumps(v, sort_keys=True, separators=(',', ':')) for v in items)


HARNESS = '''package oxtf_harness
import rego.v1
out[i] := v if {{
	some i
	inp := data.oxtf_harness_inputs[i]
	v := {entry} with input as inp
}}
'''


def opa_flags(v0):
    return ['--strict-builtin-errors'] + (['--v0-compatible'] if v0 else [])


def opa_batch(opa, policy_paths, entry, inputs, work, v0):
    work.mkdir(parents=True, exist_ok=True)
    (work / 'inputs.json').write_text(json.dumps({'oxtf_harness_inputs': inputs}))
    (work / 'harness.rego').write_text(HARNESS.format(entry=entry))
    argv = [opa, 'eval', *opa_flags(v0), '--format', 'json']
    for p in policy_paths:
        argv += ['-d', str(p)]
    argv += ['-d', str(work / 'inputs.json'), '-d', str(work / 'harness.rego'), 'data.oxtf_harness.out']
    p = subprocess.run(argv, capture_output=True, text=True)
    doc = json.loads(p.stdout or '{}')
    if 'errors' in doc or p.returncode:
        return None
    out = doc['result'][0]['expressions'][0]['value'] if doc.get('result') else {}
    return [out.get(str(i)) for i in range(len(inputs))]


def opa_one(opa, policy_paths, entry, inp, work, v0):
    """One input on its own, for batches where some input errors."""
    with tempfile.NamedTemporaryFile('w', suffix='.json', dir=work, delete=False) as f:
        json.dump(inp, f)
    argv = [opa, 'eval', *opa_flags(v0), '--format', 'json', '-i', f.name]
    for p in policy_paths:
        argv += ['-d', str(p)]
    argv.append(entry)
    p = subprocess.run(argv, capture_output=True, text=True)
    os.unlink(f.name)
    doc = json.loads(p.stdout or '{}')
    if 'errors' in doc:
        return {'error': doc['errors'][0].get('message', '')}
    exprs = doc.get('result', [{}])[0].get('expressions') if doc.get('result') else None
    return {'result': exprs[0]['value'] if exprs else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--native', type=Path, default=ROOT / 'target/release/oxtf')
    parser.add_argument('--opa', default='opa')
    parser.add_argument('--corpus', type=Path, default=ROOT / 'corpus/repos')
    parser.add_argument('--ext', type=Path, help='directory with community policy clones')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--only', help='regex over set names')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    opa_version = subprocess.run([args.opa, 'version'], capture_output=True, text=True).stdout.splitlines()[0]
    report = {'opa': opa_version, 'native_sha256': hashlib.sha256(args.native.read_bytes()).hexdigest(), 'sets': []}
    for s in sets(args.ext):
        if args.only and not re.search(args.only, s['name']):
            continue
        out = args.output / s['name']
        paths = stage(s, out / 'policy')
        trace = out / 'trace.jsonl'
        argv = [str(args.native), 'scan', str(args.corpus), '-r', '--format', 'json', '--no-diagnostics',
                '--policy-shape', s['shape']]
        for p in paths:
            argv += ['--policy', str(p)]
        for e in s['entries']:
            argv += ['--policy-entry', e]
        v0 = s.get('v0', False)
        if v0:
            argv.append('--rego-v0')
        scan = subprocess.run(argv, capture_output=True, text=True, env={**os.environ, 'OXTF_POLICY_TRACE': str(trace)})
        if scan.returncode not in (0, 1, 3):
            raise SystemExit(f'{s["name"]}: oxtf failed: {scan.stderr[:2000]}')
        record = json.loads(scan.stdout)
        if record.get('status') == 'failed' or record['rule_errors']:
            raise SystemExit(f'{s["name"]}: analysis failed: {record["rule_errors"]}')
        evals = {}
        for line in trace.read_text().splitlines() if trace.exists() else []:
            t = json.loads(line)
            key = (t['entry'], json.dumps(t['input'], sort_keys=True))
            evals[key] = t
        by_entry = {}
        for (entry, _), t in evals.items():
            by_entry.setdefault(entry, []).append(t)
        rows, differences = [], []

        def compare(entry):
            ts = by_entry[entry]
            inputs = [t['input'] for t in ts]
            work = out / 'opa' / hashlib.sha1(entry.encode()).hexdigest()[:12]
            batch = opa_batch(args.opa, paths, entry, inputs, work, v0)
            results = []
            for i, t in enumerate(ts):
                ref = {'result': batch[i]} if batch is not None else opa_one(args.opa, paths, entry, t['input'], work, v0)
                results.append((t, ref))
            return entry, results

        with ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
            compared = list(pool.map(compare, sorted(by_entry)))
        for entry, results in compared:
            for t, ref in results:
                ours = {'error': t['error']} if 'error' in t else {'result': canon(t.get('result'))}
                theirs = {'error': ref['error']} if 'error' in ref else {'result': canon(ref.get('result'))}
                if 'error' in ours or 'error' in theirs:
                    kind = 'both_error' if 'error' in ours and 'error' in theirs else (
                        'oxtf_error' if 'error' in ours else 'opa_error')
                    agree = kind == 'both_error'
                else:
                    # Undefined and an empty set are the same verdict: no violations.
                    agree = (ours['result'] or []) == (theirs['result'] or [])
                    kind = 'agree' if agree else 'differ'
                row = {'entry': entry, 'kind': kind,
                       'violations': len(ours.get('result') or [])}
                rows.append(row)
                if not agree:
                    differences.append({**row, 'oxtf': ours, 'opa': theirs, 'input': t['input']})
        kinds = {}
        for r in rows:
            kinds[r['kind']] = kinds.get(r['kind'], 0) + 1
        summary = {
            'set': s['name'], 'v0': s.get('v0', False), 'commit': s.get('commit'), 'workarounds': len(s.get('workarounds', [])),
            'entries': len(s['entries']),
            'entries_evaluated': len(by_entry), 'evaluations': len(rows),
            'with_violations': sum(r['violations'] > 0 for r in rows),
            'findings': sum(1 for f in record['findings'] if f['rule'] not in SEED),
            'rule_errors': len(record['rule_errors']), **kinds,
            'status': record['status'], 'diagnostics': record['diagnostics'],
        }
        (out / 'differences.json').write_text(json.dumps(differences, indent=1))
        report['sets'].append(summary)
        print(json.dumps(summary))
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    # A conformance job must compare real inputs and fail on differences;
    # producing a report alone must never turn a regression green.
    if not report['sets'] or any(
        s['evaluations'] == 0 or s['entries_evaluated'] != s['entries']
        or s.get('both_error', 0)
        or any(s.get(k, 0) for k in ('differ', 'oxtf_error', 'opa_error'))
        for s in report['sets']
    ):
        raise SystemExit(1)


if __name__ == '__main__':
    main()

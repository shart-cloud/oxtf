#!/usr/bin/env python3
"""Differential tests for Checkov graph policies using Checkov 3.2.328.

Every built-in graph policy and every synthetic policy
(`synthetic_policies.py`) is written to a policy file and loaded by oxtf's
native front-end (`--rule-file DIR`). Checkov's own policy parser (with the
registry's provider table), HCL vertex projection and graph solvers are the
reference. Generated HCL and explicit dependency edges exercise each tree.
This is solver conformance, not an assertion of full-runner equivalence.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys

import hcl2
import yaml
from networkx import DiGraph
from checkov.terraform import runner
from checkov.terraform.graph_builder.graph_components.blocks import TerraformBlock
from checkov.common.checks_infra.checks_parser import GraphCheckParser
from checkov.common.checks_infra.registry import Registry

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import synthetic_policies  # noqa: E402
from frontend_fixtures import compile_jsonpath  # noqa: E402


def leaves(node):
    if isinstance(node, dict) and 'cond_type' in node:
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            for child in value if isinstance(value, list) else [value]:
                yield from leaves(child)


def types(value):
    return [value] if isinstance(value, str) else (value or [])


def put(tree, path, value):
    head, *tail = path
    if head == '*':
        if not isinstance(tree, list):
            tree = [{}, {}]
        return [put(child, tail, value) if tail else copy.deepcopy(value) for child in tree]
    if not isinstance(tree, dict):
        tree = {}
    tree[head] = put(tree.get(head), tail, value) if tail else copy.deepcopy(value)
    return tree


# No escape sequences: python-hcl2 keeps them literally, where Terraform
# (and oxtf) decode them. No negative numbers inside objects either: python-hcl2
# renders them as `${-1}` expressions.
STRINGS = ['prod-web', 'stage-api', 'prod', 'x-prod', 'PROD-WEB', 'ROOT', 'root', 'a b', 'db2-ae-1', '12', '1.5',
           'private', 'PRIVATE', 'log-delivery-write', 'ingress', 'INGRESS', 'true', 'null']
POOLS = {
    'intersects': ['prod', 'a', ['a'], ['x', 'prod'], {'prod': 1}, {'x': 1}, 'xyz', ['1'], [1], [True], 'b'],
    'subset': [['a'], ['a', 'c'], ['a', 'b'], [1], [], {'a': 1}, 'a', [True], [1.0]],
    'length': ['', 'one', 'two words', 'three word str', 'a  b c', ['x'], ['x', 'y'], ['x', 'y', 'z'], {}, {'k': 'v'}, 5],
    'cidr': ['10.0.0.0/8', '10.1.0.0/16', '0.0.0.0/0', '192.168.1.1', '::/0', '2001:db8::/48',
             ['10.0.0.0/16', '172.16.0.0/12'], ['10.1.0.0/16'], [], '', 'not-an-ip', 1, True, {'a': 1},
             '10.0.0.0/255.0.0.0', ['2001:db8::1', '10.2.0.0/16']],
    'range': ['80', '*', '22-80', '1000-2000', '-5', 80, 443, 'abc', ['22', '443'], [80, '1-1024'], '8050', 8001.5,
              True, {'a': 1}, '22-', ['*'], 22, '0022'],
    'number': [4, 5, 6, '5', '10', 'x', 4.5],
}


def pool(op):
    op = op.removeprefix('jsonpath_')
    if 'intersects' in op:
        return POOLS['intersects']
    if 'subset' in op and 'cidr' not in op:
        return POOLS['subset']
    if op.startswith(('length', 'number_of_words')):
        return POOLS['length']
    if 'cidr' in op:
        return POOLS['cidr']
    if 'range' in op:
        return POOLS['range']
    if op in ('greater_than', 'greater_than_or_equal', 'less_than', 'less_than_or_equal'):
        return POOLS['number'] + STRINGS[:4]
    return STRINGS


def predicate_value(predicate, match, rng, rich):
    """A value for which the filter predicate is `match`."""
    op, value = predicate['operator'], predicate['value']
    if op == 'regex':
        candidates = STRINGS + [re.sub(r'\(\?i\)|[\^$()?*+\[\]\\]', '', value)]
        hits = [c for c in candidates if bool(re.search(value, c)) == match]
        return rng.choice(hits) if hits else ('' if not match else value)
    if isinstance(value, str):
        return value if match == (op == 'equals') else value + '_other'
    yes = {'equals': value, 'not_equals': value + 1, 'less_than': value - 1, 'less_than_or_equal': value,
           'greater_than': value + 1, 'greater_than_or_equal': value}[op]
    no = {'equals': value + 1, 'not_equals': value, 'less_than': value, 'less_than_or_equal': value + 1,
          'greater_than': value, 'greater_than_or_equal': value - 1}[op]
    chosen = yes if match else no
    # Exercise int() conversion of strings, and (single-condition policies
    # only, where Checkov skips the vertex) a TypeError from int(None).
    choices = [chosen, chosen, str(chosen), 'x' if not match else chosen]
    if rich and not match:
        choices.append(None)
    return rng.choice(choices)


def put_query(tree, path, value, variant, rng, rich):
    """Seed both selected and excluded candidates for the admitted query AST."""
    if not path:
        return copy.deepcopy(value)
    head, *tail = path
    if isinstance(head, str):
        tree = tree if isinstance(tree, dict) else {}
        tree[head] = put_query(tree.get(head), tail, value, variant, rng, rich)
        return tree
    items = []
    for index in range(2):
        child = put_query(None, tail, value, variant, rng, rich)
        if head['kind'] == 'filter':
            child = child if isinstance(child, dict) else {}
            for predicate in head['predicates']:
                match = variant % 4 != 3 and (variant < 5 or index == variant % 2)
                child = put(child, predicate['path'], predicate_value(predicate, match, rng, rich))
        items.append(child)
    if variant % 7 == 4:
        return []
    return items[0] if variant % 3 == 1 else items


ALL_TYPES = ['aws_s3_bucket', 'google_storage_bucket', 'test_resource', 'data.aws_iam_policy_document']


def node_types(doc):
    found, everything = set(), False
    for leaf in leaves(doc['definition']):
        for key in ('resource_types', 'connected_resource_types'):
            raw = leaf.get(key)
            values = types(raw)
            if key == 'resource_types' and leaf.get('cond_type') != 'filter' and (
                    not raw or (values and str(values[0]).lower() == 'all')):
                everything = True
            if raw in ('all', ['All']):
                everything = True
            found.update(t for t in values if isinstance(t, str) and t.lower() != 'all')
    out = sorted(found)
    if everything:
        out = sorted(set(out) | set(ALL_TYPES))
    return out or ['test_resource']


def seed(leaf, all_leaves, variant, rng, rich, offset=0):
    """The configured value for one leaf in one variant.

    Built-in policies keep the original value choices, which never make a
    Checkov solver raise inside a boolean tree (where the exception would
    abort the whole reference run). Single-condition synthetic policies also
    draw from operator-specific pools.
    """
    op = leaf['operator']
    expected = leaf.get('value', 'present')
    if op in ('within', 'not_within') and isinstance(expected, list):
        expected = expected[0] if expected else None
    elif op in ('contains', 'not_contains', 'jsonpath_contains', 'jsonpath_not_contains'):
        expected = [expected]
    # A containment check anywhere on this attribute (or below it) raises on
    # bools and numbers, and the exception aborts the whole reference run.
    containment = 'contains' in op or any(
        'contains' in l.get('operator', '') and (l['attribute'] == leaf['attribute']
                                                  or l['attribute'].startswith(leaf['attribute'] + '.'))
        for l in all_leaves)
    choices = [expected, None, '', 'unexpected', []] if containment else [expected, None, False, True, '', 'unexpected', [], 0, 1]
    if rich:
        nested = '.' in leaf['attribute'] or '[' in leaf['attribute']
        # python-hcl2 unwraps single-element lists inside lists of objects.
        choices = choices + [v for v in pool(op) if not (nested and isinstance(v, list) and len(v) == 1)]
    if leaf['cond_type'] == 'filter' and isinstance(leaf['value'], str):
        # Truthy nonstrings raise in Python's `value in string`.
        choices = [expected, None, '', 'unexpected', expected[:1]]
    if variant < 3:
        return expected
    if rich and variant - 3 < len(choices):
        # Every choice appears at least once; offsets vary the combinations.
        return choices[(variant - 3 + offset) % len(choices)]
    return rng.choice(choices)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, default=ROOT / 'target/release/oxtf')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variants', type=int, default=20)
    parser.add_argument('--only', help='regex over policy ids (source or synthetic)')
    args = parser.parse_args()
    terraform = Path(runner.__file__).parent
    args.output.mkdir(parents=True, exist_ok=False)
    corpus, policies = args.output / 'corpus', args.output / 'policies'
    policies.mkdir()
    sources = [(p.name, json.loads(p.read_text())) for p in sorted((terraform / 'checks/graph_checks').rglob('*.json'))]
    sources += [(doc['metadata']['id'], doc) for doc in synthetic_policies.policies()]
    if args.only:
        sources = [(n, d) for n, d in sources if re.search(args.only, d['metadata']['id'])]
    rows, errors, inventory = [], [], []
    rng = random.Random(4361)
    for source, original in sources:
        original_id = original['metadata']['id']
        name = f'GRAPH_{len(inventory)}'
        doc = copy.deepcopy(original)
        doc['metadata']['id'] = name
        synthetic = source == original_id
        policy_file = policies / (f'{name}.yaml' if synthetic else f'{name}.json')
        policy_file.write_text(yaml.safe_dump(doc) if synthetic else json.dumps(doc))
        inventory.append({'rule': name, 'id': original_id, 'source': source,
                          'sha256': hashlib.sha256(policy_file.read_bytes()).hexdigest()})
        root = corpus / name
        root.mkdir(parents=True)
        all_leaves = list(leaves(doc['definition']))
        resource_types = node_types(doc)
        graph, blocks = DiGraph(), []
        variants = max(args.variants, 3 + 2 * max(len(pool(l['operator'])) + 9 for l in all_leaves)) \
            if synthetic and all_leaves else args.variants
        for variant in range(variants):
            nodes = [(ty, f'case_{variant}_{i}_{j}') for i, ty in enumerate(resource_types) for j in range(2)]
            configs = []
            for ty, _ in nodes:
                attrs = {}
                for leaf in all_leaves:
                    attr_filter = leaf['cond_type'] == 'filter' and leaf.get('attribute') != 'resource_type'
                    if leaf['cond_type'] != 'attribute' and not attr_filter:
                        continue
                    leaf_types = types(leaf.get('resource_types'))
                    if leaf_types and str(leaf_types[0]).lower() != 'all' and ty not in leaf_types:
                        continue
                    value = seed(leaf, all_leaves, variant, rng, synthetic, 7 * all_leaves.index(leaf))
                    if variant == 0 or (variant > 4 and rng.random() < .2):
                        continue
                    if leaf['operator'].startswith('jsonpath_') and '[' in leaf['attribute']:
                        attrs = put_query(attrs, compile_jsonpath(leaf['attribute']), value, variant, rng, synthetic)
                    else:
                        attrs = put(attrs, leaf['attribute'].split('.'), value)
                configs.append(attrs)
            edges = []
            for i, (ty, _) in enumerate(nodes):
                for j, (other, _) in enumerate(nodes):
                    if i >= j:
                        continue
                    relevant = any(l['cond_type'] == 'connection' for l in all_leaves)
                    if relevant and (variant in (1, 3, 4) or variant > 4 and rng.random() < .4):
                        edges.append((i, j))
            for i, ((ty, name_), attrs) in enumerate(zip(nodes, configs)):
                address = f'{ty}.{name_}'
                contents = '\n'.join(f'{key} = {json.dumps(value)}' for key, value in attrs.items())
                refs = [f'{nodes[j][0]}.{nodes[j][1]}' for left, j in edges if left == i]
                if refs:
                    contents += '\ndepends_on = [' + ', '.join(refs) + ']'
                mode, real_ty = ('data', ty[5:]) if ty.startswith('data.') else ('resource', ty)
                text = f'{mode} "{real_ty}" "{name_}" {{\n{contents}\n}}\n'
                blocks.append(text)
                conf = hcl2.loads(text)[mode][0][real_ty][name_]
                block = TerraformBlock(name=address, config=conf, path=str(root / 'main.tf'), block_type=mode,
                                       attributes=conf, id=f'{real_ty}.{name_}', source='terraform')
                vertex = block.get_attribute_dict()
                vertex['__address__'] = address
                vertex['resource_type'] = ty
                graph.add_node(address, **vertex)
            for i, j in edges:
                graph.add_edge('.'.join(nodes[i]), '.'.join(nodes[j]))
        (root / 'main.tf').write_text('\n'.join(blocks))
        try:
            check = GraphCheckParser().parse_raw_check(doc, resources_types=Registry._get_resource_types(doc))
            passed, failed, unknown = check.run(graph)
            outcomes = {v['__address__']: status for values, status in
                        [(passed, 'PASSED'), (failed, 'FAILED'), (unknown, 'UNKNOWN')] for v in values}
        except Exception as exc:
            errors.append({'rule': name, 'id': original_id, 'error': repr(exc)})
            continue
        for address in graph.nodes:
            rows.append({'root': str(root.resolve()), 'rule': name, 'id': original_id, 'address': address,
                         'checkov': outcomes.get(address, 'SKIPPED')})
    # One scan per generated root, selecting only that root's policy. A single
    # scan of the whole corpus with every policy evaluates each policy against
    # every root: findings grow with policies x roots and the scan exhausts
    # memory (~200 MB per policy at 397 policies) for rows that are never read.
    command = [str(args.native.resolve()), 'scan', str(corpus.resolve() / '{rule}'), '--recursive', '--format',
               'json', '--no-bundled', '--rule-file', str(policies.resolve() / '{policy}'), '--rule', '{rule}']

    def scan(r):
        policy = next(policies.glob(f'{r["rule"]}.*')).name
        argv = [c.format(rule=r['rule'], policy=policy) for c in command]
        process = subprocess.run(argv, text=True, capture_output=True, timeout=600)
        if process.returncode == 2 and re.search(rf'\b{r["rule"]}\b', process.stderr):
            return r['rule'], process, None
        if process.returncode not in (0, 1):
            raise RuntimeError(f'{r["rule"]}: {process.stderr}')
        return r['rule'], process, json.loads(process.stdout)

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        scans = list(executor.map(scan, inventory))
    skipped = {rule for rule, _, result in scans if result is None}
    results = [result for _, _, result in scans if result is not None]
    result = {key: [x for r in results for x in r[key]] for key in ('diagnostics', 'findings', 'rule_errors')}
    (args.output / 'native.stdout.json').write_text(json.dumps(result))
    (args.output / 'native.stderr.txt').write_text(''.join(p.stderr for _, p, _ in scans))
    if any(d['severity'] == 'error' for d in result['diagnostics']):
        raise RuntimeError('native diagnostics')
    findings = {(f['root'], f['rule']['id'], f['resource']['address']): f['severity'] for f in result['findings']}
    rule_errors = {(e['rule'], e.get('resource')) for e in result['rule_errors']}
    disagreements = []
    for row in rows:
        if row['rule'] in skipped:
            row['oxtf'] = 'skipped'
            continue
        row['oxtf'] = findings.get((row['root'], row['rule'], row['address']), 'no_finding')
        if (row['checkov'] == 'FAILED') != (row['oxtf'] == 'definite'):
            disagreements.append(row)
    for r in inventory:
        r['status'] = 'skipped' if r['rule'] in skipped else 'native'
    summary = {'policies': len(inventory), 'synthetic': sum(r['source'] == r['id'] for r in inventory),
               'skipped': sorted(r['id'] for r in inventory if r['rule'] in skipped),
               'cases': sum(r['oxtf'] != 'skipped' for r in rows), 'disagreements': len(disagreements),
               'reference_errors': len(errors), 'rule_errors': len(rule_errors)}
    report = {**summary, 'command': command, 'native_sha256': hashlib.sha256(args.native.read_bytes()).hexdigest(),
              'inventory': inventory, 'errors': errors, 'differences': disagreements, 'rows': rows}
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'skipped'} | {'skipped': len(summary['skipped'])}))
    raise SystemExit(bool(errors or disagreements or skipped))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Differential tests for every translated graph policy using Checkov 3.2.328.

Generated HCL and explicit dependency edges exercise every admitted policy tree.
Checkov's own HCL parser/vertex projection and graph solvers are the reference.
This is solver conformance, not an assertion of full-runner equivalence.
"""
import argparse
import copy
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import random
import subprocess

import hcl2
from networkx import DiGraph
from checkov.terraform import runner
from checkov.terraform.graph_builder.graph_components.blocks import TerraformBlock
from checkov.common.checks_infra.checks_parser import GraphCheckParser

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('importer', ROOT / 'crates/tfscan_py/python/tfscan/checkov.py')
importer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(importer)


def leaves(node):
    if 'cond_type' in node:
        yield node
    else:
        for value in node.values():
            for child in value if isinstance(value, list) else [value]:
                yield from leaves(child)


def types(value):
    return [value] if isinstance(value, str) else value


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


def put_query(tree, path, value, variant):
    """Seed both selected and excluded candidates for the admitted query AST."""
    if not path:
        return copy.deepcopy(value)
    head, *tail = path
    if isinstance(head, str):
        tree = tree if isinstance(tree, dict) else {}
        tree[head] = put_query(tree.get(head), tail, value, variant)
        return tree
    items = []
    for index in range(2):
        child = put_query(None, tail, value, variant)
        if head['kind'] == 'filter':
            child = child if isinstance(child, dict) else {}
            for predicate in head['predicates']:
                match = variant % 4 != 3 and (variant < 5 or index == variant % 2)
                expected = predicate['value']
                actual = expected if match == (predicate['operator'] == 'equals') else expected + '_other'
                child = put(child, predicate['path'], actual)
        items.append(child)
    if variant % 7 == 4:
        return []
    return items[0] if variant % 3 == 1 else items


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, default=ROOT / 'target/debug/oxtf')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variants', type=int, default=20)
    args = parser.parse_args()
    version, _, terraform = importer._installed(importer.SUPPORTED_VERSION)
    args.output.mkdir(parents=True, exist_ok=False)
    corpus = args.output / 'corpus'
    rules, rows, errors, inventory = [], [], [], []
    rng = random.Random(4361)
    for source in sorted((terraform / 'checks/graph_checks').rglob('*.json')):
        doc = json.loads(source.read_text())
        try:
            rule = importer._translate_graph(doc)
        except importer.Unsupported as exc:
            inventory.append({'source':source.name, 'id':doc['metadata']['id'],
                              'status':'unsupported', 'reason':str(exc), 'blockers':exc.blockers})
            continue
        original_id = rule['name']
        rule['name'] = f'GRAPH_{len(rules)}'
        rules.append(rule)
        inventory.append({'source':source.name, 'id':original_id, 'status':'translated', 'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest()})
        root = corpus / rule['name']
        root.mkdir(parents=True)
        all_leaves = list(leaves(doc['definition']))
        resource_types = sorted({t for leaf in all_leaves for k in ('resource_types','connected_resource_types') for t in types(leaf.get(k, [])) if t not in ('all','*')}) or ['test_resource']
        graph = DiGraph()
        blocks = []
        for variant in range(args.variants):
            nodes = [(ty, f'case_{variant}_{i}_{j}') for i,ty in enumerate(resource_types) for j in range(2)]
            configs = []
            for index, (ty, name) in enumerate(nodes):
                attrs = {}
                for leaf in all_leaves:
                    attr_filter = leaf['cond_type'] == 'filter' and leaf['attribute'] != 'resource_type'
                    if (leaf['cond_type'] != 'attribute' and not attr_filter) or ty not in types(leaf.get('resource_types', resource_types)):
                        continue
                    expected = leaf.get('value', 'present')
                    if leaf['operator'] in ('within','not_within') and isinstance(expected, list):
                        expected = expected[0] if expected else None
                    elif leaf['operator'] in ('contains','not_contains'):
                        expected = [expected]
                    containment = any(l.get('operator') in ('contains','not_contains') and (l['attribute'] == leaf['attribute'] or l['attribute'].startswith(leaf['attribute'] + '.')) for l in all_leaves)
                    choices = [expected, None, '', 'unexpected', []] if containment or leaf['operator'] == 'jsonpath_not_contains' else [expected, None, False, True, '', 'unexpected', [], 0, 1]
                    if attr_filter and isinstance(leaf['value'], str):
                        # Truthy nonstrings raise in Python's `value in string`.
                        choices = [expected, None, '', 'unexpected', expected[:1]]
                    value = expected if variant < 3 else rng.choice(choices)
                    if variant == 0 or (variant > 4 and rng.random() < .2):
                        continue
                    if leaf['operator'].startswith('jsonpath_') and '[' in leaf['attribute']:
                        attrs = put_query(attrs, importer._compile_jsonpath(leaf['attribute']), value, variant)
                    else:
                        attrs = put(attrs, leaf['attribute'].split('.'), value)
                configs.append(attrs)
            edges = []
            for i, (ty, _) in enumerate(nodes):
                for j, (other, _) in enumerate(nodes):
                    if i >= j:
                        continue
                    relevant = any(l['cond_type']=='connection' and ((ty in types(l['resource_types']) and other in types(l['connected_resource_types'])) or (other in types(l['resource_types']) and ty in types(l['connected_resource_types']))) for l in all_leaves)
                    if relevant and (variant in (1,3,4) or variant > 4 and rng.random() < .4):
                        edges.append((i,j))
            for i, ((ty,name), attrs) in enumerate(zip(nodes,configs)):
                address = f'{ty}.{name}'
                contents = '\n'.join(f'{key} = {json.dumps(value)}' for key,value in attrs.items())
                refs = [f'{nodes[j][0]}.{nodes[j][1]}' for left,j in edges if left==i]
                if refs:
                    contents += '\ndepends_on = [' + ', '.join(refs) + ']'
                mode, real_ty = ('data', ty[5:]) if ty.startswith('data.') else ('resource', ty)
                text = f'{mode} "{real_ty}" "{name}" {{\n{contents}\n}}\n'
                blocks.append(text)
                conf = hcl2.loads(text)[mode][0][real_ty][name]
                block = TerraformBlock(name=address, config=conf, path=str(root/'main.tf'), block_type=mode, attributes=conf, id=f'{real_ty}.{name}', source='terraform')
                vertex = block.get_attribute_dict()
                vertex['__address__'] = address
                vertex['resource_type'] = ty
                graph.add_node(address, **vertex)
            for i,j in edges:
                graph.add_edge('.'.join(nodes[i]), '.'.join(nodes[j]))
        (root/'main.tf').write_text('\n'.join(blocks))
        try:
            passed, failed, unknown = GraphCheckParser().parse_raw_check(doc).run(graph)
            outcomes = {v['__address__']: status for values,status in [(passed,'PASSED'),(failed,'FAILED'),(unknown,'UNKNOWN')] for v in values}
        except Exception as exc:
            errors.append({'id':original_id,'source':source.name,'error':repr(exc)})
            continue
        if not outcomes:
            errors.append({'id':original_id, 'error':'reference produced no results'})
        for address in graph.nodes:
            rows.append({'root':str(root.resolve()),'rule':rule['name'],'source_id':original_id,'address':address,'checkov':outcomes.get(address,'SKIPPED')})
    rules_file = args.output / 'rules.json'
    rules_file.write_text(json.dumps(rules))
    command = [str(args.native.resolve()), 'scan', str(corpus.resolve()), '--recursive', '--format', 'json', '--rule-file', str(rules_file.resolve())]
    command += [part for r in rules for part in ('--rule', r['name'])]
    process = subprocess.run(command, text=True, capture_output=True, timeout=300)
    (args.output/'native.stdout.json').write_text(process.stdout)
    (args.output/'native.stderr.txt').write_text(process.stderr)
    if process.returncode:
        raise RuntimeError(process.stderr)
    result = json.loads(process.stdout)
    if result['rule_errors'] or any(d['severity']=='error' for d in result['diagnostics']):
        raise RuntimeError('native diagnostics or rule errors')
    findings = {(f['root'],f['rule']['id'],f['resource']['address']):f['severity'] for f in result['findings']}
    disagreements = []
    for row in rows:
        row['oxtf'] = findings.get((row['root'],row['rule'],row['address']), 'no_finding')
        if (row['checkov']=='FAILED') != (row['oxtf']=='definite'):
            disagreements.append(row)
    summary = {'version':version,'policies':len(rules),'cases':len(rows),'disagreements':len(disagreements),'reference_errors':len(errors)}
    report = {**summary,'command':command,'native_sha256':hashlib.sha256(args.native.read_bytes()).hexdigest(),'rules_sha256':hashlib.sha256(rules_file.read_bytes()).hexdigest(),'inventory':inventory,'errors':errors,'differences':disagreements,'rows':rows}
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(summary))
    raise SystemExit(bool(errors or disagreements))


if __name__ == '__main__':
    main()

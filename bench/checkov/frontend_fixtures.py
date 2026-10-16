#!/usr/bin/env python3
"""Generate differential fixtures for the native Checkov policy front-end.

Runs the pinned reference implementations (PyYAML ``safe_load`` with
Checkov's JSON round trip, and the importer's JSONPath compiler) over
tricky inputs and writes their results for
``crates/tf_rule_ir/tests/checkov_frontend.rs``. Needs Checkov 3.2.328:

    "$CHECKOV_PYTHON" -I bench/checkov/frontend_fixtures.py \
        crates/tf_rule_ir/tests/fixtures/checkov_frontend.json
"""
import importlib.util
import itertools
import json
import math
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("importer", ROOT / "crates/tfscan_py/python/tfscan/checkov.py")
importer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(importer)

SCALARS = [
    "on", "off", "On", "OFF", "yes", "No", "y", "n", "Y", "true", "False", "TRUE", "tRue",
    "~", "null", "Null", "NULL", "nULL", "", "0", "-0", "+0", "00", "012", "08", "0o12", "0b101",
    "-0b11", "0b", "0x1F", "0X1F", "-0x_ff", "1_000", "_1", "1__0", "1:30", "1:60", "-1:2:3",
    "190:20:30", "1.5", "1.", ".5", "-.5", "+1.5", "1e3", "1E3", "1.0e3", "1.0e+3", "1.0E-3",
    "1_0.5_0", "1:30.5", "1:2:3.75", ".inf", "-.Inf", "+.INF", ".nan", ".NaN", "inf", "nan",
    "2026-10-16", "2026-1-6", "2026-10-16T10:00:00Z", "2026-10-16 10:00:00.5 +01:00",
    "2026-10-16t1:00:00", "2026-10-16 10:00", "<<", "=", "1-2", "0.0.0.0/0", "12345678901234567890",
    "-9223372036854775809", "0x7fffffffffffffffffff", "3.0", "1_", "+", "-", ".", "a: b",
]
STYLES = ["{}", "'{}'", '"{}"']


def ref_yaml(text):
    try:
        loaded = yaml.safe_load(text)
        out = json.loads(json.dumps(loaded))
    except Exception as exc:  # noqa: BLE001 - any failure is an error case
        return {"error": type(exc).__name__}
    if any(isinstance(x, float) and not math.isfinite(x) for x in walk(out)):
        return {"error": "nonfinite"}
    return {"value": out}


def walk(v):
    yield v
    if isinstance(v, dict):
        for x in v.values():
            yield from walk(x)
    elif isinstance(v, list):
        for x in v:
            yield from walk(x)


def yaml_cases():
    cases = []
    for s, style in itertools.product(SCALARS, STYLES):
        if style != "{}" and ("'" in s or '"' in s):
            continue
        if style == "{}" and s in ("", "a: b", "-"):
            continue
        cases.append("v: " + style.format(s))
    cases += [f"{s}: x" for s in ("on", "1", "1.5", "null", "~", "'1'", "yes", "012", "2026-10-16", "[a]", "{a: 1}", "=")]
    cases += [
        "a: &x {p: 1, q: 2}\nb:\n  <<: *x\n  q: 3\n",
        "a: &x {p: 1}\nc: &y {p: 2, r: 3}\nb:\n  <<: [*x, *y]\n",
        "b:\n  <<: {p: 1}\n  <<: {p: 2}\n",
        "b:\n  '<<': {p: 1}\n",
        "b: {<<: [1]}\n",
        "a: 1\na: 2\n",
        "a: !!str 1\nb: !!int '7'\nc: !!float '1'\nd: !!bool 'yes'\ne: !!null ''\n",
        "a: !!binary aGk=\n", "a: !!set {x}\n", "a: !!omap [{x: 1}]\n", "a: !custom x\n",
        "a: [1, 2\n", "a: 1\n---\nb: 2\n", "", "---\n", "# only a comment\n",
        "a: |\n  line1\n  line2\n", "a: >\n  folded\n  text\n", "a: 'it''s'\n", 'a: "\\u00e9\\n"\n',
        "a:\n  - on\n  -\n  - ~\n", "? complex\n: value\n", "a: *undefined\n",
    ]
    return cases


ATTRIBUTES = [
    "a", "a.b", "a.b.c", "a-b.c_d", "a[*]", "a[*].b", "a[*][*]", "a.b[*].c", "a[:]", "a[0]", "a[0].b",
    "a..b", "$.a", "$", "@.a", "*", "a.*", "a.*.b", "[*].a", "a.[*]", "a .b", " a.b", "a.b ", "a[ * ]",
    "'a'.b", "a['b']", "a[\"b\"]", "a['b'][*]", "a.'b'[*]", "true_flag", "truex.a", "false", "a.true",
    "where.a", "a.where", "contains", "a.contains[*]", "a@b", "@a.b", "a.b@c[*]", "1a", "a.1", "a.b-1[*]",
    "a[?(@.k == 'v')]", "a[?(@.k = 'v')]", "a[?(@.k != 'v')]", "a[?(@.k == \"v\")]", "a[?(@.k == v)]",
    "a[?(@.k=='v')]", "a[?( @.k == 'v' )]", "a[?@.k == 'v']", "a[?(k == 'v')]", "a[?(k.l == 'v')]",
    "a[?(@.k.l == 'v')]", "a[?(@ == 'v')]", "a[?(@.k == 'v' & @.m == 'w')]", "a[?(@.k == 'v' && @.m == 'w')]",
    "a[?(@.k == 'v' | @.m == 'w')]", "a[?((@.k == 'v'))]", "a[?((@.k == 'v') & (@.m == 'w'))]",
    "a[?(@.k == 'v')].b", "a[?(@.k == 'v')][*]", "a[*][?(@.k == 'v')].b", "a[?(@.k == 1)]",
    "a[?(@.k == true)]", "a[?(@.k == 'it\\'s')]", "a[?(@.k =~ 'v')]", "a[?(@.k > 'v')]", "a[?(@.k)]",
    "a[?(!@.k)]", "a[?(@.k == 'v')", "a[?(@.k == '')]", "a[?(@.k == 'v w')]", "a[?(@.k == @v)]",
    "a[?(@.k == 'v')].lifecycle", "lifecycle[*]", "a[?(@.true == 'v')]", "a[?(@.k-1 == 'v')]",
    "a[?(@.k == where)]", "a[?(@.k == truthy)]", "a[?(@.k == 1.5)]", "a\t.b[*]", "a\n.b[*]", "a\r.b[*]",
]


def ref_jsonpath(attribute):
    try:
        return importer._compile_jsonpath(attribute)
    except Exception:  # noqa: BLE001 - every exception is a rejection
        return None


def main():
    out = {
        "generator": "bench/checkov/frontend_fixtures.py",
        "checkov": importer.SUPPORTED_VERSION,
        "pyyaml": yaml.__version__,
        "yaml": [{"text": t, **ref_yaml(t)} for t in yaml_cases()],
        "jsonpath": [{"attribute": a, "path": ref_jsonpath(a)} for a in ATTRIBUTES],
    }
    Path(sys.argv[1]).write_text(json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()

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
    "export_options[?(@.identity_squash =~ '(?i)^ROOT$')]",
    "export_options[?(@.identity_squash =~ '(?i)^ROOT$' & @.anonymous_gid == 65534 & @.anonymous_uid == 65534)]",
    "a[?(@.k > 5)]", "a[?(@.k >= 5)]", "a[?(@.k < 5)]", "a[?(@.k <= 5)]", "a[?(@.k != 5)]", "a[?(@.k > 'v')]",
    "a[?(@.k =~ 5)]", "a[?(@.k =~ '(')]", "a[?(@.k =~ '\\bx')]", "a[?(@.k == -5)]", "a[?(@.k == 05)]",
]


def compile_jsonpath(attribute):
    """The importer's compiler over the pinned bc_jsonpath_ng AST, extended
    with the filter forms the native front-end admits: `=~` with a string,
    and integer comparisons."""
    import re as _re
    from bc_jsonpath_ng.ext import parse
    from bc_jsonpath_ng.ext.filter import Filter
    from bc_jsonpath_ng.jsonpath import Child, Fields, Slice, This

    def field(name):
        if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", name):
            raise ValueError("nonliteral field")
        return name

    ops = {"==": "equals", "=": "equals", "!=": "not_equals", "=~": "regex", "<": "less_than",
           "<=": "less_than_or_equal", ">": "greater_than", ">=": "greater_than_or_equal"}

    def parts(query, relative=False):
        if isinstance(query, Child):
            return parts(query.left, relative) + parts(query.right, relative)
        if isinstance(query, This) and relative:
            return []
        if isinstance(query, Fields) and len(query.fields) == 1:
            return [field(query.fields[0])]
        if not relative and isinstance(query, Slice) and query.start is None and query.end is None and query.step is None:
            return [{"kind": "each"}]
        if not relative and isinstance(query, Filter) and query.expressions:
            predicates = []
            for expression in query.expressions:
                value = expression.value
                if expression.op not in ops or isinstance(value, bool) or not isinstance(value, (str, int)):
                    raise ValueError("unsupported filter")
                if isinstance(value, str) and expression.op not in {"==", "=", "!=", "=~"}:
                    raise ValueError("strings support equality and =~ only")
                if isinstance(value, int) and expression.op == "=~":
                    raise ValueError("=~ requires a string")
                if expression.op == "=~":
                    _re.compile(value)
                path = parts(expression.target, True)
                if not path:
                    raise ValueError("filter requires fields")
                predicates.append({"path": path, "operator": ops[expression.op], "value": value})
            return [{"kind": "filter", "predicates": predicates}]
        raise ValueError("unsupported JSONPath expression")

    path = parts(parse(attribute))
    if not path or not isinstance(path[0], str):
        raise ValueError("path requires a configured field")
    if all(isinstance(p, str) for p in path) and attribute != ".".join(path):
        raise ValueError("noncanonical literal path")
    return path


def ref_jsonpath(attribute):
    try:
        return compile_jsonpath(attribute)
    except Exception:  # noqa: BLE001 - every exception is a rejection
        return None


CLASSES = [r"\w", r"\s", r"\d"]

PATTERNS = [
    "(^postgres|.*sqlserver).*", "^(mariadb|mysql).*", ".*db2-ae.*", "(?i)^ROOT$", "abc", "abc$", "^a.c$",
    "a{,2}b", "a{2,}b", "a{1,3}?b", "a{x", "a{}", "a}", "[]a]+", "[^]a]", "[a-c&&b]+", "[a\\-z]", "[\\w.-]+$",
    "\\w+", "\\W", "\\s+", "\\S+", "\\d+", "\\D", "[\\d\\s]+", "[^\\w]", "(?i)[a-z]+", "(?i)straße",
    "(?i:ab)c", "(?:a|b)+$", "(?P<x>a)b", "(?#note)ab", "a|b$", "(a$)", "a$b", "\\x41", "\\u00e9", "\\n", "\\.",
    "\\-", "\\/", "\\ ", "\\%", "\\é", "[\\b]", "\\bword", "(?=a)", "(a)\\1", "a*+", "\\q", "[z-a]", "(", ")",
    "[", "\\A\\d+\\Z", "^.*$", ".", "(?s).", "(?m)^a", "(?x)a b", "(?a)\\w", "tcp|udp", "^arn:aws:iam::\\d{12}:",
    "^[0-9]{1,5}$", "^(?!x)", "^\\*$", "[+*?]", "\\{", "a{2}", "a{0}", "x{1,2}{3}", "a**",
    "(?i)i", "(?i)I", "(?i)[a-z]", "(?i)[^a-z]", "(?i)[h-j]", "(?i)s", "(?i)k", "(?i)[r-t]", "(?i)\u00e9", "a*??",
    "a??", "a{2}?", "a{2}?{3}", "(?i:i)x", "(?i:x)i",
]
INPUTS = ["", "a", "abc", "abc\n", "abc\n\n", "xabc", "aab", "a{x", "a{}", "a}", "]a]", "a&&b", "-", "é1_", "\u0301",
          "\x1f", " ", "\u00a0", "\u2028", "root", "ROOT", "Root", "STRASSE", "straße", "abc def", "postgres14",
          "sqlserver-ex-15", "mysql8.0", "mariadb10.6", "db2-ae-11", "x db2-ae", "tcp", "udp", "12345", "123456",
          "arn:aws:iam::123456789012:role/x", "\u0661\u0662", "²", "\u2167", "_", "*", "+", "word", "a\nb", "{", "aa",
          "\u0130", "\u212a", "k", "\u017f", "s", "\u0131", "i", "I", "S", "K", "\u00e5", "\u212b", "ix",
          "Ix", "\u0130x", "xi", "xI", "x\u0130", "aaa"]

IPS = ["10.0.0.0/8", "10.1.2.3/8", "10.0.0.0/255.0.0.0", "10.0.0.0/0.255.255.255", "10.0.0.0/08", "10.0.0.0/33",
       "010.0.0.0/8", "1.2.3", "1.2.3.4.5", "256.0.0.0", "0.0.0.0/0", "0.0.0.0/0.0.0.0", "1.2.3.4/255.255.0.255",
       "192.168.1.1", " 10.0.0.0/8", "10.0.0.0/ 8", "10.0.0.0/8/9", "::/0", "::", "::1", "1::", "1::2::3", ":1::2",
       "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::", "::ffff:1.2.3.4", "::ffff:1.2.3.04", "2001:db8::/32",
       "2001:DB8::/129", "2001:db8::/ff00::", "fe80::1%eth0", "12345::", "g::", "", "/8", "10.0.0.0/", "1:2:3:4:5:6:1.2.3.4",
       "1:2:3:4:5:6:7:1.2.3.4", "::1.2.3.4", "1::2:3:4:5:6:7", "1::2:3:4:5:6:7:8", "1.2.3.4/32", "1.2.3.4/0"]

STRS = [None, True, False, 0, -7, 1.5, 1e16, 1e-05, 0.0001, 100.0, "s", "", ["a", 1, True, None, 1.5],
        {"k": "v", "n": [1, {"x": "it's"}]}, ["\\", "a\nb", "q'\"", "\t\x01"], [], {}, ["é"]]

INTS = ["1", " 1 ", "-1", "+1", "1_0", "1__0", "_1", "1_", "0x10", "1.0", "", " ", "--1", "007", "١٢",
        "99999999999999999999999999"]


def class_ranges(pattern):
    import re
    rx = re.compile(pattern)
    ranges, start = [], None
    for cp in range(0x110000):
        hit = 0xD800 <= cp <= 0xDFFF or bool(rx.match(chr(cp)))
        if 0xD800 <= cp <= 0xDFFF:
            hit = start is not None  # never split a range on surrogates
        if hit and start is None:
            start = cp
        elif not hit and start is not None:
            ranges.append([start, cp - 1])
            start = None
    if start is not None:
        ranges.append([start, 0x10FFFF])
    return ranges


def unassigned_ranges():
    import unicodedata
    ranges, start = [], None
    for cp in range(0x110000):
        hit = unicodedata.category(chr(cp)) == "Cn"
        if hit and start is None:
            start = cp
        elif not hit and start is not None:
            ranges.append([start, cp - 1])
            start = None
    if start is not None:
        ranges.append([start, 0x10FFFF])
    return ranges


def ref_regex():
    import re
    out = []
    for p in PATTERNS:
        try:
            rx = re.compile(p)
        except re.error:
            out.append({"pattern": p, "error": True})
            continue
        out.append({"pattern": p, "match": {s: rx.match(s) is not None for s in INPUTS},
                    "search": {s: rx.search(s) is not None for s in INPUTS}})
    return out


def ref_ip(s):
    import ipaddress
    try:
        n = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None
    return {"version": n.version, "first": str(int(n.network_address)), "last": str(int(n.broadcast_address))}


def ref_int(s):
    try:
        return str(int(s))
    except ValueError:
        return None


def main():
    out = {
        "generator": "bench/checkov/frontend_fixtures.py",
        "checkov": importer.SUPPORTED_VERSION,
        "pyyaml": yaml.__version__,
        "yaml": [{"text": t, **ref_yaml(t)} for t in yaml_cases()],
        "jsonpath": [{"attribute": a, "path": ref_jsonpath(a)} for a in ATTRIBUTES],
        "python": sys.version.split()[0],
        "regex_classes": {c: class_ranges(c) for c in CLASSES},
        "unicode_version": __import__("unicodedata").unidata_version,
        "unassigned": unassigned_ranges(),
        "regex": ref_regex(),
        "ip": [{"text": s, "network": ref_ip(s)} for s in IPS],
        "str": [{"value": v, "str": str(v)} for v in STRS],
        "int": [{"text": s, "int": ref_int(s)} for s in INTS],
    }
    Path(sys.argv[1]).write_text(json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()

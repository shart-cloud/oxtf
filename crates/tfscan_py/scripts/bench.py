"""W6 benchmarks (release wheel). Prints markdown tables.

    python bench.py REPO_ROOT GENERATED_DIR [RUNS]
"""

import os
import statistics
import sys
import time
import timeit

import tfscan
from tfscan import _tfscan
from tfscan.examples.sg_open_ssh import CALLBACK_RULE, EXPR_RULE

REPO, GEN = sys.argv[1], sys.argv[2]
RUNS = int(sys.argv[3]) if len(sys.argv) > 3 else 7
CORPUS = os.path.join(REPO, "corpus/repos")
IR = EXPR_RULE.to_json()


def mm(xs):
    return f"{min(xs) * 1000:.1f} / {statistics.median(xs) * 1000:.1f}"


def timed(f):
    t = time.perf_counter()
    r = f()
    return time.perf_counter() - t, r


print(f"load before: {os.getloadavg()}")

# -- A: full scans -------------------------------------------------------------
configs = [
    ("analysis only (no rules)", dict(builtin=False)),
    ("built-in aws-sg-open-ssh (Rust)", dict(select=["aws-sg-open-ssh"])),
    ("expression rule (IR, Rust, no GIL)", dict(builtin=False, rules=[EXPR_RULE])),
    ("callback rule (Python, GIL per call)", dict(builtin=False, rules=[CALLBACK_RULE])),
    ("all 5 built-in rules", dict(builtin=True)),
]
for label, path in [("corpus/repos (504 roots)", CORPUS), (f"generated ({GEN})", GEN)]:
    print(f"\n### Full scan wall time, {label}, {RUNS} runs, 4 threads (ms, min / median)\n")
    print("| configuration | wall (tfscan.scan) | in-process (stats.elapsed) | findings | callback calls |")
    print("|---|---|---|---|---|")
    tfscan.scan(path, recursive=True, builtin=False)  # warm page cache
    for name, kw in configs:
        walls, inner = [], []
        for _ in range(RUNS):
            dt, r = timed(lambda: tfscan.scan(path, recursive=True, **kw))
            walls.append(dt)
            inner.append(r.stats["elapsed_s"])
        print(f"| {name} | {mm(walls)} | {mm(inner)} | {len(r.findings)} | {r.callback_calls} |")

# -- B: rule evaluation only ----------------------------------------------------
for label, path in [("corpus/repos", CORPUS), ("generated", GEN)]:
    print(f"\n### Rule evaluation only (model analysed once), {label}, 1 thread, {RUNS} runs (ms, min / median)\n")
    print("| rule path | time | findings | candidate resources (callback calls / run) | per candidate (µs, min) |")
    print("|---|---|---|---|---|")
    rows = [
        ("built-in aws-sg-open-ssh (Rust)", dict(select=["aws-sg-open-ssh"])),
        ("expression rule (IR)", dict(builtin=False, ir_rules=[IR])),
        ("callback rule (Python)", dict(builtin=False, callbacks=[CALLBACK_RULE])),
        ("callback rule returning None immediately", dict(builtin=False, callbacks=[
            tfscan.CallbackRule(lambda r: None, "noop", CALLBACK_RULE.resource_types)])),
    ]
    cand = None
    for name, kw in rows:
        times, n, calls = _tfscan._rule_time([path], recursive=True, repeat=RUNS, **kw)
        if calls:
            cand = calls // RUNS
        per = (min(times) / cand * 1e6) if cand else float("nan")
        print(f"| {name} | {mm(times)} | {n} | {cand if cand else '-'} | {per:.2f} |")

# -- C: Arrow ---------------------------------------------------------------------
print(f"\n### Arrow export, corpus/repos, {RUNS} runs (ms, min / median)\n")
import pyarrow as pa

r = tfscan.scan(CORPUS, recursive=True, builtin=False, rules=[])
res = r.resources
n = len(res)


def python_lists():
    rs = list(r._inner.resources)
    cols = {
        "root": [x.root for x in rs], "module": [x.module for x in rs], "address": [x.address for x in rs],
        "base_address": [x.base_address for x in rs], "mode": [x.mode for x in rs], "type": [x.type for x in rs],
        "name": [x.name for x in rs], "key": [x.key for x in rs], "existence": [x.existence for x in rs],
        "file": [x.file for x in rs], "line": [x.line for x in rs], "attributes": [x.to_json() for x in rs],
    }
    return pa.table(cols)


print("| method | rows | time |")
print("|---|---|---|")
for name, f in [("resources.to_arrow() (arrow-rs + C stream)", lambda: res.to_arrow()),
                ("Python handles -> lists -> pyarrow.table", python_lists)]:
    ts = []
    for _ in range(RUNS):
        dt, t = timed(f)
        ts.append(dt)
    print(f"| {name} | {t.num_rows} | {mm(ts)} |")
rf = tfscan.scan(os.path.join(REPO, "fixtures/rules"), recursive=True)
ts = [timed(rf.findings_arrow)[0] for _ in range(RUNS)]
print(f"| findings_arrow() on fixtures/rules (all built-ins) | {rf.findings_arrow().num_rows} | {mm(ts)} |")

# -- D: Q7 per-access overhead ---------------------------------------------------
print("\n### Q7: per-access cost (ns per access, min of 5 x 200k)\n")
src = open(os.path.join(REPO, "fixtures/rules/aws-sg-open-ssh/fail_port_range_and_all_protocols/main.tf")).read()
doc = tfscan.parse(src)
node = doc.blocks()[0].blocks()[0] if doc.blocks()[0].blocks() else doc.blocks()[0]
fx = tfscan.scan(os.path.join(REPO, "fixtures/rules/aws-sg-open-ssh/fail_inline_literal"))
resource = fx.resources[0]
finding = fx.findings[0]
value = resource["ingress"]


class Plain:
    def __init__(self):
        self.span = (1, 2)
        self.type = "aws_security_group"


plain = Plain()
d = {"type": "aws_security_group"}
cases = [
    ("arena AST Node.span (self_cell with_dependent + node table)", lambda: node.span),
    ("arena AST Node.kind", lambda: node.kind),
    ("arena AST Node.block_type", lambda: node.block_type),
    ("owned model Resource.type (Arc<ScanData> + 3 indices)", lambda: resource.type),
    ("owned model Finding.address", lambda: finding.address),
    ("owned model Value.kind", lambda: value.kind),
    ("baseline: Python object attribute", lambda: plain.type),
    ("baseline: dict lookup", lambda: d["type"]),
]
print("| access | ns |")
print("|---|---|")
for name, f in cases:
    t = min(timeit.repeat(f, number=200_000, repeat=5)) / 200_000 * 1e9
    print(f"| {name} | {t:.0f} |")
for mode in ("cell", "owned"):
    t = min(_tfscan._bench_node_access(doc, 20_000_000, mode) for _ in range(5))
    print(f"| Rust loop, {mode}: span lookup ({'with_dependent + AstKind::span' if mode == 'cell' else 'Vec<(u32,u32)> index'}) | {t:.2f} |")

# -- E: parse throughput through the binding -------------------------------------
files = []
for dp, dn, fn in os.walk(CORPUS):
    dn[:] = [x for x in dn if not x.startswith(".")]
    files += [os.path.join(dp, f) for f in fn if f.endswith(".tf")]
texts = [open(f, encoding="utf-8", errors="replace").read() for f in files]
nbytes = sum(len(t.encode()) for t in texts)
ts = []
for _ in range(RUNS):
    t0 = time.perf_counter()
    docs = [tfscan.parse(t) for t in texts]
    ts.append(time.perf_counter() - t0)
nodes = sum(x.node_count for x in docs)
arena = sum(x.arena_bytes for x in docs)
print(f"\n### tfscan.parse over the corpus: {len(files)} files, {nbytes} bytes, {nodes} nodes, arena {arena} bytes\n")
print(f"time (ms, min / median): {mm(ts)}; {nbytes / min(ts) / 1e6:.1f} MB/s")
t0 = time.perf_counter()
handles = [n for x in docs for n in x.walk()]
dt = time.perf_counter() - t0
print(f"materialising a Node handle for every node ({len(handles)}): {dt * 1000:.1f} ms")
print(f"\nload after: {os.getloadavg()}")

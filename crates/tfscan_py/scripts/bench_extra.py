"""Follow-ups to bench.py: callback scans vs thread count (GIL contention) and
where the Arrow export time goes.

    python bench_extra.py REPO_ROOT GENERATED_DIR [RUNS]
"""

import os
import statistics
import sys
import time

import pyarrow as pa

import tfscan
from tfscan.examples.sg_open_ssh import CALLBACK_RULE, EXPR_RULE

REPO, GEN = sys.argv[1], sys.argv[2]
RUNS = int(sys.argv[3]) if len(sys.argv) > 3 else 5
CORPUS = os.path.join(REPO, "corpus/repos")


def mm(xs):
    return f"{min(xs) * 1000:.1f} / {statistics.median(xs) * 1000:.1f}"


def bench(f):
    ts = []
    for _ in range(RUNS):
        t = time.perf_counter()
        f()
        ts.append(time.perf_counter() - t)
    return ts


print(f"load before: {os.getloadavg()}")
print(f"\n### Full scan of the generated corpus by thread count, {RUNS} runs (ms, min / median)\n")
print("| threads | expression rule | callback rule |")
print("|---|---|---|")
for th in (1, 2, 4):
    e = bench(lambda: tfscan.scan(GEN, recursive=True, builtin=False, rules=[EXPR_RULE], threads=th))
    c = bench(lambda: tfscan.scan(GEN, recursive=True, builtin=False, rules=[CALLBACK_RULE], threads=th))
    print(f"| {th} | {mm(e)} | {mm(c)} |")

print(f"\n### Arrow export breakdown, corpus/repos (5227 resources), {RUNS} runs (ms, min / median)\n")
r = tfscan.scan(CORPUS, recursive=True, builtin=False)
rs = list(r._inner.resources)
print("| step | time |")
print("|---|---|")
print(f"| build RecordBatch in Rust (`_resources_stream()`, GIL released) | {mm(bench(lambda: r._inner._resources_stream()))} |")
s = [r._inner._resources_stream() for _ in range(RUNS)]
it = iter(s)
print(f"| pyarrow import of the C stream (`RecordBatchReader.from_stream(...).read_all()`) | {mm(bench(lambda: pa.RecordBatchReader.from_stream(next(it)).read_all()))} |")
print(f"| attributes JSON alone via handles (`[x.to_json() for x in rs]`) | {mm(bench(lambda: [x.to_json() for x in rs]))} |")
print(f"| 11 scalar columns via handles (Python lists, no JSON) | {mm(bench(lambda: [(x.root, x.module, x.address, x.base_address, x.mode, x.type, x.name, x.key, x.existence, x.file, x.line) for x in rs]))} |")
print(f"| creating the 5227 Resource handles (`r._inner.resources`) | {mm(bench(lambda: r._inner.resources))} |")
print(f"\nload after: {os.getloadavg()}")

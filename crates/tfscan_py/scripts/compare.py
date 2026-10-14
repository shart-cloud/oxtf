"""Exit criterion: seed rule 1 in the expression API (and as a callback) vs
the built-in Rust rule, on every aws-sg-open-ssh fixture and on the corpus.

    python compare.py <repo root> [generated corpus dir]

Compares rule-agnostic sets of (address, root, severity), and separately the
same with the message.
"""

import os
import sys
from collections import Counter

import tfscan
from tfscan.examples.sg_open_ssh import CALLBACK_RULE, EXPR_RULE

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."


def run(path, recursive, which):
    if which == "builtin":
        r = tfscan.scan(path, recursive=recursive, builtin=["aws-sg-open-ssh"])
    elif which == "expr":
        r = tfscan.scan(path, recursive=recursive, builtin=False, rules=[EXPR_RULE])
    else:
        r = tfscan.scan(path, recursive=recursive, builtin=False, rules=[CALLBACK_RULE])
    keys = {(f.address, f.root, f.severity) for f in r.findings}
    with_msg = {(f.address, f.root, f.severity, f.message) for f in r.findings}
    return r, keys, with_msg


def compare(label, path, recursive):
    b, bk, bm = run(path, recursive, "builtin")
    e, ek, em = run(path, recursive, "expr")
    c, ck, cm = run(path, recursive, "callback")
    sev = Counter(s for (_, _, s) in bk)
    print(
        f"| {label} | {len(b.findings)} ({sev['definite']} definite, {sev['conditional']} conditional) "
        f"| {len(e.findings)} | {len(c.findings)} | {'yes' if bk == ek else 'NO'} | {'yes' if bk == ck else 'NO'} "
        f"| {'yes' if bm == em else 'NO'} | {'yes' if bm == cm else 'NO'} | {c.callback_calls} |"
    )
    if bk != ek or bk != ck:
        print("  builtin - expr:", sorted(bk - ek))
        print("  expr - builtin:", sorted(ek - bk))
        print("  builtin - callback:", sorted(bk - ck))
        print("  callback - builtin:", sorted(ck - bk))
    return bk, ek, ck


print("| scope | built-in findings | expression | callback | expr == built-in (address, root, severity) | callback == built-in | expr == built-in incl. message | callback == built-in incl. message | callback calls |")
print("|---|---|---|---|---|---|---|---|---|")
fx = os.path.join(ROOT, "fixtures/rules/aws-sg-open-ssh")
for case in sorted(os.listdir(fx)):
    compare(f"fixture {case}", os.path.join(fx, case), False)
compare("all fixtures/rules (31 cases, recursive)", os.path.join(ROOT, "fixtures/rules"), True)
corpus = os.path.join(ROOT, "corpus/repos")
if os.path.isdir(corpus):
    bk, _, _ = compare("corpus/repos (recursive)", corpus, True)
    for k in sorted(bk):
        print("  corpus finding:", k)
if len(sys.argv) > 2:
    compare(f"generated differential corpus ({sys.argv[2]})", sys.argv[2], True)

"""Seed rules 4 and 5 in the expression API vs the built-in rules
(rule-agnostic (address, root, severity) sets; messages differ by design:
the built-ins choose among three message texts).

    python compare_other_rules.py REPO_ROOT
"""

import os
import sys

import tfscan
from tfscan import col, rule

REPO = sys.argv[1]
rds = (
    rule("py-rds-unencrypted", ["aws_db_instance"], level="high", category="encryption")
    # Built-in skips read replicas: any non-null replicate_source_db (also
    # Tainted / Unknown). `is_null & is_known` is that two-valued test.
    .where_(col("replicate_source_db").is_null() & col("replicate_source_db").is_known()
            & (col("storage_encrypted", default=True) != True))  # noqa: E712
    .message("storage_encrypted is {witness|not true}")
)
gcp = (
    rule("py-gcp-uniform", ["google_storage_bucket"], category="storage")
    .where_(col("uniform_bucket_level_access", default=True) != True)  # noqa: E712
    .message("uniform_bucket_level_access is {witness|not true}")
)
print("| rule | scope | built-in findings | expression findings | identical (address, root, severity) |")
print("|---|---|---|---|---|")
for builtin, expr in [("aws-rds-unencrypted", rds), ("gcp-storage-uniform-access", gcp)]:
    for label, path in [("fixtures/rules (recursive)", "fixtures/rules"), ("corpus/repos (recursive)", "corpus/repos")]:
        p = os.path.join(REPO, path)
        b = tfscan.scan(p, recursive=True, builtin=[builtin])
        e = tfscan.scan(p, recursive=True, builtin=False, rules=[expr])
        kb = {(f.address, f.root, f.severity) for f in b.findings}
        ke = {(f.address, f.root, f.severity) for f in e.findings}
        print(f"| {builtin} | {label} | {len(kb)} | {len(ke)} | {'yes' if kb == ke else 'NO'} |")

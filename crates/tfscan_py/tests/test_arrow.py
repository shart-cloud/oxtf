import json

import pyarrow as pa
import pytest

import tfscan
from conftest import FIXTURES, SSH_FIXTURES

FINDING_COLUMNS = [
    "fingerprint", "rule", "category", "level", "severity", "address", "resource_type",
    "module", "message", "root", "attribute", "file", "line", "column", "provenance",
    "record",
]
RESOURCE_COLUMNS = [
    "root", "module", "address", "base_address", "mode", "type", "name", "key",
    "existence", "file", "line", "column", "attributes",
]


def test_findings_table():
    r = tfscan.scan(FIXTURES, recursive=True, bundled=False)
    t = r.findings_arrow()
    assert isinstance(t, pa.Table)
    assert t.column_names == FINDING_COLUMNS
    assert t.num_rows == len(r.findings) == r.stats["findings"]
    assert t.schema.field("line").type == pa.uint32()
    prov = t.schema.field("provenance").type
    assert pa.types.is_list(prov)
    assert [f.name for f in prov.value_type] == [
        "kind", "label", "file", "line", "column", "resource", "attribute"]
    rows = t.to_pylist()
    by_addr = {(x["address"], x["root"]): x for x in rows}
    for f in r.findings:
        x = by_addr[(f.address, f.root)]
        assert (x["rule"], x["severity"], x["message"], x["file"], x["line"]) == (
            f.rule, f.severity, f.message, f.file, f.line)
        assert [p["label"] for p in x["provenance"]] == [p["label"] for p in f.provenance]
        rec = json.loads(x["record"])
        assert rec["fingerprint"] == x["fingerprint"] == f.fingerprint
        assert rec == f.to_dict()


def test_resources_table():
    r = tfscan.analyze(FIXTURES, recursive=True)
    t = r.resources.to_arrow()
    assert t.column_names == RESOURCE_COLUMNS
    assert t.num_rows == len(r.resources) == len(list(r.resources))
    assert t.schema.field("key").nullable
    assert set(t.column("mode").to_pylist()) <= {"managed", "data"}
    import json
    for a in t.column("attributes").to_pylist():
        assert isinstance(json.loads(a), dict)


def test_capsule_protocol_and_empty():
    r = tfscan.scan(SSH_FIXTURES / "pass_restricted", bundled=False)
    t = pa.table(r)  # ScanResult implements __arrow_c_stream__
    assert t.num_rows == 0 and t.column_names == FINDING_COLUMNS
    stream = r._inner._findings_stream()
    stream.__arrow_c_stream__()
    with pytest.raises(RuntimeError):
        stream.__arrow_c_stream__()

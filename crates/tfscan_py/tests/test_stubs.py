import subprocess
import sys

import pytest

import tfscan
from tfscan import schema

GOOD = '''
import tfscan
from tfscan.schema import col_of, AwsSecurityGroupIngress
from tfscan.examples.sg_open_ssh import EXPR_RULE

r = (tfscan.rule("typed", ["aws_security_group"]).for_each("ingress")
     .where_((col_of("aws_security_group.ingress", "from_port") <= 22)
             & col_of("aws_security_group.ingress", "cidr_blocks").list.contains("0.0.0.0/0")))
x: AwsSecurityGroupIngress = {"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
res = tfscan.scan(".", rules=[r, EXPR_RULE])
for f in res.findings:
    line: int = f.line
    sev: str = f.certainty
'''

BAD = '''
from tfscan.schema import col_of, AwsSecurityGroupIngress
col_of("aws_security_group.ingress", "frm_port")
y: AwsSecurityGroupIngress = {"from_port": "22"}
'''


def test_runtime_schema_module():
    assert "aws_security_group" in schema.ATTRIBUTES
    assert "from_port" in schema.ATTRIBUTES["aws_security_group.ingress"]
    e = schema.col_of("aws_security_group.ingress", "from_port")
    assert e.to_ir() == {"op": "col", "path": ["from_port"]}
    with pytest.raises(KeyError):
        schema.col_of("aws_security_group.ingress", "frm_port")


def test_mypy_checks_attribute_names(tmp_path):
    pytest.importorskip("mypy")
    good = tmp_path / "good.py"
    good.write_text(GOOD)
    bad = tmp_path / "bad.py"
    bad.write_text(BAD)
    run = lambda p: subprocess.run([sys.executable, "-m", "mypy", "--strict", "--no-incremental", str(p)],
                                   capture_output=True, text=True, cwd=tmp_path)
    g = run(good)
    assert g.returncode == 0, g.stdout
    b = run(bad)
    assert b.returncode == 1, b.stdout
    assert 'bad.py:3: error: No overload variant of "col_of"' in b.stdout
    assert 'bad.py:4: error: Incompatible types' in b.stdout and "typeddict-item" in b.stdout

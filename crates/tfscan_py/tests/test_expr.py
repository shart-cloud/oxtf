import json

import pytest

import tfscan
from conftest import CORPUS, FIXTURES, RULES, SSH_FIXTURES
from tfscan import col, element, rule
from tfscan.examples.sg_open_ssh import CALLBACK_RULE, EXPR_RULE


def keys(r, msg=False):
    return {(f.address, f.root, f.severity) + ((f.message,) if msg else ()) for f in r.findings}


def triple(path, recursive=False):
    b = tfscan.scan(path, recursive=recursive, select=["aws-sg-open-ssh"])
    e = tfscan.scan(path, recursive=recursive, builtin=False, rules=[EXPR_RULE])
    c = tfscan.scan(path, recursive=recursive, builtin=False, rules=[CALLBACK_RULE])
    return b, e, c


@pytest.mark.parametrize("case", sorted(p.name for p in SSH_FIXTURES.iterdir() if p.is_dir()))
def test_expression_rule_equals_builtin_on_fixtures(case):
    b, e, c = triple(SSH_FIXTURES / case)
    assert keys(e, msg=True) == keys(b, msg=True)
    assert keys(c, msg=True) == keys(b, msg=True)
    assert all(f.rule == "py-sg-open-ssh" for f in e.findings)
    for fb, fe in zip(sorted(b.findings, key=lambda f: f.address), sorted(e.findings, key=lambda f: f.address)):
        assert (fe.file, fe.line) == (fb.file, fb.line)
        assert fe.provenance == fb.provenance


def test_expression_rule_equals_builtin_generated(generated):
    d = generated(120, 7)
    b, e, c = triple(d, recursive=True)
    assert len(b.findings) > 50
    sev = {f.severity for f in b.findings}
    assert sev == {"definite", "conditional"}
    assert keys(e, msg=True) == keys(b, msg=True)
    assert keys(c, msg=True) == keys(b, msg=True)


@pytest.mark.skipif(not CORPUS.is_dir(), reason="corpus not fetched")
def test_expression_rule_equals_builtin_corpus():
    b, e, c = triple(CORPUS, recursive=True)
    assert keys(e) == keys(b) and keys(c) == keys(b)
    assert c.callback_calls == 267  # every candidate resource (W4 audit: 111 + 70 + 86)


def test_ir_round_trip():
    ir = EXPR_RULE.to_ir()
    assert ir == json.loads((RULES / "sg_open_ssh.json").read_text())
    compiled = EXPR_RULE.compile()
    assert compiled.name == "py-sg-open-ssh"
    assert json.loads(compiled.to_json()) == ir  # Python -> Rust (serde) -> JSON
    again = tfscan.Rule.from_ir(json.loads(compiled.to_json()))
    assert again.to_ir() == ir


def test_save_and_load(tmp_path):
    p = tmp_path / "rules.json"
    tfscan.save_rules(str(p), [EXPR_RULE])
    (r,) = tfscan.load_rules(str(p))
    assert r.to_ir() == EXPR_RULE.to_ir()
    with pytest.raises(TypeError):
        tfscan.save_rules(str(p), [CALLBACK_RULE])  # callbacks do not port


def test_validation_in_rust():
    bad = rule("x", ["aws_security_group"]).where_(col("a") == 1).message("{nope}")
    with pytest.raises(ValueError, match="placeholder"):
        bad.compile()
    with pytest.raises(ValueError):
        tfscan.compile_rules('{"name": "x", "message": "m", "clauses": [], "version": 1}')
    with pytest.raises(ValueError):
        tfscan.compile_rules('{"name": "x", "message": "m", "version": 2, "clauses": '
                             '[{"resource_types": ["t"], "condition": {"op": "lit", "value": true}}]}')
    with pytest.raises(ValueError):
        rule("x", level="severe")
    with pytest.raises(TypeError):
        bool(col("a") == 1)
    with pytest.raises(TypeError):
        col("a") == [1, 2]


def write(tmp_path, text):
    (tmp_path / "main.tf").write_text(text)
    return tmp_path


def test_operators_and_lattice(tmp_path):
    d = write(tmp_path, '''
variable "free" { type = string }
resource "aws_s3_bucket" "known" {
  bucket = "logs"
  tags   = { env = "prod" }
}
resource "aws_s3_bucket" "tainted" { bucket = var.free }
resource "aws_s3_bucket" "absent" {}
resource "aws_vpc" "v" { cidr_block = "10.0.0.0/16" }
resource "aws_s3_bucket" "unknown" { bucket = aws_vpc.v.id }
''')

    def run(cond, **kw):
        r = rule("t", ["aws_s3_bucket"]).where_(cond).message("{address} {witness|-}")
        res = tfscan.scan(d, builtin=False, rules=[r], **kw)
        return {f.address.split(".")[1]: f.severity for f in res.findings}

    assert run(col("bucket") == "logs") == {"known": "definite", "tainted": "conditional"}
    assert run(col("bucket") != "logs") == {"tainted": "conditional", "absent": "definite"}
    assert run(col("bucket").is_null()) == {"absent": "definite", "tainted": "conditional"}
    assert run(col("bucket").is_known() & col("bucket").is_not_null()) == {"known": "definite"}
    assert run(col("tags.env") == "prod") == {"known": "definite"}
    assert run(col("tags", "env").is_in(["dev", "prod"])) == {"known": "definite"}
    assert run(~(col("bucket") == "logs") & col("bucket").is_not_null()) == {"tainted": "conditional"}
    # Unknown never reports, even negated.
    assert "unknown" not in run(~(col("bucket") == "x"))


def test_list_predicates(tmp_path):
    d = write(tmp_path, '''
resource "aws_security_group" "a" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
  }
}
resource "aws_security_group" "b" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
''')

    def run(r):
        return sorted(f.address for f in tfscan.scan(d, builtin=False, rules=[r]).findings)

    base = rule("t", ["aws_security_group"]).message("{witness}")
    assert run(rule("t", ["aws_security_group"]).for_each("ingress")
               .where_(col("cidr_blocks").list.contains("0.0.0.0/0"))) == ["aws_security_group.a"]
    assert run(rule("t", ["aws_security_group"]).for_each("ingress")
               .where_(col("cidr_blocks").list.all(element() != "0.0.0.0/0"))) == ["aws_security_group.b"]
    assert run(rule("t", ["aws_security_group"])
               .where_(col("ingress").list.any(col("from_port") == 443))) == ["aws_security_group.b"]
    assert run(rule("t", ["aws_security_group"]).where_(col("ingress.0.to_port") >= 400)) == ["aws_security_group.b"]
    msgs = [f.message for f in tfscan.scan(d, builtin=False, rules=[
        rule("t", ["aws_security_group"]).for_each("ingress")
        .where_(col("cidr_blocks").list.any(element() == "0.0.0.0/0")).message("{address}: {witness}")]).findings]
    assert msgs == ["aws_security_group.a: 0.0.0.0/0"]
    assert base.name == "t"

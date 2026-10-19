import pytest

import tfscan
from conftest import FIXTURES, SSH_FIXTURES


def test_callback_sees_only_filtered_types():
    seen = []

    @tfscan.callback_rule("cb-types", resource_types=["aws_db_instance"])
    def check(res):
        seen.append(res.type)
        return None

    r = tfscan.scan(FIXTURES, recursive=True, builtin=False, rules=[check])
    assert seen and set(seen) == {"aws_db_instance"}
    assert r.callback_calls == len(seen)
    assert r.findings == []


def test_callback_reports():
    @tfscan.callback_rule("cb-rds", resource_types=["aws_db_instance"], level="high")
    def rds(res):
        v = res.get_or_default("storage_encrypted")
        if v.kind == "tainted":
            return tfscan.Report("maybe unencrypted", witness=v, conditional=True)
        if v.kind == "known" and v.py() is not True:
            return tfscan.Report(f"{res.address} unencrypted", witness=v)
        return None

    r = tfscan.scan(FIXTURES / "aws-rds-unencrypted", recursive=True, builtin=False, rules=[rds])
    b = tfscan.scan(FIXTURES / "aws-rds-unencrypted", recursive=True, select=["aws-rds-unencrypted"])
    assert {(f.address, f.root, f.severity) for f in r.findings} == {
        (f.address, f.root, f.severity) for f in b.findings}
    f = [x for x in r.findings if x.severity == "definite"][0]
    assert f.rule == "cb-rds" and f.level == "high" and f.provenance


def test_callback_return_forms():
    @tfscan.callback_rule("cb-forms", resource_types=["aws_security_group"])
    def forms(res):
        return ["first", tfscan.Report("second"), None, False]

    r = tfscan.scan(SSH_FIXTURES / "fail_inline_literal", builtin=False, rules=[forms])
    assert sorted(f.message for f in r.findings) == ["first", "second"]


def test_callback_exception_propagates():
    @tfscan.callback_rule("cb-boom", resource_types=["aws_security_group"])
    def boom(res):
        raise ZeroDivisionError("boom")

    with pytest.raises(ZeroDivisionError):
        tfscan.scan(SSH_FIXTURES / "fail_inline_literal", builtin=False, rules=[boom])


def test_mixed_rules():
    from tfscan.examples.sg_open_ssh import CALLBACK_RULE, EXPR_RULE

    r = tfscan.scan(SSH_FIXTURES / "fail_inline_literal", rules=[EXPR_RULE, CALLBACK_RULE], bundled=False)
    assert sorted(f.rule for f in r.findings) == ["aws-sg-open-ssh", "py-cb-sg-open-ssh", "py-sg-open-ssh"]

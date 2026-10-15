import pytest

import tfscan
from conftest import FIXTURES, SSH_FIXTURES


def test_scan_fixture_findings_fields():
    r = tfscan.scan(SSH_FIXTURES / "fail_tfvars_through_local")
    assert len(r.findings) == 1
    f = r.findings[0]
    assert f.rule == "aws-sg-open-ssh"
    assert f.level == "high"
    assert f.severity == "definite"
    assert f.address == "aws_security_group.admin"
    assert f.resource_type == "aws_security_group"
    assert f.module == ""
    assert f.message == "ingress allows SSH (port 22) from 0.0.0.0/0"
    assert f.file.endswith("fail_tfvars_through_local/main.tf")
    assert (f.line, f.column) == (6, 5)
    assert f.root.endswith("fail_tfvars_through_local")
    chain = [(p["kind"], p["file"].rsplit("/", 1)[1], p["line"]) for p in f.provenance]
    assert chain == [
        ("tfvars", "terraform.tfvars", 1),
        ("variable", "variables.tf", 1),
        ("local", "locals.tf", 2),
        ("attribute", "main.tf", 6),
    ]
    assert "provenance step 1/4" in f.render()
    assert '"severity":"definite"' in f.to_json().replace(" ", "")


def test_conditional_severity():
    r = tfscan.scan(SSH_FIXTURES / "conditional_unconstrained_variable")
    (f,) = r.findings
    assert f.severity == "conditional"
    assert "var.ssh_cidr" in f.message


def test_recursive_all_fixtures_match_expect():
    r = tfscan.scan(FIXTURES, recursive=True)
    got = {(f.rule, f.address, f.severity, f.root.rsplit("/", 1)[1]) for f in r.findings}
    expected = set()
    for case in FIXTURES.glob("*/*"):
        if not case.is_dir():
            continue
        for line in (case / "EXPECT").read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                rule, addr, sev = line.split()
                expected.add((rule, addr, sev, case.name))
    assert got == expected
    s = r.stats
    assert s["roots"] == 36  # keep in step with crates/tf_linter/tests/fixtures.rs
    assert s["findings"] == len(r.findings)
    assert s["definite"] + s["conditional"] + s["indeterminate"] == s["findings"]
    assert r.diagnostics == [] or all("severity" in d for d in r.diagnostics)


def test_builtin_selection_and_paths():
    r = tfscan.scan([SSH_FIXTURES / "fail_inline_literal", SSH_FIXTURES / "pass_restricted"])
    assert r.stats["roots"] == 2 and len(r.findings) == 1
    assert tfscan.scan(SSH_FIXTURES / "fail_inline_literal", builtin=False).findings == []
    assert len(tfscan.scan(SSH_FIXTURES / "fail_inline_literal", builtin=["aws-sg-open-ssh"]).findings) == 1
    assert tfscan.scan(SSH_FIXTURES / "fail_inline_literal", builtin=["aws-rds-unencrypted"]).findings == []
    names = {r["name"] for r in tfscan.builtin_rules()}
    assert "aws-sg-open-ssh" in names and len(names) == 5


def test_var_files(tmp_path):
    vf = tmp_path / "open.tfvars"
    vf.write_text('admin_cidr = "10.0.0.0/8"\n')
    r = tfscan.scan(SSH_FIXTURES / "fail_tfvars_through_local", var_files=[vf])
    assert r.findings == []


def test_not_a_directory():
    with pytest.raises(ValueError):
        tfscan.scan("/nonexistent/dir")


def test_resources_and_values():
    r = tfscan.analyze(FIXTURES / "aws-sg-open-ssh" / "conditional_unconstrained_variable")
    assert r.findings == []
    (res,) = [x for x in r.resources if x.type == "aws_security_group"]
    assert res.address == "aws_security_group.maybe" and res.mode == "managed"
    assert res.existence == "true" and res.line == 5 and res.root.endswith("variable")
    ingress = res["ingress"]
    assert ingress.kind == "known" and ingress.type_name == "list"
    (rule,) = ingress.items()
    cidrs = rule.get("cidr_blocks")
    (c,) = cidrs.items()
    assert c.kind == "tainted" and c.variable == "ssh_cidr"
    assert rule.get("from_port").py() == 22
    assert rule.get("nonexistent").is_null
    assert "ingress" in res and "nope" not in res and res.get("nope") is None
    with pytest.raises(KeyError):
        res["nope"]
    py = ingress.py()
    assert py[0]["protocol"] == "tcp"
    assert isinstance(py[0]["cidr_blocks"][0], tfscan.Value)
    assert '"$tainted": "var.ssh_cidr"' in res.to_json().replace('":"', '": "')


def test_defaults_overlay_and_unknown():
    r = tfscan.analyze(FIXTURES / "aws-rds-unencrypted" / "fail_absent_uses_default")
    (db,) = [x for x in r.resources if x.type == "aws_db_instance"]
    assert db.get("storage_encrypted") is None
    d = db.get_or_default("storage_encrypted")
    assert d.py() is False
    assert d.provenance[0]["kind"] == "default"
    r = tfscan.analyze(FIXTURES / "aws-s3-public-access-block" / "fail_permissive_block")
    (pab,) = [x for x in r.resources if x.type == "aws_s3_bucket_public_access_block"]
    b = pab["bucket"]
    assert b.kind == "unknown" and "computed by provider" in b.origin


@pytest.mark.parametrize("ids", [["typo"], ["aws-sg-open-ssh", "typo"]])
def test_unknown_builtin_rule_is_an_error(ids):
    with pytest.raises(ValueError, match="unknown rule ID.*typo"):
        tfscan.scan(SSH_FIXTURES / "fail_inline_literal", builtin=ids)


def test_explicit_empty_builtin_selection():
    assert tfscan.scan(SSH_FIXTURES / "fail_inline_literal", builtin=[]).findings == []

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
    assert len(tfscan.scan(SSH_FIXTURES / "fail_inline_literal", select=["aws-sg-open-ssh"]).findings) == 1
    assert tfscan.scan(SSH_FIXTURES / "fail_inline_literal", select=["aws-rds-unencrypted"]).findings == []
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
def test_unknown_rule_id_is_an_error(ids):
    with pytest.raises(ValueError, match="unknown rule ID.*typo"):
        tfscan.scan(SSH_FIXTURES / "fail_inline_literal", select=ids)


def test_explicit_empty_selection():
    assert tfscan.scan(SSH_FIXTURES / "fail_inline_literal", select=[]).findings == []
    assert tfscan.scan(SSH_FIXTURES / "fail_inline_literal", builtin=False).rule_errors == []


def test_selection_covers_custom_rules_too():
    from tfscan.examples.sg_open_ssh import EXPR_RULE

    r = tfscan.scan(SSH_FIXTURES / "fail_inline_literal", rules=[EXPR_RULE], select=[EXPR_RULE.name])
    assert {f.rule for f in r.findings} == {EXPR_RULE.name}
    r = tfscan.scan(SSH_FIXTURES / "fail_inline_literal", rules=[EXPR_RULE], select=["aws-sg-open-ssh"])
    assert {f.rule for f in r.findings} == {"aws-sg-open-ssh"}
    r = tfscan.scan(SSH_FIXTURES / "fail_inline_literal", rules=[EXPR_RULE])
    assert {f.rule for f in r.findings} == {EXPR_RULE.name, "aws-sg-open-ssh"}


def test_scan_plan_maps_to_source():
    plan = FIXTURES.parent / "plans" / "aws-s3-public-access-block" / "fail_permissive_block.json"
    src = FIXTURES / "aws-s3-public-access-block" / "fail_permissive_block"
    r = tfscan.scan_plan(plan, source=src)
    (f,) = r.findings
    assert (f.address, f.severity) == ("aws_s3_bucket.data", "definite")
    assert f.file.endswith("fail_permissive_block/main.tf") and f.line == 1
    assert r.stats["roots"] == 1
    assert len(r.resources) >= 2
    with pytest.raises(ValueError, match="invalid JSON"):
        tfscan.scan_plan(src / "main.tf")


def test_rego_native_matches_builtin():
    root = FIXTURES / "aws-rds-unencrypted"
    rego = tfscan.scan(root, recursive=True, rego_native=True)
    native = tfscan.scan(root, recursive=True)
    key = lambda r: sorted((f.rule, f.address, f.severity, f.message) for f in r.findings)
    assert key(rego) == key(native) and len(rego.findings) == 5


def test_foreign_policy_and_rule_errors():
    rego = FIXTURES.parent / "rego"
    policy = rego / "foreign" / "conftest_hcl2_deny.rego"
    r = tfscan.scan(rego / "foreign", builtin=False, policies=[policy], policy_shape="hcl")
    assert {f.rule for f in r.findings} == {"rego:conftest_hcl2_deny"}
    assert sorted(f.severity for f in r.findings) == ["conditional", "definite", "definite", "indeterminate"]
    assert r.rule_errors == []
    r = tfscan.scan(rego / "foreign_sprintf", builtin=False, policies=[policy], policy_shape="hcl")
    (e,) = r.rule_errors
    assert e["rule"] == "rego:conftest_hcl2_deny" and e["resource"] == "aws_security_group_rule.open"
    assert "%q" in e["message"]
    with pytest.raises(ValueError, match="cannot read policy"):
        tfscan.scan(rego / "foreign", policies=[rego / "missing.rego"])

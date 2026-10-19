import pytest

import tfscan
from conftest import FIXTURES, SSH_FIXTURES


def test_scan_fixture_findings_fields():
    r = tfscan.scan(SSH_FIXTURES / "fail_tfvars_through_local", bundled=False)
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
    r = tfscan.scan(SSH_FIXTURES / "conditional_unconstrained_variable", bundled=False)
    (f,) = r.findings
    assert f.severity == "conditional"
    assert "var.ssh_cidr" in f.message


def test_recursive_all_fixtures_match_expect():
    r = tfscan.scan(FIXTURES, recursive=True, bundled=False)
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
    r = tfscan.scan([SSH_FIXTURES / "fail_inline_literal", SSH_FIXTURES / "pass_restricted"], bundled=False)
    assert r.stats["roots"] == 2 and len(r.findings) == 1
    assert tfscan.scan(SSH_FIXTURES / "fail_inline_literal", builtin=False).findings == []
    assert len(tfscan.scan(SSH_FIXTURES / "fail_inline_literal", select=["aws-sg-open-ssh"]).findings) == 1
    assert tfscan.scan(SSH_FIXTURES / "fail_inline_literal", select=["aws-rds-unencrypted"]).findings == []
    names = {r["name"] for r in tfscan.builtin_rules()}
    assert "aws-sg-open-ssh" in names and len(names) == 5


def test_var_files(tmp_path):
    vf = tmp_path / "open.tfvars"
    vf.write_text('admin_cidr = "10.0.0.0/8"\n')
    r = tfscan.scan(SSH_FIXTURES / "fail_tfvars_through_local", var_files=[vf], bundled=False)
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

    r = tfscan.scan(SSH_FIXTURES / "fail_inline_literal", rules=[EXPR_RULE], select=[EXPR_RULE.name], bundled=False)
    assert {f.rule for f in r.findings} == {EXPR_RULE.name}
    r = tfscan.scan(SSH_FIXTURES / "fail_inline_literal", rules=[EXPR_RULE], select=["aws-sg-open-ssh"], bundled=False)
    assert {f.rule for f in r.findings} == {"aws-sg-open-ssh"}
    r = tfscan.scan(SSH_FIXTURES / "fail_inline_literal", rules=[EXPR_RULE], bundled=False)
    assert {f.rule for f in r.findings} == {EXPR_RULE.name, "aws-sg-open-ssh"}


def test_scan_plan_maps_to_source():
    plan = FIXTURES.parent / "plans" / "aws-s3-public-access-block" / "fail_permissive_block.json"
    src = FIXTURES / "aws-s3-public-access-block" / "fail_permissive_block"
    r = tfscan.scan_plan(plan, source=src, bundled=False)
    (f,) = r.findings
    assert (f.address, f.severity) == ("aws_s3_bucket.data", "definite")
    assert f.file.endswith("fail_permissive_block/main.tf") and f.line == 1
    assert r.stats["roots"] == 1
    assert len(r.resources) >= 2
    with pytest.raises(ValueError, match="invalid JSON"):
        tfscan.scan_plan(src / "main.tf")


def test_rego_native_matches_builtin():
    root = FIXTURES / "aws-rds-unencrypted"
    rego = tfscan.scan(root, recursive=True, rego_native=True, bundled=False)
    native = tfscan.scan(root, recursive=True, bundled=False)
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
    # Conftest evaluates the whole file, so the error names the file.
    assert e["rule"] == "rego:conftest_hcl2_deny" and e["resource"] is None
    assert "%q" in e["message"] and "foreign_sprintf/main.tf" in e["message"]
    with pytest.raises(ValueError, match="missing.rego"):
        tfscan.scan(rego / "foreign", policies=[rego / "missing.rego"])


def test_rule_files_of_every_format_and_policy_options():
    mixed = FIXTURES.parent / "rules_mixed"
    r = tfscan.scan(mixed / "tf", builtin=False, rule_files=[mixed / "policies"])
    assert sorted(f.rule for f in r.findings) == ["CKV2_MIXED_1", "MIXED_OWNER_TAG", "py-sg-open-ssh"]
    assert r.rule_errors == []
    listed = {x["name"]: x for x in tfscan.rules([mixed / "policies"], builtin=False)}
    assert listed["CKV2_MIXED_1"]["source"]["engine"] == "checkov"
    assert listed["CKV2_MIXED_1"]["guideline"] == "https://example.com/guidelines/s3-versioning"
    assert listed["MIXED_OWNER_TAG"]["source"]["line"] == 13
    conftest = FIXTURES.parent / "rego" / "conftest"
    r = tfscan.scan(conftest / "tf", builtin=False, rule_files=[conftest / "policy"])
    subjects = sorted(f.subject["kind"] for f in r.findings)
    assert subjects == ["file", "file", "resource"]
    assert {f.resource_type for f in r.findings} == {None, "aws_s3_bucket"}
    outcomes = {o["rule"]: o["result"] for o in tfscan.test_policies([conftest / "policy"])}
    assert outcomes == {
        "data.main.test_unpinned_module_is_denied": "pass",
        "data.main.test_pinned_module_passes": "pass",
        "data.main.test_a_failing_test_fails": "fail",
        "data.main.todo_test_regions": "skip",
    }
    # OPA mode with several entries, from Python.
    ports = FIXTURES.parent / "rego" / "ports"
    r = tfscan.scan(
        FIXTURES.parent / "rego" / "ports_tf" / "known",
        builtin=False,
        rule_files=[ports],
        policy_entries=["data.ports.rds.deny", "data.ports.s3_public_access_block.deny"],
        policy_shape="plan",
    )
    assert sorted(f.rule for f in r.findings) == ["PORT-AWS-RDS-UNENCRYPTED", "PORT-AWS-S3-PUBLIC-ACCESS-BLOCK"]


def test_overlay_shadows_disk_and_verifies_a_fix():
    case = FIXTURES / "aws-rds-unencrypted" / "fail_explicit_false"
    before = tfscan.scan(case, bundled=False)
    (f,) = before.findings
    fixed = (case / "main.tf").read_text().replace("= false", "= true")
    after = tfscan.scan(case, overlay={case / "main.tf": fixed}, bundled=False)
    assert after.findings == [] and after.stats["files"] == 1
    assert f.fingerprint not in {g.fingerprint for g in after.findings}
    assert "= false" in (case / "main.tf").read_text()
    # A module that exists only in memory.
    mem = "/nonexistent/oxtf-py-overlay"
    r = tfscan.scan(mem, overlay={f"{mem}/main.tf": 'resource "aws_db_instance" "x" { storage_encrypted = false }'}, bundled=False)
    assert [(g.address, g.severity) for g in r.findings] == [("aws_db_instance.x", "definite")]
    assert r.findings[0].file == f"{mem}/main.tf"


def test_checkov_skip_comments_are_reported():
    base = FIXTURES.parent / "checkov_skip"
    r = tfscan.scan(base / "tf", builtin=False, rule_files=[base / "policies"])
    assert sorted(f.address for f in r.findings) == [
        "aws_db_instance.other_id", "aws_db_instance.outside", "module.child2.aws_db_instance.inner"]
    assert sorted((s["resource"], s["comment"]) for s in r.suppressed) == [
        ("aws_db_instance.bare_skip", "No comment provided"),
        ("aws_db_instance.skipped", "encrypted by the platform"),
        ("module.child.aws_db_instance.inner", "module-wide"),
    ]


def test_bundled_checkov_catalog_runs_by_default():
    case = FIXTURES / "aws-rds-unencrypted" / "fail_explicit_false"
    ids = {f.rule for f in tfscan.scan(case).findings}
    assert {"CKV_AWS_16", "aws-rds-unencrypted"} <= ids
    assert {f.rule for f in tfscan.scan(case, bundled=False).findings} == {"aws-rds-unencrypted"}
    assert tfscan.scan(case, builtin=False).findings == []
    assert [f.rule for f in tfscan.scan(case, select=["CKV_AWS_16"]).findings] == ["CKV_AWS_16"]
    listed = {r["name"]: r for r in tfscan.rules()}
    assert listed["CKV_AWS_16"]["source"]["engine"] == "checkov"
    # gcp-storage-uniform-access replaces CKV_GCP_29, its alias.
    assert len(listed) == len(tfscan.rules(bundled=False)) + 1079 - 1
    assert listed["gcp-storage-uniform-access"]["aliases"] == ["CKV_GCP_29"]
    assert "CKV_GCP_29" not in listed


def test_a_seed_rule_answers_to_its_checkov_alias():
    case = FIXTURES / "gcp-storage-uniform-access" / "fail_absent"
    ids = {f.rule for f in tfscan.scan(case).findings}
    assert "gcp-storage-uniform-access" in ids and "CKV_GCP_29" not in ids
    selected = tfscan.scan(case, select=["CKV_GCP_29"]).findings
    assert [f.rule for f in selected] == ["gcp-storage-uniform-access"]

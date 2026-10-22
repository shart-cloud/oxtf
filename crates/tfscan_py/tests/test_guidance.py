import json

import pytest

import tfscan


def test_curated_metadata_is_available_in_catalog_and_findings(tmp_path):
    catalog = {r["name"]: r for r in tfscan.rules()}
    for name, level in [("CKV_AWS_17", "high"), ("CKV_AZURE_190", "medium"),
                        ("CKV_AWS_61", "medium"), ("CKV_AWS_355", "medium"),
                        ("aws-rds-unencrypted", "medium")]:
        assert catalog[name]["level"] == level
        assert catalog[name]["rationale"]
        assert catalog[name]["remediation"]
        assert catalog[name]["guideline"].startswith("https://")
    result = tfscan.scan(tmp_path, overlay={tmp_path / "main.tf":
        'resource "aws_db_instance" "db" { storage_encrypted = false }'},
        select=["aws-rds-unencrypted", "CKV_AWS_16"])
    record = json.loads(result.to_json())
    assert len(record["findings"]) == 2
    for name, info in record["rules"].items():
        assert info["remediation"] == catalog[name]["remediation"]
        assert "snapshot" in info["remediation"]
        assert info["rationale"] == catalog[name]["rationale"]


def test_custom_keys_are_not_reported_as_missing_baseline_encryption(tmp_path):
    result = tfscan.scan(tmp_path, overlay={tmp_path / "main.tf":
        'resource "aws_cloudwatch_log_group" "logs" { name = "example" }'})
    assert "CKV_AWS_158" not in {f.rule for f in result.findings}
    result = tfscan.scan(tmp_path, overlay={tmp_path / "main.tf":
        'resource "aws_cloudwatch_log_group" "logs" { name = "example" }'},
        select=["CKV_AWS_158"])
    [finding] = result.findings
    assert finding.level == "low"
    info = json.loads(result.to_json())["rules"][finding.rule]
    assert "encrypts log data by default" in info["rationale"]
    assert "customer" in info["remediation"]


@pytest.mark.parametrize("module,resource,attribute,rule", [
    ("GKEPodSecurityPolicyEnabled", "google_container_cluster", "min_master_version", "CKV_GCP_24"),
    ("GKEUseCosImage", "google_container_node_pool", "version", "CKV_GCP_22"),
])
def test_pinned_checkov_null_version_errors_are_not_hidden(tmp_path, module, resource, attribute, rule):
    checker = pytest.importorskip("checkov.terraform.checks.resource.gcp." + module).check
    with pytest.raises(AttributeError):
        checker.scan_resource_conf({attribute: [None]})
    result = tfscan.scan(tmp_path, overlay={tmp_path / "main.tf":
        f'resource "{resource}" "r" {{ {attribute} = null }}'}, select=[rule])
    record = json.loads(result.to_json())
    assert result.status == "failed"
    assert len(record["rule_errors"]) == 1
    assert "AttributeError" in record["rule_errors"][0]["message"]

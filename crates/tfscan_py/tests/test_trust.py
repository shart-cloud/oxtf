import json

import tfscan


def test_status_reports_parse_and_coverage_failures(tmp_path):
    path = tmp_path / "main.tf"
    failed = tfscan.scan(tmp_path, overlay={path: "bad = )"}, bundled=False)
    assert failed.status == "failed"
    assert json.loads(failed.to_json())["status"] == "failed"
    partial = tfscan.scan(tmp_path, overlay={path: 'module "m" { source = "vendor/name/aws" }'},
                          bundled=False)
    assert partial.status == "incomplete"


def test_sensitive_exports_and_fix_preview(tmp_path):
    secret = "DO-NOT-PRINT-SECRET"
    path = tmp_path / "main.tf"
    overlay = {path: f'resource "aws_db_instance" "db" {{\npassword = "{secret}"\nstorage_encrypted = false\n}}\n'}
    result = tfscan.scan(tmp_path, overlay=overlay, bundled=False)
    assert result.status == "complete"
    resource = result.resources[0]
    assert resource["password"].sensitive
    assert resource["password"].to_str() == secret  # Explicit evaluator access.
    assert secret not in result.to_json()
    assert secret not in result.findings[0].render()
    assert secret not in json.dumps(result.resources.to_arrow().to_pylist())
    assert secret not in json.dumps(result.findings_arrow().to_pylist())
    fixed = tfscan.fix(result.findings[0].fingerprint, tmp_path, overlay=overlay, bundled=False)
    assert fixed["verified"]
    assert fixed["target_resolved"] and fixed["no_new_findings"]
    assert fixed["verification_errors"] == []
    assert secret not in fixed["diff"]
    assert secret not in json.dumps(fixed["finding_delta"])


def test_fix_distinguishes_target_resolution_from_new_findings(tmp_path):
    path = tmp_path / "main.tf"
    overlay = {path: '''
variable "encrypted" { default = false }
resource "aws_db_instance" "target" { storage_encrypted = var.encrypted }
resource "aws_db_instance" "other" { storage_encrypted = !var.encrypted }
'''}
    opts = dict(overlay=overlay, select=["aws-rds-unencrypted"])
    [finding] = tfscan.scan(tmp_path, **opts).findings
    fixed = tfscan.fix(finding.fingerprint, tmp_path, at="default", **opts)
    assert fixed["target_resolved"]
    assert not fixed["no_new_findings"] and not fixed["verified"]
    assert fixed["verification_errors"] == []
    delta = fixed["finding_delta"]
    assert delta["before"] == delta["after"] == 1
    assert delta["removed"][0]["fingerprint"] == finding.fingerprint
    assert delta["added"][0]["occurrences"][0]["address"] == "aws_db_instance.other"
    assert delta["changed"] == [] and delta["unchanged"] == 0

    fixed = tfscan.fix(finding.fingerprint, tmp_path, **opts)
    assert fixed["site"] == "attribute"
    assert fixed["target_resolved"] and fixed["no_new_findings"] and fixed["verified"]
    assert fixed["finding_delta"]["after"] == 0
    assert not path.exists()


def test_fix_reports_new_occurrences_of_an_existing_finding(tmp_path):
    overlay = {tmp_path / "main.tf": '''
variable "encrypted" { default = false }
resource "aws_db_instance" "target" { storage_encrypted = var.encrypted }
resource "aws_db_instance" "other" {
  count = 2
  storage_encrypted = count.index == 0 ? false : !var.encrypted
}
'''}
    opts = dict(overlay=overlay, select=["aws-rds-unencrypted"])
    before = json.loads(tfscan.scan(tmp_path, **opts).to_json())
    target = next(f for f in before["findings"]
                  if f["occurrences"][0]["address"] == "aws_db_instance.target")
    fixed = tfscan.fix(target["fingerprint"], tmp_path, at="default", **opts)
    assert fixed["target_resolved"] and not fixed["no_new_findings"]
    assert not fixed["verified"]
    delta = fixed["finding_delta"]
    assert (delta["before"], delta["after"]) == (2, 1)
    assert delta["added"] == []
    [change] = delta["changed"]
    assert change["before"]["fingerprint"] == change["after"]["fingerprint"]
    assert len(change["before"]["occurrences"]) == 1
    assert len(change["after"]["occurrences"]) == 2
    assert change["added_occurrences"][0]["address"] == "aws_db_instance.other[1]"
    assert change["removed_occurrences"] == []


def test_fix_does_not_claim_resolution_when_analysis_is_incomplete(tmp_path):
    overlay = {tmp_path / "main.tf": '''
module "missing" { source = "vendor/name/aws" }
resource "aws_db_instance" "target" { storage_encrypted = false }
'''}
    opts = dict(overlay=overlay, select=["aws-rds-unencrypted"])
    [finding] = tfscan.scan(tmp_path, **opts).findings
    fixed = tfscan.fix(finding.fingerprint, tmp_path, **opts)
    assert not fixed["target_resolved"] and not fixed["no_new_findings"]
    assert not fixed["verified"]
    assert fixed["verification_errors"]
    assert fixed["finding_delta"]["before"] == 1
    assert fixed["finding_delta"]["after"] == 0


def test_callback_messages_and_recorded_errors_are_redacted(tmp_path):
    secret = "DO-NOT-PRINT-SECRET"
    overlay = {tmp_path / "main.tf": f'resource "test_resource" "r" {{ value = sensitive("{secret}") }}'}

    def report(resource):
        return resource["value"].to_str()

    def fail(resource):
        raise RuntimeError(resource["value"].to_str())

    rules = [tfscan.CallbackRule(report, "report", ["test_resource"]),
             tfscan.CallbackRule(fail, "fail", ["test_resource"], record_errors=True)]
    result = tfscan.scan(tmp_path, overlay=overlay, rules=rules, builtin=False, bundled=False)
    assert result.status == "failed"
    assert len(result.findings) == 1 and len(result.rule_errors) == 1
    assert secret not in result.to_json()

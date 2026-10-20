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
    assert fixed["verification_errors"] == []
    assert secret not in fixed["diff"]


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

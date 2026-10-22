"""Depth and worker limits retain their contracts through Python entry points."""
import json

import pytest
import tfscan


@pytest.mark.parametrize("workers", [0, 65])
def test_invalid_workers_are_value_errors(tmp_path, workers):
    with pytest.raises(ValueError, match="worker count"):
        tfscan.scan(tmp_path, threads=workers, bundled=False)


@pytest.mark.parametrize("name, content", [
    ("main.tf", "v = " + "!" * 1000 + "true\n"),
    ("main.tf", "v = " + "+".join(["1"] * 1000) + "\n"),
    ("main.tf.json", json.dumps({"locals": {"v": "${" + "!" * 1000 + "true}"}})),
    ("terraform.tfvars.json", '{"v":' + "[" * 1000 + "0" + "]" * 1000 + "}"),
])
def test_depth_is_incomplete_through_scan(tmp_path, name, content):
    (tmp_path / name).write_text(content)
    (tmp_path / "resource.tf").write_text('resource "aws_db_instance" "db" { storage_encrypted = false }')
    result = tfscan.scan(tmp_path, bundled=False)
    assert result.status == "incomplete"
    assert any(d["code"] == "coverage-parse-limit" for d in result.diagnostics)
    assert not any(d["code"] == "parse-error" for d in result.diagnostics)


def test_parse_does_not_expose_an_oversized_ast():
    document = tfscan.parse("v = " + "+".join(["1"] * 30_000) + "\n")
    assert document.errors
    assert document.root.attributes() == []
    assert document.node_count == 2  # File and its empty Body.


@pytest.mark.parametrize("limits", [
    {"evaluation_steps": 0}, {"evaluation_steps": -1}, {"evaluation_steps": True},
    {"evaluation_steps": None}, {"evaluation_steps": 1.0}, {"evaluation_steps": "1"},
    {"evaluation_steps": 2**64}, {"unknown": 1},
    {"loader_steps": 0}, {"loader_steps": -1}, {"loader_steps": True},
    {"loader_steps": None}, {"loader_steps": 1.0}, {"loader_steps": "1"},
    {"loader_steps": 2**64},
    {"rule_steps": 0}, {"rule_steps": -1}, {"rule_steps": True},
    {"rule_steps": None}, {"rule_steps": 1.0}, {"rule_steps": "1"},
    {"rule_steps": 2**64},
])
def test_invalid_budgets_fail_before_inputs(tmp_path, limits):
    with pytest.raises(ValueError, match="evaluation_steps|loader_steps|rule_steps|limits"):
        tfscan.scan(tmp_path / "missing", limits=limits)


@pytest.mark.parametrize("field", [
    "input_bytes", "source_bytes", "file_entries", "directory_entries", "roots", "rego_time_ms", "arena_bytes", "ast_nodes", "text_bytes", "collection_bytes"
])
def test_invalid_storage_and_backend_limits_fail_before_inputs(tmp_path, field):
    for value in [0, -1, True, None, 1.0, "1", 2**64]:
        with pytest.raises(ValueError, match=field):
            tfscan.scan(tmp_path / "missing", limits={field: value})
    if field in ["input_bytes", "file_entries"]:
        with pytest.raises(ValueError, match=field):
            tfscan.scan(tmp_path / "missing", limits={field: 2**32})


def test_input_admission_reaches_scan_analyze_overlay_plan_and_fix(tmp_path):
    source = 'resource "aws_db_instance" "db" { storage_encrypted = false }'
    path = tmp_path / "main.tf"
    path.write_text(source)
    base = tfscan.scan(tmp_path, bundled=False)
    fingerprint = base.findings[0].fingerprint
    limits = {"input_bytes": len(source) - 1}
    for result in [
        tfscan.scan(tmp_path, bundled=False, limits=limits),
        tfscan.analyze(tmp_path, limits=limits),
        tfscan.scan(tmp_path, bundled=False, overlay={str(path): source}, limits=limits),
        tfscan.scan_plan(path, bundled=False, limits=limits),
    ]:
        assert result.status == "incomplete"
        assert sum(d["code"] == "coverage-storage" for d in result.diagnostics) == 1
    # A limit may prevent the finding from being constructed at all; no edit can verify.
    try:
        outcome = tfscan.fix(fingerprint, tmp_path, bundled=False, limits=limits)
    except ValueError as error:
        assert "finding" in str(error)
    else:
        assert not outcome["verified"]
    assert tfscan.scan(tmp_path, bundled=False, limits={"input_bytes": len(source)}).status == "complete"


def test_rego_timer_failure_survives_python_adapter(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_db_instance" "db" {}')
    policy = tmp_path / "policy.rego"
    policy.write_text('''package main
import rego.v1
deny contains "bad" if {
    input.resource.aws_db_instance.db
    some x in numbers.range(1, 2000)
    some y in numbers.range(1, 2000)
    x + y == 999999
}''')
    result = tfscan.scan(tmp_path, builtin=False, bundled=False,
                         policies=[policy], limits={"rego_time_ms": 1})
    assert result.status == "failed"
    assert len(result.rule_errors) == 1
    assert "rego_time_ms" in result.rule_errors[0]["message"]


def test_budget_config_survives_fix_and_analyze(tmp_path):
    (tmp_path / "main.tf").write_text('''resource "aws_db_instance" "db" {
      storage_encrypted = false
      allocated_storage = 1 + 2
    }''')
    limits = {"evaluation_steps": 3}
    result = tfscan.scan(tmp_path, limits=limits, bundled=False)
    assert result.status == "incomplete"
    assert any(d["code"] == "coverage-budget" for d in result.diagnostics)
    assert tfscan.analyze(tmp_path, limits=limits).status == "incomplete"
    assert tfscan.scan(tmp_path, limits={}, bundled=False).status == "complete"
    fingerprint = result.findings[0].fingerprint
    limited = tfscan.fix(fingerprint, tmp_path, limits=limits, bundled=False)
    assert not limited["verified"]
    assert any("coverage-budget" in error for error in limited["verification_errors"])
    assert tfscan.fix(fingerprint, tmp_path, limits={"evaluation_steps": 100},
                      bundled=False)["verified"]


def test_plan_source_mapping_uses_the_same_budget(tmp_path):
    (tmp_path / "main.tf").write_text('''resource "aws_db_instance" "db" {
      storage_encrypted = false
      allocated_storage = 1 + 2
    }''')
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"format_version": "1.2", "planned_values": {
        "root_module": {"resources": [{"address": "aws_db_instance.db", "mode": "managed",
        "type": "aws_db_instance", "name": "db", "values": {"storage_encrypted": False}}]}
    }}))
    result = tfscan.scan_plan(plan, source=tmp_path, limits={"evaluation_steps": 1}, bundled=False)
    assert result.status == "incomplete"
    assert any(d["code"] == "coverage-budget" for d in result.diagnostics)


@pytest.mark.parametrize("format", ["hcl", "json"])
def test_cached_default_allowance_reaches_scan_and_analyze(tmp_path, format):
    if format == "hcl":
        (tmp_path / "main.tf").write_text('''variable "value" {
          type = list(number)
          default = [1, 2, 3]
        }''')
        (tmp_path / "override.tf").write_text("")
    else:
        (tmp_path / "main.tf.json").write_text(json.dumps({"variable": {
            "value": {"type": "list(number)", "default": [1, 2, 3]}}}))
        (tmp_path / "override.tf.json").write_text("{}")
    limits = {"loader_steps": 1}
    for result in [tfscan.scan(tmp_path, limits=limits, bundled=False),
                   tfscan.analyze(tmp_path, limits=limits)]:
        assert result.status == "incomplete"
        diagnostic = next(d for d in result.diagnostics if d["code"] == "coverage-budget")
        assert "loader_steps" in diagnostic["message"]
        assert not any(d["code"] == "parse-error" for d in result.diagnostics)
    assert tfscan.scan(tmp_path, limits={"loader_steps": 1000}, bundled=False).status == "complete"


def test_plan_mapping_retains_loader_exhaustion(tmp_path):
    (tmp_path / "main.tf").write_text('variable "value" { default = [1, 2, 3] }')
    (tmp_path / "override.tf").write_text("")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"format_version": "1.2", "planned_values": {"root_module": {}}}))
    result = tfscan.scan_plan(plan, source=tmp_path, limits={"loader_steps": 1}, bundled=False)
    assert result.status == "incomplete"
    diagnostic = next(d for d in result.diagnostics if d["code"] == "coverage-budget")
    assert "loader_steps" in diagnostic["message"]


@pytest.mark.parametrize("format", ["hcl", "json"])
def test_runtime_cached_conversion_has_a_separate_root_allowance(tmp_path, format):
    values = list(range(64))
    if format == "hcl":
        (tmp_path / "main.tf").write_text(
            'variable "value" {\n type = list(number)\n default = ' + json.dumps(values) + '\n}')
        (tmp_path / "override.tf").write_text("")
    else:
        (tmp_path / "main.tf.json").write_text(json.dumps({"variable": {
            "value": {"type": "list(number)", "default": values}}}))
        (tmp_path / "override.tf.json").write_text("{}")
    for result in [tfscan.scan(tmp_path, limits={"evaluation_steps": 2}, bundled=False),
                   tfscan.analyze(tmp_path, limits={"evaluation_steps": 2})]:
        assert result.status == "incomplete"
        diagnostic = next(d for d in result.diagnostics if d["code"] == "coverage-budget")
        assert "evaluation_steps" in diagnostic["message"]
    assert tfscan.scan(tmp_path, limits={"evaluation_steps": 1000}, bundled=False).status == "complete"


def test_rule_budget_stops_rules_and_fix_verification(tmp_path):
    (tmp_path / "main.tf").write_text('''
        resource "aws_db_instance" "a" { storage_encrypted = false }
        resource "aws_db_instance" "b" { storage_encrypted = false }
    ''')
    options = dict(select=["aws-rds-unencrypted"], bundled=False)
    limited = tfscan.scan(tmp_path, limits={"rule_steps": 1}, **options)
    assert limited.status == "failed"
    assert len(limited.findings) == len(limited.rule_errors) == 1
    assert "rule_steps" in limited.rule_errors[0]["message"]
    fixed = tfscan.fix(limited.findings[0].fingerprint, tmp_path,
                       limits={"rule_steps": 1}, **options)
    assert not fixed["verified"]
    assert any("rule_steps" in error for error in fixed["verification_errors"])
    assert tfscan.scan(tmp_path, limits={"rule_steps": 2}, **options).status == "complete"


def test_plan_rules_have_the_same_allowance_without_source_mapping(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"format_version": "1.2", "resource_changes": [
        {"address": f"aws_db_instance.{name}", "mode": "managed", "type": "aws_db_instance",
         "name": name, "change": {"actions": ["create"], "after": {"storage_encrypted": False},
                                  "after_unknown": {}, "after_sensitive": {}}}
        for name in ["a", "b"]
    ]}))
    for allowance, status in [(1, "failed"), (2, "complete")]:
        result = tfscan.scan_plan(plan, limits={"rule_steps": allowance},
                                  select=["aws-rds-unencrypted"], bundled=False)
        assert result.stats["resources"] == 2
        assert result.status == status
        assert len(result.findings) == allowance
        assert len(result.rule_errors) == (1 if allowance == 1 else 0)


def test_callback_admission_stops_after_the_root_allowance(tmp_path):
    (tmp_path / "main.tf").write_text('''
        resource "test_resource" "a" {}
        resource "test_resource" "b" {}
    ''')
    seen = []

    @tfscan.callback_rule("budget-callback", resource_types=["test_resource"])
    def check(resource):
        seen.append(resource.address)
        return None

    result = tfscan.scan(tmp_path, rules=[check], builtin=False, bundled=False,
                         limits={"rule_steps": 1})
    assert result.status == "failed"
    assert result.callback_calls == len(seen) == 1
    assert len(result.rule_errors) == 1
    assert "rule_steps" in result.rule_errors[0]["message"]


@pytest.mark.parametrize("field", ["arena_bytes", "ast_nodes"])
def test_arena_admission_reaches_scan_analyze_and_plan_mapping(tmp_path, field):
    source = 'resource "aws_db_instance" "db" { storage_encrypted = false }'
    path = tmp_path / "main.tf"
    path.write_text(source)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"format_version": "1.2", "planned_values": {
        "root_module": {"resources": [{"address": "aws_db_instance.db", "mode": "managed",
        "type": "aws_db_instance", "name": "db", "values": {"storage_encrypted": False}}]}
    }}))
    limits = {field: 1}
    for result in [
        tfscan.scan(tmp_path, bundled=False, limits=limits),
        tfscan.analyze(tmp_path, limits=limits),
        tfscan.scan_plan(plan, source=tmp_path, bundled=False, limits=limits),
    ]:
        assert result.status == "incomplete"
        diagnostics = [d for d in result.diagnostics if d["code"] == "coverage-storage"]
        assert len(diagnostics) == 1
        assert field in diagnostics[0]["message"]


def test_text_amplification_is_incomplete_through_python(tmp_path):
    path = tmp_path / "main.tf"
    path.write_text('resource "aws_db_instance" "db" { storage_encrypted = false }\n'
                    'locals { v = try(replace("aa", "a", "long text"), "fallback") }')
    for result in [tfscan.scan(tmp_path, bundled=False, limits={"text_bytes": 32}),
                   tfscan.analyze(tmp_path, limits={"text_bytes": 32})]:
        assert result.status == "incomplete"
        limited = [d for d in result.diagnostics if d["code"] == "coverage-storage"]
        assert len(limited) == 1
        assert "text_bytes" in limited[0]["message"]


@pytest.mark.parametrize("expression", [
    "try(reverse([1, 2, 3]), [])", "try([1, 2, 3], [])",
    "{for x in [1, 2, 1] : x => x...}", "[{a = 1}, {a = 2}][*].a",
])
def test_collection_refusal_is_incomplete_through_python(tmp_path, expression):
    (tmp_path / "main.tf").write_text(
        f'locals {{ v = {expression} }}')
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"format_version": "1.2", "planned_values": {
        "root_module": {"resources": []}}}))
    for result in [tfscan.scan(tmp_path, bundled=False, limits={"collection_bytes": 1}),
                   tfscan.analyze(tmp_path, limits={"collection_bytes": 1}),
                   tfscan.scan_plan(plan, source=tmp_path, bundled=False,
                                    limits={"collection_bytes": 1})]:
        assert result.status == "incomplete"
        limited = [d for d in result.diagnostics if d["code"] == "coverage-storage"]
        assert len(limited) == 1
        assert "collection_bytes" in limited[0]["message"]


@pytest.mark.parametrize("cached", [False, True])
def test_semantic_conversion_refusal_reaches_python(tmp_path, cached):
    (tmp_path / "main.tf").write_text('''
      variable "v" {
        type = object({x=optional(number, 7)})
        default = {}
      }
      locals { used = try(var.v, {}) }
    ''')
    if cached:
        (tmp_path / "override.tf").write_text("")
    # Empty literals need no payload; model and semantic preparation still require admission.
    for result in [tfscan.scan(tmp_path, bundled=False, limits={"collection_bytes": 1}),
                   tfscan.analyze(tmp_path, limits={"collection_bytes": 1})]:
        assert result.status == "incomplete"
        limited = [d for d in result.diagnostics if d["code"] == "coverage-storage"]
        assert len(limited) == 1
        assert "collection_bytes" in limited[0]["message"]
        assert not any(d["code"] == "parse-error" for d in result.diagnostics)


def test_scalar_model_storage_refusal_reaches_python_and_fix(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_db_instance" "db" { storage_encrypted = false }')
    complete = tfscan.scan(tmp_path, bundled=False)
    assert complete.status == "complete"
    fingerprint = complete.findings[0].fingerprint
    limits = {"collection_bytes": 1}
    for result in [tfscan.scan(tmp_path, bundled=False, limits=limits),
                   tfscan.analyze(tmp_path, limits=limits)]:
        assert result.status == "incomplete"
        refused = [d for d in result.diagnostics if d["code"] == "coverage-storage"]
        assert len(refused) == 1
        assert "collection_bytes" in refused[0]["message"]
    try:
        result = tfscan.fix(fingerprint, tmp_path, bundled=False, limits=limits)
    except ValueError as error:
        assert "finding" in str(error)
    else:
        assert not result["verified"]


@pytest.mark.parametrize("filename,content", [
    ("terraform.tfvars", "v = 1"), ("terraform.tfvars.json", '{"v":1}'),
])
def test_variable_file_cache_admission_reaches_python(tmp_path, filename, content):
    (tmp_path / "main.tf").write_text('variable "v" {}\noutput "v" { value = var.v }')
    (tmp_path / filename).write_text(content)
    assert tfscan.scan(tmp_path, bundled=False).status == "complete"
    for result in [tfscan.scan(tmp_path, bundled=False, limits={"collection_bytes": 1}),
                   tfscan.analyze(tmp_path, limits={"collection_bytes": 1})]:
        assert result.status == "incomplete"
        assert sum(d["code"] == "coverage-storage" for d in result.diagnostics) == 1
        assert not any(d["code"] == "parse-error" for d in result.diagnostics)

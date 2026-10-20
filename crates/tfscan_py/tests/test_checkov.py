"""Checkov is an optional export/callback dependency, pinned by the adapter.

Graph policies are read natively (``rule_files``); only value checks are
exported to a pack.
"""
import json
from pathlib import Path
import re

import pytest

import tfscan
from tfscan import checkov

pytest.importorskip("checkov")


@pytest.fixture(scope="module")
def pack(tmp_path_factory):
    path = tmp_path_factory.mktemp("checkov") / "pack"
    manifest = checkov.export_rules(path)
    return path, manifest


@pytest.fixture(scope="module")
def graph_checks():
    from checkov.terraform import runner

    return Path(runner.__file__).parent / "checks" / "graph_checks"


def policy(directory, doc):
    """Write a Checkov policy (with default metadata) for ``rule_files``."""
    metadata = {"id": "TEST_POLICY", "name": "test", "category": "GENERAL_SECURITY", **doc.get("metadata", {})}
    path = Path(directory) / f"{metadata['id']}.json"
    path.write_text(json.dumps({**doc, "metadata": metadata}))
    return path


def blockers(tmp_path, doc):
    """The (pointer, code) of every reason the native loader rejects ``doc``."""
    with pytest.raises(ValueError) as error:
        tfscan.rules([policy(tmp_path, doc)], builtin=False)
    return {(path, code) for code, path in re.findall(r"\[(\w+)\] at (\S+)", str(error.value))}


def test_export_accounts_for_every_check_and_excludes_overrides(pack):
    path, manifest = pack
    inventory = {x["id"]: x for x in manifest["checks"]}
    assert inventory["CKV_AWS_16"]["status"] == "translated"
    assert inventory["CKV_AWS_134"]["status"] == "unsupported"
    assert "overridden" in inventory["CKV_AWS_134"]["reason"]
    assert all(x.get("reason") for x in manifest["checks"] if x["status"] == "unsupported")
    assert (path / "LICENSE.checkov").read_text()
    assert len(checkov.load_rules(path)) == manifest["translated"]


def test_builtin_graph_catalog_loads_natively(pack, graph_checks):
    # The pack holds value checks only; every built-in graph policy loads
    # natively from Checkov's own directory.
    assert all(x["kind"] == "resource" for x in pack[1]["checks"])
    loaded = [r for r in tfscan.rules([graph_checks], builtin=False)]
    assert len(loaded) == len({p.name for p in graph_checks.rglob("*.json")}) == 186
    assert all(r["source"]["engine"] == "checkov" and r["source"]["line"] for r in loaded)


@pytest.mark.parametrize("operator,expected", [
    ("exists", None), ("not_exists", None), ("equals", True),
    ("equals", "false"), ("equals", None),
])
@pytest.mark.parametrize("nested", [False, True, "deep"])
def test_basic_jsonpath_matches_checkov_vertex_projection(tmp_path, operator, expected, nested):
    import hcl2
    from checkov.common.checks_infra.checks_parser import operators_to_attributes_solver_classes
    from checkov.terraform.graph_builder.graph_components.blocks import TerraformBlock

    bodies = ["", "settings = null", "settings = {}", "settings = []",
              'settings = "text"', 'settings = [{value=true}]',
              'settings = [{value=true},{value=false}]',
              'settings { value = true }', 'settings { value = [true] }',
              'settings {}', 'settings { value = true }\nsettings { value = false }']
    bodies += [f"settings = {{value={json.dumps(v)}}}" for v in
               [None, True, False, "true", "FALSE", "", 0, 1, [], [True], [True, False], {}, {"a": True}]]
    if nested == "deep":
        bodies = []
        for leaf in [True, [True], [True, False], None]:
            value = {"value": leaf}
            for _ in range(3):
                bodies += [f"settings = {{nested={json.dumps(value)}}}",
                           f"settings {{ nested={json.dumps(value)} }}"]
                value = [value]
        bodies += ['settings = {"nested.value"=true}']
    blocks, failed = [], set()
    path = "settings.nested.value" if nested == "deep" else "wrapper.settings.value" if nested else "settings.value"
    solver = operators_to_attributes_solver_classes[operator](["test_resource"], path, expected, True)
    for i, body in enumerate(bodies):
        if nested is True:
            body = f"wrapper {{\n{body}\n}}"
        address = f"test_resource.case_{i}"
        source = f'resource "test_resource" "case_{i}" {{\n{body}\n}}'
        blocks.append(source)
        conf = hcl2.loads(source)["resource"][0]["test_resource"][f"case_{i}"]
        vertex = TerraformBlock(name=address, config=conf, path=str(tmp_path / "main.tf"),
                                block_type="resource", attributes=conf, id=address,
                                source="terraform").get_attribute_dict()
        vertex["resource_type"] = "test_resource"
        result = solver.get_operation(vertex)
        assert result is not None
        if not result:
            failed.add(address)
    doc = {"metadata": {"id": "JSONPATH_TEST", "name": "jsonpath"}, "definition": {
        "cond_type": "attribute", "resource_types": ["test_resource"],
        "attribute": path, "operator": f"jsonpath_{operator}", "value": expected}}
    (tmp_path / "main.tf").write_text("\n".join(blocks))
    native = tfscan.scan(tmp_path, builtin=False,
                         rule_files=[policy(tmp_path, doc)])
    assert not native.diagnostics and not native.rule_errors
    assert {f.address for f in native.findings} == failed
    assert all(f.certainty == "definite" for f in native.findings)


def test_basic_jsonpath_rejects_unsupported_syntax(tmp_path):
    base = {"cond_type": "attribute", "resource_types": ["test_resource"],
            "attribute": "settings.value", "operator": "jsonpath_exists"}
    for path in ["settings[0].value", "$.settings.value", "settings..value", "settings[0:2]",
                 "settings.*.value", "settings['value']", "settings.where", "settings.0",
                 "settings[?(@.x == on | @.y == off)]"]:
        assert "jsonpath" in {code for _, code in blockers(tmp_path, {"definition": {**base, "attribute": path}})}, path
    # Numeric and regex filters are supported since F2 (checked against
    # Checkov's solvers by bench/checkov/graph_compare.py).
    for path in ["settings[?(@.x==1)].value", "settings[?(@.x =~ 'on')]"]:
        assert tfscan.rules([policy(tmp_path, {"definition": {**base, "attribute": path}})], builtin=False), path
    # Every registry operator has a jsonpath_ form (F2).
    assert tfscan.rules([policy(tmp_path, {"definition": {**base, "operator": "jsonpath_contains", "value": "x"}})],
                        builtin=False)


@pytest.mark.parametrize("operator,expected", [
    ("exists", None), ("not_exists", None), ("equals", "iam:*"),
    ("not_equals", "iam:*"), ("not_contains", ".elb."), ("equals", None),
])
@pytest.mark.parametrize("path", [
    "items[*]", "items[*].value", "items[?(@.name == Allow)]",
    "items[?(@.name == Allow)].value[*]", "items[?(@.name != Allow)].value",
    "items[?(@.nested.name == Allow & @.value != off)]",
])
def test_filtered_jsonpath_matches_checkov(tmp_path, operator, expected, path):
    import hcl2
    from checkov.common.checks_infra.checks_parser import operators_to_attributes_solver_classes
    from checkov.terraform.graph_builder.graph_components.blocks import TerraformBlock

    values = [None, False, True, 0, 1, "", "iam:*", [], {}]
    leaves = [None, False, 0, "", "iam:*", "safe", "service.elb.local", [], ["iam:*"], ["safe", "iam:*"], {}]
    if operator == "not_contains":
        # Python raises on scalar membership. Invalid operands have separate
        # native uncertainty tests and are not comparable pass/fail cases.
        values = [v for v in values if not isinstance(v, (bool, int))]
        leaves = [v for v in leaves if not isinstance(v, (bool, int))]
    for leaf in leaves:
        entry = {"name": "Allow", "nested": {"name": "Allow"}, "value": leaf}
        values += [entry, [entry], [entry, {"name": "Deny", "value": "safe"}],
                   [entry, {"name": "Allow", "value": "safe"}]]
    values += [{"value": "iam:*"}, {"name": "Deny", "value": "iam:*"},
               [{"name": "Allow"}, {"name": "Allow", "value": "iam:*"}],
               {"outer": {"inner": "service.elb.local"}}, {"outer": {".elb.": "safe"}}]
    solver = operators_to_attributes_solver_classes[operator](["test_resource"], path, expected, True)
    sources, failed = [], set()
    for i, value in enumerate(values):
        name = f"case_{i}"
        source = f'resource "test_resource" "{name}" {{\nitems = {json.dumps(value)}\n}}'
        sources.append(source)
        conf = hcl2.loads(source)["resource"][0]["test_resource"][name]
        vertex = TerraformBlock(name=f"test_resource.{name}", config=conf, path=str(tmp_path / "main.tf"),
                                block_type="resource", attributes=conf, id=name, source="terraform").get_attribute_dict()
        vertex["resource_type"] = "test_resource"
        result = solver.get_operation(vertex)
        assert result is not None
        if not result:
            failed.add(f"test_resource.{name}")
    (tmp_path / "main.tf").write_text("\n".join(sources))
    doc = {"metadata": {"id": "JSONPATH_FILTER_TEST", "name": "jsonpath filters"}, "definition": {
        "cond_type": "attribute", "resource_types": ["test_resource"],
        "attribute": path, "operator": f"jsonpath_{operator}", "value": expected}}
    native = tfscan.scan(tmp_path, builtin=False, rule_files=[policy(tmp_path, doc)])
    assert not native.diagnostics and not native.rule_errors
    assert {f.address for f in native.findings} == failed
    assert all(f.certainty == "definite" for f in native.findings)


def test_jsonpath_flattened_key_collisions_preserve_uncertainty(tmp_path):
    # Checkov chooses by source insertion order; native Terraform maps are
    # ordered by key. Retain both possibilities rather than choosing one.
    (tmp_path / "main.tf").write_text('''
resource "test_resource" "first" {
  settings = {nested={value=false}, "nested.value"=true}
}
resource "test_resource" "last" {
  settings = {"nested.value"=true, nested={value=false}}
}
''')
    doc = {"metadata": {"id": "JSONPATH_TEST", "name": "jsonpath"}, "definition": {
        "cond_type": "attribute", "resource_types": ["test_resource"],
        "attribute": "settings.nested.value", "operator": "jsonpath_equals", "value": True}}
    native = tfscan.scan(tmp_path, builtin=False,
                         rule_files=[policy(tmp_path, doc)])
    assert not native.diagnostics and not native.rule_errors
    assert {f.address for f in native.findings} == {"test_resource.first", "test_resource.last"}
    assert all(f.certainty == "conditional" and f.provenance for f in native.findings)


@pytest.mark.parametrize("boolean", ["and", "or"])
@pytest.mark.parametrize("expected", ["postgres", ["postgres", "post", ""], [True, False, 0, 1, 2, None]])
def test_attribute_filter_membership_matches_checkov(tmp_path, boolean, expected):
    from checkov.common.checks_infra.solvers.filter_solvers.within_filter_solver import WithinFilterSolver

    values = [None, False, 0, "", [], {}, "postgres", "post", "POSTGRES", "mysql"]
    if isinstance(expected, list):
        values += [True, 1, 2, 3, ["postgres"], {"postgres": True}]
    reference = WithinFilterSolver(["ignored_metadata"], "engine", expected)
    failed, blocks = set(), []
    for i in range(len(values) + 1):
        body = "" if i == len(values) else f"engine = {json.dumps(values[i])}"
        blocks.append(f'resource "test_node" "case_{i}" {{ {body} }}')
        vertex = {} if i == len(values) else {"engine": values[i]}
        if reference.get_operation(vertex):
            failed.add(f"test_node.case_{i}")
    doc = {"metadata": {"id": "FILTER_TEST", "name": "filter"}, "definition": {boolean: [
        {"cond_type": "connection", "resource_types": ["test_node"],
         "connected_resource_types": ["test_link"], "operator": "exists"},
        {"cond_type": "filter", "resource_types": ["ignored_metadata"],
         "attribute": "engine", "operator": "within", "value": expected},
    ]}}
    (tmp_path / "main.tf").write_text("\n".join(blocks))
    native = tfscan.scan(tmp_path, builtin=False, rule_files=[policy(tmp_path, doc)])
    assert not native.diagnostics and not native.rule_errors
    assert {f.address for f in native.findings} == failed
    assert all(f.certainty == "definite" for f in native.findings)


def test_attribute_filters_reject_unsupported_shapes_and_scope(tmp_path):
    connection = {"cond_type": "connection", "resource_types": ["test_node"],
                  "connected_resource_types": ["test_link"], "operator": "exists"}
    base = {"cond_type": "filter", "attribute": "engine", "operator": "within", "value": "postgres"}
    for change, code in [({"operator": "not_within"}, "filter_operator"),
                         ({"attribute": "settings.engine"}, "filter_path"),
                         ({"attribute": "depends_on"}, "meta_argument"),
                         ({"value": [["postgres"]]}, "filter_value")]:
        assert code in {c for _, c in blockers(tmp_path, {"definition": {"and": [connection, {**base, **change}]}})}
    for definition in [base, {"not": base}, {"and": [base, base]}, {"or": [base,
            {"cond_type":"attribute", "resource_types":["test_node"], "attribute":"enabled", "operator":"is_true"}]}]:
        assert blockers(tmp_path, {"definition": definition})


def test_rejections_check_siblings_and_independent_leaf_constraints(tmp_path):
    leaf = {"cond_type": "attribute", "resource_types": ["test_resource"],
            "attribute": "value", "operator": "equals", "value": True}
    doc = {"definition": {"and": [
        {**leaf, "attribute": "lifecycle.ignore_changes[*]", "operator": "regex_match", "value": "x"},
        {**leaf, "operator": "subset", "value": [[1]]},
        {**leaf, "operator": "length_greater_than", "value": "invalid"},
    ]}}
    assert blockers(tmp_path, doc) == {
        ("/definition/and/0/attribute", "jsonpath"),
        ("/definition/and/0/attribute", "meta_argument"),
        ("/definition/and/1/value", "scalar_list"),
        ("/definition/and/2/value", "integer_operand"),
    }


@pytest.mark.parametrize("operator,expected", [
    ("number_of_words_not_equals", 0), ("number_of_words_not_equals", "2"),
    ("number_of_words_not_equals", True),
    ("length_greater_than", 0), ("length_greater_than", 1),
    ("length_greater_than", -1), ("length_greater_than", " 1_0 "),
    ("length_greater_than", 1.9),
    ("length_less_than_or_equal", 0), ("length_less_than_or_equal", 1),
    ("subset", ["s3", "azuredb"]), ("subset", [0, 1, None, "s3"]), ("subset", []),
])
def test_graph_size_and_subset_operators_match_checkov(tmp_path, operator, expected):
    from checkov.common.checks_infra.checks_parser import operators_to_attributes_solver_classes

    values = [None, False, True, "", " \t\n", "a\u001cb", "a\u0085b", "é🙂", "a b",
              "s3", 0, 1, 2, [], ["s3"], ["s3", "azuredb"], ["s3", "bad"],
              [0, False], {}, {"s3": 42}, {"s3": 1, "azuredb": 2}, {"bad": 0}]
    solver = operators_to_attributes_solver_classes[operator](["test_resource"], "value", expected)
    blocks, failed = [], set()
    for i in range(len(values) + 1):
        address = f"test_resource.case_{i}"
        body = "" if i == len(values) else f"value = {json.dumps(values[i], ensure_ascii=False)}"
        source = f'resource "test_resource" "case_{i}" {{ {body} }}'
        blocks.append(source)
        # Compare identical evaluated operands. Checkov's HCL parser retains
        # some literal escapes (e.g. backslash-t), whereas oxtf evaluates them.
        # Actual parser/runner parity is covered by the per-policy fixtures.
        vertex = {"resource_type": "test_resource", "source_": "terraform"}
        if i != len(values):
            vertex["value"] = values[i]
        # Call synchronously: the upstream threaded solver can swallow exceptions.
        outcome = solver.get_operation(vertex)
        assert outcome is not None
        if not outcome:
            failed.add(address)
    doc = {"metadata": {"id": "TEST_OPERATOR", "name": operator},
           "definition": {"cond_type": "attribute", "resource_types": ["test_resource"],
                          "attribute": "value", "operator": operator, "value": expected}}
    (tmp_path / "main.tf").write_text("\n".join(blocks))
    native = tfscan.scan(tmp_path, builtin=False, rule_files=[policy(tmp_path, doc)])
    assert not native.diagnostics and not native.rule_errors
    assert {f.address for f in native.findings} == failed
    assert all(f.certainty == "definite" for f in native.findings)


def test_export_refuses_wrong_version_and_existing_destination(pack, tmp_path):
    with pytest.raises(ValueError, match="requires"):
        checkov.export_rules(tmp_path / "bad", expected_version="0.0.0")
    assert not (tmp_path / "bad").exists()
    with pytest.raises(FileExistsError):
        checkov.export_rules(pack[0])


def test_portable_rules_keep_certainty_and_provenance(pack, tmp_path):
    (tmp_path / "main.tf").write_text('''
variable "enabled" { type = bool }
resource "aws_db_instance" "bad" { storage_encrypted = false }
resource "aws_db_instance" "good" { storage_encrypted = true }
resource "aws_db_instance" "maybe" { storage_encrypted = var.enabled }
''')
    result = tfscan.scan(tmp_path, rules=checkov.load_rules(pack[0]), builtin=False, select=["CKV_AWS_16"])
    assert not result.rule_errors
    assert {(f.address, f.certainty) for f in result.findings} == {
        ("aws_db_instance.bad", "definite"), ("aws_db_instance.maybe", "conditional")}
    assert all(f.provenance for f in result.findings)


def test_pack_checksum_is_checked(pack, tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps(pack[1]))
    (tmp_path / "rules.json").write_text("[]")
    with pytest.raises(ValueError, match="checksum"):
        checkov.load_rules(tmp_path)


def test_custom_override_uses_original_check_and_records_unknown(tmp_path):
    (tmp_path / "main.tf").write_text('''
resource "aws_elasticache_cluster" "bad" {
  engine = "redis"
  snapshot_retention_limit = 0
}
resource "aws_elasticache_cluster" "good" {
  engine = "redis"
  snapshot_retention_limit = 3
}
resource "aws_elasticache_cluster" "unknown" { engine = "memcached" }
''')
    result = tfscan.scan(tmp_path, builtin=False, rules=checkov.custom_rules(["CKV_AWS_134"]))
    assert [f.address for f in result.findings] == ["aws_elasticache_cluster.bad"]
    assert len(result.rule_errors) == 1
    assert result.rule_errors[0]["resource"] == "aws_elasticache_cluster.unknown"
    assert "UNKNOWN" in result.rule_errors[0]["message"]


def test_custom_unknown_values_cannot_become_definite_findings(tmp_path):
    (tmp_path / "main.tf").write_text('''
variable "enabled" { type = bool }
resource "aws_db_instance" "maybe" { storage_encrypted = var.enabled }
resource "aws_db_instance" "computed" { storage_encrypted = aws_db_instance.computed.id }
''')
    result = tfscan.scan(tmp_path, builtin=False, rules=checkov.custom_rules(["CKV_AWS_16"]))
    assert {(f.address, f.certainty) for f in result.findings} == {
        ("aws_db_instance.maybe", "conditional"), ("aws_db_instance.computed", "indeterminate")}
    assert all(f.to_dict()["hidden"] for f in result.findings)


def test_custom_nested_blocks_and_unknown_rule_selection(tmp_path):
    (tmp_path / "main.tf").write_text('''
resource "aws_security_group" "ssh" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')
    result = tfscan.scan(tmp_path, builtin=False, rules=checkov.custom_rules(["CKV_AWS_24"]))
    assert not result.rule_errors
    assert len(result.findings) == 1
    with pytest.raises(ValueError, match="unknown Checkov"):
        checkov.custom_rules(["CKV_FAKE_1"])


def test_custom_projected_pass_is_an_explicit_unresolved_result(tmp_path):
    (tmp_path / "main.tf").write_text('''
variable "name" { type = string }
resource "aws_db_instance" "good" {
  storage_encrypted = true
  identifier = var.name
}
''')
    result = tfscan.scan(tmp_path, builtin=False, rules=checkov.custom_rules(["CKV_AWS_16"]))
    assert not result.findings
    assert len(result.rule_errors) == 1
    assert "projected inputs were abstract" in result.rule_errors[0]["message"]


def test_record_errors_keeps_scanning_and_default_exceptions_still_propagate(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_db_instance" "db" {}')

    def broken(resource):
        raise ValueError("intentional check failure")

    error = tfscan.CallbackRule(broken, "broken", ["aws_db_instance"], record_errors=True)
    finding = tfscan.CallbackRule(lambda r: "still scanned", "ok", ["aws_db_instance"])
    result = tfscan.scan(tmp_path, builtin=False, rules=[error, finding])
    assert [f.rule for f in result.findings] == ["ok"]
    assert len(result.rule_errors) == 1
    assert "intentional check failure" in result.rule_errors[0]["message"]
    error.record_errors = False
    with pytest.raises(ValueError, match="intentional check failure"):
        tfscan.scan(tmp_path, builtin=False, rules=[error, finding])


def test_graph_policies_connect_across_local_module_outputs(graph_checks, tmp_path):
    child = tmp_path / 'child'
    child.mkdir()
    (child / 'main.tf').write_text('''
resource "aws_vpc" "connected" {}
output "id" { value = aws_vpc.connected.id }
''')
    (tmp_path / 'main.tf').write_text('''
module "vpc" { source = "./child" }
resource "aws_vpc" "missing" {}
resource "aws_flow_log" "log" { vpc_id = module.vpc.id }
''')
    result = tfscan.scan(tmp_path, builtin=False, rule_files=[graph_checks], select=['CKV2_AWS_11'])
    assert not result.rule_errors
    assert [(f.address, f.certainty) for f in result.findings] == [('aws_vpc.missing', 'definite')]
    assert result.to_arrow().num_rows == 1


def test_graph_predicates_on_connected_resource_and_uncertainty(graph_checks, tmp_path):
    (tmp_path / 'main.tf').write_text('''
variable "enabled" { type = bool }
resource "aws_s3_bucket" "bad" {}
resource "aws_s3_bucket" "good" {}
resource "aws_s3_bucket" "maybe" {}
resource "aws_s3_bucket_public_access_block" "bad" {
  bucket = aws_s3_bucket.bad.id
  block_public_acls = false
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_public_access_block" "good" {
  bucket = aws_s3_bucket.good.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_public_access_block" "maybe" {
  bucket = aws_s3_bucket.maybe.id
  block_public_acls = var.enabled
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
''')
    result = tfscan.scan(tmp_path, builtin=False, rule_files=[graph_checks], select=['CKV2_AWS_6'])
    assert not result.rule_errors
    assert {(f.address, f.certainty) for f in result.findings} == {('aws_s3_bucket.bad','definite'),('aws_s3_bucket.maybe','conditional')}
    assert all(f.provenance for f in result.findings)


@pytest.mark.parametrize('check_id,source', [
    ('CKV2_AWS_11', '''
resource "aws_vpc" "good" {}
resource "aws_vpc" "bad" {}
resource "aws_flow_log" "log" { vpc_id = aws_vpc.good.id }
'''),
    ('CKV2_GIT_1', '''
resource "github_repository" "good" { name = "protected" }
resource "github_repository" "bad" { name = "unprotected" }
resource "github_branch_protection" "protection" { repository_id = github_repository.good.node_id }
'''),
    ('CKV2_AWS_28', '''
resource "aws_lb" "internal" { internal = true }
resource "aws_lb" "public" { internal = false }
resource "aws_lb" "protected" { internal = false }
resource "aws_wafv2_web_acl_association" "waf" { resource_arn = aws_lb.protected.arn }
'''),
    ('CKV2_AWS_23', '''
resource "aws_lb" "target" { dns_name = "target.example.com" }
resource "aws_route53_record" "good" {
  type = "A"
  alias { name = aws_lb.target.dns_name }
}
resource "aws_route53_record" "bad" {
  type = "A"
  alias { name = "unattached.example.com" }
}
resource "aws_route53_record" "excluded" {
  type = "AAAA"
  alias { name = "unattached.example.com" }
}
'''),
    ('CKV2_AWS_27', '''
resource "aws_rds_cluster_parameter_group" "good" {
  name = "good"
  parameter { name = "log_statement"
    value = "all" }
  parameter { name = "log_min_duration_statement"
    value = "1" }
}
resource "aws_rds_cluster_parameter_group" "bad" {
  name = "bad"
  parameter { name = "unrelated"
    value = "1" }
}
resource "aws_rds_cluster" "good" {
  engine = "aurora-postgresql"
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.good.name
}
resource "aws_rds_cluster" "bad" {
  engine = "aurora-postgresql"
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.bad.name
}
resource "aws_rds_cluster" "excluded" { engine = "aurora-mysql" }
'''),
    ('CKV2_AWS_30', '''
resource "aws_db_parameter_group" "group" {
  name = "group"
  parameter { name = "unrelated"
    value = "1" }
}
resource "aws_db_instance" "good" {
  engine = "postgres"
  parameter_group_name = aws_db_parameter_group.group.name
}
resource "aws_db_instance" "bad" { engine = "postgres" }
resource "aws_db_instance" "excluded" { engine = "mysql" }
'''),
    ('CKV2_AWS_49', '''
resource "aws_dms_endpoint" "good" {
  endpoint_type = "source"
  engine_name = "postgres"
  ssl_mode = "require"
}
resource "aws_dms_endpoint" "bad" {
  endpoint_type = "source"
  engine_name = "postgres"
  ssl_mode = "none"
}
resource "aws_dms_endpoint" "exempt" {
  endpoint_type = "source"
  engine_name = "s3"
  ssl_mode = "none"
}
'''),
    ('CKV2_AZURE_27', '''
resource "azurerm_mssql_server" "good" {
  azuread_administrator { login_username = "admin" }
}
resource "azurerm_mssql_server" "bad" {
  azuread_administrator { login_username = "" }
}
'''),
    ('CKV2_AZURE_28', '''
resource "azurerm_container_group" "good" {
  identity { type = "SystemAssigned" }
}
resource "azurerm_container_group" "bad" {
  identity { type = "" }
}
'''),
    ('CKV2_AZURE_35', '''
resource "azurerm_recovery_services_vault" "good" {
  identity { type = "SystemAssigned" }
}
resource "azurerm_recovery_services_vault" "bad" {
  identity { type = "" }
}
'''),
    ('CKV2_AZURE_36', '''
resource "azurerm_automation_account" "good" {
  identity { type = "SystemAssigned" }
}
resource "azurerm_automation_account" "bad" {
  identity { type = "" }
}
'''),
    ('CKV2_AZURE_39', '''
resource "azurerm_network_interface" "good" {
  ip_configuration { public_ip_address_id = "public" }
}
resource "azurerm_network_interface" "bad" {
  ip_configuration { public_ip_address_id = "public" }
}
resource "azurerm_linux_virtual_machine" "good" {
  network_interface_ids = [azurerm_network_interface.good.id]
}
resource "azurerm_linux_virtual_machine" "bad" {
  network_interface_ids = [azurerm_network_interface.bad.id]
  boot_diagnostics {}
}
'''),
    ('CKV2_AZURE_41', '''
resource "azurerm_storage_account" "good" {
  shared_access_key_enabled = true
  sas_policy { expiration_period = "1.00:00:00" }
}
resource "azurerm_storage_account" "bad" {
  shared_access_key_enabled = true
  sas_policy { expiration_period = "" }
}
'''),
    ('CKV2_OCI_3', '''
resource "oci_containerengine_cluster" "good" {
  endpoint_config { nsg_ids = ["nsg"] }
}
resource "oci_containerengine_cluster" "bad" {
  endpoint_config { nsg_ids = [] }
}
'''),
    ('CKV2_GCP_27', '''
resource "google_workbench_instance" "good" {
  gce_setup {
    boot_disk { kms_key = "key" }
    data_disks { kms_key = "key" }
  }
}
resource "google_workbench_instance" "good_no_data" {
  gce_setup {
    boot_disk { kms_key = "key" }
  }
}
resource "google_workbench_instance" "bad" {
  gce_setup {
    boot_disk { kms_key = "key" }
    data_disks {}
  }
}
resource "google_workbench_instance" "bad_boot" {
  gce_setup {}
}
'''),
    ('CKV2_GCP_28', '''
resource "google_workbench_instance" "good" {
  gce_setup { disable_public_ip = true }
}
resource "google_workbench_instance" "bad" {
  gce_setup { disable_public_ip = false }
}
'''),
    ('CKV2_GCP_32', '''
resource "google_tpu_v2_vm" "good" {
  network_config { enable_external_ips = false }
}
resource "google_tpu_v2_vm" "bad" {
  network_config { enable_external_ips = true }
}
'''),
    ('CKV2_GCP_35', '''
resource "google_notebooks_runtime" "good" {
  virtual_machine {
    virtual_machine_config {
      encryption_config { kms_key = "key" }
    }
  }
}
resource "google_notebooks_runtime" "bad" {
  virtual_machine {
    virtual_machine_config {
      encryption_config {}
    }
  }
}
'''),
    ('CKV2_GCP_36', '''
resource "google_notebooks_runtime" "good" {
  virtual_machine {
    virtual_machine_config { internal_ip_only = true }
  }
}
resource "google_notebooks_runtime" "bad" {
  virtual_machine {
    virtual_machine_config { internal_ip_only = false }
  }
}
'''),
    ('CKV2_AWS_40', '''
resource "aws_iam_policy" "good" {
  policy = jsonencode({Statement=[{Effect="Allow", Action=["iam:GetRole"]}]})
}
resource "aws_iam_policy" "bad" {
  policy = jsonencode({Statement=[{Effect="Allow", Action=["iam:GetRole", "iam:*"]}]})
}
resource "aws_iam_policy" "bad_literal" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Action":["iam:*"]}]}
POLICY
}
resource "aws_ssoadmin_permission_set_inline_policy" "bad" {
  inline_policy = jsonencode({Statement=[{Effect="Allow", Action="*"}]})
}
data "aws_iam_policy_document" "good" {
  statement {
    effect = "Deny"
    actions = ["*"]
  }
}
data "aws_iam_policy_document" "bad" {
  statement {
    effect = "Allow"
    actions = ["iam:*"]
  }
}
'''),
    ('CKV2_AWS_68', '''
resource "aws_iam_role" "good" {
  policy = jsonencode({Statement=[{Effect="Allow", Action="s3:GetObject"}]})
}
resource "aws_iam_role" "bad" {
  policy = jsonencode({Statement=[{Effect="Allow", Action=["s3:GetObject", "*"]}]})
}
resource "aws_sagemaker_notebook_instance" "good" { role_arn = aws_iam_role.good.arn }
resource "aws_sagemaker_notebook_instance" "bad" { role_arn = aws_iam_role.bad.arn }
resource "aws_sagemaker_notebook_instance" "missing" {}
'''),
    ('CKV2_AWS_72', '''
resource "aws_cloudfront_distribution" "good" {
  enabled = true
  origin {
    domain_name = "service.elb.amazonaws.com"
    custom_origin_config { origin_protocol_policy = "https-only" }
  }
}
resource "aws_cloudfront_distribution" "bad" {
  enabled = true
  origin {
    domain_name = "example.org"
    custom_origin_config { origin_protocol_policy = "https-only" }
  }
  origin {
    domain_name = "service.elb.amazonaws.com"
    custom_origin_config { origin_protocol_policy = "http-only" }
  }
}
resource "aws_cloudfront_distribution" "disabled" {
  enabled = false
  origin {
    domain_name = "service.elb.amazonaws.com"
    custom_origin_config { origin_protocol_policy = "http-only" }
  }
}
'''),
] + [(check_id, f'''
resource "google_sql_database_instance" "good" {{
  database_version = "POSTGRES_15"
  settings {{
    database_flags {{
      name = "{flag}"
      value = "{good}"
    }}
    database_flags {{
      name = "unrelated"
      value = "on"
    }}
  }}
}}
resource "google_sql_database_instance" "bad" {{
  database_version = "POSTGRES_15"
  settings {{
    database_flags {{
      name = "{flag}"
      value = "{bad}"
    }}
  }}
}}
resource "google_sql_database_instance" "missing" {{ database_version = "POSTGRES_15" }}
resource "google_sql_database_instance" "mysql" {{ database_version = "MYSQL_8_0" }}
''') for check_id, flag, good, bad in [
    ("CKV2_GCP_13", "log_duration", "on", "off"),
    ("CKV2_GCP_14", "log_executor_stats", "off", "on"),
    ("CKV2_GCP_15", "log_parser_stats", "off", "on"),
    ("CKV2_GCP_16", "log_planner_stats", "off", "on"),
    ("CKV2_GCP_17", "log_statement_stats", "off", "on"),
]])
def test_graph_findings_match_full_checkov_runner(graph_checks, tmp_path, check_id, source):
    import hcl2
    from checkov.terraform.runner import Runner
    from checkov.runner_filter import RunnerFilter

    (tmp_path / 'main.tf').write_text(source)
    reference = Runner().run(root_folder=str(tmp_path), runner_filter=RunnerFilter(checks=[check_id], download_external_modules=False))
    native = tfscan.scan(tmp_path, builtin=False, rule_files=[graph_checks], select=[check_id])
    assert reference.passed_checks and reference.failed_checks
    assert not native.rule_errors
    data_addresses = {f"{ty}.{name}" for block in hcl2.loads(source).get("data", [])
                      for ty, configs in block.items() for name in configs}
    assert {f.address for f in native.findings} == {
        f"data.{f.resource}" if f.resource in data_addresses else f.resource for f in reference.failed_checks}


def test_filter_eligibility_preserves_conditional_findings_and_evidence(graph_checks, tmp_path):
    (tmp_path / 'main.tf').write_text('''
variable "engine" { type = string }
resource "aws_db_instance" "maybe" { engine = var.engine }
resource "aws_db_instance" "excluded" { engine = "mysql" }
resource "aws_db_instance" "missing" {}
''')
    result = tfscan.scan(tmp_path, builtin=False, rule_files=[graph_checks], select=['CKV2_AWS_30'])
    assert not result.rule_errors
    assert [(f.address, f.certainty) for f in result.findings] == [('aws_db_instance.maybe', 'conditional')]
    assert result.findings[0].provenance

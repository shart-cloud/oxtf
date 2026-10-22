import json
import os
import shutil
import subprocess

import pytest
import tfscan


def terraform_reference():
    terraform = shutil.which("terraform")
    if terraform:
        version = json.loads(subprocess.check_output([terraform, "version", "-json"]))
        if version["terraform_version"] == "1.16.1":
            return terraform
    if os.environ.get("OXTF_REQUIRE_TERRAFORM"):
        pytest.fail("Terraform 1.16.1 is required")
    pytest.skip("source conformance is pinned to Terraform 1.16.1 (HCL 2.24.0)")


def terraform_env():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("TF_VAR_", "TF_CLI_ARGS", "TF_DATA_DIR"))}
    env.update(TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1")
    return env


def test_file_template_and_hash_values_match_terraform(tmp_path):
    terraform = terraform_reference()
    (tmp_path / "child").mkdir()
    (tmp_path / "text.txt").write_text("héllo\n")
    (tmp_path / "binary.bin").write_bytes(bytes([255, 0, 128]))
    (tmp_path / "child/value.tftpl").write_text("${value}")
    (tmp_path / "child/list.tftpl").write_text("%{ for item in items ~}\n${upper(item)};\n%{ endfor ~}")
    (tmp_path / "child/unused.tftpl").write_text('${true ? "ok" : missing}')
    (tmp_path / "child/main.tf").write_text('''
locals {
  values = {
    text = file("text.txt")
    binary = filebase64("binary.bin")
    filehash = filesha256("text.txt")
    encodedhash = filebase64sha256("binary.bin")
    md5 = filemd5("binary.bin")
    sha1 = sha1("héllo")
    sha512 = sha512("héllo")
    base64sha512 = base64sha512("héllo")
    typed = templatefile("${path.module}/value.tftpl", { value = [true, 3], true = 1, null = 2 })
    list = templatefile("${path.module}/list.tftpl", { items = ["a", "b"] })
    caught = try(file("missing.txt"), "missing")
    invalid_utf8 = can(file("binary.bin"))
    missing_unused_var = can(templatefile("${path.module}/unused.tftpl", {}))
    absolute = abspath("child/../text.txt")
  }
}
output "values" { value = local.values }
''')
    (tmp_path / "main.tf").write_text('''
module "child" { source = "./child" }
resource "terraform_data" "r" { input = module.child.values }
''')
    subprocess.run([terraform, "get", "-no-color"], cwd=tmp_path, env=terraform_env(),
                   check=True, capture_output=True)
    reference = subprocess.run([terraform, "console", "-no-color"],
                               input="jsonencode(module.child.values)\n", cwd=tmp_path,
                               env=terraform_env(), text=True, check=True, capture_output=True)
    expected = json.loads(json.loads(reference.stdout))
    actual = tfscan.scan(tmp_path, builtin=False, bundled=False)
    assert actual.status == "complete", actual.to_json()
    assert actual.resources[0]["input"].py() == expected


def test_terraform_json_configuration_values_and_source_locations(tmp_path):
    terraform = terraform_reference()
    (tmp_path / "child").mkdir()
    (tmp_path / "child/main.tf.json").write_text(json.dumps({
        "variable": {"payload": {}},
        "output": {"payload": {"value": "${var.payload}"}},
    }))
    values = {
        "flag": "${var.flag}",
        "literal": "${var.literal}",
        "object": '${jsondecode("{\\"ok\\":false}")}',
        "escaped": 'a\n"b"\\c 🚀 $${literal}',
        "directive": "%{ for x in [1,2] }${x}%{ endfor }",
        "map": {"${local.key}": "${[true, null, 2]}"},
    }
    (tmp_path / "main.tf.json").write_text(json.dumps({
        "variable": {
            "flag": {"type": "bool", "default": "false"},
            "literal": {"default": {"${key}": "${literal"}, "description": "${literal"},
        },
        "locals": {"values": values},
        "module": {"child": {"source": "./child", "payload": "${local.values}"}},
        "resource": {"terraform_data": {"r": {"input": "${module.child.payload}"}}},
    }, ensure_ascii=True))
    (tmp_path / "locals.tf").write_text('locals { key = "dynamic-key" }\n')
    env = terraform_env()
    subprocess.run([terraform, "get", "-no-color"], cwd=tmp_path, env=env,
                   check=True, capture_output=True)
    reference = subprocess.run([terraform, "console", "-no-color"],
                               input="jsonencode(module.child.payload)\n",
                               cwd=tmp_path, env=env, text=True,
                               check=True, capture_output=True)
    assert "Error:" not in reference.stderr, reference.stderr
    expected = json.loads(json.loads(reference.stdout))
    actual = tfscan.scan(tmp_path, builtin=False, bundled=False)
    assert actual.status == "complete", actual.to_json()
    assert actual.resources[0]["input"].py() == expected


def test_json_configuration_sensitive_values_and_no_hcl_fixes(tmp_path):
    source = json.dumps({
        "variable": {"secret": {"default": "json-private-secret", "sensitive": True}},
        "resource": {"aws_db_instance": {"db": {
            "storage_encrypted": False, "password": "${var.secret}",
        }}},
    })
    overlay = {tmp_path / "main.tf.json": source}
    result = tfscan.scan(tmp_path, overlay=overlay, bundled=False)
    assert result.status == "complete"
    record = json.loads(result.to_json())
    assert len(record["findings"]) == 1
    assert record["findings"][0]["fix_hint"] is None
    assert "json-private-secret" not in json.dumps(result.resources.to_arrow().to_pylist())
    with pytest.raises(ValueError, match="fix hint"):
        tfscan.fix(record["findings"][0]["fingerprint"], tmp_path, overlay=overlay,
                   bundled=False)


@pytest.mark.parametrize("base_json", [False, True])
@pytest.mark.parametrize("override_json", [False, True])
def test_terraform_override_composition_matches_all_format_pairs(tmp_path, base_json, override_json):
    terraform = terraform_reference()
    child = tmp_path / "child"
    child.mkdir()
    (child / "main.tf").write_text('variable "value" {}\noutput "value" { value = true }\n')
    (child / "override.tf.json").write_text('{"output":{"value":{"value":"${var.value}"}}}')
    if base_json:
        (tmp_path / "main.tf.json").write_text(json.dumps({
            "variable": {"x": {"type": "number", "default": "01"}},
            "locals": {"first": True},
            "module": {"child": {"source": "./child", "value": True}},
            "resource": {"terraform_data": {"r": {
                "input": {"x": "${var.x}", "first": "${local.first}",
                          "second": "${local.second}", "child": "${module.child.value}"}
            }}},
        }))
    else:
        (tmp_path / "main.tf").write_text('''
variable "x" {
  type = number
  default = "01"
}
locals { first = true }
module "child" {
  source = "./child"
  value = true
}
resource "terraform_data" "r" {
  input = {x=var.x, first=local.first, second=local.second, child=module.child.value}
}
''')
    (tmp_path / "other.tf").write_text("locals { second = true }\n")
    if override_json:
        (tmp_path / "override.tf.json").write_text(json.dumps({
            "variable": {"x": {"type": "string"}},
            "locals": {"first": False, "second": "${local.first}"},
            "module": {"child": {"value": "${local.second}"}},
        }))
    else:
        (tmp_path / "override.tf").write_text('''
variable "x" { type = string }
locals {
  first = false
  second = local.first
}
module "child" { value = local.second }
''')
    env = terraform_env()
    subprocess.run([terraform, "get", "-no-color"], cwd=tmp_path, env=env,
                   check=True, capture_output=True)
    reference = subprocess.run([terraform, "console", "-no-color"],
                               input="jsonencode({x=var.x,first=local.first,second=local.second,child=module.child.value})\n",
                               cwd=tmp_path, env=env, text=True, check=True, capture_output=True)
    assert "Error:" not in reference.stderr, reference.stderr
    expected = json.loads(json.loads(reference.stdout))
    result = tfscan.scan(tmp_path, builtin=False, bundled=False)
    assert result.status == "complete", result.to_json()
    assert result.resources[0]["input"].py() == expected == {
        "x": "1", "first": False, "second": False, "child": False,
    }


@pytest.mark.parametrize("base,override", [
    ('variable "x" {\ntype=string\ndefault="bad"\n}', 'variable "x" { type=bool }'),
    ('variable "x" {\ntype=number\ndefault=1\n}', 'variable "x" { default="bad" }'),
    ('variable "x" { default="ok" }', 'variable "x" {\ndefault=null\nnullable=false\n}'),
    ('resource "terraform_data" "r" {}', 'resource "terraform_data" "missing" {}'),
    ('resource "terraform_data" "r" {}', 'resource "terraform_data" "r" { depends_on=[terraform_data.r] }'),
    ('locals { x=1 }', 'locals { missing=2 }'),
    ('terraform {}', 'terraform { backend "local" {} }\nterraform { backend "local" {} }'),
    ('variable "x" {}', 'variable "x" { type=invalid }'),
    ('variable "x" { default=null }', 'variable "x" { type=list(invalid) }'),
])
def test_invalid_overrides_match_terraform(tmp_path, base, override):
    terraform = terraform_reference()
    (tmp_path / "main.tf").write_text(base)
    (tmp_path / "override.tf").write_text(override)
    reference = subprocess.run([terraform, "console", "-no-color"], input="true\n",
                               cwd=tmp_path, env=terraform_env(), text=True, capture_output=True)
    assert reference.returncode != 0 or "Error:" in reference.stderr
    result = tfscan.scan(tmp_path, builtin=False, bundled=False)
    assert result.status == "failed", result.to_json()


def test_override_fixes_use_the_effective_file(tmp_path):
    overlay = {
        tmp_path / "main.tf.json": '{"resource":{"aws_db_instance":{"db":{"storage_encrypted":true}}}}',
        tmp_path / "override.tf": 'resource "aws_db_instance" "db" { storage_encrypted=false }\n',
    }
    result = tfscan.scan(tmp_path, overlay=overlay, bundled=False)
    assert result.status == "complete"
    record = json.loads(result.to_json())
    finding = record["findings"][0]
    assert finding["location"]["file"] == str(tmp_path / "override.tf")
    fixed = tfscan.fix(finding["fingerprint"], tmp_path, overlay=overlay, bundled=False)
    assert fixed["verified"]
    assert fixed["file"] == str(tmp_path / "override.tf")


@pytest.mark.parametrize("type_expr,default", [
    ("list(any)", '[1,"2"]'),
    ("set(any)", '[1,"1","2"]'),
    ("map(any)", '{a=1,b="2"}'),
    ("list(object({x=any}))", '[{x=1},{x="2"}]'),
    ("list(list(any))", '[[1],["2","3"]]'),
    ("list(any)", '[{a=1},{b="2"}]'),
    ("list(any)", '[[1,true],["2",false]]'),
    ("list", '[1,"2"]'),
    ("map", '{a=1,b="2"}'),
])
def test_override_defaults_unify_dynamic_collection_types(tmp_path, type_expr, default):
    terraform = terraform_reference()
    (tmp_path / "main.tf").write_text(f'''
variable "x" {{
  type = {type_expr}
  default = {default}
}}
resource "terraform_data" "r" {{ input = var.x }}
''')
    (tmp_path / "override.tf").write_text('variable "x" { description = "effective" }\n')
    reference = subprocess.run([terraform, "console", "-no-color"], input="jsonencode(var.x)\n",
                               cwd=tmp_path, env=terraform_env(), text=True,
                               check=True, capture_output=True)
    assert "Error:" not in reference.stderr, reference.stderr
    expected = json.loads(json.loads(reference.stdout))
    actual = tfscan.scan(tmp_path, builtin=False, bundled=False)
    assert actual.status == "complete", actual.to_json()
    assert actual.resources[0]["input"].py() == expected


@pytest.mark.parametrize("json_config", [False, True])
@pytest.mark.parametrize("base_type,default,overrides", [
    ("object({encrypted=optional(bool)})", {},
     [("object({encrypted=optional(bool,true)})", None)]),
    ("object({encrypted=optional(bool,true)})", {},
     [("object({encrypted=optional(bool,false)})", None)]),
    ("object({nested=object({encrypted=optional(bool)})})", {"nested": {}},
     [("object({nested=object({encrypted=optional(bool,true)})})", None)]),
    ("list(string)", ["a", "b"], [("tuple([string,string])", None)]),
    ("set(string)", ["a", "b"], [("any", None), ("tuple([string,string])", None)]),
    ("object({xs=list(string)})", {"xs": ["a", "b"]},
     [("any", None), ("object({xs=tuple([string,string])})", None)]),
    ("list(list(string))", [["a", "b"]],
     [("list(tuple([string,string]))", None)]),
    ("list(string)", ["a", "b"], [("tuple([string,string])", ["c", "d"])]),
    ("object({a=optional(string,\"original\")})", {}, [(None, {})]),
    ("object({a=optional(string,\"original\")})", {}, [(None, {"a": None})]),
    ("object({a=optional(string,\"original\")})", {},
     [("object({a=optional(string,\"overridden\")})", None), (None, {})]),
    ("object({a=optional(string,\"original\")})", {}, [("object({})", None)]),
    ("string", None, [("list(string)", None)]),
    ("bool", None, [("number", None)]),
    ("object({a=string})", None, [("string", None)]),
    ("list(bool)", [], [("list(number)", None)]),
    ("map(bool)", {}, [("map(number)", None)]),
    ("set(bool)", [], [("set(number)", None)]),
    ("list(object({a=string}))", [], [("list(number)", None)]),
    ("string", None, [("bool", None)]),
    ("any", None, [("list(string)", None)]),
    ("list(bool)", [], [("list(string)", None)]),
    ("list(bool)", [], [("list(any)", None), ("list(number)", None)]),
    ("list(bool)", None, [("list(any)", None), ("list(number)", None)]),
    ("map(bool)", {}, [("map(any)", None), ("map(number)", None)]),
    ("set(bool)", [], [("set(any)", None), ("set(number)", None)]),
])
def test_override_converted_defaults_match_terraform(tmp_path, json_config, base_type, default, overrides):
    terraform = terraform_reference()
    declarations = [{"type": base_type, "default": default}]
    declarations += [
        {**({"type": ty} if ty is not None else {}),
         **({"default": value} if value is not None else {})}
        for ty, value in overrides
    ]
    for i, declaration in enumerate(declarations):
        name = "main" if i == 0 else f"{i}_override"
        if json_config:
            source = json.dumps({"variable": {"config": declaration}})
            suffix = ".tf.json"
        else:
            settings = [f"type = {declaration['type']}"] if "type" in declaration else []
            if "default" in declaration:
                settings.append(f"default = {json.dumps(declaration['default'])}")
            source = 'variable "config" {\n' + "\n".join(settings) + "\n}\n"
            suffix = ".tf"
        (tmp_path / (name + suffix)).write_text(source)
    (tmp_path / "resource.tf").write_text('resource "terraform_data" "r" { input = var.config }\n')
    reference = subprocess.run([terraform, "console", "-no-color"], input="jsonencode(var.config)\n",
                               cwd=tmp_path, env=terraform_env(), text=True, capture_output=True)
    result = tfscan.scan(tmp_path, builtin=False, bundled=False)
    if reference.returncode:
        assert result.status == "failed", result.to_json()
    else:
        assert result.status == "complete", result.to_json()
        assert result.resources[0]["input"].py() == json.loads(json.loads(reference.stdout))


@pytest.mark.parametrize("input_source", ["tfvars", "module"])
@pytest.mark.parametrize("base_type,final_type,value", [
    ("object({a=optional(bool)})", "object({a=optional(bool,true)})", {}),
    ("object({a=optional(bool,true)})", "object({a=optional(bool,false)})", {}),
    ("list(object({a=optional(bool,true)}))", "list(object({a=optional(bool,false)}))", [{}]),
    ("map(object({a=optional(bool,true)}))", "map(object({a=optional(bool,false)}))", {"k": {}}),
])
def test_overridden_input_types_keep_original_optional_defaults(tmp_path, input_source, base_type, final_type, value):
    terraform = terraform_reference()
    declaration_dir = tmp_path
    if input_source == "module":
        declaration_dir = tmp_path / "child"
        declaration_dir.mkdir()
        (tmp_path / "main.tf").write_text(
            'module "child" {\nsource="./child"\nconfig=' + json.dumps(value) + '\n}\n')
        expression = "module.child.config"
    else:
        (tmp_path / "terraform.tfvars.json").write_text(json.dumps({"config": value}))
        expression = "var.config"
    (declaration_dir / "variable.tf").write_text(f'variable "config" {{ type={base_type} }}\n')
    (declaration_dir / "override.tf").write_text(f'variable "config" {{ type={final_type} }}\n')
    (declaration_dir / "resource.tf").write_text(
        'resource "terraform_data" "r" { input=var.config }\noutput "config" { value=var.config }\n')
    env = terraform_env()
    subprocess.run([terraform, "get", "-no-color"], cwd=tmp_path, env=env, check=True, capture_output=True)
    reference = subprocess.run([terraform, "console", "-no-color"], input=f"jsonencode({expression})\n",
                               cwd=tmp_path, env=env, text=True, check=True, capture_output=True)
    result = tfscan.scan(tmp_path, builtin=False, bundled=False)
    assert result.status == "complete", result.to_json()
    assert result.resources[0]["input"].py() == json.loads(json.loads(reference.stdout))


def test_terraform_lifecycle_merge_and_whole_file_policy_view(tmp_path):
    terraform = terraform_reference()
    (tmp_path / "main.tf").write_text('''
resource "terraform_data" "r" {
  input = "old"
  lifecycle { ignore_changes = [input] }
}
''')
    env = terraform_env()
    for args in [
        ["init", "-backend=false", "-input=false", "-no-color"],
        ["apply", "-auto-approve", "-input=false", "-no-color"],
    ]:
        subprocess.run([terraform, *args], cwd=tmp_path, env=env, check=True, capture_output=True)
    (tmp_path / "override.tf.json").write_text(json.dumps({
        "resource": {"terraform_data": {"r": {
            "input": "new",
            "lifecycle": {"create_before_destroy": True, "ignore_changes": []},
        }}},
    }))
    subprocess.run([terraform, "plan", "-out=reference.plan", "-input=false", "-no-color"],
                   cwd=tmp_path, env=env, check=True, capture_output=True)
    plan = json.loads(subprocess.check_output([terraform, "show", "-json", "reference.plan"],
                                             cwd=tmp_path, env=env))
    assert plan["resource_changes"][0]["change"]["actions"] == ["no-op"]
    policy = tmp_path / "lifecycle.rego"
    policy.write_text('''
package main
deny contains "lost inherited lifecycle" if {
  input.resource.terraform_data.r[0].lifecycle[0].ignore_changes != ["${input}"]
}
deny contains "empty override was evaluated as a separate configuration" if {
  not input.resource
}
''')
    result = tfscan.scan(tmp_path, builtin=False, bundled=False,
                         policies=[policy], policy_shape="hcl")
    assert result.status == "complete", result.to_json()
    assert result.resources[0]["input"].py() == "new"
    assert json.loads(result.to_json())["findings"] == []


def test_json_vars_and_installed_modules_share_scan_and_fix_options(tmp_path):
    overlay = {
        tmp_path / "main.tf": '''
variable "encrypted" { default = true }
module "db" {
  source = "acme/db/aws"
  encrypted = var.encrypted
}
resource "aws_db_instance" "consumer" { storage_encrypted = module.db.encrypted }
''',
        tmp_path / "terraform.tfvars.json": '{"encrypted": false}',
        tmp_path / "cache/modules/modules.json": json.dumps({"Modules": [
            {"Key": "db", "Source": "acme/db/aws", "Version": "1.2.3",
             "Dir": "cache/modules/db"}
        ]}),
        tmp_path / "cache/modules/db/main.tf": '''
variable "encrypted" {}
resource "aws_db_instance" "db" { storage_encrypted = var.encrypted }
output "encrypted" { value = var.encrypted }
''',
    }
    result = tfscan.scan(tmp_path, overlay=overlay, data_dir="cache",
                         recursive=True, bundled=False)
    assert result.status == "complete"
    record = json.loads(result.to_json())
    assert record["stats"]["roots"] == 1
    remote = next(f for f in record["findings"] if f.get("package"))
    assert remote["package"]["version"] == "1.2.3"
    assert remote["fix_hint"] is None
    with pytest.raises(ValueError, match="fix hint"):
        tfscan.fix(remote["fingerprint"], tmp_path, data_dir="cache",
                   overlay=overlay, bundled=False)
    local = next(f for f in record["findings"] if not f.get("package"))
    fixed = tfscan.fix(local["fingerprint"], tmp_path, data_dir="cache",
                       overlay=overlay, bundled=False)
    assert fixed["verified"]
    assert fixed["file"] == str(tmp_path / "main.tf")


def test_explicit_json_vars_and_sensitive_exports(tmp_path):
    overlay = {
        tmp_path / "main.tf": '''
variable "secret" { sensitive = true }
resource "test_resource" "r" { value = var.secret }
''',
        tmp_path / "values.json": '{"secret": "${literal-secret}"}',
    }
    result = tfscan.scan(tmp_path, overlay=overlay, var_files=[tmp_path / "values.json"],
                         builtin=False, bundled=False)
    assert result.status == "complete"
    value = result.resources[0]["value"]
    assert value.sensitive and value.to_str() == "${literal-secret}"
    assert "literal-secret" not in json.dumps(result.resources.to_arrow().to_pylist())


def test_terraform_1_16_1_json_and_installed_git_conformance(tmp_path):
    """Pinned Terraform oracle; all Git transport stays on the local filesystem."""
    terraform = shutil.which("terraform")
    if not terraform or not shutil.which("git"):
        if os.environ.get("OXTF_REQUIRE_TERRAFORM"):
            pytest.fail("Terraform 1.16.1 and Git are required")
        pytest.skip("Terraform 1.16.1 and Git required for source conformance")
    version = json.loads(subprocess.check_output([terraform, "version", "-json"]))
    if version["terraform_version"] != "1.16.1":
        if os.environ.get("OXTF_REQUIRE_TERRAFORM"):
            pytest.fail(f"expected Terraform 1.16.1, found {version['terraform_version']}")
        pytest.skip("source conformance is pinned to Terraform 1.16.1")
    repo = tmp_path / "module-repo"
    main = repo / "modules/main"
    shared = repo / "modules/shared"
    main.mkdir(parents=True)
    shared.mkdir()
    (main / "main.tf").write_text('''
variable "value" {}
module "inner" {
  source = "../shared"
  value = var.value
}
output "value" { value = module.inner.value }
''')
    (shared / "main.tf").write_text('variable "value" {}\noutput "value" { value = var.value }\n')
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Conformance",
                    "-c", "user.email=conformance@example.invalid", "commit", "-qm", "fixture"], check=True)
    revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    root = tmp_path / "root"
    root.mkdir()
    (root / "main.tf").write_text(f'''
variable "x" {{ default = 0 }}
variable "template" {{ type = string }}
variable "payload" {{}}
module "child" {{
  source = "git::{repo.as_uri()}//modules/main?ref={revision}"
  value = var.payload
}}
resource "terraform_data" "r" {{
  input = {{ x = var.x, template = var.template, payload = module.child.value }}
}}
''')
    (root / "terraform.tfvars").write_text("x = 1\n")
    (root / "terraform.tfvars.json").write_text(json.dumps({
        "x": 2, "template": "${do_not_interpolate}",
        "payload": {"${key}": [None, True, -125, "a\n☺"]}
    }))
    (root / "a.auto.tfvars.json").write_text('{"x": 3}')
    (root / "b.auto.tfvars").write_text("x = 4\n")
    (root / "last.json").write_text('{"x": 5}')
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TF_VAR_", "TF_CLI_ARGS"))}
    env.update(TF_DATA_DIR="cache", TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1")
    subprocess.run([terraform, "get", "-no-color"], cwd=root, env=env, check=True, capture_output=True)
    expression = "jsonencode({x=var.x, template=var.template, payload=module.child.value})\n"
    reference = subprocess.run([terraform, "console", "-no-color", "-var-file=last.json"],
                               input=expression, cwd=root, env=env, text=True,
                               check=True, capture_output=True)
    expected = json.loads(json.loads(reference.stdout))
    result = tfscan.scan(root, data_dir="cache", var_files=[root / "last.json"],
                         builtin=False, bundled=False)
    assert result.status == "complete", result.to_json()
    assert result.resources[0]["input"].py() == expected

    # Exercise Terraform's actual installed-module loader for registry version
    # constraints without contacting a registry. Only installed files are read.
    versions = tmp_path / "versions"
    child = versions / "cache/modules/db"
    child.mkdir(parents=True)
    (child / "main.tf").write_text('output "ok" { value = true }\n')
    for installed, constraint in [
        ("1.2.3", "~> 1.2"), ("1.3.0", "~> 1.2.3"),
        ("1.2.3+build", "= 1.2.3"), ("1.2.3", "!= 1.2.3"),
        ("1.2.3-beta.2", ">= 1.2.3-beta.1"), ("1.2.3", "~> 1.2.3-beta.1"),
        ("1.2.0", "1.2"), ("1.2.1", "1.2"), ("1.3.0", "~> 1"),
        ("1.2.0", ""), ("1.2.0", "<=1.2"),
    ]:
        (versions / "main.tf").write_text(
            'module "db" {\nsource = "acme/db/aws"\nversion = ' + json.dumps(constraint) + '\n}\n'
        )
        (versions / "cache/modules/modules.json").write_text(json.dumps({"Modules": [{
            "Key": "db", "Source": "acme/db/aws", "Version": installed, "Dir": "cache/modules/db"
        }]}))
        reference = subprocess.run([terraform, "console", "-no-color"], input="module.db.ok\n",
                                   cwd=versions, env=env, text=True, capture_output=True)
        actual = tfscan.scan(versions, data_dir="cache", builtin=False, bundled=False)
        assert (actual.status == "complete") == (reference.returncode == 0), (installed, constraint)


@pytest.mark.parametrize("json_config", [False, True])
def test_terraform_count_instances_outputs_and_regex_match_plan(tmp_path, json_config):
    terraform = terraform_reference()
    (tmp_path / "child").mkdir()
    (tmp_path / "child/main.tf").write_text('''
variable "index" {}
resource "terraform_data" "node" {
  count = 2
  input = var.index * 10 + count.index
}
output "index" { value = var.index }
output "values" { value = terraform_data.node[*].input }
''')
    if json_config:
        (tmp_path / "main.tf.json").write_text(json.dumps({
            "module": {"child": {"source": "./child", "count": 1, "index": "${count.index}"}},
            "resource": {"terraform_data": {"result": {"input": {
                "all": "${module.child[*].index}",
                "nested": "${module.child[*].values}",
                "selected": '${module.child["1.0"].values[1]}',
                "legacy": "${module.child.*.index[1]}",
                "replacement": '${replace("policy-name!", "/[^0-9A-Za-z]*/", "")}',
                "capture": '${regex("projects/([^/]+)/", "projects/example/global/")}',
            }}}},
        }))
    else:
        (tmp_path / "main.tf").write_text('''
module "child" {
  source = "./child"
  count = 1
  index = count.index
}
resource "terraform_data" "result" {
  input = {
    all = module.child[*].index
    nested = module.child[*].values
    selected = module.child["1.0"].values[1]
    legacy = module.child.*.index[1]
    replacement = replace("policy-name!", "/[^0-9A-Za-z]*/", "")
    capture = regex("projects/([^/]+)/", "projects/example/global/")
  }
}
''')
    (tmp_path / "override.tf.json").write_text('{"module":{"child":{"count":2}}}')
    env = terraform_env()
    subprocess.run([terraform, "init", "-backend=false", "-no-color"], cwd=tmp_path, env=env, check=True, capture_output=True)
    subprocess.run([terraform, "plan", "-input=false", "-no-color", "-out=reference.plan"], cwd=tmp_path, env=env, check=True, capture_output=True)
    plan = json.loads(subprocess.check_output([terraform, "show", "-json", "reference.plan"], cwd=tmp_path, env=env))
    expected = {r["address"]: r["change"]["after"]["input"] for r in plan["resource_changes"]}
    result = tfscan.scan(tmp_path, builtin=False, bundled=False)
    assert result.status == "complete", result.to_json()
    assert {r.address: r["input"].py() for r in result.resources} == expected


@pytest.mark.parametrize("count", ["-1", "1.5", "null", "true", '"invalid"'])
def test_invalid_counts_agree_with_terraform(tmp_path, count):
    terraform = terraform_reference()
    (tmp_path / "main.tf").write_text(f'resource "terraform_data" "r" {{ count = {count} }}\n')
    reference = subprocess.run([terraform, "plan", "-input=false", "-no-color"], cwd=tmp_path, env=terraform_env(), capture_output=True)
    assert reference.returncode != 0
    result = tfscan.scan(tmp_path, builtin=False, bundled=False)
    assert result.status == "failed", result.to_json()
    assert any(d["code"] == "invalid-count" for d in json.loads(result.to_json())["diagnostics"])


def test_sensitive_instance_selections_match_plan_and_mask_exports(tmp_path):
    terraform = terraform_reference()
    (tmp_path / "child").mkdir()
    (tmp_path / "child/main.tf").write_text('variable "value" {}\noutput "value" { value=var.value }\n')
    (tmp_path / "main.tf").write_text('''
resource "terraform_data" "n" {
  count = 2
  input = "private-${count.index}"
}
module "child" {
  count = 2
  source = "./child"
  value = "private-${count.index}"
}
locals {
  node = terraform_data.n[sensitive("1.0")]
  child = module.child[sensitive("1.0")]
}
resource "terraform_data" "result" {
  input = {
    resource = terraform_data.n[sensitive("1e0")].input
    module = module.child[sensitive("1e0")].value
    object = local.node.input
    module_object = local.child.value
  }
}
''')
    env = terraform_env()
    subprocess.run([terraform, "init", "-backend=false", "-no-color"], cwd=tmp_path, env=env, check=True, capture_output=True)
    subprocess.run([terraform, "plan", "-input=false", "-no-color", "-out=reference.plan"], cwd=tmp_path, env=env, check=True, capture_output=True)
    plan = json.loads(subprocess.check_output([terraform, "show", "-json", "reference.plan"], cwd=tmp_path, env=env))
    expected = next(r["change"] for r in plan["resource_changes"] if r["address"] == "terraform_data.result")
    assert all(expected["after_sensitive"]["input"].values())
    result = tfscan.scan(tmp_path, builtin=False, bundled=False)
    selected = next(r for r in result.resources if r.address == "terraform_data.result")
    assert result.status == "complete", result.to_json()
    assert selected["input"].py() == expected["after"]["input"]
    assert selected["input"].sensitive
    exported = next(r for r in result.resources.to_arrow().to_pylist() if r["address"] == selected.address)
    assert "private-1" not in json.dumps(exported)


@pytest.mark.parametrize("selection", [
    "aws_db_instance.r[local.choice].storage_encrypted",
    "module.child[local.choice].encrypted",
])
def test_sensitive_selectors_are_masked_in_source_and_verified_fix_diffs(tmp_path, selection):
    (tmp_path / "child").mkdir()
    (tmp_path / "child/main.tf").write_text(
        'variable "encrypted" {}\noutput "encrypted" { value = var.encrypted }\n')
    (tmp_path / "main.tf").write_text(f'''
resource "aws_db_instance" "r" {{
  count = 2
  storage_encrypted = count.index == 0
}}
module "child" {{
  source = "./child"
  count = 2
  encrypted = count.index == 0
}}
locals {{ choice = sensitive(1) }}
resource "aws_db_instance" "consumer" {{
  storage_encrypted = {selection}
}}
''')
    result = tfscan.scan(tmp_path, bundled=False)
    assert result.status == "complete", result.to_json()
    finding = next(f for f in result.findings if f.address == "aws_db_instance.consumer")
    assert "sensitive(1)" not in finding.render()
    fixed = tfscan.fix(finding.fingerprint, tmp_path, bundled=False)
    assert fixed["verified"], fixed
    assert "sensitive(1)" not in fixed["diff"]


def test_fetched_counted_modules_share_definitions_but_keep_instance_values(tmp_path):
    repo = tmp_path / "package"
    repo.mkdir()
    (repo / "main.tf.json").write_text(json.dumps({
        "variable": {"index": {}},
        "resource": {"aws_db_instance": {"db": {"storage_encrypted": "${var.index != 0}"}}},
        "output": {"index": {"value": "${var.index}"}},
    }))
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], check=True)
    root = tmp_path / "root"
    root.mkdir()
    (root / "main.tf").write_text(f'''
module "db" {{
  source = "git::{repo.as_uri()}"
  count = 3
  index = count.index
}}
resource "terraform_data" "values" {{ input = module.db[*].index }}
''')
    assert tfscan.scan(root, bundled=False).status == "incomplete"
    fetched = tfscan.fetch(root, data_dir=".data")
    assert fetched["modules"][0]["revision"]
    repo.rename(tmp_path / "unavailable")
    assert tfscan.fetch(root, data_dir=".data")["modules"][0]["reused"]
    result = tfscan.scan(root, bundled=False, data_dir=".data")
    assert result.status == "complete", result.to_json()
    record = json.loads(result.to_json())
    assert len(record["findings"]) == 1
    finding = record["findings"][0]
    assert finding["package"]["revision"] == fetched["modules"][0]["revision"]
    assert finding["fix_hint"] is None
    assert result.resources[0]["input"].py() == [0, 1, 2]
    assert result.findings[0].address == "module.db[0].aws_db_instance.db"

"""Import pinned Checkov resource checks into portable oxtf rule IR.

Checkov is needed only for export. ``load_rules`` reads an exported pack
without importing Checkov. Unsupported checks are inventoried in the manifest.

Graph checks are not exported: oxtf reads Checkov's YAML/JSON policies
natively (``tfscan.scan(rule_files=[...])``, ``oxtf --rule-file``), the
built-in catalog included (``checkov/terraform/checks/graph_checks``).
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import shutil

SUPPORTED_VERSION = "3.2.328"


class Unsupported(ValueError):
    def __init__(self, reason, *, blockers=()):
        super().__init__(reason)
        self.blockers = list(blockers)


def _installed(expected_version: str):
    version = importlib.metadata.version("checkov")
    if version != expected_version or version != SUPPORTED_VERSION:
        raise ValueError(
            f"Checkov {version} is installed; this importer requires {SUPPORTED_VERSION} "
            f"(requested {expected_version})."
        )
    from checkov.terraform import runner
    from checkov.terraform.checks.resource.registry import resource_registry

    checks = {}
    for registry in (resource_registry.checks, resource_registry.wildcard_checks):
        for group in registry.values():
            for check in group:
                checks[check.id] = check
    return version, checks, Path(inspect.getfile(runner)).parent


def _metadata(check):
    category_names = {c.name for c in check.categories}
    category = next((out for source, out in (
        ("ENCRYPTION", "encryption"), ("IAM", "iam"),
        ("NETWORKING", "network"), ("BACKUP_AND_RECOVERY", "storage"),
    ) if source in category_names), "other")
    level = getattr(check.severity, "name", "medium").lower()
    if level not in {"low", "medium", "high", "critical"}:
        level = "medium"
    return {
        "version": 2, "name": check.id, "description": check.name,
        "message": check.name.replace("{", "{{").replace("}", "}}"),
        "category": category, "level": level,
    }


def _translate(check):
    from checkov.common.models.consts import ANY_VALUE
    from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
    from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceValueCheck as Positive
    from checkov.terraform.checks.resource.base_resource_negative_value_check import BaseResourceNegativeValueCheck as Negative

    if type(check).scan_entity_conf is not BaseResourceCheck.scan_entity_conf:
        raise Unsupported("overridden scan_entity_conf")
    if isinstance(check, Positive):
        base, negative = Positive, False
    elif isinstance(check, Negative):
        base, negative = Negative, True
    else:
        return _translate_python(check, "custom Python scan_resource_conf")
    if type(check).scan_resource_conf is not base.scan_resource_conf:
        return _translate_python(check, "overridden scan_resource_conf")
    if not negative and type(check)._is_variable_dependant is not BaseResourceCheck._is_variable_dependant:
        raise Unsupported("overridden variable-dependency predicate")

    clauses = [{"resource_types": [t], "condition": {"op": "checkov_value", **params}}
               for t, params in _value_check_params(check, negative).items()]
    if not clauses:
        raise Unsupported("no supported resource types")
    return {**_metadata(check), "clauses": clauses}


def _value_check_params(check, negative):
    """The generic value check's parameters per resource type (the
    ``checkov_value`` condition without its op)."""
    from checkov.common.models.consts import ANY_VALUE

    out = {}
    for resource_type in sorted(check.supported_entities):
        if any(c in resource_type for c in "*?["):
            raise Unsupported("resource-type wildcard")
        instance = copy.copy(check)
        instance.entity_type = resource_type
        if negative and instance.get_excluded_key() is not None:
            raise Unsupported("custom exclusion predicate")
        path = instance.get_inspected_key().split("/")
        if not all(path) or any(any(c in p for c in "*?") for p in path):
            raise Unsupported("nonliteral inspected path")
        if path[0] in {"lifecycle", "provisioner", "connection", "provider", "depends_on", "count", "for_each"}:
            raise Unsupported("meta-argument is not retained in the rule model")
        values = instance.get_forbidden_values() if negative else instance.get_expected_values()
        if not isinstance(values, (list, tuple)):
            raise Unsupported("expected/forbidden values are not a list (upstream uses string membership)")
        values = list(values)
        if any(isinstance(v, str) and ("${" in v or "%{" in v) for v in values):
            raise Unsupported("predicate compares unevaluated Terraform expression text")
        any_value = ANY_VALUE in values
        values = [v for v in values if v != ANY_VALUE]
        # Reject non-JSON and non-finite metadata rather than emitting a broken pack.
        json.dumps(values, allow_nan=False)
        missing = instance.missing_attribute_result if negative else instance.missing_block_result
        missing = {"PASSED": "pass", "FAILED": "fail", "UNKNOWN": "unknown"}.get(missing.value)
        if missing is None:
            raise Unsupported("unsupported missing-value outcome")
        out[resource_type] = {"path": path, "values": values, "negative": negative,
                              "any_value": any_value, "missing": missing}
    return out


def _sibling(name):
    """A module of this package, also when this file runs as a script
    (``scripts/import_checkov.py`` runs it without the package)."""
    import importlib
    if __package__:
        return importlib.import_module(f"{__package__}.{name}")
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _translate_python(check, kind):
    """A check whose scan_resource_conf is Python of its own, as a
    ``checkov_python`` program (see ``checkov_python.py``)."""
    from checkov.common.checks.base_check import BaseCheck
    from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
    from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceValueCheck
    from checkov.terraform.checks.resource.base_resource_negative_value_check import BaseResourceNegativeValueCheck
    checkov_python = _sibling("checkov_python")

    generic = {BaseResourceCheck, BaseResourceValueCheck, BaseResourceNegativeValueCheck, BaseCheck, object}
    types = sorted(check.supported_entities)
    if any(any(c in t for c in "*?[") for t in types):
        raise Unsupported(f"{kind}: resource-type wildcard")
    def value_check(c):
        try:
            return _value_check_params(c, isinstance(c, BaseResourceNegativeValueCheck))
        except Unsupported as exc:
            raise checkov_python.Unsupported(f"the generic value check: {exc}") from None

    try:
        program = checkov_python.export(check, generic, value_check)
    except checkov_python.Unsupported as exc:
        raise Unsupported(f"{kind}: {exc}") from None
    return {**_metadata(check), "version": 4, "clauses": [{"resource_types": types, "condition": {
        "op": "checkov_python", "program": program}}]}


def export_rules(directory, *, expected_version=SUPPORTED_VERSION):
    """Export to a new directory: rules.json, manifest.json, LICENSE.checkov.

    The destination must not exist. No downloads occur. Existing check IDs
    are retained; missing levels default to medium and are marked in the manifest.
    """
    version, checks, terraform_dir = _installed(expected_version)
    rules, inventory = [], []
    for check_id, check in sorted(checks.items()):
        source = Path(inspect.getfile(type(check)))
        entry = {
            "id": check_id, "kind": "resource", "name": check.name,
            "source": source.relative_to(terraform_dir.parent).as_posix(),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "severity_defaulted": check.severity is None,
        }
        try:
            rules.append(_translate(check))
            entry["status"] = "translated"
        except (Unsupported, TypeError, ValueError, AttributeError, NotImplementedError) as exc:
            entry.update(status="unsupported", reason=str(exc))
        inventory.append(entry)
    # Some upstream IDs have several files for different resource types.
    merged = {}
    for rule in rules:
        if rule["name"] in merged:
            merged[rule["name"]]["clauses"].extend(rule["clauses"])
            merged[rule["name"]]["version"] = max(merged[rule["name"]]["version"], rule["version"])
        else:
            merged[rule["name"]] = rule
    rules = [merged[k] for k in sorted(merged)]
    dist = importlib.metadata.distribution("checkov")
    license_file = next((dist.locate_file(f) for f in dist.files or [] if f.name == "LICENSE" and ".dist-info" in str(f)), None)
    if license_file is None:
        raise ValueError("installed Checkov distribution has no LICENSE")
    manifest = {
        "schema": 1, "source": "checkov", "source_version": version, "ir_version": 4,
        "translated": len(rules), "unsupported": sum(x["status"] == "unsupported" for x in inventory),
        "checks": inventory,
        "semantics": "configured values; Checkov missing-value policy; oxtf abstract-value lattice",
    }
    payload = json.dumps(rules, indent=2, sort_keys=True, allow_nan=False) + "\n"
    manifest["rules_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=False)
    (out / "rules.json").write_text(payload)
    # The IAM database programs that use cloudsplaining read (policy_sentry).
    if '"iam": "definition"' in payload or '"iam":"definition"' in payload:
        iam = _sibling("checkov_python").iam_data()
        # One service per line, after a header line: a scan parses only the
        # services its policies name.
        services = iam.pop("services")
        lines = [json.dumps({"header": iam}, separators=(",", ":"), sort_keys=True)]
        lines += [json.dumps({"prefix": p, "service": services[p]}, separators=(",", ":"), sort_keys=True)
                  for p in sorted(services)]
        (out / "iam.ndjson").write_text("\n".join(lines) + "\n")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    shutil.copyfile(license_file, out / "LICENSE.checkov")
    return manifest


def load_rules(directory):
    """Load a portable exported pack; Checkov is not required at scan time."""
    from ._tfscan import compile_rules

    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    payload = (directory / "rules.json").read_bytes()
    if manifest.get("schema") != 1 or manifest.get("source") != "checkov":
        raise ValueError("unsupported Checkov pack manifest")
    if hashlib.sha256(payload).hexdigest() != manifest["rules_sha256"]:
        raise ValueError("Checkov pack rules do not match manifest checksum")
    return compile_rules(payload.decode())


def custom_rules(ids, *, expected_version=SUPPORTED_VERSION):
    """Run explicitly selected Checkov resource checks through Python.

    Every call uses a fresh check instance. Exceptions and unresolved results
    are recorded in ``ScanResult.rule_errors``. This adapter cannot supply
    Checkov's graph or runner context; checks requiring those report errors.
    """
    from . import CallbackRule, Report, Value
    from checkov.common.models.enums import CheckResult

    _, checks, _ = _installed(expected_version)
    ids = list(dict.fromkeys(ids))
    missing = sorted(set(ids) - checks.keys())
    if missing:
        raise ValueError(f"unknown Checkov resource checks: {', '.join(missing)}")

    absent = object()

    def callback(template):
        def run(resource):
            check = copy.deepcopy(template)
            check.evaluated_keys = []
            check.details = []
            hidden = []
            witness = None

            def known(value, path=""):
                nonlocal witness
                if isinstance(value, Value):
                    kind = "tainted" if value.tainted else "unknown"
                    hidden.append((path, kind))
                    if witness is None or value.tainted:
                        witness = value
                    return absent
                if isinstance(value, dict):
                    return {k: v for k, x in value.items()
                            if (v := known(x, f"{path}.{k}".lstrip("."))) is not absent}
                if isinstance(value, list):
                    return [v for i, x in enumerate(value)
                            if (v := known(x, f"{path}[{i}]")) is not absent]
                return value

            conf = known(resource.checkov_configuration().py())
            conf["__address__"] = resource.address
            result = check.scan_entity_conf(conf, resource.type)
            if result == CheckResult.FAILED:
                if not hidden:
                    # Recover the inspected value's evidence when available.
                    keys = check.get_evaluated_keys()
                    if keys:
                        witness = resource.get(keys[0].split("/")[0])
                conditional = any(k == "tainted" for _, k in hidden)
                return Report(check.name, witness, conditional, bool(hidden) and not conditional, hidden)
            if hidden:
                raise RuntimeError("Checkov result unresolved: projected inputs were abstract: " + ", ".join(p for p, _ in hidden))
            if result == CheckResult.PASSED:
                return None
            raise RuntimeError(f"Checkov returned {result.value}; this is not a proven pass")
        return run

    out = []
    for check_id in ids:
        check = checks[check_id]
        if any(any(c in t for c in "*?[") for t in check.supported_entities):
            raise ValueError(f"{check_id}: resource-type wildcard is not supported by the callback dispatcher")
        meta = _metadata(check)
        out.append(CallbackRule(callback(check), check.id, check.supported_entities,
                                meta["level"], meta["category"], check.name, record_errors=True))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new output directory")
    parser.add_argument("--expect-version", default=SUPPORTED_VERSION)
    args = parser.parse_args(argv)
    try:
        manifest = export_rules(args.output, expected_version=args.expect_version)
    except (ValueError, OSError, importlib.metadata.PackageNotFoundError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps({k: manifest[k] for k in ("source_version", "translated", "unsupported")}, sort_keys=True))


if __name__ == "__main__":
    main()

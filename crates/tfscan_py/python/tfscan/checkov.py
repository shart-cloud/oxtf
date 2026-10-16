"""Import pinned Checkov resource checks into portable oxtf rule IR.

Checkov is needed only for export. ``load_rules`` reads an exported pack
without importing Checkov. Unsupported checks are inventoried in the manifest.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import re
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

    if isinstance(check, Positive):
        base, negative = Positive, False
    elif isinstance(check, Negative):
        base, negative = Negative, True
    else:
        raise Unsupported("custom Python scan_resource_conf")
    if type(check).scan_resource_conf is not base.scan_resource_conf:
        raise Unsupported("overridden scan_resource_conf; metadata alone is insufficient")
    if type(check).scan_entity_conf is not BaseResourceCheck.scan_entity_conf:
        raise Unsupported("overridden scan_entity_conf")
    if not negative and type(check)._is_variable_dependant is not BaseResourceCheck._is_variable_dependant:
        raise Unsupported("overridden variable-dependency predicate")

    clauses = []
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
        clauses.append({"resource_types": [resource_type], "condition": {
            "op": "checkov_value", "path": path, "values": values,
            "negative": negative, "any_value": any_value, "missing": missing,
        }})
    if not clauses:
        raise Unsupported("no supported resource types")
    return {**_metadata(check), "clauses": clauses}


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
    for source in sorted((terraform_dir / "checks" / "graph_checks").rglob("*.json")):
        doc = json.loads(source.read_text())
        entry = {
            "id": doc["metadata"]["id"], "kind": "graph", "status": "unsupported",
            "source": source.relative_to(terraform_dir.parent).as_posix(),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "severity_defaulted": True,
        }
        try:
            rules.append(_translate_graph(doc))
            entry["status"] = "translated"
        except Unsupported as exc:
            entry["reason"] = str(exc)
            entry["blockers"] = exc.blockers
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
        "schema": 1, "source": "checkov", "source_version": version, "ir_version": 3,
        "translated": len(rules), "unsupported": sum(x["status"] == "unsupported" for x in inventory),
        "checks": inventory,
        "semantics": "configured values; Checkov missing-value policy; oxtf abstract-value lattice",
    }
    payload = json.dumps(rules, indent=2, sort_keys=True, allow_nan=False) + "\n"
    manifest["rules_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=False)
    (out / "rules.json").write_text(payload)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    shutil.copyfile(license_file, out / "LICENSE.checkov")
    return manifest


def _compile_jsonpath(attribute):
    """Compile the pinned parser AST; never interpret a query string in Rust."""
    from bc_jsonpath_ng.ext import parse
    from bc_jsonpath_ng.ext.filter import Filter
    from bc_jsonpath_ng.jsonpath import Child, Fields, Slice, This

    def field(name):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", name):
            raise ValueError("nonliteral field")
        return name

    def parts(query, relative=False):
        if isinstance(query, Child):
            return parts(query.left, relative) + parts(query.right, relative)
        if isinstance(query, This) and relative:
            return []
        if isinstance(query, Fields) and len(query.fields) == 1:
            return [field(query.fields[0])]
        if not relative and isinstance(query, Slice) and query.start is None and query.end is None and query.step is None:
            return [{"kind": "each"}]
        if not relative and isinstance(query, Filter) and query.expressions:
            predicates = []
            for expression in query.expressions:
                if expression.op not in {"==", "!=", "="} or not isinstance(expression.value, str):
                    raise ValueError("filter requires string equality/inequality")
                path = parts(expression.target, True)
                if not path:
                    raise ValueError("filter requires fields")
                predicates.append({"path": path, "operator": "equals" if expression.op in {"==", "="} else "not_equals",
                                   "value": expression.value})
            return [{"kind": "filter", "predicates": predicates}]
        raise ValueError("unsupported JSONPath expression")

    path = parts(parse(attribute))
    if not path or not isinstance(path[0], str):
        raise ValueError("path requires a configured field")
    # Preserve the literal-path grammar accepted by existing v3 packs.
    if all(isinstance(p, str) for p in path) and attribute != ".".join(path):
        raise ValueError("noncanonical literal path")
    return path


def _translate_graph(doc):
    """Compile connection, attribute and filter solvers to portable graph IR."""
    allowed = {"exists", "not_exists", "equals", "not_equals", "equals_ignore_case",
               "not_equals_ignore_case", "within", "not_within", "contains", "not_contains",
               "starting_with", "not_starting_with", "greater_than", "greater_than_or_equal",
               "less_than", "less_than_or_equal", "is_empty", "is_not_empty", "is_true", "is_false",
               "number_of_words_not_equals", "length_greater_than", "length_less_than_or_equal", "subset"}
    size_operators = {"number_of_words_not_equals", "length_greater_than", "length_less_than_or_equal"}
    jsonpath_operators = {"jsonpath_exists", "jsonpath_not_exists", "jsonpath_equals",
                          "jsonpath_not_equals", "jsonpath_not_contains"}
    meta_args = {"lifecycle", "provisioner", "connection", "count", "for_each", "provider", "depends_on"}
    blockers = []

    def reject(path, code, reason):
        blockers.append({"path": path, "code": code, "reason": reason})

    def types(value, path):
        value = [value] if isinstance(value, str) else value
        if not isinstance(value, list) or not value or any(not isinstance(t, str) or not t for t in value):
            reject(path, "resource_types", "graph requires nonempty resource types")
            return []
        value = ["*" if t == "all" else t for t in value]
        if any(t == "taggable" or (t != "*" and any(c in t for c in "*?[")) for t in value):
            reject(path, "resource_selector", "graph resource-type wildcard/taggable selector")
        return sorted(set(value))

    def is_filter(node):
        return node is not None and node["kind"] in {"filter", "attribute_filter"}

    def has_connection(node):
        if node is None:
            return False
        if node["kind"] == "connection":
            return True
        if node["kind"] == "not":
            return has_connection(node["arg"])
        return any(has_connection(child) for child in node.get("args", []))

    def expression(node, path):
        if not isinstance(node, dict):
            reject(path, "structure", "graph condition requires an object")
            return None
        logical = [op for op in ("and", "or", "not") if op in node]
        if logical:
            if len(node) != 1:
                reject(path, "structure", "unsupported graph boolean structure")
            children = []
            # Visit every branch even when a sibling or parent is unsupported.
            for op in logical:
                args = node[op]
                if op == "not" and isinstance(args, dict):
                    children.append(expression(args, f"{path}/{op}"))
                    continue
                if not isinstance(args, list) or not args or (op == "not" and len(args) != 1):
                    reject(f"{path}/{op}", "structure", "unsupported graph boolean structure")
                if isinstance(args, list):
                    children.extend(expression(x, f"{path}/{op}/{i}") for i, x in enumerate(args))
            op = logical[0]
            if op == "not":
                if any(is_filter(child) for child in children):
                    reject(path, "filter_scope", "cannot negate a graph filter")
                return {"kind": op, "arg": children[0] if children else None}
            if children and all(is_filter(child) for child in children):
                reject(path, "filter_only", "graph filters require a predicate")
            if (any(child and child["kind"] == "attribute_filter" for child in children)
                    and not any(has_connection(child) for child in children)):
                reject(path, "filter_scope", "graph attribute filters require a connection expression")
            return {"kind": op, "args": children}
        kind, operator = node.get("cond_type"), node.get("operator")
        if kind == "connection":
            if operator not in {"exists", "not_exists", "one_exists"}:
                reject(f"{path}/operator", "connection_operator", f"unsupported connection operator: {operator}")
            # 'attribute' is descriptive metadata; Checkov's connection solver
            # does not use it to restrict an edge to a Terraform attribute.
            if set(node) - {"cond_type", "resource_types", "connected_resource_types", "operator", "attribute"}:
                reject(path, "fields", "unknown graph connection fields")
            return {"kind": kind, "resource_types": types(node.get("resource_types"), f"{path}/resource_types"),
                    "connected_resource_types": types(node.get("connected_resource_types"), f"{path}/connected_resource_types"), "operator": operator}
        if kind == "filter":
            if set(node) - {"cond_type", "resource_types", "attribute", "operator", "value"}:
                reject(path, "fields", "unknown graph filter fields")
            # The pinned filter solver ignores resource_types. Other predicates
            # select candidates; filters restrict the resulting vertices only.
            if "resource_types" in node:
                types(node["resource_types"], f"{path}/resource_types")
            attribute, value = node.get("attribute"), node.get("value")
            if attribute == "resource_type":
                if operator not in {"within", "not_within"}:
                    reject(f"{path}/operator", "filter_operator", "graph resource-type filter requires within/not_within")
                return {"kind": kind, "resource_types": types(value, f"{path}/value"), "exclude": operator == "not_within"}
            if operator != "within":
                reject(f"{path}/operator", "filter_operator", "graph attribute filter requires within")
            if not isinstance(attribute, str) or not attribute or any(c in attribute for c in ".*?[]/"):
                reject(f"{path}/attribute", "filter_path", "graph attribute filter requires a literal top-level configured attribute")
            if isinstance(attribute, str) and attribute.split(".")[0] in meta_args:
                reject(f"{path}/attribute", "meta_argument", "graph filter requires meta-argument support")
            if not isinstance(value, str) and not (isinstance(value, list) and all(not isinstance(v, (list, dict)) for v in value)):
                reject(f"{path}/value", "filter_value", "graph attribute filter expects a string or list of scalars")
            return {"kind": "attribute_filter", "check": {"attribute": attribute, "value": value}}
        if kind != "attribute":
            reject(path, "condition", f"unsupported graph condition: {kind}")
            return None
        jsonpath = operator in jsonpath_operators
        if operator not in allowed and not jsonpath:
            reject(f"{path}/operator", "attribute_operator", f"unsupported graph operator: {operator}")
        attribute = node.get("attribute")
        compiled_path = []
        if not isinstance(attribute, str) or not attribute:
            reject(f"{path}/attribute", "attribute_path", "graph requires a nonempty attribute path")
        elif jsonpath:
            try:
                compiled_path = _compile_jsonpath(attribute)
            except Exception:
                reject(f"{path}/attribute", "jsonpath", "unsupported JSONPath syntax or filter predicate")
            if "=~" in attribute:
                reject(f"{path}/attribute", "jsonpath_regex", "graph JSONPath predicate requires regex support")
        elif not jsonpath and any(c in attribute for c in "[]/"):
            reject(f"{path}/attribute", "jsonpath", "graph predicate requires JSONPath support")
            if "=~" in attribute:
                reject(f"{path}/attribute", "jsonpath_regex", "graph JSONPath predicate requires regex support")
        elif any(not part or ("*" in part and part != "*") for part in attribute.split(".")):
            reject(f"{path}/attribute", "attribute_path", "graph path requires literal segments or '*' elements")
        root_field = compiled_path[0] if compiled_path else attribute.split(".")[0] if isinstance(attribute, str) else None
        if root_field in meta_args:
            reject(f"{path}/attribute", "meta_argument", "graph predicate requires meta-argument support")
        value = node.get("value")
        if operator in {"within", "not_within", "subset"}:
            if not isinstance(value, list) or any(isinstance(v, (list, dict)) for v in value):
                reject(f"{path}/value", "scalar_list", f"graph {operator} requires scalar list")
        elif operator in size_operators:
            # Match Checkov's force_int at export time; native operands are
            # canonical integers, with no Python coercion needed at runtime.
            try:
                value = int(value)
                if not -(2**63) <= value < 2**63:
                    raise ValueError()
            except (TypeError, ValueError, OverflowError):
                reject(f"{path}/value", "integer_operand", "graph size comparison requires a signed 64-bit integer threshold")
        elif isinstance(value, (list, dict)):
            reject(f"{path}/value", "composite_comparison", "graph composite comparison")
        if set(node) - {"cond_type", "resource_types", "attribute", "operator", "value"}:
            reject(path, "fields", "unknown graph predicate fields")
        if jsonpath:
            return {"kind": "jsonpath", "resource_types": types(node.get("resource_types"), f"{path}/resource_types"),
                    "check": {"path": compiled_path,
                              "operator": operator.removeprefix("jsonpath_"), "value": value}}
        return {"kind": kind, "resource_types": types(node.get("resource_types"), f"{path}/resource_types"),
                "check": {"attribute": attribute, "operator": operator, "value": value}}

    definition = expression(doc.get("definition"), "/definition")
    if is_filter(definition):
        reject("/definition", "filter_only", "graph filters require a predicate")
    if blockers:
        raise Unsupported(blockers[0]["reason"], blockers=blockers)
    def targets(node):
        if node["kind"] in {"attribute", "connection", "jsonpath"}:
            return set(node["resource_types"]) | set(node.get("connected_resource_types", []))
        if is_filter(node):
            return set()
        if node["kind"] == "not":
            return targets(node["arg"])
        return set().union(*(targets(arg) for arg in node["args"]))

    resource_types = targets(definition)
    metadata = doc["metadata"]
    return {
        "version": 3, "name": metadata["id"], "description": metadata["name"],
        "message": metadata["name"].replace("{", "{{").replace("}", "}}"),
        "category": "other", "level": "medium",
        "clauses": [{"resource_types": ["*"] if "*" in resource_types else sorted(resource_types),
                     "condition": {"op": "checkov_graph", "definition": definition}}],
    }


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

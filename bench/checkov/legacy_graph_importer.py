#!/usr/bin/env python3
"""The retired Python translator of Checkov graph policies to rule IR.

oxtf reads Checkov policies natively (`tf_rule_ir::checkov_policy`, a
line-for-line port of this file). This copy is kept only as an offline
oracle: `frontend_fixtures.py` compares the native JSONPath compiler with
`_compile_jsonpath`, and `--export DIR` writes the built-in graph catalog as
a rule-IR pack (`rules.json`, `manifest.json`) for the IR-equality test
(`crates/tf_rule_ir/tests/checkov_policy.rs`). It is not part of tfscan.

    "$CHECKOV_PYTHON" -I bench/checkov/legacy_graph_importer.py --export DIR
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


SUPPORTED_VERSION = "3.2.328"


class Unsupported(ValueError):
    def __init__(self, reason, *, blockers=()):
        super().__init__(reason)
        self.blockers = list(blockers)


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




def export(directory):
    from checkov.terraform import runner

    terraform_dir = Path(runner.__file__).parent
    rules, inventory = [], []
    for source in sorted((terraform_dir / "checks" / "graph_checks").rglob("*.json")):
        doc = json.loads(source.read_text())
        entry = {
            "id": doc["metadata"]["id"], "kind": "graph", "status": "unsupported",
            "source": source.relative_to(terraform_dir.parent).as_posix(),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        }
        try:
            rules.append(_translate_graph(doc))
            entry["status"] = "translated"
        except Unsupported as exc:
            entry["reason"] = str(exc)
            entry["blockers"] = exc.blockers
        inventory.append(entry)
    merged = {}
    for rule in rules:
        if rule["name"] in merged:
            merged[rule["name"]]["clauses"].extend(rule["clauses"])
        else:
            merged[rule["name"]] = rule
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=False)
    (out / "rules.json").write_text(json.dumps([merged[k] for k in sorted(merged)], indent=2, sort_keys=True) + "\n")
    (out / "manifest.json").write_text(json.dumps({"checks": inventory}, indent=2, sort_keys=True) + "\n")
    return inventory


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--export", required=True, help="new output directory")
    args = parser.parse_args()
    inv = export(args.export)
    print(json.dumps({"translated": sum(x["status"] == "translated" for x in inv),
                      "unsupported": sum(x["status"] == "unsupported" for x in inv)}))
    sys.exit(0)

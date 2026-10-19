#!/usr/bin/env python3
"""Classify the Checkov Terraform resource checks the bundled catalog does
not translate (custom or overridden ``scan_resource_conf``) by what their
Python does, to decide which rule-IR operators would translate them.

Run with the pinned Checkov interpreter (``python -I``)::

    "$CHECKOV_PYTHON" -I scripts/classify_checkov.py \\
        --manifest crates/tf_rule_ir/data/checkov/manifest.json \\
        --output bench/checkov/python_checks.json

For each check it reads the code that decides it: the methods of the check
class and of its helper bases (``Abs*`` classes and similar), stopping at
Checkov's generic bases. From the AST it extracts a feature signature
(attributes read, loops, comparisons, calls, constants) and assigns a
*shape*: the kind of operator that would express the check. Shapes are
heuristics over the signature; ``docs/plans/CATALOG_FOLLOWUPS_PLAN.md``
records the hand review of each.
"""
import argparse
import ast
import collections
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import re
import textwrap

from checkov.terraform import runner  # noqa: F401  (registers the checks)
from checkov.terraform.checks.resource.registry import resource_registry
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceValueCheck
from checkov.terraform.checks.resource.base_resource_negative_value_check import (
    BaseResourceNegativeValueCheck,
)
from checkov.common.checks.base_check import BaseCheck

GENERIC = {BaseResourceCheck, BaseResourceValueCheck, BaseResourceNegativeValueCheck, BaseCheck, object}

# Calls whose presence alone places a check.
SECRETS = {"string_has_secrets", "get_secrets_from_string"}
POLICY = {"extract_policy_dict", "json.loads", "loads", "is_json", "is_yaml"}
NETWORK = {"ip_network", "ip_address", "IPv4Network", "IPv6Network", "ipaddress.ip_network"}
POLICY_KEYS = {"Statement", "Effect", "Action", "Resource", "Principal", "NotAction", "Condition"}
CIDR_CONSTANTS = {"0.0.0.0/0", "::/0", "*", "0.0.0.0", "Internet", "any", "Any"}
PORT_KEYS = {"from_port", "to_port", "port", "ports", "port_range", "destination_port_range",
             "destination_port_ranges", "destination_ports", "source_port_range", "protocol"}
CIDR_KEYS = {"cidr_blocks", "ipv6_cidr_blocks", "cidr_block", "source_ranges", "source_address_prefix",
             "source_address_prefixes", "cidr_ip", "source", "source_cidr_ip", "ip_range", "cidr"}
VERSION_HINTS = ("version", "tls", "ssl", "protocol", "minimum", "runtime", "engine")


def checks_by_id():
    out = {}
    for registry in (resource_registry.checks, resource_registry.wildcard_checks):
        for group in registry.values():
            for check in group:
                out.setdefault(check.id, check)
    return out


def deciding_code(check):
    """Source of every method on the check's class and helper bases, and of
    the module-level checkov functions they call (transitively)."""
    parts, classes, seen = [], [], set()

    def add(fn):
        if fn in seen:
            return
        seen.add(fn)
        source = textwrap.dedent(inspect.getsource(fn))
        parts.append(source)
        module = inspect.getmodule(fn)
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                target = vars(module).get(node.func.id) if module else None
                # Helpers of the checks themselves; Checkov's shared utilities
                # (force_list, extract_policy_dict, ...) are placed by name.
                if inspect.isfunction(target) and target.__module__.startswith("checkov.terraform.checks."):
                    add(target)

    for cls in type(check).__mro__:
        if cls in GENERIC:
            break
        classes.append(cls)
        for name, member in vars(cls).items():
            if inspect.isfunction(member) and name != "__init__":
                add(member)
    return classes, strip_annotations("\n".join(parts))


def strip_annotations(code):
    """The code without type annotations, which are not executed."""
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.arg):
            node.annotation = None
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node.returns = None
        elif isinstance(node, ast.AnnAssign):
            node.annotation = ast.Constant(value=None)
    return ast.unparse(tree)


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = dotted(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    return None


def features(code):
    tree = ast.parse(code)
    f = collections.Counter()
    keys, strings, numbers, calls, methods = set(), set(), set(), collections.Counter(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            methods.add(node.name)
        elif isinstance(node, (ast.For, ast.comprehension)):
            f["loop"] += 1
        elif isinstance(node, ast.While):
            f["while"] += 1
        elif isinstance(node, ast.Call):
            name = dotted(node.func) or ""
            short = name.rsplit(".", 1)[-1]
            calls[short] += 1
            if name.endswith(".get") or short == "get":
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    keys.add(node.args[0].value)
            if name in POLICY or short in POLICY:
                f["policy_parse"] += 1
            if short in SECRETS:
                f["secrets"] += 1
            if name in NETWORK or short in NETWORK:
                f["ip_math"] += 1
            if short in {"match", "search", "fullmatch", "findall", "compile", "sub"} and name.startswith("re"):
                f["regex"] += 1
            if short in {"startswith", "endswith", "lower", "upper", "split", "strip", "replace", "find"}:
                f["string_op"] += 1
            if short in {"any", "all"}:
                f["quantifier"] += 1
            if short in {"int", "float", "force_int"}:
                f["number_cast"] += 1
            if short == "len":
                f["length"] += 1
        elif isinstance(node, ast.Subscript):
            sl = node.slice
            if isinstance(sl, ast.Constant):
                if isinstance(sl.value, str):
                    keys.add(sl.value)
                elif isinstance(sl.value, int):
                    f["index"] += 1
        elif isinstance(node, ast.Compare):
            for op in node.ops:
                f["cmp_" + type(op).__name__] += 1
            for side in [node.left, *node.comparators]:
                if isinstance(side, ast.Constant) and isinstance(side.value, str):
                    if side.value in {k for k in keys} or side.value.isidentifier():
                        keys.add(side.value) if node.ops and isinstance(node.ops[0], (ast.In, ast.NotIn)) and side is node.left else None
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                strings.add(node.value)
            elif isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
                numbers.add(node.value)
        elif isinstance(node, ast.If):
            f["branch"] += 1
        elif isinstance(node, ast.Return):
            value = dotted(node.value) if node.value is not None else None
            if value and value.startswith("CheckResult."):
                f["return_" + value.split(".")[1]] += 1
        elif isinstance(node, ast.Try):
            f["try"] += 1
    # What the check reads beyond its own configuration.
    reads = {n for n in calls if n in {"open", "getenv", "environ"}}
    if "self.entity_path" in code or "self.details" in code:
        f["self_state"] += 1
    return {
        "counts": dict(f),
        "keys": sorted(keys),
        "strings": sorted(s for s in strings if len(s) < 80),
        "numbers": sorted(numbers),
        "calls": dict(calls.most_common()),
        "methods": sorted(methods),
        "external": sorted(reads),
        "lines": len([l for l in code.splitlines() if l.strip() and not l.strip().startswith("#")]),
    }


# The restricted Python that a native interpreter over Checkov-shaped
# configuration could run. Each construct belongs to the lowest tier that
# needs it; a check's tier is the highest tier among its constructs.
TIERS = ["decision-tree", "loops", "string-number-ops", "regex", "exceptions", "domain-helper", "outside-subset"]
CORE_CALLS = {"get", "keys", "values", "items", "isinstance", "bool", "list", "dict", "set", "tuple",
              "force_list", "append", "extend", "index", "type", "copy", "pop",
              # Checkov's generic value check, and its unknown-value test (the
              # abstract lattice already models variables it cannot resolve).
              "super", "scan_resource_conf", "_is_variable_dependant", "get_inspected_key",
              "get_expected_value", "get_expected_values", "get_forbidden_values", "add", "update",
              "discard", "remove", "ValueError", "KeyError", "TypeError"}
# Helpers inherited from Checkov's generic bases, by the tier they need.
INHERITED = {"version_string_to_tuple": "string-number-ops", "scan_conf": "domain-helper"}
IGNORED_MODULES = {"logging"}
MODULE_TIERS = {"re": "regex", "fnmatch": "string-number-ops", "itertools": "loops", "json": "domain-helper",
                "yaml": "domain-helper", "dpath": "domain-helper", "ipaddress": "domain-helper"}
LOOP_CALLS = {"any", "all", "len", "enumerate", "range", "zip", "sorted", "filter", "map", "sum", "min", "max",
              "count", "reversed", "sort"}
STRING_NUMBER_CALLS = {"str", "int", "float", "force_int", "force_float", "lower", "upper", "startswith",
                       "endswith", "strip", "lstrip", "rstrip", "split", "rsplit", "replace", "join", "find",
                       "isdigit", "isnumeric", "casefold", "format", "abs", "round", "title", "partition",
                       "zfill", "removeprefix", "removesuffix"}
REGEX_CALLS = {"match", "search", "fullmatch", "compile", "findall", "sub", "group", "groups"}
DOMAIN_CALLS = {"loads", "extract_policy_dict", "is_json", "is_yaml", "safe_load", "string_has_secrets",
                "ip_network", "ip_address", "find_in_dict", "get_resource_tags", "get_secrets_from_string",
                "PolicyDocument", "ResourcePolicyDocument", "search", "fnmatch"}
CONSTANT_TYPES = (str, int, float, bool, list, tuple, set, frozenset, dict, type(None))


def subset(code, classes, check):
    """(tier, blockers): the restricted-Python tier the code stays within,
    and the constructs that put it in a higher tier than decision-tree."""
    tree = ast.parse(code)
    own_methods = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    module_globals = {}
    for cls in classes:
        module = inspect.getmodule(cls)
        if module is not None:
            module_globals.update(vars(module))
    # Globals of the inlined helper functions' modules too.
    for name, value in list(module_globals.items()):
        if inspect.isfunction(value) and value.__module__.startswith("checkov.terraform.checks."):
            module_globals.update({k: v for k, v in vars(inspect.getmodule(value)).items()
                                   if k not in module_globals})
    local_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.arg):
            local_names.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            local_names.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            local_names.add(node.id)
    found = {}

    def need(tier, what):
        if TIERS.index(tier) > TIERS.index(found.get(what, TIERS[0])) or what not in found:
            found[what] = tier

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            # `except ...: return R` as a fallback for any failing lookup.
            need("exceptions", "try")
        elif isinstance(node, ast.Lambda):
            need("loops", "lambda")
        elif isinstance(node, (ast.While, ast.Global, ast.Nonlocal, ast.With, ast.Yield, ast.YieldFrom,
                               ast.ClassDef, ast.Await, ast.NamedExpr)):
            need("outside-subset", type(node).__name__)
        elif isinstance(node, (ast.For, ast.comprehension, ast.Break, ast.Continue)):
            need("loops", "loop")
        elif isinstance(node, ast.BinOp):
            need("string-number-ops", "arithmetic/" + type(node.op).__name__)
        elif isinstance(node, ast.Call):
            name = dotted(node.func) or ""
            short = name.rsplit(".", 1)[-1]
            if name.startswith("self.") and short in own_methods:
                continue
            if name.startswith("CheckResult"):
                continue
            if name.startswith("self.evaluated_keys"):
                continue
            root = name.split(".", 1)[0]
            if root in IGNORED_MODULES:
                continue
            if name.startswith("self.graph"):
                need("outside-subset", "the resource graph")
                continue
            if short in CORE_CALLS:
                continue
            if name.startswith("self.") and short in INHERITED:
                need(INHERITED[short], short)
                continue
            helper = module_globals.get(name)
            if inspect.isfunction(helper) and helper.__module__.startswith("checkov.terraform.checks."):
                continue  # a helper of the checks, whose source is included
            if short in LOOP_CALLS:
                need("loops", short)
            elif short in STRING_NUMBER_CALLS:
                need("string-number-ops", short)
            elif root in MODULE_TIERS:
                need(MODULE_TIERS[root], name)
            elif short in REGEX_CALLS and (name.startswith("re.") or "pattern" in name.lower()
                                           or "regex" in name.lower() or name.split(".")[0].isupper()
                                           or short in {"group", "groups"}):
                need("regex", "re." + short)
            elif short in DOMAIN_CALLS:
                need("domain-helper", short)
            else:
                need("outside-subset", "call " + name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in local_names or node.id in {"self", "CheckResult", "True", "False", "None"}:
                continue
            if node.id in dir(__builtins__) if not isinstance(__builtins__, dict) else node.id in __builtins__:
                continue
            value = module_globals.get(node.id, ast)
            if value is ast:
                need("outside-subset", "unknown name " + node.id)
            elif inspect.ismodule(value):
                name = value.__name__.split(".")[0]
                if name not in IGNORED_MODULES:
                    need(MODULE_TIERS.get(name, "outside-subset"), "module " + name)
            elif isinstance(value, re.Pattern):
                need("regex", "pattern " + node.id)
            elif isinstance(value, range):
                continue
            elif not isinstance(value, CONSTANT_TYPES) and not callable(value):
                need("outside-subset", "global " + node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
            if node.attr in own_methods or node.attr in CORE_CALLS or node.attr in INHERITED \
                    or node.attr in {"evaluated_keys", "id", "name"}:
                continue
            value = getattr(check, node.attr, ast)
            if value is ast or not isinstance(value, CONSTANT_TYPES):
                need("outside-subset", "self." + node.attr)
    if any("Cloudsplaining" in cls.__name__ for cls in classes):
        need("domain-helper", "cloudsplaining IAM action database")
    tier = max((TIERS.index(t) for t in found.values()), default=0)
    return TIERS[tier], sorted(f"{w} ({t})" for w, t in found.items())


def shape(check_id, classes, sig, code):
    """The operator family a check needs, by decreasing specificity."""
    c, keys, strings, calls = sig["counts"], set(sig["keys"]), set(sig["strings"]), sig["calls"]
    names = " ".join(cls.__name__ for cls in classes)
    if sig["external"]:
        return "untranslatable", "reads outside the resource configuration"
    if c.get("secrets"):
        return "secret-scan", "string_has_secrets over attribute values"
    if "Cloudsplaining" in names or c.get("policy_parse") or len(POLICY_KEYS & strings) >= 2:
        return "policy-document", "IAM/resource policy JSON: statements matched on Effect/Action/Resource"
    if (PORT_KEYS & (keys | strings)) and (CIDR_KEYS & (keys | strings) or CIDR_CONSTANTS & strings) \
            or "Unrestricted" in names or "Ingress" in names or "NACL" in names or "Firewall" in names \
            or "NSGRule" in names or "InboundRule" in names:
        return "open-ingress", "rule block admits a port range from a world-open source"
    if c.get("ip_math") or CIDR_CONSTANTS & strings and CIDR_KEYS & (keys | strings):
        return "cidr", "address or CIDR compared to world-open or private ranges"
    if "Flags" in names or "Parameter" in names or {"database_flags", "parameter", "setting", "settings"} & keys \
            and {"name", "value"} <= keys:
        return "named-setting", "find the element of a block list with name N, test its value"
    if c.get("number_cast") or (c.get("cmp_Lt") or c.get("cmp_Gt") or c.get("cmp_LtE") or c.get("cmp_GtE")):
        if any(h in s.lower() for s in keys | strings for h in VERSION_HINTS):
            return "version-compare", "a version/TLS/runtime string parsed and ordered"
        return "number-compare", "a number (possibly a numeric string) compared with a bound"
    if c.get("regex") or c.get("string_op"):
        return "string-match", "prefix/suffix/regex/case-folded match on a value"
    if c.get("loop") or c.get("quantifier"):
        return "quantified-block", "any/all elements of a block list satisfy a predicate"
    if c.get("branch", 0) >= 2 or len(keys) >= 2:
        return "multi-attribute", "a boolean combination of value tests on several attributes"
    return "single-attribute", "one attribute test the value-check metadata could not express"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    assert importlib.metadata.version("checkov") == manifest["source_version"]
    by_id = checks_by_id()
    rows = []
    for entry in manifest["checks"]:
        if entry["kind"] != "resource" or entry["status"] != "unsupported":
            continue
        if not entry["reason"].startswith(("custom Python", "overridden")):
            continue
        check = by_id[entry["id"]]
        classes, code = deciding_code(check)
        sig = features(code)
        label, why = shape(entry["id"], classes, sig, code)
        tier, blockers = subset(code, classes, check)
        rows.append({
            "id": entry["id"],
            "name": entry.get("name") or check.name,
            "file": inspect.getfile(type(check)).split("site-packages/", 1)[1],
            "classes": [cls.__name__ for cls in classes],
            "resource_types": sorted(check.supported_resources),
            "reason": entry["reason"],
            "tier": tier,
            "tier_constructs": blockers,
            "shape": label,
            "shape_reason": why,
            "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
            "signature": sig,
        })
    rows.sort(key=lambda r: r["id"])
    summary = collections.Counter(r["shape"] for r in rows)
    tiers = collections.Counter(r["tier"] for r in rows)
    doc = {
        "schema": 1,
        "source": "checkov",
        "source_version": manifest["source_version"],
        "checks": len(rows),
        "tiers": {t: tiers.get(t, 0) for t in TIERS},
        "shapes": dict(summary.most_common()),
        "rows": rows,
    }
    args.output.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n")
    print(json.dumps({"tiers": doc["tiers"], "shapes": doc["shapes"]}, indent=1))


if __name__ == "__main__":
    main()

"""Serialize a Checkov resource check's Python into a ``checkov_python``
program: the restricted-Python AST that oxtf interprets natively over the
Checkov-shaped resource configuration (``tf_rule_ir::checkov_python``).

The program holds the check's own methods (and those of its helper bases,
up to Checkov's generic bases), the module-level helper functions of the
checks they call, and every constant they read: module globals and the
check instance's attributes are folded in at export. Anything outside the
subset the interpreter implements raises ``Unsupported`` naming it.

The format is plain JSON; ``tf_rule_ir/src/checkov_python.rs`` documents
the same shapes. Python values are tagged so that lists, tuples, sets,
dicts, check results and types stay distinct::

    null | true | 1 | 1.5 | "s"
    {"list": [...]} {"tuple": [...]} {"set": [...]} {"dict": [[k, v], ...]}
    {"result": "PASSED"} {"type": "list"} {"pattern": "regex"} {"range": [a, b, s]}
    {"enum": "Class.MEMBER"} {"funcref": "key"} {"builtin": "name"}
"""
from __future__ import annotations

import ast
import inspect
import json
import math
import re
import textwrap

PROGRAM_VERSION = 1

# Calls the interpreter implements, by the name the program uses.
BUILTINS = {
    "len", "isinstance", "any", "all", "enumerate", "range", "sorted", "reversed", "min", "max",
    "sum", "zip", "list", "dict", "set", "tuple", "bool", "str", "int", "float", "abs", "round",
    "force_list", "force_int", "force_float",
    "re.match", "re.search", "re.fullmatch", "re.findall", "re.compile", "re.sub", "re.split",
    "fnmatch.fnmatch", "json.loads", "json.dumps", "type", "map", "filter",
    "yaml.safe_load", "itertools.chain", "dpath.search", "dpath.get",
    "ipaddress.ip_network", "ipaddress.ip_address", "hasattr",
}
# Checkov helpers run natively, by qualified name: their Python reads
# parser internals, and their meaning over evaluated values is simple.
NATIVE = {
    "checkov.common.util.var_utils.is_terraform_variable_dependent": "is_terraform_variable_dependent",
    "BaseResourceCheck._is_variable_dependant": "is_terraform_variable_dependent",
}
# Modules whose functions and classes are inlined as their Python.
INLINE_MODULES = ("checkov.", "cloudsplaining.", "policy_sentry.")
# Builtins that Checkov's checks import from its utilities.
CHECKOV_HELPERS = {"force_list", "force_int", "force_float"}
TYPES = {list: "list", dict: "dict", str: "str", int: "int", float: "float", bool: "bool",
         tuple: "tuple", set: "set", type(None): "NoneType"}
EXCEPTIONS = {"Exception", "KeyError", "IndexError", "LookupError", "TypeError", "ValueError",
              "AttributeError", "ZeroDivisionError", "ArithmeticError", "JSONDecodeError", "YAMLError"}
# Instance attributes Checkov sets per run; reads of these are state.
RUN_STATE = {"evaluated_keys": [], "details": []}
# Generic-base methods the programs may call; folded by calling them on the
# instance at export (they take no arguments and read only constants).
FOLDABLE = {"get_inspected_key", "get_expected_value", "get_expected_values", "get_forbidden_values",
            "get_excluded_key"}
COMPARE = {ast.Eq: "eq", ast.NotEq: "ne", ast.Lt: "lt", ast.LtE: "le", ast.Gt: "gt", ast.GtE: "ge",
           ast.In: "in", ast.NotIn: "not_in", ast.Is: "is", ast.IsNot: "is_not"}
BINARY = {ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul", ast.Div: "div", ast.FloorDiv: "floordiv",
          ast.Mod: "mod", ast.Pow: "pow"}


class Unsupported(ValueError):
    pass


def value(v, what="constant"):
    """A Python constant in the program's tagged form."""
    # CheckResult is a str enum: tag it before plain strings.
    if type(v).__name__ == "CheckResult":
        return {"result": v.name}
    # Other enums with a str or int mixin compare equal to their value.
    import enum
    if isinstance(v, enum.Enum) and isinstance(v, (str, int)):
        return value(v.value, what)
    # A plain enum member: equal only to itself.
    if isinstance(v, enum.Enum):
        return {"enum": f"{type(v).__name__}.{v.name}"}
    if v is None or isinstance(v, (bool, str)):
        return v
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        if not math.isfinite(v):
            raise Unsupported(f"non-finite {what}")
        return v
    if isinstance(v, list):
        return {"list": [value(x, what) for x in v]}
    if isinstance(v, tuple):
        return {"tuple": [value(x, what) for x in v]}
    if isinstance(v, (set, frozenset)):
        return {"set": [value(x, what) for x in sorted(v, key=repr)]}
    if isinstance(v, dict):
        return {"dict": [[value(k, what), value(x, what)] for k, x in v.items()]}
    if isinstance(v, range):
        return {"range": [v.start, v.stop, v.step]}
    if isinstance(v, re.Pattern):
        if v.flags & ~(re.UNICODE | re.IGNORECASE | re.MULTILINE | re.DOTALL):
            raise Unsupported(f"regex flags in {what}")
        flags = "".join(f for f, bit in (("i", re.IGNORECASE), ("m", re.MULTILINE), ("s", re.DOTALL))
                        if v.flags & bit)
        return {"pattern": (f"(?{flags})" if flags else "") + v.pattern}
    if isinstance(v, type) and v in TYPES:
        return {"type": TYPES[v]}
    raise Unsupported(f"{what} of type {type(v).__name__}")


class Exporter:
    def __init__(self, check, generic, value_check=None):
        self.check = check
        self.generic = generic
        self.functions = {}
        self.pending = []
        self.self_attrs = dict(RUN_STATE)
        # `super().scan_resource_conf` of a value check: its parameters per
        # resource type, run natively (`value_check` builtin).
        self.value_check = value_check
        self.value_check_params = None
        # Whether the function being exported is a method of the check (its
        # `self` is the check instance) rather than of another class.
        self.in_check = True
        self.exported_classes = {}
        self.classes = []
        self.inherited = []
        for cls in type(check).__mro__:
            if cls in generic:
                self.inherited = [c for c in type(check).__mro__[len(self.classes):] if c is not object]
                break
            self.classes.append(cls)

    # -- functions -------------------------------------------------------

    def method(self, name):
        """The defining function of method `name`, and its key: the check's
        own classes first, then helpers of Checkov's generic bases."""
        for cls in self.classes + self.inherited:
            member = vars(cls).get(name)
            if member is None:
                continue
            static = isinstance(member, staticmethod)
            if isinstance(member, (staticmethod, classmethod)):
                member = member.__func__
            if inspect.isfunction(member):
                return f"{cls.__name__}.{name}", member, static
        return None

    def add_function(self, key, fn, *, is_method, static=False, check=True):
        if key in self.functions or key in self.pending:
            return
        self.pending.append(key)
        outer, self.in_check = self.in_check, check
        try:
            self._add_function(key, fn, is_method=is_method, static=static, check=check)
        finally:
            self.in_check = outer
            if key in self.pending:
                self.pending.remove(key)

    def _add_function(self, key, fn, *, is_method, static, check):
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        node = tree.body[0]
        if not isinstance(node, ast.FunctionDef):
            raise Unsupported(f"{key} is not a plain function")
        module_globals = vars(inspect.getmodule(fn))
        args = node.args
        if args.kwarg or args.kwonlyargs or args.posonlyargs:
            raise Unsupported(f"{key}: **kwargs or keyword-only parameters")
        params = [a.arg for a in args.args]
        if is_method and not static and check:
            params = params[1:]
        defaults = [None] * (len(params) - len(args.defaults)) + [
            self.expr(d, module_globals, set()) for d in args.defaults]
        local = set(params) | assigned_names(node)
        body = self.block(node.body, module_globals, local)
        self.functions[key] = {"params": params, "defaults": defaults, "body": body}
        if args.vararg:
            self.functions[key]["vararg"] = args.vararg.arg

    def add_class(self, cls):
        """Export `cls` (a class of an inlined module): its methods and
        properties, through its MRO. A member outside the subset is left out;
        calling it at run time is outside the subset then."""
        key = f"{cls.__module__}.{cls.__qualname__}"
        if key in self.exported_classes:
            return key
        entry = {"methods": {}, "properties": {}, "attrs": {}}
        self.exported_classes[key] = entry
        for c in cls.__mro__:
            if c is object:
                continue
            for name, member in vars(c).items():
                if name in entry["methods"] or name in entry["properties"] or name in entry["attrs"]:
                    continue
                if name.startswith("__") and name != "__init__":
                    continue
                fkey = f"{c.__module__}.{c.__qualname__}.{name}"
                try:
                    if isinstance(member, property):
                        self.add_function(fkey, member.fget, is_method=True, check=False)
                        entry["properties"][name] = fkey
                    elif type(member).__name__ == "cached_property" and hasattr(member, "func"):
                        self.add_function(fkey, member.func, is_method=True, check=False)
                        entry["properties"][name] = fkey
                    elif isinstance(member, staticmethod):
                        self.add_function(fkey, member.__func__, is_method=True, static=True, check=False)
                        entry["methods"][name] = fkey
                        entry.setdefault("static", []).append(name)
                    elif inspect.isfunction(member):
                        self.add_function(fkey, member, is_method=True, check=False)
                        entry["methods"][name] = fkey
                    elif not callable(member) and not isinstance(member, (classmethod,)):
                        entry["attrs"][name] = value(member, f"{key}.{name}")
                except Unsupported:
                    self.functions.pop(fkey, None)
        return key

    # -- statements ------------------------------------------------------

    def block(self, stmts, g, local):
        out = []
        for s in stmts:
            st = self.stmt(s, g, local)
            if st is not None:
                out.append(st)
        return out

    def stmt(self, s, g, local):
        if isinstance(s, ast.Expr):
            if isinstance(s.value, ast.Constant):
                return None  # docstring
            if is_logging(s.value, g):
                return None
            return {"s": "expr", "value": self.expr(s.value, g, local)}
        if isinstance(s, ast.Return):
            return {"s": "return", "value": None if s.value is None else self.expr(s.value, g, local)}
        if isinstance(s, ast.If):
            return {"s": "if", "test": self.expr(s.test, g, local), "body": self.block(s.body, g, local),
                    "orelse": self.block(s.orelse, g, local)}
        if isinstance(s, ast.For):
            return {"s": "for", "target": self.target(s.target, g, local), "iter": self.expr(s.iter, g, local),
                    "body": self.block(s.body, g, local), "orelse": self.block(s.orelse, g, local)}
        if isinstance(s, ast.Assign):
            return {"s": "assign", "targets": [self.target(t, g, local) for t in s.targets],
                    "value": self.expr(s.value, g, local)}
        if isinstance(s, ast.AnnAssign):
            if s.value is None:
                return None
            return {"s": "assign", "targets": [self.target(s.target, g, local)], "value": self.expr(s.value, g, local)}
        if isinstance(s, ast.AugAssign):
            op = BINARY.get(type(s.op))
            if op is None:
                raise Unsupported(f"augmented operator {type(s.op).__name__}")
            return {"s": "aug", "target": self.target(s.target, g, local), "op": op,
                    "value": self.expr(s.value, g, local)}
        if isinstance(s, ast.Pass):
            return {"s": "pass"}
        if isinstance(s, ast.Break):
            return {"s": "break"}
        if isinstance(s, ast.Continue):
            return {"s": "continue"}
        if isinstance(s, ast.Try):
            handlers = []
            for h in s.handlers:
                handlers.append({"types": self.exception_types(h.type, g), "name": h.name,
                                 "body": self.block(h.body, g, local)})
            return {"s": "try", "body": self.block(s.body, g, local), "handlers": handlers,
                    "orelse": self.block(s.orelse, g, local), "finally": self.block(s.finalbody, g, local)}
        if isinstance(s, ast.Raise):
            if s.exc is None:
                return {"s": "raise", "type": None}
            exc = s.exc.func if isinstance(s.exc, ast.Call) else s.exc
            name = exc.id if isinstance(exc, ast.Name) else None
            if name not in EXCEPTIONS:
                raise Unsupported(f"raise of {ast.unparse(s.exc)}")
            return {"s": "raise", "type": name}
        raise Unsupported(f"statement {type(s).__name__}")

    def exception_types(self, node, g):
        if node is None:
            return None
        names = node.elts if isinstance(node, ast.Tuple) else [node]
        out = []
        for n in names:
            name = n.attr if isinstance(n, ast.Attribute) else getattr(n, "id", None)
            if name not in EXCEPTIONS:
                raise Unsupported(f"except {ast.unparse(n)}")
            out.append(name)
        return out

    def target(self, t, g, local):
        if isinstance(t, ast.Name):
            return {"t": "name", "id": t.id}
        if isinstance(t, (ast.Tuple, ast.List)):
            return {"t": "tuple", "elts": [self.target(e, g, local) for e in t.elts]}
        if isinstance(t, ast.Subscript):
            return {"t": "sub", "value": self.expr(t.value, g, local), "index": self.expr(t.slice, g, local)}
        if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self" \
                and self.in_check:
            return {"t": "self", "attr": t.attr}
        if isinstance(t, ast.Attribute):
            return {"t": "attr", "value": self.expr(t.value, g, local), "attr": t.attr}
        raise Unsupported(f"assignment to {ast.unparse(t)}")

    # -- expressions -----------------------------------------------------

    def expr(self, e, g, local):
        if isinstance(e, ast.Constant):
            return {"e": "const", "v": value(e.value)}
        if isinstance(e, ast.Name):
            if e.id in local:
                return {"e": "name", "id": e.id}
            return {"e": "const", "v": self.global_value(e.id, g)}
        if isinstance(e, ast.Attribute):
            return self.attribute(e, g, local)
        if isinstance(e, ast.Call):
            return self.call(e, g, local)
        if isinstance(e, ast.Subscript):
            if isinstance(e.slice, ast.Slice):
                sl = e.slice
                part = lambda x: None if x is None else self.expr(x, g, local)  # noqa: E731
                return {"e": "slice", "value": self.expr(e.value, g, local),
                        "lower": part(sl.lower), "upper": part(sl.upper), "step": part(sl.step)}
            return {"e": "sub", "value": self.expr(e.value, g, local), "index": self.expr(e.slice, g, local)}
        if isinstance(e, ast.Compare):
            return {"e": "cmp", "left": self.expr(e.left, g, local),
                    "ops": [COMPARE[type(o)] for o in e.ops],
                    "comparators": [self.expr(c, g, local) for c in e.comparators]}
        if isinstance(e, ast.BoolOp):
            return {"e": "and" if isinstance(e.op, ast.And) else "or",
                    "values": [self.expr(v, g, local) for v in e.values]}
        if isinstance(e, ast.UnaryOp):
            op = {ast.Not: "not", ast.USub: "neg", ast.UAdd: "pos"}.get(type(e.op))
            if op is None:
                raise Unsupported(f"unary {type(e.op).__name__}")
            return {"e": op, "operand": self.expr(e.operand, g, local)}
        if isinstance(e, ast.BinOp):
            op = BINARY.get(type(e.op))
            if op is None:
                raise Unsupported(f"operator {type(e.op).__name__}")
            return {"e": "bin", "op": op, "left": self.expr(e.left, g, local), "right": self.expr(e.right, g, local)}
        if isinstance(e, ast.IfExp):
            return {"e": "ifexp", "test": self.expr(e.test, g, local), "body": self.expr(e.body, g, local),
                    "orelse": self.expr(e.orelse, g, local)}
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            if any(isinstance(x, ast.Starred) for x in e.elts):
                raise Unsupported("starred element")
            kind = {ast.List: "list", ast.Tuple: "tuple", ast.Set: "set"}[type(e)]
            return {"e": kind, "elts": [self.expr(x, g, local) for x in e.elts]}
        if isinstance(e, ast.Dict):
            if any(k is None for k in e.keys):
                raise Unsupported("dict unpacking")
            return {"e": "dict", "keys": [self.expr(k, g, local) for k in e.keys],
                    "values": [self.expr(v, g, local) for v in e.values]}
        if isinstance(e, (ast.ListComp, ast.GeneratorExp, ast.SetComp, ast.DictComp)):
            inner = local | comprehension_names(e)
            gens = [{"target": self.target(c.target, g, inner), "iter": self.expr(c.iter, g, inner),
                     "ifs": [self.expr(i, g, inner) for i in c.ifs]} for c in e.generators]
            if any(c.is_async for c in e.generators):
                raise Unsupported("async comprehension")
            kind = {ast.ListComp: "listcomp", ast.GeneratorExp: "genexp", ast.SetComp: "setcomp",
                    ast.DictComp: "dictcomp"}[type(e)]
            out = {"e": kind, "generators": gens}
            if isinstance(e, ast.DictComp):
                out.update(key=self.expr(e.key, g, inner), value=self.expr(e.value, g, inner))
            else:
                out["elt"] = self.expr(e.elt, g, inner)
            return out
        if isinstance(e, ast.Lambda):
            a = e.args
            if a.vararg or a.kwarg or a.kwonlyargs or a.defaults:
                raise Unsupported("lambda with defaults or variadic parameters")
            params = [x.arg for x in a.args]
            return {"e": "lambda", "params": params, "body": self.expr(e.body, g, local | set(params))}
        if isinstance(e, ast.JoinedStr):
            parts = []
            for v in e.values:
                if isinstance(v, ast.Constant):
                    parts.append({"e": "const", "v": v.value})
                else:
                    if v.format_spec is not None or v.conversion not in (-1, ord("s")):
                        raise Unsupported("f-string format spec or conversion")
                    parts.append({"e": "call", "func": {"builtin": "str"}, "args": [self.expr(v.value, g, local)],
                                  "kwargs": []})
            return {"e": "fstr", "parts": parts}
        raise Unsupported(f"expression {type(e).__name__}")

    def global_value(self, name, g):
        if name in {"True", "False", "None"}:
            return value({"True": True, "False": False, "None": None}[name])
        if name in g:
            target = g[name]
        elif name in TYPE_NAMES:
            return {"type": TYPE_NAMES[name]}
        else:
            raise Unsupported(f"unknown name {name}")
        if inspect.isfunction(target) and target.__module__.startswith(INLINE_MODULES):
            key = f"{target.__module__}.{target.__name__}"
            self.add_function(key, target, is_method=False)
            return {"funcref": key}
        if name in BUILTINS and getattr(target, "__module__", "") in ("builtins", "checkov.common.util.type_forcers"):
            return {"builtin": name}
        if inspect.isfunction(target) or inspect.ismodule(target) or inspect.isclass(target) and target not in TYPES:
            raise Unsupported(f"{name} used as a value")
        return value(target, f"global {name}")

    def attribute(self, e, g, local):
        base = e.value
        if isinstance(base, ast.Name) and base.id == "self" and "self" in local and self.in_check:
            found = self.method(e.attr)
            if found is not None:
                key, fn, static = found
                self.add_function(key, fn, is_method=True, static=static)
                return {"e": "const", "v": {"funcref": key}}
            return {"e": "self", "attr": e.attr}
        if isinstance(base, ast.Name) and base.id not in local:
            holder = g.get(base.id)
            if holder is not None and (inspect.ismodule(holder) or inspect.isclass(holder)):
                target = getattr(holder, e.attr)
                name = f"{getattr(holder, '__name__', base.id)}.{e.attr}"
                if name in BUILTINS:
                    return {"e": "const", "v": {"builtin": name}}
                if inspect.isfunction(target) and target.__module__.startswith(INLINE_MODULES):
                    key = f"{target.__module__}.{target.__name__}"
                    self.add_function(key, target, is_method=False)
                    return {"e": "const", "v": {"funcref": key}}
                return {"e": "const", "v": value(target, name)}
        return {"e": "attr", "value": self.expr(base, g, local), "attr": e.attr}

    def call(self, e, g, local):
        if any(isinstance(a, ast.Starred) for a in e.args) or any(k.arg is None for k in e.keywords):
            raise Unsupported("*args or **kwargs in a call")
        args = [self.expr(a, g, local) for a in e.args]
        kwargs = [[k.arg, self.expr(k.value, g, local)] for k in e.keywords]
        f = e.func
        call = lambda func: {"e": "call", "func": func, "args": args, "kwargs": kwargs}  # noqa: E731
        # self.method(...)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self" \
                and "self" in local and self.in_check:
            found = self.method(f.attr)
            if found is not None:
                key, fn, static = found
                if key in NATIVE:
                    return call({"builtin": NATIVE[key]})
                self.add_function(key, fn, is_method=True, static=static)
                return call({"func": key})
            if f.attr in FOLDABLE and not args and not kwargs:
                return {"e": "const", "v": value(getattr(self.check, f.attr)(), f"self.{f.attr}()")}
            raise Unsupported(f"call self.{f.attr}")
        # super().method(...)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call) \
                and isinstance(f.value.func, ast.Name) and f.value.func.id == "super":
            if f.attr == "scan_resource_conf" and self.value_check is not None:
                if self.value_check_params is None:
                    self.value_check_params = self.value_check(self.check)
                return call({"builtin": "value_check"})
            found = None
            for cls in self.inherited:
                member = vars(cls).get(f.attr)
                if inspect.isfunction(member) and f.attr != "scan_resource_conf":
                    found = (f"{cls.__name__}.{f.attr}", member)
                    break
            if found is None:
                raise Unsupported(f"super().{f.attr}")
            self.add_function(found[0], found[1], is_method=True)
            return call({"func": found[0]})
        # module.function(...) and builtins
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id not in local:
            holder = g.get(f.value.id)
            name = f"{getattr(holder, '__name__', f.value.id)}.{f.attr}"
            if inspect.ismodule(holder) and name in BUILTINS:
                return call({"builtin": name})
            if inspect.ismodule(holder) and holder.__name__ == "logging":
                return {"e": "const", "v": None}
            if isinstance(holder, re.Pattern) and f.attr in {"match", "search", "fullmatch", "findall", "sub", "split"}:
                return {"e": "call", "func": {"builtin": f"re.{f.attr}"},
                        "args": [{"e": "const", "v": value(holder)}, *args], "kwargs": kwargs}
            if holder is not None and inspect.isclass(holder):
                member = inspect.getattr_static(holder, f.attr, None)
                if isinstance(member, staticmethod):
                    member = member.__func__
                if inspect.isfunction(member) and member.__module__.startswith("checkov."):
                    key = f"{holder.__name__}.{f.attr}"
                    if key in NATIVE:
                        return call({"builtin": NATIVE[key]})
                    self.add_function(key, member, is_method=False)
                    return call({"func": key})
                raise Unsupported(f"call {ast.unparse(f)}")
        if isinstance(f, ast.Attribute):
            return call({"method": f.attr, "obj": self.expr(f.value, g, local)})
        if isinstance(f, ast.Name):
            if f.id in local:
                return call({"local": f.id})
            target = g.get(f.id)
            # hasattr(self, "x") on the check: decided at export.
            if f.id == "hasattr" and target is None and self.in_check and len(e.args) == 2 \
                    and isinstance(e.args[0], ast.Name) and e.args[0].id == "self" \
                    and isinstance(e.args[1], ast.Constant):
                return {"e": "const", "v": hasattr(self.check, e.args[1].value)}
            qualified = f"{getattr(target, '__module__', '')}.{getattr(target, '__name__', '')}"
            if callable(target) and qualified in BUILTINS:
                return call({"builtin": qualified})
            if f.id in BUILTINS and (target is None or getattr(target, "__module__", "").startswith(
                    ("builtins", "checkov.common.util.type_forcers"))):
                return call({"builtin": f.id})
            if target is None and f.id in TYPE_NAMES:
                return call({"builtin": f.id})
            if f.id in EXCEPTIONS:
                return {"e": "exception", "type": f.id}
            if inspect.isfunction(target) and target.__module__.startswith(INLINE_MODULES):
                key = f"{target.__module__}.{target.__name__}"
                if key in NATIVE:
                    return call({"builtin": NATIVE[key]})
                self.add_function(key, target, is_method=False)
                return call({"func": key})
            if inspect.isclass(target) and target.__module__.startswith(INLINE_MODULES) and target not in TYPES:
                return call({"class": self.add_class(target)})
            raise Unsupported(f"call {f.id}")
        raise Unsupported(f"call {ast.unparse(f)}")


TYPE_NAMES = {"list": "list", "dict": "dict", "str": "str", "int": "int", "float": "float", "bool": "bool",
              "tuple": "tuple", "set": "set"}


def is_logging(e, g):
    """A call on the `logging` module or a Logger: dropped."""
    import logging
    if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and isinstance(e.func.value, ast.Name):
        holder = g.get(e.func.value.id)
        return (inspect.ismodule(holder) and holder.__name__ == "logging") or isinstance(holder, logging.Logger)
    return False


def assigned_names(fn):
    names = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
    return names


def comprehension_names(e):
    return {n.id for c in e.generators for n in ast.walk(c.target) if isinstance(n, ast.Name)}


def export(check, generic, value_check=None):
    """The ``checkov_python`` program for ``check``, or ``Unsupported``.

    ``value_check(check)`` gives the parameters of the generic value check
    per resource type, for checks that call ``super().scan_resource_conf``.
    """
    ex = Exporter(check, generic, value_check)
    found = ex.method("scan_resource_conf")
    if found is None:
        raise Unsupported("scan_resource_conf is not defined below the generic bases")
    key, fn, static = found
    ex.add_function(key, fn, is_method=True, static=static)
    # Only the attributes the program reads (and the per-run state).
    reads = walk_tagged(ex.functions, "e", "self")
    attrs = {}
    for name, v in vars(check).items():
        if name in RUN_STATE or name.startswith("__") or name not in reads:
            continue
        try:
            attrs[name] = value(v, f"self.{name}")
        except Unsupported:
            pass  # unreadable: a program that reads it fails at runtime
    for name, v in RUN_STATE.items():
        attrs[name] = value(v)
    program = {"version": PROGRAM_VERSION, "entry": key, "functions": ex.functions, "self": attrs}
    if ex.exported_classes:
        program["classes"] = ex.exported_classes
    if ex.value_check_params is not None:
        program["value_check"] = ex.value_check_params
    # Where a failing check points: its get_evaluated_keys, when it has one
    # and self.evaluated_keys is left empty.
    found = ex.method("get_evaluated_keys")
    if found is not None:
        k, f, static = found
        try:
            ex.add_function(k, f, is_method=True, static=static)
            program["evaluated_keys"] = k
            program["functions"] = ex.functions
        except Unsupported:
            ex.functions.pop(k, None)
    used = walk_tagged(program, "e", "self") - walk_tagged(program, "t", "self")
    missing = sorted(used - attrs.keys() - {"entity_type"})
    if missing:
        raise Unsupported("reads instance state: " + ", ".join(f"self.{m}" for m in missing))
    json.dumps(program, allow_nan=False)
    return program


def walk_tagged(node, tag, kind, out=None):
    """The `attr` of every node tagged `{tag: kind}` (self reads or writes)."""
    out = set() if out is None else out
    if isinstance(node, dict):
        if node.get(tag) == kind and "attr" in node:
            out.add(node["attr"])
        for v in node.values():
            walk_tagged(v, tag, kind, out)
    elif isinstance(node, list):
        for v in node:
            walk_tagged(v, tag, kind, out)
    return out

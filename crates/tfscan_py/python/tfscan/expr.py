"""Polars-style rule expressions that build the JSON rule IR.

The IR schema is defined (and validated) in Rust (``crates/tf_rule_ir``);
this module only builds it. ``Rule.compile()`` hands the JSON to Rust, which
parses, validates and compiles it; scans then evaluate it on Rust worker
threads without the GIL.

    from tfscan import col, element, rule

    open_ssh = (
        rule("py-sg-open-ssh", level="high")
        .on("aws_security_group")
        .for_each("ingress")
        .where_(col("cidr_blocks").list.contains("0.0.0.0/0") & (col("from_port") <= 22))
        .message("ingress allows SSH from {witness|the internet}")
    )

Evaluation uses the engine's four-valued truth: a condition that holds
because of an unconstrained variable gives a *conditional* finding, one that
depends on an apply-time unknown gives no finding.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Iterable, Sequence, Union

Scalar = Union[None, bool, int, float, str]

LEVELS = ("low", "medium", "high", "critical")
CATEGORIES = ("network", "storage", "iam", "encryption")


def _scalar(v: Any) -> Scalar:
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    raise TypeError(f"literal must be None, bool, int, float or str, got {type(v).__name__}")


def _ir(x: Any) -> dict:
    if isinstance(x, Expr):
        return x._ir
    return {"op": "lit", "value": _scalar(x)}


class Expr:
    """An expression node. Combine with ``& | ~`` and compare with
    ``== != < <= > >=``. Using an ``Expr`` in a Python ``if``/``and``/``or``
    raises (as in polars), because that would not build an expression."""

    __slots__ = ("_ir",)
    __hash__ = None  # type: ignore[assignment]

    def __init__(self, ir: dict):
        self._ir = ir

    # -- IR -------------------------------------------------------------
    def to_ir(self) -> dict:
        return copy.deepcopy(self._ir)

    def __repr__(self) -> str:
        return f"Expr({json.dumps(self._ir)})"

    def __bool__(self) -> bool:
        raise TypeError("an Expr has no truth value; use & | ~ instead of and/or/not")

    # -- comparisons ------------------------------------------------------
    def _cmp(self, op: str, other: Any) -> "Expr":
        return Expr({"op": "cmp", "cmp": op, "left": self._ir, "right": _ir(other)})

    def __eq__(self, other: Any) -> "Expr":  # type: ignore[override]
        return self._cmp("eq", other)

    def __ne__(self, other: Any) -> "Expr":  # type: ignore[override]
        return self._cmp("ne", other)

    def __lt__(self, other: Any) -> "Expr":
        return self._cmp("lt", other)

    def __le__(self, other: Any) -> "Expr":
        return self._cmp("le", other)

    def __gt__(self, other: Any) -> "Expr":
        return self._cmp("gt", other)

    def __ge__(self, other: Any) -> "Expr":
        return self._cmp("ge", other)

    # -- boolean ----------------------------------------------------------
    def _join(self, op: str, other: Any) -> "Expr":
        args: list = []
        for x in (self, other):
            ir = _ir(x)
            if ir.get("op") == op:
                args.extend(ir["args"])
            else:
                args.append(ir)
        return Expr({"op": op, "args": args})

    def __and__(self, other: Any) -> "Expr":
        return self._join("and", other)

    def __rand__(self, other: Any) -> "Expr":
        return Expr(_ir(other))._join("and", self)

    def __or__(self, other: Any) -> "Expr":
        return self._join("or", other)

    def __ror__(self, other: Any) -> "Expr":
        return Expr(_ir(other))._join("or", self)

    def __invert__(self) -> "Expr":
        return Expr({"op": "not", "arg": self._ir})

    # -- predicates ---------------------------------------------------------
    def is_in(self, values: Iterable[Scalar]) -> "Expr":
        return Expr({"op": "is_in", "expr": self._ir, "values": [_scalar(v) for v in values]})

    def is_null(self) -> "Expr":
        return Expr({"op": "is_null", "expr": self._ir})

    def is_not_null(self) -> "Expr":
        return ~self.is_null()

    def is_known(self) -> "Expr":
        """Wholly known (two-valued: never conditional or unknown itself)."""
        return Expr({"op": "is_known", "expr": self._ir})

    @property
    def list(self) -> "ListNamespace":
        return ListNamespace(self)


class ListNamespace:
    __slots__ = ("_e",)

    def __init__(self, e: Expr):
        self._e = e

    def contains(self, value: Scalar) -> Expr:
        """Some element equals ``value``."""
        return Expr({"op": "list_contains", "list": self._e._ir, "value": _scalar(value)})

    def any(self, pred: Expr) -> Expr:
        """Some element satisfies ``pred`` (use ``element()`` / ``col()`` inside)."""
        return Expr({"op": "list_any", "list": self._e._ir, "pred": _ir(pred)})

    def all(self, pred: Expr) -> Expr:
        """Every element satisfies ``pred`` (true for an empty list)."""
        return Expr({"op": "list_all", "list": self._e._ir, "pred": _ir(pred)})


def col(name: str, *path: str, default: bool = False) -> Expr:
    """Attribute access: ``col("ingress")``, ``col("versioning", "enabled")``
    or ``col("versioning.enabled")``. At resource scope an absent attribute is
    ``null`` (or, with ``default=True``, the provider default from the
    defaults overlay); inside ``for_each`` / ``list.any`` it reads fields of
    the current element."""
    parts = name.split(".") + list(path)
    ir: dict = {"op": "col", "path": parts}
    if default:
        ir["default"] = True
    return Expr(ir)


def element() -> Expr:
    """The current list element (inside ``list.any`` / ``list.all``)."""
    return Expr({"op": "element"})


def lit(value: Scalar) -> Expr:
    return Expr({"op": "lit", "value": _scalar(value)})


def all_of(*exprs: Expr) -> Expr:
    out = exprs[0]
    for e in exprs[1:]:
        out = out & e
    return out


def any_of(*exprs: Expr) -> Expr:
    out = exprs[0]
    for e in exprs[1:]:
        out = out | e
    return out


class Rule:
    """A rule made of clauses. ``rule(name, resource_types=[...])`` starts
    the first clause; ``.on(types)`` starts another (clauses are or-ed for a
    resource whose type several of them name)."""

    def __init__(
        self,
        name: str,
        resource_types: Sequence[str] | None = None,
        *,
        level: str = "medium",
        category: str = "network",
        description: str = "",
        message: str = "{address} violates {rule}",
    ):
        if level not in LEVELS:
            raise ValueError(f"level must be one of {LEVELS}")
        if category not in CATEGORIES:
            raise ValueError(f"category must be one of {CATEGORIES}")
        self.name = name
        self.level = level
        self.category = category
        self.description = description
        self._message = message
        self._clauses: list[dict] = []
        if resource_types:
            self.on(*resource_types)

    def _cur(self) -> dict:
        if not self._clauses:
            raise ValueError("call .on(resource_type, ...) first")
        return self._clauses[-1]

    def on(self, *resource_types: str) -> "Rule":
        types = [t for ts in resource_types for t in ([ts] if isinstance(ts, str) else ts)]
        self._clauses.append({"resource_types": types, "condition": None})
        return self

    def for_each(self, attr: str | Expr) -> "Rule":
        """Evaluate the condition per element of a list attribute (or
        attribute-as-blocks such as ``ingress``)."""
        self._cur()["for_each"] = (col(attr) if isinstance(attr, str) else attr)._ir
        return self

    def where_(self, cond: Expr) -> "Rule":
        c = self._cur()
        c["condition"] = cond._ir if c["condition"] is None else (Expr(c["condition"]) & cond)._ir
        return self

    where = where_

    def message(self, template: str) -> "Rule":
        """Placeholders: {address} {type} {name} {rule} {witness} {witness|fallback}."""
        self._message = template
        return self

    def to_ir(self) -> dict:
        clauses = []
        for c in self._clauses:
            if c["condition"] is None:
                raise ValueError(f"rule {self.name}: clause {c['resource_types']} has no .where_()")
            out = {"resource_types": list(c["resource_types"])}
            if "for_each" in c:
                out["for_each"] = copy.deepcopy(c["for_each"])
            out["condition"] = copy.deepcopy(c["condition"])
            clauses.append(out)
        return {
            "version": 1,
            "name": self.name,
            "description": self.description,
            "level": self.level,
            "category": self.category,
            "message": self._message,
            "clauses": clauses,
        }

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_ir(), indent=indent)

    def compile(self):
        """Validate in Rust; returns the ``CompiledRule``."""
        from . import _tfscan

        return _tfscan.compile_rules(self.to_json())[0]

    @staticmethod
    def from_ir(ir: dict) -> "Rule":
        r = Rule(
            ir["name"],
            level=ir.get("level", "medium"),
            category=ir.get("category", "network"),
            description=ir.get("description", ""),
            message=ir["message"],
        )
        r._clauses = [copy.deepcopy(c) for c in ir["clauses"]]
        return r

    def __repr__(self) -> str:
        return f"Rule({self.name!r}, clauses={len(self._clauses)})"


rule = Rule


def save_rules(path: str, rules: Sequence[Rule]) -> None:
    """Write rules as an IR document runnable by ``oxtf scan --rule-file``.
    Callback rules are Python functions and cannot be serialized."""
    for r in rules:
        if not isinstance(r, Rule):
            raise TypeError(
                f"{r!r} is not an expression rule; only tfscan.rule(...) rules serialize to the rule IR"
            )
    with open(path, "w") as f:
        json.dump({"rules": [r.to_ir() for r in rules]}, f, indent=2)
        f.write("\n")


def load_rules(path: str) -> list[Rule]:
    with open(path) as f:
        doc = json.load(f)
    items = doc["rules"] if isinstance(doc, dict) and "rules" in doc else doc
    if isinstance(items, dict):
        items = [items]
    return [Rule.from_ir(x) for x in items]

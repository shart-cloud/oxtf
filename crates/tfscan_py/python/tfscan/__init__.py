"""tfscan: Python bindings for the oxtf Terraform security analyzer.

    import tfscan
    from tfscan import col, rule

    res = tfscan.scan("path/to/root", recursive=True)
    for f in res.findings:
        print(f.rule, f.severity, f.address, f.message, f.file, f.line)
    table = res.findings_arrow()            # pyarrow.Table
    resources = res.resources.to_arrow()    # pyarrow.Table

The scan (parse, analysis, built-in and expression rules) runs in Rust with
the GIL released. Callback rules (``@tfscan.callback_rule``) re-acquire the
GIL once per resource that passes their Rust-side type filter.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Iterable, Iterator, NamedTuple, Optional, Sequence, Union, overload

from . import _tfscan
from ._tfscan import (
    IR_VERSION,
    CompiledRule,
    Document,
    Finding,
    Node,
    Resource,
    Value,
    builtin_rules,
    compile_rules,
)
from .expr import Expr, Rule, all_of, any_of, col, element, lit, load_rules, rule, save_rules

__version__ = "0.0.1"

__all__ = [
    "scan",
    "scan_plan",
    "analyze",
    "parse",
    "ScanResult",
    "Resources",
    "Finding",
    "Resource",
    "Value",
    "Document",
    "Node",
    "Expr",
    "Rule",
    "rule",
    "col",
    "element",
    "lit",
    "all_of",
    "any_of",
    "save_rules",
    "load_rules",
    "CallbackRule",
    "callback_rule",
    "Report",
    "CompiledRule",
    "compile_rules",
    "builtin_rules",
    "IR_VERSION",
]

PathLike = Union[str, "os.PathLike[str]"]


class Report(NamedTuple):
    """What a callback rule returns to report a finding. ``witness`` (a
    ``Value``) supplies the provenance chain and primary location;
    ``conditional=True`` reports a conditional finding."""

    message: str
    witness: Optional[Value] = None
    conditional: bool = False


class CallbackRule:
    """A Python function run for each resource of ``resource_types`` (the
    filter is applied in Rust). It returns ``None``/``False`` (no finding),
    a message string, a ``Report``, or a list of those."""

    def __init__(
        self,
        func: Callable[[Resource], Any],
        name: str,
        resource_types: Sequence[str],
        level: str = "medium",
        category: str = "network",
        description: str = "",
    ):
        if not resource_types:
            raise ValueError("callback rules need resource_types (the Rust-side filter)")
        self.func = func
        self.name = name
        self.resource_types = list(resource_types)
        self.level = level
        self.category = category
        self.description = description or (func.__doc__ or "").strip()

    def __call__(self, resource: Resource) -> Any:
        return self.func(resource)

    def __repr__(self) -> str:
        return f"CallbackRule({self.name!r}, {self.resource_types})"


def callback_rule(
    name: str,
    resource_types: Sequence[str],
    *,
    level: str = "medium",
    category: str = "network",
    description: str = "",
) -> Callable[[Callable[[Resource], Any]], CallbackRule]:
    def deco(func: Callable[[Resource], Any]) -> CallbackRule:
        return CallbackRule(func, name, resource_types, level, category, description)

    return deco


def _arrow_table(stream: Any) -> Any:
    import pyarrow as pa  # type: ignore[import-untyped]

    return pa.RecordBatchReader.from_stream(stream).read_all()


class Resources(Sequence[Resource]):
    """All resource and data-source instances of a scan."""

    def __init__(self, inner: _tfscan.ScanResult):
        self._inner = inner
        self._items: Optional[list[Resource]] = None

    def _list(self) -> list[Resource]:
        if self._items is None:
            self._items = self._inner.resources
        return self._items

    def __len__(self) -> int:
        return self._inner.resource_count

    @overload
    def __getitem__(self, i: int) -> Resource: ...
    @overload
    def __getitem__(self, i: slice) -> Sequence[Resource]: ...
    def __getitem__(self, i):  # type: ignore[no-untyped-def]
        return self._list()[i]

    def __iter__(self) -> Iterator[Resource]:
        return iter(self._list())

    def of_type(self, ty: str) -> list[Resource]:
        return [r for r in self._list() if r.type == ty]

    def to_arrow(self) -> Any:
        """``pyarrow.Table``: root, module, address, base_address, mode, type,
        name, key, existence, file, line, column, attributes (JSON)."""
        return _arrow_table(self._inner._resources_stream())

    def __arrow_c_stream__(self, requested_schema: Any = None) -> Any:
        return self._inner._resources_stream().__arrow_c_stream__(requested_schema)


class ScanResult:
    def __init__(self, inner: _tfscan.ScanResult, callback_calls: int = 0):
        self._inner = inner
        self._findings: Optional[list[Finding]] = None
        #: Number of Python callback invocations during the scan.
        self.callback_calls = callback_calls

    @property
    def findings(self) -> list[Finding]:
        if self._findings is None:
            self._findings = self._inner.findings
        return self._findings

    @property
    def resources(self) -> Resources:
        return Resources(self._inner)

    @property
    def stats(self) -> dict:
        return self._inner.stats

    @property
    def diagnostics(self) -> list[dict]:
        return self._inner.diagnostics

    @property
    def rule_errors(self) -> list[dict]:
        """Rules that failed on some resource (``rule``, ``resource``,
        ``message``). Never silent: a missing finding from such a rule is
        not a pass."""
        return self._inner.rule_errors

    def to_json(self) -> str:
        return self._inner.to_json()

    def findings_arrow(self) -> Any:
        """``pyarrow.Table`` of findings (provenance as list<struct>)."""
        return _arrow_table(self._inner._findings_stream())

    to_arrow = findings_arrow

    def __arrow_c_stream__(self, requested_schema: Any = None) -> Any:
        return self._inner._findings_stream().__arrow_c_stream__(requested_schema)

    def __repr__(self) -> str:
        return repr(self._inner)


def _paths(path: Union[PathLike, Iterable[PathLike]]) -> list[str]:
    if isinstance(path, (str, os.PathLike)):
        return [os.fspath(path)]
    return [os.fspath(p) for p in path]


def _split_rules(
    rules: Sequence[Union[Rule, CallbackRule, CompiledRule]],
) -> tuple[list[str], list[CallbackRule]]:
    ir: list[str] = []
    callbacks: list[CallbackRule] = []
    for r in rules:
        if isinstance(r, Rule):
            ir.append(r.to_json())
        elif isinstance(r, CompiledRule):
            ir.append(r.to_json())
        elif isinstance(r, CallbackRule):
            callbacks.append(r)
        else:
            raise TypeError(f"not a rule: {r!r}")
    return ir, callbacks


def _run(
    *,
    paths: list[str] = [],
    recursive: bool = False,
    plan: Optional[str] = None,
    source: Optional[str] = None,
    var_files: Sequence[PathLike] = (),
    rules: Sequence[Union[Rule, CallbackRule, CompiledRule]] = (),
    builtin: bool = True,
    select: Optional[Sequence[str]] = None,
    policies: Sequence[PathLike] = (),
    policy_shape: Optional[str] = None,
    policy_entry: Optional[str] = None,
    rego_native: bool = False,
    threads: Optional[int] = None,
) -> ScanResult:
    ir, callbacks = _split_rules(rules)
    inner, calls = _tfscan.scan(
        paths,
        recursive=recursive,
        plan=plan,
        source=source,
        var_files=[os.fspath(v) for v in var_files],
        builtin=builtin,
        select=None if select is None else list(select),
        ir_rules=ir,
        callbacks=callbacks,
        rego_native=rego_native,
        policies=[os.fspath(p) for p in policies],
        policy_shape=policy_shape,
        policy_entry=policy_entry,
        threads=threads,
    )
    return ScanResult(inner, calls)


def scan(
    path: Union[PathLike, Iterable[PathLike]],
    *,
    recursive: bool = False,
    var_files: Sequence[PathLike] = (),
    rules: Sequence[Union[Rule, CallbackRule, CompiledRule]] = (),
    builtin: bool = True,
    select: Optional[Sequence[str]] = None,
    policies: Sequence[PathLike] = (),
    policy_shape: Optional[str] = None,
    policy_entry: Optional[str] = None,
    rego_native: bool = False,
    threads: Optional[int] = None,
) -> ScanResult:
    """Scan Terraform root module directories.

    ``recursive``: every directory under ``path`` containing ``.tf`` files is
    a root module. The rule catalog is the built-in rules (``builtin``),
    plus ``rules``: expression rules (``tfscan.rule``), compiled IR rules
    and callback rules, plus foreign Rego ``policies`` (Conftest / OPA
    style, run unchanged; ``policy_shape`` is ``"plan"`` or ``"hcl"``,
    ``policy_entry`` defaults to ``data.main.deny``). ``select`` narrows the
    whole catalog to the given rule ids, exactly as ``oxtf scan --rule``
    does: unknown ids raise ``ValueError`` and an empty list runs nothing.
    A rule that fails on a resource is reported in ``result.rule_errors``,
    never dropped."""
    return _run(
        paths=_paths(path),
        recursive=recursive,
        var_files=var_files,
        rules=rules,
        builtin=builtin,
        select=select,
        policies=policies,
        policy_shape=policy_shape,
        policy_entry=policy_entry,
        rego_native=rego_native,
        threads=threads,
    )


def scan_plan(
    plan: PathLike,
    *,
    source: Optional[PathLike] = None,
    rules: Sequence[Union[Rule, CallbackRule, CompiledRule]] = (),
    builtin: bool = True,
    select: Optional[Sequence[str]] = None,
    policies: Sequence[PathLike] = (),
    policy_shape: Optional[str] = None,
    policy_entry: Optional[str] = None,
    rego_native: bool = False,
    threads: Optional[int] = None,
) -> ScanResult:
    """Scan ``terraform show -json`` output. Findings are mapped back to
    ``.tf`` spans in ``source`` (default: the plan's directory when it has
    ``.tf`` files, else locations point into the JSON). The rule catalog
    and ``select`` work as in :func:`scan`."""
    return _run(
        plan=os.fspath(plan),
        source=None if source is None else os.fspath(source),
        rules=rules,
        builtin=builtin,
        select=select,
        policies=policies,
        policy_shape=policy_shape,
        policy_entry=policy_entry,
        rego_native=rego_native,
        threads=threads,
    )


def analyze(
    path: Union[PathLike, Iterable[PathLike]],
    *,
    recursive: bool = False,
    var_files: Sequence[PathLike] = (),
    threads: Optional[int] = None,
) -> ScanResult:
    """Build the evaluated model only (no rules); use ``.resources``."""
    return scan(path, recursive=recursive, var_files=var_files, builtin=False, threads=threads)


def parse(source: str) -> Document:
    """Parse HCL text into the arena AST (GIL released). Nodes are handles
    (``Arc`` to the parse + node id)."""
    return _tfscan.parse_hcl(source)

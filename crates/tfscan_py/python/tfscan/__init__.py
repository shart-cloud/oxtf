"""tfscan: Python bindings for the oxtf Terraform security analyzer.

    import tfscan
    from tfscan import col, rule

    res = tfscan.scan("path/to/root", recursive=True)
    for f in res.findings:
        print(f.rule, f.certainty, f.address, f.message, f.file, f.line)
    table = res.findings_arrow()            # pyarrow.Table
    resources = res.resources.to_arrow()    # pyarrow.Table

The scan (parse, analysis, built-in and expression rules) runs in Rust with
the GIL released. Callback rules (``@tfscan.callback_rule``) re-acquire the
GIL once per resource that passes their Rust-side type filter.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Iterable, Iterator, Mapping, NamedTuple, Optional, Sequence, Union, overload

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

#: The engine's version (one source: the Cargo workspace).
__version__: str = _tfscan.__version__
#: The Checkov release whose Terraform checks are bundled.
CHECKOV_VERSION: str = _tfscan.CHECKOV_VERSION

__all__ = [
    "fetch",
    "scan",
    "scan_plan",
    "fix",
    "rules",
    "test_policies",
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


def fetch(
    root: PathLike = ".",
    *,
    data_dir: Optional[PathLike] = None,
    refresh: bool = False,
    registry_origins: Optional[Mapping[str, str]] = None,
) -> dict[str, Any]:
    """Fetch module dependencies for subsequent offline scans.

    Cached revisions are reused unless ``refresh=True``. Git uses the user's
    credential helpers or SSH agent; registries use ``TF_TOKEN_<hostname>``.
    """
    import json
    return json.loads(_tfscan.fetch(
        os.fspath(root),
        data_dir=None if data_dir is None else os.fspath(data_dir),
        refresh=refresh,
        registry_origins=None if registry_origins is None else dict(registry_origins),
    ))


class Report(NamedTuple):
    """What a callback rule returns to report a finding. ``witness`` (a
    ``Value``) supplies the provenance chain and primary location;
    ``conditional=True`` reports a conditional finding. ``indeterminate=True``
    marks a finding depending on apply-time data. ``hidden`` records projected
    input paths paired with ``"tainted"`` or ``"unknown"``."""

    message: str
    witness: Optional[Value] = None
    conditional: bool = False
    indeterminate: bool = False
    hidden: Sequence[tuple[str, str]] = ()


class CallbackRule:
    """A Python function run for each resource of ``resource_types`` (the
    filter is applied in Rust). It returns ``None``/``False`` (no finding),
    a message string, a ``Report``, or a list of those. By default exceptions
    propagate to the caller; ``record_errors=True`` instead retains them in
    ``ScanResult.rule_errors`` and lets other rules continue."""

    def __init__(
        self,
        func: Callable[[Resource], Any],
        name: str,
        resource_types: Sequence[str],
        level: str = "medium",
        category: str = "network",
        description: str = "",
        *,
        record_errors: bool = False,
    ):
        if not resource_types:
            raise ValueError("callback rules need resource_types (the Rust-side filter)")
        self.func = func
        self.name = name
        self.resource_types = list(resource_types)
        self.level = level
        self.category = category
        self.description = description or (func.__doc__ or "").strip()
        self.record_errors = record_errors

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

    @property
    def status(self) -> str:
        """Analysis completion: ``complete``, ``incomplete`` or ``failed``.
        Independent of whether findings were reported."""
        return self._inner.status

    @property
    def roots(self) -> list[dict]:
        """Each scanned root's own ``path`` and ``status``. Scan-wide limits
        affect only :attr:`status`, so a complete root can sit inside an
        incomplete scan."""
        return self._inner.roots

    @property
    def suppressed(self) -> list[dict]:
        """Findings a ``checkov:skip`` line suppressed (``rule``,
        ``resource``, ``comment``, ``file``, ``line``)."""
        return self._inner.suppressed

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
    data_dir: PathLike | None = None,
    rules: Sequence[Union[Rule, CallbackRule, CompiledRule]] = (),
    builtin: bool = True,
    bundled: bool = True,
    select: Optional[Sequence[str]] = None,
    rule_files: Sequence[PathLike] = (),
    policies: Sequence[PathLike] = (),
    data: Sequence[PathLike] = (),
    namespaces: Sequence[str] = (),
    all_namespaces: bool = False,
    policy_entries: Sequence[str] = (),
    policy_shape: Optional[str] = None,
    policy_entry: Optional[str] = None,
    rego_v0: bool = False,
    overlay: Mapping[PathLike, str] = {},
    threads: Optional[int] = None,
    limits: Mapping[str, int] | None = None,
    profiles: Optional[Sequence[str]] = None,
    fetch: bool = False,
) -> ScanResult:
    ir, callbacks = _split_rules(rules)
    inner, calls = _tfscan.scan(
        paths,
        recursive=recursive,
        plan=plan,
        source=source,
        var_files=[os.fspath(v) for v in var_files],
        data_dir=os.fspath(data_dir) if data_dir is not None else None,
        builtin=builtin,
        bundled=bundled,
        select=None if select is None else list(select),
        ir_rules=ir,
        callbacks=callbacks,
        policies=[os.fspath(p) for p in policies],
        policy_shape=policy_shape,
        policy_entry=policy_entry,
        overlay=[(os.fspath(p), t) for p, t in overlay.items()],
        threads=threads,
        limits=None if limits is None else dict(limits),
        rule_files=[os.fspath(p) for p in rule_files],
        data=[os.fspath(p) for p in data],
        namespaces=list(namespaces),
        all_namespaces=all_namespaces,
        policy_entries=list(policy_entries),
        rego_v0=rego_v0,
        profiles=None if profiles is None else list(profiles),
        fetch=fetch,
    )
    return ScanResult(inner, calls)


def scan(
    path: Union[PathLike, Iterable[PathLike]],
    *,
    recursive: bool = False,
    var_files: Sequence[PathLike] = (),
    data_dir: PathLike | None = None,
    rules: Sequence[Union[Rule, CallbackRule, CompiledRule]] = (),
    builtin: bool = True,
    bundled: bool = True,
    select: Optional[Sequence[str]] = None,
    rule_files: Sequence[PathLike] = (),
    policies: Sequence[PathLike] = (),
    data: Sequence[PathLike] = (),
    namespaces: Sequence[str] = (),
    all_namespaces: bool = False,
    policy_entries: Sequence[str] = (),
    policy_shape: Optional[str] = None,
    policy_entry: Optional[str] = None,
    rego_v0: bool = False,
    overlay: Mapping[PathLike, str] = {},
    threads: Optional[int] = None,
    limits: Mapping[str, int] | None = None,
    profiles: Optional[Sequence[str]] = None,
    fetch: bool = False,
) -> ScanResult:
    """Scan Terraform root module directories.

    HCL/JSON configuration and ordered overrides share one source loader.
    HCL and JSON variable files share Terraform's file precedence. Installed
    remote modules are resolved offline; ``data_dir`` defaults to ``.terraform``
    and is relative to each root unless absolute. Pass a custom Terraform
    data directory explicitly, including when your workflow uses ``TF_DATA_DIR``.
    ``fetch=True`` first installs remote modules for roots that lack them, as
    ``oxtf fetch`` does (network access, writing each root's data directory),
    then scans; a root that cannot be fetched gains a ``coverage-fetch``
    diagnostic. ``result.roots`` gives each root's own ``status``.

    ``recursive``: every directory under ``path`` containing ``.tf`` or ``.tf.json`` files is
    a root module. The rule catalog is the shipped rules (unless
    ``builtin`` is false): the seed rules and, unless ``bundled`` is false,
    the bundled Checkov catalog (Checkov 3.2.328's Terraform value checks
    and graph policies, run natively); plus ``rules``: expression rules (``tfscan.rule``), compiled IR rules
    and callback rules, plus ``rule_files``: files and directories of any
    rule format (rule IR JSON, Checkov YAML/JSON policies, Rego), each file
    detected by its content, exactly as ``oxtf scan --rule-file``.
    ``policies`` is an alias. Rego runs unchanged: by default as Conftest
    (``deny``/``violation``/``warn`` rules in ``namespaces``, default
    ``main``, or ``all_namespaces``; ``data`` adds data documents), or as
    ``opa eval`` for ``policy_entries`` (``policy_entry`` adds one).
    ``policy_shape`` is ``"plan"`` or ``"hcl"``; ``rego_v0`` parses Rego v0.
    ``select`` narrows the
    whole catalog to the given rule ids, exactly as ``oxtf scan --rule``
    does: unknown ids raise ``ValueError`` and an empty list runs nothing.
    A rule that fails on a resource is reported in ``result.rule_errors``,
    never dropped. ``overlay`` maps paths to text that shadows the disk for
    this scan (an unsaved buffer, a proposed patch); a path need not exist,
    nor its directory. Overlay paths are matched as written, so spell them
    the way ``path`` is spelled. ``profiles`` picks which profiles of the
    shipped rules run: ``security`` (the default, with bundled rules not
    yet curated), ``audit``, ``hygiene``, or ``all``; rules passed in
    ``rules`` or ``rule_files`` always run, and ``select`` chooses from
    every profile.

    ``limits`` accepts positive integers for ``evaluation_steps`` and
    ``loader_steps`` (each defaults to 1,000,000 per root), and ``rule_steps``
    (10,000,000 per root). ``rego_time_ms`` defaults to 10,000 per root.
    Scan input admission uses ``input_bytes`` (16 MiB), ``source_bytes``
    (256 MiB), ``file_entries`` (16,384), ``directory_entries`` (262,144),
    and ``roots`` (4,096). Arena construction uses ``arena_bytes`` (256 MiB)
    and ``ast_nodes`` (4,000,000) per scan. Evaluator text construction uses
    ``text_bytes`` (256 MiB) per scan. Builtin collection payload uses
    ``collection_bytes`` (256 MiB) per scan. Findings plus rule errors use
    ``results`` (100,000) per scan. Children and template files share
    the runtime allowance; cached override defaults
    consume the loader allowance. Analysis exhaustion reports ``incomplete``;
    rule exhaustion reports ``failed`` and stops later hooks for that root. See
    ``docs/LIMITS.md`` for the measured units and current accounting scope."""
    return _run(
        paths=_paths(path),
        recursive=recursive,
        var_files=var_files,
        data_dir=data_dir,
        rules=rules,
        builtin=builtin,
        bundled=bundled,
        select=select,
        rule_files=rule_files,
        policies=policies,
        data=data,
        namespaces=namespaces,
        all_namespaces=all_namespaces,
        policy_entries=policy_entries,
        policy_shape=policy_shape,
        policy_entry=policy_entry,
        rego_v0=rego_v0,
        overlay=overlay,
        threads=threads,
        limits=None if limits is None else dict(limits),
        profiles=profiles,
        fetch=fetch,
    )


def fix(
    fingerprint: str,
    path: Union[PathLike, Iterable[PathLike]],
    *,
    recursive: bool = False,
    var_files: Sequence[PathLike] = (),
    data_dir: PathLike | None = None,
    rules: Sequence[Union[Rule, CompiledRule]] = (),
    builtin: bool = True,
    bundled: bool = True,
    select: Optional[Sequence[str]] = None,
    rule_files: Sequence[PathLike] = (),
    policies: Sequence[PathLike] = (),
    data: Sequence[PathLike] = (),
    namespaces: Sequence[str] = (),
    all_namespaces: bool = False,
    policy_entries: Sequence[str] = (),
    policy_shape: Optional[str] = None,
    policy_entry: Optional[str] = None,
    rego_v0: bool = False,
    overlay: Mapping[PathLike, str] = {},
    threads: Optional[int] = None,
    limits: Mapping[str, int] | None = None,
    profiles: Optional[Sequence[str]] = None,
    at: Optional[str] = None,
) -> dict[str, Any]:
    """Fix the finding with ``fingerprint`` in the scan the other arguments
    describe (as :func:`scan`'s; callback rules cannot be re-run, so they
    are refused): its fix hint is applied in memory and the source is
    rescanned with the edit as an overlay, as ``oxtf fix`` does.

    A value written as ``var.x`` is fixed at the variable's default first
    (keeping the module's interface), and at the attribute when that leaves
    the target unresolved or introduces findings; ``at="default"`` or
    ``at="attribute"`` picks one.

    Returns a dict: ``fingerprint``, ``rule``, ``file``, ``resource``,
    ``attribute``, ``action``, ``value``, ``site`` (where the literal
    went), ``original`` and ``text`` (the file before and after the edit),
    ``diff`` (unified, sensitive context masked), ``verification_errors``,
    ``target_resolved`` (the rule no longer fails on the declaration),
    ``no_new_findings`` (no added findings or affected instances anywhere in
    the selected scan), and ``verified`` (both checks passed). Both checks
    require complete scans; existing unrelated findings may remain.

    ``finding_delta`` contains grouped finding counts ``before`` and ``after``,
    ``added`` and ``removed`` finding records, ``changed`` records with before/
    after evidence and added/removed occurrences, and an ``unchanged`` count.
    It matches fingerprints and root/address occurrences, ignoring shifted
    source positions. It is only an observed delta if either scan is incomplete.
    ``original`` and ``text`` contain raw
    source, including secrets. Nothing is written: write
    ``text`` to ``file`` when ``verified`` is what you need. Raises
    ``ValueError`` when no finding has the fingerprint, the finding has no
    fix hint, or the scan fails."""
    ir, callbacks = _split_rules(rules)
    if callbacks:
        raise ValueError("fix cannot re-run callback rules to verify an edit")
    return _tfscan.fix_finding(
        fingerprint,
        _paths(path),
        recursive=recursive,
        var_files=[os.fspath(v) for v in var_files],
        data_dir=os.fspath(data_dir) if data_dir is not None else None,
        builtin=builtin,
        bundled=bundled,
        select=None if select is None else list(select),
        ir_rules=ir,
        policies=[os.fspath(p) for p in policies],
        policy_shape=policy_shape,
        policy_entry=policy_entry,
        overlay=[(os.fspath(p), t) for p, t in overlay.items()],
        threads=threads,
        limits=None if limits is None else dict(limits),
        rule_files=[os.fspath(p) for p in rule_files],
        data=[os.fspath(p) for p in data],
        namespaces=list(namespaces),
        all_namespaces=all_namespaces,
        policy_entries=list(policy_entries),
        rego_v0=rego_v0,
        profiles=None if profiles is None else list(profiles),
        at=at,
    )


def scan_plan(
    plan: PathLike,
    *,
    source: Optional[PathLike] = None,
    data_dir: PathLike | None = None,
    rules: Sequence[Union[Rule, CallbackRule, CompiledRule]] = (),
    builtin: bool = True,
    bundled: bool = True,
    select: Optional[Sequence[str]] = None,
    rule_files: Sequence[PathLike] = (),
    policies: Sequence[PathLike] = (),
    data: Sequence[PathLike] = (),
    namespaces: Sequence[str] = (),
    all_namespaces: bool = False,
    policy_entries: Sequence[str] = (),
    policy_shape: Optional[str] = None,
    policy_entry: Optional[str] = None,
    rego_v0: bool = False,
    overlay: Mapping[PathLike, str] = {},
    threads: Optional[int] = None,
    limits: Mapping[str, int] | None = None,
    profiles: Optional[Sequence[str]] = None,
) -> ScanResult:
    """Scan ``terraform show -json`` output. Findings are mapped back to
    ``.tf`` spans in ``source`` (default: the plan's directory when it has
    ``.tf`` files, else locations point into the JSON). The rule catalog
    and ``select`` work as in :func:`scan`. ``data_dir`` selects installed
    modules for the source mapping, as in :func:`scan`."""
    return _run(
        plan=os.fspath(plan),
        source=None if source is None else os.fspath(source),
        data_dir=data_dir,
        rules=rules,
        builtin=builtin,
        bundled=bundled,
        select=select,
        rule_files=rule_files,
        policies=policies,
        data=data,
        namespaces=namespaces,
        all_namespaces=all_namespaces,
        policy_entries=policy_entries,
        policy_shape=policy_shape,
        policy_entry=policy_entry,
        rego_v0=rego_v0,
        overlay=overlay,
        threads=threads,
        limits=None if limits is None else dict(limits),
        profiles=profiles,
    )


def analyze(
    path: Union[PathLike, Iterable[PathLike]],
    *,
    recursive: bool = False,
    var_files: Sequence[PathLike] = (),
    data_dir: PathLike | None = None,
    threads: Optional[int] = None,
    limits: Mapping[str, int] | None = None,
) -> ScanResult:
    """Build the evaluated model only (no rules); use ``.resources``."""
    return scan(
        path, recursive=recursive, var_files=var_files, data_dir=data_dir,
        builtin=False, threads=threads, limits=limits,
    )


def parse(source: str) -> Document:
    """Parse HCL text into the arena AST (GIL released). Nodes are handles
    (``Arc`` to the parse + node id)."""
    return _tfscan.parse_hcl(source)


def rules(
    rule_files: Sequence[PathLike] = (),
    *,
    builtin: bool = True,
    bundled: bool = True,
    data: Sequence[PathLike] = (),
    namespaces: Sequence[str] = (),
    all_namespaces: bool = False,
    policy_entries: Sequence[str] = (),
    policy_shape: Optional[str] = None,
    rego_v0: bool = False,
) -> list[dict[str, Any]]:
    """The rule catalog, as ``oxtf rules``: the shipped rules (unless
    ``builtin`` is false: the seed rules and, unless ``bundled`` is false,
    the bundled Checkov catalog) and every rule in ``rule_files`` (any format), each
    a dict with ``name``, ``level``, ``category``, ``description``,
    ``resource_types``, ``runs_on_module``, ``guideline``, ``rationale``
    (severity justification), ``remediation`` (actionable guidance), ``source``
    (``engine``, ``file``, ``line``) and ``aliases`` (other IDs that select
    the rule; a seed rule lists the bundled rule it replaces). Guidance fields
    are ``None`` when not supplied. A rule file
    in a directory that does not load is skipped with a ``UserWarning``."""
    import warnings

    out, skipped = _tfscan.rules_info(
        [os.fspath(p) for p in rule_files],
        builtin=builtin,
        bundled=bundled,
        data=[os.fspath(p) for p in data],
        namespaces=list(namespaces),
        all_namespaces=all_namespaces,
        policy_entries=list(policy_entries),
        policy_shape=policy_shape,
        rego_v0=rego_v0,
    )
    for w in skipped:
        warnings.warn(w, stacklevel=2)
    return out


def test_policies(
    rule_files: Sequence[PathLike],
    *,
    data: Sequence[PathLike] = (),
    namespaces: Sequence[str] = (),
    rego_v0: bool = False,
) -> list[dict[str, Any]]:
    """Run the ``test_*`` rules of the Rego in ``rule_files``, as ``oxtf
    rules test`` and ``conftest verify`` do. Each outcome is a dict with
    ``rule``, ``file``, ``result`` (``pass``, ``fail``, ``skip`` or
    ``error``) and ``error``."""
    return [
        {"rule": r, "file": f, "result": res, "error": e}
        for r, f, res, e in _tfscan.test_policies(
            [os.fspath(p) for p in rule_files],
            data=[os.fspath(p) for p in data],
            namespaces=list(namespaces),
            rego_v0=rego_v0,
        )
    ]


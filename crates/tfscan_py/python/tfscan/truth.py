"""The engine's four-valued truth (``tf_eval::truth``) in Python, for
callback rules that want the same severity semantics as the built-in and
expression rules: ``False < Unknown < Tainted < True``; ``and`` = min,
``or`` = max; ``Tainted`` → conditional finding, ``Unknown`` → none.

Operates on ``tfscan.Value`` handles (``kind``, ``items()``, ``get()``,
``alternatives``, ``tainted``).
"""

from __future__ import annotations

from typing import Callable, NamedTuple, Optional

from ._tfscan import Value

FALSE, UNKNOWN, TAINTED, TRUE = 0, 1, 2, 3


class Verdict(NamedTuple):
    truth: int
    witness: Optional[Value]


V_FALSE = Verdict(FALSE, None)


def and_(a: Verdict, b: Verdict) -> Verdict:
    return b if b.truth < a.truth else a


def or_(a: Verdict, b: Verdict) -> Verdict:
    return b if b.truth > a.truth else a


def _one_of(vs: list[Verdict], tainted: bool) -> Verdict:
    tainted = tainted or any(x.truth == TAINTED for x in vs)
    if vs and all(x.truth == TRUE for x in vs):
        return vs[0]
    best = max(vs, key=lambda x: x.truth, default=V_FALSE)
    if best.truth in (TRUE, TAINTED):
        return Verdict(TAINTED if tainted else UNKNOWN, best.witness)
    return best


def test(v: Value, pred: Callable[[Value], bool]) -> Verdict:
    """Predicate on a scalar; ``pred`` only sees Known values."""
    k = v.kind
    if k == "known":
        return Verdict(TRUE if pred(v) else FALSE, v)
    if k == "tainted":
        return Verdict(TAINTED, v)
    if k == "unknown":
        return Verdict(UNKNOWN, v)
    return _one_of([test(a, pred) for a in v.alternatives], v.tainted)


def map_(v: Value, f: Callable[[Value], Verdict]) -> Verdict:
    k = v.kind
    if k == "known":
        return f(v)
    if k == "tainted":
        return Verdict(TAINTED, v)
    if k == "unknown":
        return Verdict(UNKNOWN, v)
    return _one_of([map_(a, f) for a in v.alternatives], v.tainted)


def exists(v: Value, pred: Callable[[Value], Verdict]) -> Verdict:
    """Some element of the list ``v`` satisfies ``pred``."""
    k = v.kind
    if k == "known":
        items = v.items()
        if items is not None:
            acc = V_FALSE
            for e in items:
                acc = or_(acc, pred(e))
                if acc.truth == TRUE:
                    break
            return acc
        if v.is_null:
            return V_FALSE
        return pred(v)
    if k == "tainted":
        return Verdict(TAINTED, v)
    if k == "unknown":
        return Verdict(UNKNOWN, v)
    return _one_of([exists(a, pred) for a in v.alternatives], v.tainted)


def report(v: Verdict, message: Callable[[Optional[Value]], str]):
    """A ``tfscan.Report`` for a holding verdict, else ``None``."""
    from . import Report

    if v.truth == TRUE:
        return Report(message(v.witness), v.witness, False)
    if v.truth == TAINTED:
        return Report(message(v.witness), v.witness, True)
    return None

"""Seed rule 1 (``aws-sg-open-ssh``) written twice in Python:

- ``EXPR_RULE``: the polars-style expression API (compiled to the rule IR,
  evaluated in Rust without the GIL);
- ``CALLBACK_RULE``: a Python callback using ``tfscan.truth`` for the same
  four-valued semantics (runs with the GIL, once per candidate resource).

Both mirror ``crates/tf_linter/src/rules/aws_sg_open_ssh.rs``: some ingress
rule is open (``0.0.0.0/0`` / ``::/0`` in ``cidr_blocks`` /
``ipv6_cidr_blocks``, or ``cidr_ipv4`` / ``cidr_ipv6``) and reaches port 22
(protocol ``-1``/``all``, or ``tcp``/``6``/``TCP`` with
``from_port <= 22 <= to_port``); ``aws_security_group_rule`` also needs
``type == "ingress"``. Run as a script to write the IR JSON.
"""

from __future__ import annotations

import sys

from .. import Report, callback_rule
from .. import truth as T
from ..expr import col, element, rule

OPEN = ["0.0.0.0/0", "::/0"]
ANY_PROTO = ["-1", "all"]
TCP = ["tcp", "6", "TCP"]
MESSAGE = "ingress allows SSH (port 22) from {witness|the internet}"


def _reaches_22(protocol: str, from_port: str = "from_port", to_port: str = "to_port"):
    return col(protocol).is_in(ANY_PROTO) | (
        col(protocol).is_in(TCP) & (col(from_port) <= 22) & (col(to_port) >= 22)
    )


def _open_list(name: str):
    return col(name).list.any(element().is_in(OPEN))


EXPR_RULE = (
    rule(
        "py-sg-open-ssh",
        level="high",
        category="network",
        description="Security group ingress allows SSH (port 22) from 0.0.0.0/0 or ::/0",
    )
    .on("aws_security_group")
    .for_each("ingress")
    .where_((_open_list("cidr_blocks") | _open_list("ipv6_cidr_blocks")) & _reaches_22("protocol"))
    .on("aws_vpc_security_group_ingress_rule")
    .where_(
        (col("cidr_ipv4").is_in(OPEN) | col("cidr_ipv6").is_in(OPEN)) & _reaches_22("ip_protocol")
    )
    .on("aws_security_group_rule")
    .where_(
        (_open_list("cidr_blocks") | _open_list("ipv6_cidr_blocks"))
        & _reaches_22("protocol")
        & (col("type") == "ingress")
    )
    .message(MESSAGE)
)


# -- the same rule as a Python callback -------------------------------------


def _str_in(v, options) -> bool:
    s = v.to_str()
    return s is not None and s.strip() in options


def _open_cidr(v):
    return T.test(v, lambda x: _str_in(x, OPEN))


def _open_list_v(v):
    return T.exists(v, _open_cidr)


def _num_test(v, pred):
    def p(x):
        n = x.as_number()
        return n is not None and pred(n)

    return T.test(v, p)


def _reaches_22_v(protocol, from_port, to_port):
    any_ = T.test(protocol, lambda x: _str_in(x, ANY_PROTO))
    tcp = T.test(protocol, lambda x: _str_in(x, TCP))
    lo = _num_test(from_port, lambda n: n <= 22)
    hi = _num_test(to_port, lambda n: n >= 22)
    return T.or_(any_, T.and_(T.and_(tcp, lo), hi))


def _inline_rule(r):
    def f(r):
        open_ = T.or_(_open_list_v(r.get("cidr_blocks")), _open_list_v(r.get("ipv6_cidr_blocks")))
        return T.and_(open_, _reaches_22_v(r.get("protocol"), r.get("from_port"), r.get("to_port")))

    return T.map_(r, f)


def _message(w) -> str:
    s = w.to_str() if w is not None else None
    return f"ingress allows SSH (port 22) from {s if s is not None else 'the internet'}"


@callback_rule(
    "py-cb-sg-open-ssh",
    resource_types=["aws_security_group", "aws_vpc_security_group_ingress_rule", "aws_security_group_rule"],
    level="high",
)
def CALLBACK_RULE(res) -> Report | None:
    from .._tfscan import Value

    null = Value.null()

    def get(n):
        v = res.get(n)
        return null if v is None else v

    t = res.type
    if t == "aws_security_group":
        ingress = res.get("ingress")
        if ingress is None:
            return None
        v = T.exists(ingress, _inline_rule)
    elif t == "aws_vpc_security_group_ingress_rule":
        open_ = T.or_(_open_cidr(get("cidr_ipv4")), _open_cidr(get("cidr_ipv6")))
        v = T.and_(open_, _reaches_22_v(get("ip_protocol"), get("from_port"), get("to_port")))
    else:
        ingress = T.test(get("type"), lambda x: x.to_str() == "ingress")
        open_ = T.or_(_open_list_v(get("cidr_blocks")), _open_list_v(get("ipv6_cidr_blocks")))
        v = T.and_(
            T.and_(open_, _reaches_22_v(get("protocol"), get("from_port"), get("to_port"))),
            ingress,
        )
    return T.report(v, _message)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "-"
    text = EXPR_RULE.to_json(indent=2) + "\n"
    if out == "-":
        sys.stdout.write(text)
    else:
        with open(out, "w") as f:
            f.write(text)

package oxtf.ssh
import rego.v1
import data.oxtf.lattice

matches(v, op) if {
    op == "open"
    v.text in {"0.0.0.0/0", "::/0"}
}
matches(v, op) if {
    op == "any"
    v.text in {"-1", "all"}
}
matches(v, op) if {
    op == "tcp"
    v.text in {"tcp", "6", "TCP"}
}
matches(v, op) if {
    op == "lo"
    is_number(v.number)
    v.number <= 22
}
matches(v, op) if {
    op == "hi"
    is_number(v.number)
    v.number >= 22
}
matches(v, op) if {
    op == "lo"
    v.negative_infinity
}
matches(v, op) if {
    op == "hi"
    v.positive_infinity
}
matches(v, op) if {
    op == "ingress"
    v.string == "ingress"
}
scalar(v, op) := {"rank": 3, "evidence": v.handle} if {
    v.kind == "known"
    matches(v, op)
}
scalar(v, op) := {"rank": 0, "evidence": v.handle} if {
    v.kind == "known"
    not matches(v, op)
}
scalar(v, op) := {"rank": 1, "evidence": v.handle} if v.kind == "unknown"
scalar(v, op) := {"rank": 2, "evidence": v.handle} if v.kind == "tainted"
atom(v, op) := scalar(v, op) if v.kind != "one_of"
atom(v, op) := result if {
    v.kind == "one_of"
    values := [scalar(a, op) | a := v.alternatives[_]]
    result := lattice.choice(values, v.tainted)
}

cidr_base(v) := result if {
    v.kind == "known"
    v.type == "list"
    values := [atom(a, "open") | a := v.elements[_]]
    result := lattice.any(values)
}
cidr_base(v) := lattice.false_result if {
    v.kind == "known"
    v.type == "null"
}
cidr_base(v) := atom(v, "open") if {
    not list_or_null(v)
}
list_or_null(v) if {
    v.kind == "known"
    v.type in {"list", "null"}
}
cidrs(v) := cidr_base(v) if v.kind != "one_of"
cidrs(v) := result if {
    v.kind == "one_of"
    values := [cidr_base(a) | a := v.alternatives[_]]
    result := lattice.choice(values, v.tainted)
}

ports(f) := result if {
    any_protocol := atom(f.protocol, "any")
    tcp := atom(f.protocol, "tcp")
    lower := atom(f.from_port, "lo")
    upper := atom(f.to_port, "hi")
    result := lattice.or(any_protocol, lattice.and(lattice.and(tcp, lower), upper))
}
inline_base(v) := lattice.and(lattice.or(cidrs(v.fields.cidr_blocks), cidrs(v.fields.ipv6_cidr_blocks)), ports(v.fields)) if v.kind == "known"
inline_base(v) := scalar(v, "open") if v.kind != "known"
inline(v) := inline_base(v) if v.kind != "one_of"
inline(v) := result if {
    v.kind == "one_of"
    values := [inline_base(a) | a := v.alternatives[_]]
    result := lattice.choice(values, v.tainted)
}
ingress_base(v) := result if {
    v.kind == "known"
    v.type == "list"
    values := [inline(a) | a := v.elements[_]]
    result := lattice.any(values)
}
ingress_base(v) := lattice.false_result if {
    v.kind == "known"
    v.type == "null"
}
ingress_base(v) := inline(v) if not list_or_null(v)
ingress(v) := ingress_base(v) if v.kind != "one_of"
ingress(v) := result if {
    v.kind == "one_of"
    values := [ingress_base(a) | a := v.alternatives[_]]
    result := lattice.choice(values, v.tainted)
}

result := ingress(input.ingress) if input.target.resource_type == "aws_security_group"
result := lattice.and(lattice.or(atom(input.fields.cidr_ipv4, "open"), atom(input.fields.cidr_ipv6, "open")), ports(input.fields)) if input.target.resource_type == "aws_vpc_security_group_ingress_rule"
result := lattice.and(lattice.and(lattice.or(cidrs(input.fields.cidr_blocks), cidrs(input.fields.ipv6_cidr_blocks)), ports(input.fields)), atom(input.fields.type, "ingress")) if input.target.resource_type == "aws_security_group_rule"

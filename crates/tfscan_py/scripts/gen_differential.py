"""Generate a seeded corpus of security-group modules that exercise every
lattice path the sg-open-ssh rule can take (literal / variable default /
tfvars / unconstrained variable / provider-computed / conditional / dynamic
blocks over known and unconstrained collections / count on a variable), for
the three resource types the rule covers.

    python gen_differential.py OUT_DIR [N] [SEED]
"""

import os
import random
import sys

CIDRS = [
    '"0.0.0.0/0"', '"10.0.0.0/8"', '"::/0"', 'var.cidr', 'var.free_cidr',
    'data.aws_vpc.main.cidr_block', 'local.cidr', '(var.flag ? "0.0.0.0/0" : "10.0.0.0/8")',
    '(var.free_flag ? "0.0.0.0/0" : "10.0.0.0/8")', '(var.free_flag ? "0.0.0.0/0" : "::/0")',
]
PROTOS = ['"tcp"', '"-1"', '"all"', '"6"', '"udp"', '"TCP"', '-1', 'var.proto', 'var.free_proto']
PORTS = ['22', '0', '80', '443', '"22"', 'var.port', 'var.free_port', '1024']

HEADER = """
variable "cidr" {
  type    = string
  default = %(cidr_default)s
}
variable "free_cidr" { type = string }
variable "flag" {
  type    = bool
  default = %(flag)s
}
variable "free_flag" { type = bool }
variable "proto" {
  type    = string
  default = %(proto_default)s
}
variable "free_proto" { type = string }
variable "port" {
  type    = number
  default = %(port_default)s
}
variable "free_port" { type = number }
variable "rules" {
  type    = list(object({ cidr = string, from = number, to = number }))
  default = %(rules_default)s
}
variable "free_rules" { type = list(object({ cidr = string, from = number, to = number })) }
variable "enabled" { type = bool }
data "aws_vpc" "main" {}
locals {
  cidr = %(local_cidr)s
}
"""


def pick(r, xs):
    return r.choice(xs)


def ports(r):
    a, b = pick(r, PORTS), pick(r, PORTS)
    return a, b


def sg(r, i):
    lines = [f'resource "aws_security_group" "sg{i}" {{']
    if r.random() < 0.15:
        lines.append(f'  count = {pick(r, ["var.enabled ? 1 : 0", "1", "0", "var.flag ? 1 : 0"])}')
    kind = r.random()
    if kind < 0.5:
        for _ in range(r.randint(1, 2)):
            f, t = ports(r)
            cidrs = ", ".join(pick(r, CIDRS) for _ in range(r.randint(1, 2)))
            attr = "ipv6_cidr_blocks" if r.random() < 0.2 else "cidr_blocks"
            lines += [
                "  ingress {",
                f"    from_port = {f}",
                f"    to_port   = {t}",
                f"    protocol  = {pick(r, PROTOS)}",
                f"    {attr} = [{cidrs}]",
                "  }",
            ]
    elif kind < 0.85:
        coll = pick(r, ["var.rules", "var.free_rules", '[{ cidr = "0.0.0.0/0", from = 22, to = 22 }]',
                        '[{ cidr = "10.0.0.0/8", from = 0, to = 65535 }]'])
        lines += [
            '  dynamic "ingress" {',
            f"    for_each = {coll}",
            "    content {",
            "      from_port   = ingress.value.from",
            "      to_port     = ingress.value.to",
            f"      protocol    = {pick(r, PROTOS)}",
            "      cidr_blocks = [ingress.value.cidr]",
            "    }",
            "  }",
        ]
    lines.append("}")
    return lines


def vpc_rule(r, i):
    f, t = ports(r)
    attr = "cidr_ipv6" if r.random() < 0.2 else "cidr_ipv4"
    return [
        f'resource "aws_vpc_security_group_ingress_rule" "r{i}" {{',
        '  security_group_id = "sg-123"',
        f"  {attr} = {pick(r, CIDRS)}",
        f"  from_port = {f}",
        f"  to_port = {t}",
        f"  ip_protocol = {pick(r, PROTOS)}",
        "}",
    ]


def sg_rule(r, i):
    f, t = ports(r)
    return [
        f'resource "aws_security_group_rule" "x{i}" {{',
        "  type = " + pick(r, ['"ingress"', '"egress"', "var.free_proto"]),
        '  security_group_id = "sg-123"',
        f"  from_port = {f}",
        f"  to_port = {t}",
        f"  protocol = {pick(r, PROTOS)}",
        f"  cidr_blocks = [{pick(r, CIDRS)}]",
        "}",
    ]


def main():
    out = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    r = random.Random(seed)
    for m in range(n):
        d = os.path.join(out, f"m{m:04d}")
        os.makedirs(d, exist_ok=True)
        body = HEADER % {
            "cidr_default": pick(r, ['"0.0.0.0/0"', '"10.0.0.0/8"', '"::/0"']),
            "flag": pick(r, ["true", "false"]),
            "proto_default": pick(r, ['"tcp"', '"-1"', '"udp"']),
            "port_default": pick(r, ["22", "443"]),
            "rules_default": pick(r, ['[{ cidr = "0.0.0.0/0", from = 22, to = 22 }]',
                                      '[{ cidr = "10.0.0.0/8", from = 22, to = 22 }]',
                                      '[{ cidr = "0.0.0.0/0", from = 80, to = 80 }]', "[]"]),
            "local_cidr": pick(r, CIDRS[:6]),
        }
        lines = [body]
        for i in range(r.randint(2, 5)):
            g = pick(r, [sg, sg, vpc_rule, sg_rule])
            lines += g(r, i)
        with open(os.path.join(d, "main.tf"), "w") as f:
            f.write("\n".join(lines) + "\n")
        if r.random() < 0.3:
            with open(os.path.join(d, "terraform.tfvars"), "w") as f:
                f.write("cidr = " + pick(r, ['"0.0.0.0/0"', '"192.168.0.0/16"']) + "\n")


if __name__ == "__main__":
    main()

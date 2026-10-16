# METADATA
# title: Security group ingress allows SSH (port 22) from 0.0.0.0/0 or ::/0
# custom:
#   id: PORT-AWS-SG-OPEN-SSH
#   severity: high
#   oxtf:
#     resource_types:
#       - aws_security_group
#       - aws_vpc_security_group_ingress_rule
#       - aws_security_group_rule
package ports.sg_open_ssh

import rego.v1

open_cidrs := {"0.0.0.0/0", "::/0"}

any_protocol(p) if p in {"-1", "all"}

tcp(p) if p in {"tcp", "6", "TCP"}

reaches_22(protocol, _, _) if any_protocol(protocol)

reaches_22(protocol, from, to) if {
	tcp(protocol)
	from <= 22
	to >= 22
}

open_list(cidrs) if {
	some c in cidrs
	c in open_cidrs
}

open_rule(rule) if open_list(rule.cidr_blocks)

open_rule(rule) if open_list(rule.ipv6_cidr_blocks)

violates(r) if {
	r.type == "aws_security_group"
	some i, rule in r.change.after.ingress
	open_rule(rule)
	reaches_22(rule.protocol, rule.from_port, rule.to_port)
}

violates(r) if {
	r.type == "aws_vpc_security_group_ingress_rule"
	after := r.change.after
	some cidr in [object.get(after, "cidr_ipv4", null), object.get(after, "cidr_ipv6", null)]
	cidr in open_cidrs
	reaches_22(after.ip_protocol, after.from_port, after.to_port)
}

violates(r) if {
	r.type == "aws_security_group_rule"
	after := r.change.after
	after.type == "ingress"
	open_rule(after)
	reaches_22(after.protocol, after.from_port, after.to_port)
}

deny contains violation if {
	some r in input.resource_changes
	violates(r)
	violation := {"msg": sprintf("%s: SSH is open to the internet", [r.address]), "address": r.address}
}

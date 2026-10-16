# Rego v0 (no `import rego.v1`): partial set rules with `deny[msg] { ... }`,
# a multi-value `[_]` iteration, `default`, and a v0 function. Load with
# `--rego-v0`; the opa_compare harness checks it against
# `opa eval --v0-compatible`.
package main

default max_ingress_port = 1024

open_cidr(cidr) {
	cidr == "0.0.0.0/0"
}

open_cidr(cidr) {
	cidr == "::/0"
}

deny[msg] {
	rule := input.resource_changes[_]
	rule.type == "aws_security_group_rule"
	rule.change.after.type == "ingress"
	open_cidr(rule.change.after.cidr_blocks[_])
	rule.change.after.from_port < max_ingress_port
	msg := sprintf("%s: ingress from the internet below port %d", [rule.address, max_ingress_port])
}

deny[msg] {
	bucket := input.resource_changes[_]
	bucket.type == "aws_s3_bucket"
	tags := object.get(bucket.change.after, "tags", {})
	not tags.owner
	msg := sprintf("%s: no owner tag", [bucket.address])
}

package main

import rego.v1

# Fails at runtime on any rule whose protocol is a name, not a number.
deny contains msg if {
	some name
	some r in input.resource.aws_security_group_rule[name]
	to_number(r.protocol) == 6
	msg := sprintf("security group rule `%v` allows TCP", [name])
}

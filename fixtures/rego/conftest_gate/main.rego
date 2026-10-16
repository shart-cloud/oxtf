# Conftest conformance set for bench/rego/conftest_compare.py: every rule
# convention (deny, deny_*, violation_*, warn, warn_*, exception) across
# two namespaces, over resources, modules and the terraform block.
package main

import rego.v1

deny contains msg if {
	some type, resources in input.resource
	startswith(type, "aws_")
	some name, blocks in resources
	some r in blocks
	is_object(r)
	not r.tags
	msg := sprintf("%s.%s has no tags", [type, name])
}

violation_public_acl contains {"msg": msg, "acl": acl} if {
	some name, blocks in input.resource.aws_s3_bucket
	some b in blocks
	acl := b.acl
	acl in {"public-read", "public-read-write"}
	msg := sprintf("aws_s3_bucket.%s has ACL %s", [name, acl])
}

deny_module_ref contains msg if {
	some name, calls in input.module
	some call in calls
	is_string(call.source)
	startswith(call.source, "git::")
	not contains(call.source, "ref=")
	msg := sprintf("module %s is not pinned", [name])
}

warn contains msg if {
	some t in input.terraform
	not t.required_version
	msg := "terraform block has no required_version"
}

warn_count contains msg if {
	some type, resources in input.resource
	some name, blocks in resources
	some r in blocks
	is_number(r.count)
	r.count > 1
	msg := sprintf("%s.%s has count %v", [type, name, r.count])
}

exception contains ["module_ref"] if {
	data.conftest.file.name == "main.tf"
	contains(data.conftest.file.dir, "examples")
}

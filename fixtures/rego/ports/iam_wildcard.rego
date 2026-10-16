# METADATA
# title: IAM policy allows Action "*" on Resource "*"
# custom:
#   id: PORT-AWS-IAM-WILDCARD-POLICY
#   severity: critical
#   oxtf:
#     resource_types:
#       - aws_iam_policy
#       - aws_iam_role_policy
#       - aws_iam_user_policy
#       - aws_iam_group_policy
package ports.iam_wildcard

import rego.v1

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

wildcard(field) if "*" in as_list(field)

deny contains violation if {
	some r in input.resource_changes
	is_string(r.change.after.policy)
	json.is_valid(r.change.after.policy)
	doc := json.unmarshal(r.change.after.policy)
	some statement in as_list(doc.Statement)
	statement.Effect == "Allow"
	wildcard(statement.Action)
	wildcard(statement.Resource)
	violation := {
		"msg": sprintf("%s: policy statement allows Action \"*\" on Resource \"*\"", [r.address]),
		"address": r.address,
		"path": "policy",
	}
}

# METADATA
# title: RDS instance storage is not encrypted
# description: Rego port of the aws-rds-unencrypted seed rule, over plan JSON.
# custom:
#   id: PORT-AWS-RDS-UNENCRYPTED
#   severity: high
#   oxtf:
#     resource_types: [aws_db_instance]
package ports.rds

import rego.v1

deny contains violation if {
	some r in input.resource_changes
	r.type == "aws_db_instance"
	object.get(r.change.after, "replicate_source_db", null) == null
	not r.change.after.storage_encrypted == true
	violation := {
		"msg": sprintf("%s: storage_encrypted is not true", [r.address]),
		"address": r.address,
		"path": "storage_encrypted",
		"fix": {"attribute": "storage_encrypted", "value": true},
	}
}

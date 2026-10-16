# METADATA
# title: Cloud Storage bucket does not enforce uniform bucket-level access
# custom:
#   id: PORT-GCP-STORAGE-UNIFORM-ACCESS
#   severity: medium
#   oxtf:
#     resource_types: [google_storage_bucket]
package ports.gcp_storage

import rego.v1

deny contains violation if {
	some r in input.resource_changes
	r.type == "google_storage_bucket"
	not r.change.after.uniform_bucket_level_access == true
	violation := {
		"msg": sprintf("%s: uniform_bucket_level_access is not true", [r.address]),
		"address": r.address,
		"path": "uniform_bucket_level_access",
	}
}

# METADATA
# title: Buckets carry an owner tag
# related_resources:
#   - ref: https://example.com/guidelines/owner-tag
# custom:
#   id: MIXED_OWNER_TAG
#   severity: medium
#   category: CONVENTION
package main

import rego.v1

deny contains msg if {
	some name, buckets in input.resource.aws_s3_bucket
	some b in buckets
	not b.tags.owner
	msg := sprintf("bucket %s has no owner tag", [name])
}

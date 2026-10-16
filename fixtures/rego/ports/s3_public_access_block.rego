# METADATA
# title: S3 bucket has no public access block with all four protections enabled
# description: >-
#   Rego port of aws-s3-public-access-block over plan JSON. It joins a block
#   to a bucket by the known bucket name, so it needs the whole root module.
# custom:
#   id: PORT-AWS-S3-PUBLIC-ACCESS-BLOCK
#   severity: high
#   oxtf:
#     input: module
#     resource_types: [aws_s3_bucket, aws_s3_bucket_public_access_block]
package ports.s3_public_access_block

import rego.v1

flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

protects(pab) if every flag in flags {
	pab.change.after[flag] == true
}

protected(bucket) if {
	some pab in input.resource_changes
	pab.type == "aws_s3_bucket_public_access_block"
	pab.change.after.bucket == bucket.change.after.bucket
	protects(pab)
}

deny contains violation if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	not protected(bucket)
	violation := {
		"msg": sprintf("%s: no public access block protects this bucket", [bucket.address]),
		"address": bucket.address,
	}
}

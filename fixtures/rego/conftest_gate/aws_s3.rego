package aws.s3

import rego.v1

deny_force_destroy contains msg if {
	some name, blocks in input.resource.aws_s3_bucket
	some b in blocks
	b.force_destroy == true
	msg := sprintf("aws_s3_bucket.%s sets force_destroy", [name])
}

warn_versioning_block contains msg if {
	some name, blocks in input.resource.aws_s3_bucket
	some b in blocks
	b.versioning
	msg := sprintf("aws_s3_bucket.%s uses the deprecated versioning block", [name])
}

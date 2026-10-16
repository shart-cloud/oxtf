# Conftest conventions over whole files: rules no single resource
# reproduces (module and provider checks) become findings on the file, a
# join between resources is attributed to the bucket by ablation, and an
# exception keyed on data.conftest.file suppresses one rule in one file.
package main

import rego.v1

deny_unpinned_module contains msg if {
	some name, calls in input.module
	some call in calls
	startswith(call.source, "git::")
	not contains(call.source, "?ref=")
	msg := sprintf("module %s is not pinned to a ref", [name])
}

warn_provider_region contains msg if {
	some p in input.provider.aws
	not p.region
	msg := "aws provider has no region"
}

versioned(bucket) if {
	some _, vs in input.resource.aws_s3_bucket_versioning
	some v in vs
	v.bucket == bucket.bucket
}

deny_unversioned contains msg if {
	some name, buckets in input.resource.aws_s3_bucket
	some bucket in buckets
	not versioned(bucket)
	msg := sprintf("bucket %s has no aws_s3_bucket_versioning", [name])
}

exception contains ["unversioned"] if {
	data.conftest.file.name == "exempt.tf"
}

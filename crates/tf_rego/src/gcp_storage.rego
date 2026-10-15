# gcp-storage-uniform-access as a native-tier leaf policy.
package oxtf.gcp_storage
import rego.v1

subject := {"attribute": "uniform_bucket_level_access", "mode": "effective"}

default skip := false

violates if input.subject.boolean != true

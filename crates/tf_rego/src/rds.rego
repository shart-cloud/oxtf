# aws-rds-unencrypted as a native-tier leaf policy. The adapter reads the
# subject with the lattice and calls `violates` only on Known values.
package oxtf.rds
import rego.v1

subject := {"attribute": "storage_encrypted", "mode": "effective"}

# Read replicas inherit encryption from their source.
default skip := false
skip if input.configured.replicate_source_db.set

violates if input.subject.boolean != true

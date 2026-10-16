Terraform for the Rego seed-rule ports in `../ports`
(`crates/tf_scan/tests/rego.rs`).

- `known/`: every value is known. `exposed` has no public access block (a
  definite finding from the module-input S3 port), and `db` sets
  `storage_encrypted = false` (the RDS port's `path` points the finding at
  that attribute).
- `tainted/`: the bucket name comes from an unconstrained variable, so
  whether the block protects it is conditional.

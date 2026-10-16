Conftest conventions (`crates/tf_scan/tests/rego.rs`). `conftest test
--policy policy tf/main.tf tf/exempt.tf` (v0.71.0) reports the module
failure, the provider warning and bucket `a`, and nothing for `exempt.tf`;
oxtf reports the same, the first two on `main.tf` itself and the third on
`aws_s3_bucket.a`.

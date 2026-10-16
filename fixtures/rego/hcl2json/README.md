`tricky.tf` covers hcl2json's expression rendering (escapes, strip markers,
`%{}` directives, heredocs, parentheses, object keys, unary literals, large
numbers). `tricky.conftest.json` is `conftest parse --parser hcl2
tricky.tf` from Conftest v0.71.0; `tf_rego::hcl2json::raw` must reproduce
it exactly (`crates/tf_rego/tests/hcl2json.rs`).

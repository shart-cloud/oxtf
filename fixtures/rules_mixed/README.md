One `--rule-file policies` with every format mixed: rule IR JSON
(`sg_open_ssh.json`), a Checkov YAML policy (`s3_versioning.yaml`), a Rego
policy (`rego/main.rego`) and a test mock next to it (`main.mock.json`,
which is data, not a rule). `crates/tf_scan/tests/rule_files.rs`.

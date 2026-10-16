`checkov:skip` comments for Checkov-sourced rules
(`crates/tf_scan/tests/rule_files.rs`). Checkov 3.2.328 with
`--external-checks-dir policies` on `tf/` passes `skipped`, `bare_skip` and
`module.child.aws_db_instance.inner` as skipped, and fails `other_id`,
`outside` and `module.child2.aws_db_instance.inner`; oxtf does the same.

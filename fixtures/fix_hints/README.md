Fix hints applied and rescanned (`crates/tf_scan/tests/fix_hints.rs`).
`policies/` holds one Checkov policy per operator that implies a fix
(`equals`, `is_false`, `within` one value, beside a filter) and two that
must not (`exists`, two fixable leaves). Each case directory fails one
policy; applying its hint with `tf_scan::apply_fix` and rescanning passes.

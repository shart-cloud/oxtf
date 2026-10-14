//! The IR version of seed rule 1 (`aws-sg-open-ssh`), as produced by the
//! Python expression API (`python/tfscan/examples/sg_open_ssh.py` writes the
//! same JSON), must give the same (address, root, severity, message) set as
//! the built-in Rust rule on every aws-sg-open-ssh fixture.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use tf_linter::{Linter, ScanOptions, discover_roots, scan_with};

type Key = (String, String, String, String);

fn keys(l: &Linter, roots: &[PathBuf]) -> BTreeSet<Key> {
    let (r, _) = scan_with(l, roots, &ScanOptions::default());
    r.findings
        .iter()
        .map(|f| {
            (
                f.address.to_string(),
                f.root.display().to_string(),
                f.severity.as_str().to_string(),
                f.message.clone(),
            )
        })
        .collect()
}

#[test]
fn ir_sg_open_ssh_matches_builtin_on_fixtures() {
    let ws = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let json = std::fs::read_to_string(ws.join("crates/tfscan_py/rules/sg_open_ssh.json")).unwrap();
    let ir = tf_rule_ir::compile_json(&json).unwrap();
    let ir = Linter::new(ir.into_iter().map(|r| Box::new(r) as _).collect());
    let builtin = Linter::filtered(tf_linter::rules::all(), &["aws-sg-open-ssh".into()]).unwrap();
    let dir = ws.join("fixtures/rules/aws-sg-open-ssh");
    let mut cases: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    cases.sort();
    let mut n = 0;
    for c in cases {
        let roots = discover_roots(&c, false);
        let (a, b) = (keys(&builtin, &roots), keys(&ir, &roots));
        assert_eq!(a, b, "{}", c.display());
        n += a.len();
    }
    assert_eq!(n, 7, "findings over all aws-sg-open-ssh fixtures");
}

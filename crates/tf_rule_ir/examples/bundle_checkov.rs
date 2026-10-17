//! Regenerate the bundled Checkov catalog (`data/checkov/`).
//!
//! ```sh
//! "$CHECKOV_PYTHON" -I scripts/import_checkov.py --output /tmp/pack
//! cargo run -p tf_rule_ir --example bundle_checkov -- /tmp/pack \
//!   .../site-packages/checkov/terraform/checks/graph_checks
//! ```

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [pack, graph_checks] = args.as_slice() else {
        eprintln!("usage: bundle_checkov VALUE_PACK_DIR GRAPH_CHECKS_DIR");
        std::process::exit(2);
    };
    let pack = Path::new(pack);
    let generated =
        tf_rule_ir::bundled::generate(pack, Path::new(graph_checks)).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/checkov");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("rules.json"), generated.rules_json).unwrap();
    std::fs::write(out.join("manifest.json"), generated.manifest_json).unwrap();
    std::fs::copy(pack.join("LICENSE.checkov"), out.join("LICENSE.checkov")).unwrap();
    println!("wrote {}", out.display());
}

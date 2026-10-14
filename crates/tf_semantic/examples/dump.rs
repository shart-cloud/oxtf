//! Print the evaluated model of a module directory.
//! cargo run -p tf_semantic --example dump -- DIR [--prov] [--filter SUBSTR]

use tf_semantic::{AnalyzeOptions, FileTable, analyze_module};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = args.first().expect("DIR");
    let prov = args.iter().any(|a| a == "--prov");
    let filter = args
        .iter()
        .position(|a| a == "--filter")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let files = FileTable::new();
    let a = analyze_module(dir.as_ref(), &AnalyzeOptions::default(), &files);
    for d in &a.diagnostics {
        println!(
            "diag {:?} {} {} {}",
            d.severity,
            d.code,
            d.at.map(|x| files.location(x)).unwrap_or_default(),
            d.message
        );
    }
    let show = |name: &str| filter.as_deref().is_none_or(|f| name.contains(f));
    for m in &a.modules {
        println!("== module {:?} ({})", m.address, m.dir.display());
        for v in &m.variables {
            if show(&format!("var.{}", v.name)) {
                println!("  var.{} = {}", v.name, v.value);
            }
        }
        for r in &m.resources {
            if !show(&r.address) {
                continue;
            }
            println!(
                "  {} existence={:?} count={:?} for_each={}",
                r.address,
                r.existence,
                r.count.as_ref().map(|c| c.to_string()),
                r.for_each
                    .as_ref()
                    .map(|c| c.to_string())
                    .unwrap_or_default()
            );
            for at in &r.body.attrs {
                println!("    {} = {}", at.name, at.value);
                if prov {
                    for s in at.value.prov.steps() {
                        println!("        <- {} {}", files.location(s.at), s.label);
                    }
                }
            }
            for b in &r.body.blocks {
                println!(
                    "    block {} (existence {:?}) {:?}",
                    b.ty,
                    b.existence,
                    b.body
                        .attrs
                        .iter()
                        .map(|a| format!("{} = {}", a.name, a.value))
                        .collect::<Vec<_>>()
                );
            }
        }
        for o in &m.outputs {
            if show(&format!("output.{}", o.name)) {
                println!("  output.{} = {}", o.name, o.value);
            }
        }
    }
}

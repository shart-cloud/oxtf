//! `tf_schema_codegen` CLI. Run from anywhere inside the repo:
//!
//! ```text
//! cargo run -p tf_schema_codegen --release -- generate      # rewrite crates/tf_schema/src/generated
//! cargo run -p tf_schema_codegen --release -- check         # exit 1 if generated files are stale
//! cargo run -p tf_schema_codegen --release -- diff OLD.json NEW.json
//! cargo run -p tf_schema_codegen --release -- coverage [--list]
//! cargo run -p tf_schema_codegen --release -- views-all aws OUT.rs   # Q4 experiment
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use tf_schema::ir::SchemaKind;
use tf_schema_codegen::*;

fn repo_root() -> PathBuf {
    if let Ok(r) = std::env::var("OXTF_ROOT") {
        return PathBuf::from(r);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = Paths { root: repo_root() };
    let res = match args.first().map(String::as_str) {
        Some("generate") => cmd_generate(&paths, false),
        Some("check") => cmd_generate(&paths, true),
        Some("diff") if args.len() >= 3 => cmd_diff(&paths, &args[1], &args[2]),
        Some("coverage") => cmd_coverage(&paths, args.iter().any(|a| a == "--list")),
        Some("views-all") if args.len() >= 3 => {
            cmd_views_all(&paths, &args[1], &args[2], args.get(3).map(String::as_str).unwrap_or(""))
        }
        _ => Err("usage: tf_schema_codegen generate|check|diff OLD NEW|coverage [--list]|views-all PROVIDER OUT.rs [EXCLUDE,..]".into()),
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_generate(paths: &Paths, check: bool) -> Result<ExitCode> {
    let t = std::time::Instant::now();
    let g = generate_from_disk(paths)?;
    let out = paths.out_dir();
    let mut stale = Vec::new();
    for (name, bytes) in &g.files {
        let p = out.join(name);
        let cur = std::fs::read(&p).ok();
        if cur.as_deref() != Some(bytes.as_slice()) {
            stale.push(name.clone());
            if !check {
                std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
                std::fs::write(&p, bytes).map_err(|e| format!("{}: {e}", p.display()))?;
            }
        }
        let lines = if name.ends_with(".rs") {
            bytes.iter().filter(|&&b| b == b'\n').count().to_string()
        } else {
            "-".into()
        };
        println!("{name:16} {:>10} bytes {:>8} lines", bytes.len(), lines);
    }
    println!(
        "{} schemas, {} defaults, {:.2?}",
        g.entry_count,
        g.default_count,
        t.elapsed()
    );
    if check && !stale.is_empty() {
        eprintln!(
            "stale generated files: {stale:?}; run `cargo run -p tf_schema_codegen --release -- generate`"
        );
        return Ok(ExitCode::FAILURE);
    }
    if !check {
        println!("wrote {} changed file(s) to {}", stale.len(), out.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn kind_str(k: SchemaKind) -> &'static str {
    match k {
        SchemaKind::Resource => "resource",
        SchemaKind::DataSource => "data",
    }
}

fn cmd_diff(paths: &Paths, old: &str, new: &str) -> Result<ExitCode> {
    let old_l = [load_schema_file(old.as_ref())?];
    let new_l = [load_schema_file(new.as_ref())?];
    let old_e = build_entries(&old_l)?;
    let new_e = build_entries(&new_l)?;
    let r = diff_entries(&old_e, &new_e);
    let targets =
        parse_rule_targets(&std::fs::read_to_string(paths.rule_targets()).unwrap_or_default());
    println!(
        "added: {}  removed: {}  changed paths: {}",
        r.added.len(),
        r.removed.len(),
        r.changed.len()
    );
    for (k, n) in &r.added {
        let note = if targets.contains(&(*k, n.clone())) {
            ""
        } else {
            "  (no rule targets it)"
        };
        println!("+ {} {n}{note}", kind_str(*k));
    }
    for (k, n) in &r.removed {
        println!("- {} {n}", kind_str(*k));
    }
    for (k, n, p, o, nw) in &r.changed {
        match (o.is_empty(), nw.is_empty()) {
            (true, _) => println!("~ {} {n}: + {p}: {nw}", kind_str(*k)),
            (_, true) => println!("~ {} {n}: - {p}: {o}", kind_str(*k)),
            _ => println!("~ {} {n}: {p}: {o} -> {nw}", kind_str(*k)),
        }
    }
    // Typed-view breakage: an allowlisted view present in OLD whose resource or
    // `uses` paths are missing from NEW. (Views for resources that are in
    // neither snapshot, e.g. another provider's, are ignored.)
    let allow =
        parse_allowlist(&std::fs::read_to_string(paths.allowlist()).map_err(|e| e.to_string())?)?;
    let relevant = Allowlist {
        view: allow
            .view
            .into_iter()
            .filter(|a| {
                a.schema_kind()
                    .is_ok_and(|k| find_entry(&old_e, k, &a.ty).is_some())
            })
            .collect(),
    };
    let errs = check_allowlist(&new_e, &relevant);
    if !errs.is_empty() {
        for e in &errs {
            eprintln!("BREAKING: {e}");
        }
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_coverage(paths: &Paths, list: bool) -> Result<ExitCode> {
    let loaded = load_all(&paths.schemas_dir())?;
    let entries = build_entries(&loaded)?;
    let targets = parse_rule_targets(
        &std::fs::read_to_string(paths.rule_targets()).map_err(|e| e.to_string())?,
    );
    let missing: Vec<_> = targets
        .iter()
        .filter(|(k, n)| find_entry(&entries, *k, n).is_none())
        .collect();
    for (k, n) in &missing {
        eprintln!("rule target {} {n} is not in any schema", kind_str(*k));
    }
    let unc = uncovered(&entries, &targets);
    for p in tf_schema::ir::Provider::ALL {
        for k in [SchemaKind::Resource, SchemaKind::DataSource] {
            let total = entries
                .iter()
                .filter(|e| e.provider == p && e.kind == k)
                .count();
            let u = unc
                .iter()
                .filter(|e| e.provider == p && e.kind == k)
                .count();
            println!(
                "{:8} {:9} total {total:5}  with rules {:3}  without {u:5}",
                p.name(),
                kind_str(k),
                total - u
            );
        }
    }
    if list {
        for e in unc {
            println!("{} {} {}", e.provider.name(), kind_str(e.kind), e.name);
        }
    }
    Ok(if missing.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Q4 experiment: views for every resource of `provider`, minus the
/// comma-separated `exclude` list.
fn cmd_views_all(paths: &Paths, provider: &str, out: &str, exclude: &str) -> Result<ExitCode> {
    let exclude: Vec<&str> = exclude.split(',').filter(|s| !s.is_empty()).collect();
    let p = provider_from_name(provider).ok_or("unknown provider")?;
    let loaded = [load_schema_file(
        &paths.schemas_dir().join(format!("{provider}.json")),
    )?];
    let entries = build_entries(&loaded)?;
    let allow: Vec<AllowEntry> = entries
        .iter()
        .filter(|e| e.kind == SchemaKind::Resource && e.provider == p && !exclude.contains(&e.name))
        .map(|e| AllowEntry {
            ty: e.name.to_string(),
            kind: "resource".into(),
            uses: vec![],
        })
        .collect();
    let src = views_source(&entries, &allow)?;
    std::fs::write(out, &src).map_err(|e| e.to_string())?;
    println!(
        "{} views, {} lines, {} bytes -> {out}",
        allow.len(),
        src.lines().count(),
        src.len()
    );
    Ok(ExitCode::SUCCESS)
}

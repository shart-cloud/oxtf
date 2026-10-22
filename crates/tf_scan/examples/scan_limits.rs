//! Scan-storage/performance matrix and repeated plan scans on one persistent thread.
use std::path::PathBuf;
use std::time::Instant;
use tf_scan::{Catalog, ScanInput, ScanRequest};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "plan") {
        return plans(&args[1..]);
    }
    let [path, catalog, workers, keep] = args.as_slice() else {
        return Err(
            "expected PATH seed|standard WORKERS KEEP_MODELS, or plan PLAN POLICY COUNT".into(),
        );
    };
    let mut request = ScanRequest::dirs(vec![path.into()], true);
    request.catalog = match catalog.as_str() {
        "seed" => Catalog::seed(),
        "standard" => Catalog::standard(),
        _ => return Err("expected seed or standard".into()),
    };
    request.threads = Some(workers.parse()?);
    request.keep_models = keep.parse()?;
    let started = Instant::now();
    let out = tf_scan::scan(request)?;
    let input = out.result.files.input_budget().stats();
    let max_source = out
        .result
        .files
        .all()
        .iter()
        .map(|f| f.text.len())
        .max()
        .unwrap_or(0);
    println!(
        "{}",
        serde_json::json!({
            "catalog": catalog, "workers": workers, "keep_models": keep,
            "elapsed_ms": started.elapsed().as_millis(), "status": out.result.status().as_str(),
            "roots": out.result.stats.roots, "files": out.result.stats.files,
            "resources": out.result.stats.resources,
            "module_instances": out.result.stats.module_instances,
            "retained_models": out.analyses.len(), "findings": out.result.findings.len(),
            "errors": out.result.rule_errors.len(), "source_bytes": input.source_bytes,
            "file_entries": input.file_entries, "directory_entries": input.directory_entries,
            "roots_admitted": input.roots,
            "arena_bytes": input.arena_bytes, "ast_nodes": input.ast_nodes,
            "text_bytes": input.text_bytes,
            "collection_bytes": input.collection_bytes,
            "input_exhausted": out.result.files.input_budget().exhaustion().is_some(),
            "max_source_text_bytes": max_source,
        })
    );
    Ok(())
}

fn plans(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [plan, policy, count] = args else {
        return Err("expected PLAN POLICY COUNT".into());
    };
    let count: usize = count.parse()?;
    let started = Instant::now();
    for i in 0..count {
        let mut request = ScanRequest::dirs(Vec::new(), false);
        request.input = ScanInput::Plan {
            plan: PathBuf::from(plan),
            source: None,
        };
        request.catalog = Catalog::default();
        request.catalog.policies.foreign.push(PathBuf::from(policy));
        request.catalog.policies.shape = Some(tf_scan::Shape::Plan);
        request.catalog.policies.all_namespaces = true;
        request.keep_models = false;
        let out = tf_scan::scan(request)?;
        if !out.result.rule_errors.is_empty() {
            return Err(format!("{:?}", out.result.rule_errors).into());
        }
        if i == 0 || (i + 1) % 100 == 0 || i + 1 == count {
            let rss = std::fs::read_to_string("/proc/self/status")?
                .lines()
                .find(|line| line.starts_with("VmRSS:"))
                .unwrap_or("VmRSS unavailable")
                .to_owned();
            println!(
                "iteration={} elapsed_ms={} {} findings={}",
                i + 1,
                started.elapsed().as_millis(),
                rss,
                out.result.findings.len()
            );
        }
    }
    Ok(())
}

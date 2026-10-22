//! Measure rule allowances over a fixed corpus, dropping each root model after use.
use std::path::PathBuf;
use tf_linter::{Linter, Profile, Sources};
use tf_scan::{Catalog, Limits};
use tf_semantic::{AnalyzeOptions, FileTable, ModuleStore, analyze_module_shared};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(std::env::args().nth(1).ok_or("expected corpus path")?);
    let mode = std::env::args().nth(2).unwrap_or_else(|| "standard".into());
    let mut catalog = catalog(&mode)?;
    if mode == "rego" {
        catalog.policies.foreign.push(PathBuf::from(
            std::env::args().nth(3).ok_or("expected policy path")?,
        ));
        catalog.policies.shape = Some(tf_scan::Shape::Hcl);
    }
    let linter = Linter::new(catalog.resolve()?.rules);
    let limits = Limits::default().with_rule_steps(u64::MAX)?;
    let opts = AnalyzeOptions {
        whole_files: linter.needs_files(),
        limits,
        ..AnalyzeOptions::default()
    };
    let roots = tf_linter::scan::discover_roots_checked(&path, true)?;
    let files = FileTable::new();
    let store = ModuleStore::new();
    let mut samples = Vec::new();
    let mut times = Vec::new();
    let (mut errors, mut exhausted, mut resources, mut findings) = (0, 0, 0, 0);
    for root in &roots {
        let analysis = analyze_module_shared(root, &opts, &files, &store);
        resources += analysis.stats.resources;
        let out = linter.run_with_limits(
            &analysis,
            Some(Sources {
                files: &files,
                store: &store,
                limits,
            }),
            limits,
        );
        samples.push((out.rule_steps, root.clone()));
        times.push((out.rego_elapsed, root.clone()));
        errors += out.rule_errors.len();
        exhausted += usize::from(out.rule_exhaustion.is_some());
        findings += out.findings.len();
    }
    samples.sort();
    println!(
        concat!(
            "catalog={} roots={} files={} resources={} findings={} ",
            "errors={} exhausted={}"
        ),
        mode,
        roots.len(),
        files.len(),
        resources,
        findings,
        errors,
        exhausted
    );
    report(&samples, &mut times);
    println!(
        "input={:?} input_exhaustion={:?}",
        files.input_budget().stats(),
        files.input_budget().exhaustion()
    );
    Ok(())
}

fn report(samples: &[(u64, PathBuf)], times: &mut [(std::time::Duration, PathBuf)]) {
    if let Some((maximum, largest)) = samples.last() {
        println!(
            "steps={} median={} p95={} max={} largest={}",
            samples
                .iter()
                .map(|(used, _)| u128::from(*used))
                .sum::<u128>(),
            samples[samples.len() / 2].0,
            samples[(samples.len() - 1) * 95 / 100].0,
            maximum,
            largest.display()
        );
    }
    times.sort();
    if let Some((maximum, root)) = times.last() {
        println!(
            "rego_total_us={} median_us={} p95_us={} max_us={} largest={}",
            times.iter().map(|(t, _)| t.as_micros()).sum::<u128>(),
            times[times.len() / 2].0.as_micros(),
            times[(times.len() - 1) * 95 / 100].0.as_micros(),
            maximum.as_micros(),
            root.display()
        );
    }
}

fn catalog(mode: &str) -> Result<Catalog, &'static str> {
    let mut catalog = match mode {
        "seed" => Catalog::seed(),
        "standard" | "all" => Catalog::standard(),
        "rego" => Catalog::default(),
        _ => return Err("expected seed, standard, all, or rego"),
    };
    if mode == "all" {
        catalog.profiles = Some(vec![
            Profile::Security,
            Profile::Audit,
            Profile::Hygiene,
            Profile::Unreviewed,
        ]);
    }
    Ok(catalog)
}

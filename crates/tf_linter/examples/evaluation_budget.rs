//! Measure runtime and cached-default work with one shared module cache.
use std::path::{Path, PathBuf};

use tf_semantic::{AnalyzeOptions, FileTable, ModuleStore, analyze_module_shared};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("expected a corpus directory")?,
    );
    let roots = tf_linter::scan::discover_roots_checked(&path, true)?;
    let files = FileTable::new();
    let store = ModuleStore::new();
    let opts = AnalyzeOptions {
        whole_files: true,
        ..AnalyzeOptions::default()
    };
    let mut runtime = Counts::default();
    let mut loader = Counts::default();
    for root in &roots {
        let analysis = analyze_module_shared(root, &opts, &files, &store);
        let exhausted = |resource| {
            analysis
                .diagnostics
                .iter()
                .any(|d| d.code == "coverage-budget" && d.message.starts_with(resource))
        };
        runtime.observe(
            root,
            analysis.stats.evaluation_steps,
            exhausted("evaluation_steps"),
        );
        loader.observe(root, analysis.stats.loader_steps, exhausted("loader_steps"));
    }
    println!("roots={} files={}", roots.len(), files.len());
    runtime.report("evaluation_steps");
    loader.report("loader_steps");
    Ok(())
}

#[derive(Default)]
struct Counts {
    steps: Vec<u64>,
    exhausted: usize,
    maximum: u64,
    largest: PathBuf,
}

impl Counts {
    fn observe(&mut self, root: &Path, used: u64, exhausted: bool) {
        self.steps.push(used);
        self.exhausted += usize::from(exhausted);
        if used > self.maximum {
            self.maximum = used;
            self.largest = root.to_owned();
        }
    }

    fn report(&mut self, resource: &str) {
        self.steps.sort_unstable();
        println!(
            "{resource}: steps={} active_roots={} exhausted={}",
            self.steps.iter().sum::<u64>(),
            self.steps.iter().filter(|&&steps| steps > 0).count(),
            self.exhausted,
        );
        if !self.steps.is_empty() {
            println!(
                "median={} p95={} max={} largest={}",
                self.steps[self.steps.len() / 2],
                self.steps[(self.steps.len() - 1) * 95 / 100],
                self.maximum,
                self.largest.display()
            );
        }
    }
}

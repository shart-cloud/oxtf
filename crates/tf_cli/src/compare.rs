use std::io::Read;
use std::process::ExitCode;
use tf_linter::record::ScanRecord;
use tf_scan::ScanComparison;

const USAGE: &str = "usage: oxtf compare BEFORE.json AFTER.json [-f json|text]\nCompare full JSON scan records. Exit 0: comparable, no new findings; 1: new findings\nor increased certainty; 2: invalid input; 4: comparison cannot verify resolution.";

pub fn run(args: impl Iterator<Item = String>) -> ExitCode {
    match compare(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn compare(mut args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let mut paths = Vec::new();
    let mut text = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "-f" | "--format" => {
                text = match args.next().as_deref() {
                    Some("text") => true,
                    Some("json") => false,
                    _ => return Err("--format expects json or text".into()),
                };
            }
            _ if arg.starts_with('-') => return Err(format!("unknown compare option {arg}")),
            _ => paths.push(arg),
        }
    }
    let [before, after] = paths.as_slice() else {
        return Err("expected two scan record files".into());
    };
    let result = ScanComparison::between(&read(before)?, &read(after)?)?;
    if text {
        print_text(&result);
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("comparison is JSON")
        );
    }
    Ok(ExitCode::from(if !result.comparable {
        4
    } else if result.has_regressions() {
        1
    } else {
        0
    }))
}

fn read(path: &str) -> Result<ScanRecord, String> {
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{path}: {e}"))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(format!("{path}: scan record exceeds 64 MiB"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("{path}: expected a full JSON scan record: {e}"))
}

fn print_text(r: &ScanComparison) {
    println!(
        "{} added, {} resolved, {} removed but unverified, {} changed, {} unchanged; comparison {}",
        r.delta.added.len(),
        r.resolved.len(),
        r.unverified_removed.len(),
        r.delta.changed.len(),
        r.delta.unchanged,
        if r.comparable {
            "complete"
        } else {
            "incomplete"
        }
    );
    for issue in &r.issues {
        println!("  coverage: {issue}");
    }
    for f in &r.delta.added {
        println!("  added: {} ({})", f.fingerprint, f.rule);
    }
    for fingerprint in &r.resolved {
        println!("  resolved: {fingerprint}");
    }
    for fingerprint in &r.unverified_removed {
        println!("  unverified removal: {fingerprint}");
    }
    for change in &r.delta.changed {
        println!(
            "  changed: {} ({}); {} added occurrences, {} removed occurrences",
            change.after.fingerprint,
            change.after.rule,
            change.added_occurrences.len(),
            change.removed_occurrences.len()
        );
    }
    for change in &r.certainty_changes {
        for occurrence in &change.occurrences {
            println!(
                "  certainty: {} {} in {}: {} -> {}",
                change.fingerprint,
                occurrence.address,
                occurrence.root,
                occurrence.before.as_str(),
                occurrence.after.as_str()
            );
        }
    }
}

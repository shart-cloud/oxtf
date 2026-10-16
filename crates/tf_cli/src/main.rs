//! `oxtf`: Terraform security scanner (spike).
//!
//! ```text
//! oxtf scan [PATH...] [-r|--recursive] [--format text|json] [--var-file FILE]...
//!           [--rule ID]... [--rule-file PATH]... [--threads N] [--color] [--no-diagnostics] [--quiet]
//! oxtf scan --plan PLAN.json [--source DIR] [options]
//! oxtf rules
//! ```
//!
//! Exit codes: 0 clean, 1 some rule failed on some resource (output is
//! still printed; see `rule_errors`), 2 the scan could not run.

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use tf_linter::Linter;

/// The scan allocates many short-lived small objects from worker threads;
/// mimalloc cut single-thread CPU by about a quarter against glibc malloc,
/// which also grew worker arenas with thousands of mprotect calls. Its
/// worker heaps keep freed memory committed until exit, so a multi-threaded
/// corpus scan peaks at ~190 MB where glibc peaked at ~60 MB; running with
/// `MIMALLOC_PURGE_DELAY=0 MIMALLOC_ARENA_EAGER_COMMIT=0` brings that to
/// ~50 MB at the same speed. (Setting those through `mi_option_set` at the
/// start of `main` does not have the same effect: the first arena is
/// already reserved by then.)
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
use tf_linter::render::{location, render_finding, result_json};
use tf_scan::{Catalog, ScanInput, ScanRequest};

const USAGE: &str = "usage:
  oxtf scan [PATH...] [options]   scan Terraform module directories (default: .)
  oxtf scan --plan PLAN.json [--source DIR] [options]
                                  scan `terraform show -json` output; findings are mapped
                                  back to .tf spans in DIR (default: the plan's directory
                                  if it has .tf files, else locations point into the JSON)
  oxtf rules [--rule-file PATH]... list built-in and imported rules

scan options:
  -r, --recursive         every directory under PATH containing .tf files is a root module
  -f, --format FMT        text (default) or json
      --var-file FILE     extra .tfvars for the root module(s) (repeatable)
      --rule ID           only run this rule (repeatable); ids come from the whole
                          catalog: seed rules, --rule-file rules and Rego policies
      --rule-file PATH    also run rules from PATH (repeatable): a rule-IR JSON file (e.g.
                          written by the tfscan Python expression API), a Checkov YAML/JSON
                          policy, or a directory of them (searched recursively)
      --rego-native       run the seed rules that have a bundled native-tier Rego
                          policy (RDS encryption, GCS uniform access) as Rego
      --policy PATH       also run foreign Rego policies (repeatable): .rego files and
                          .json/.yaml data, or directories of them, loaded as one bundle
                          as `opa eval -d PATH` loads them; run unchanged
      --policy-shape S    input document shape for --policy: plan (default) or hcl
      --policy-entry R    entry rule read for violations, one rule each (repeatable;
                          default: data.main.deny)
      --rego-v0           parse --policy files as Rego v0 (`opa eval --v0-compatible`)
      --overlay PATH=FILE scan FILE's contents as if it were at PATH (repeatable;
                          FILE `-` reads stdin). PATH may be a file that does not exist,
                          in a directory that does not exist. Unsaved buffers, patches.
      --threads N         worker threads (default: all CPUs)
      --color             force colored output
      --no-diagnostics    do not print parse / strict-bool / module diagnostics
  -q, --quiet             text format: print only the summary";

/// The command line, as parsed: a scan request plus output switches.
struct Args {
    request: ScanRequest,
    json: bool,
    color: bool,
    diagnostics: bool,
    quiet: bool,
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut recursive = false;
    let mut plan: Option<PathBuf> = None;
    let mut source: Option<PathBuf> = None;
    let mut catalog = Catalog::seed();
    let mut selection: Option<Vec<String>> = None;
    let mut var_files = Vec::new();
    let mut threads = None;
    let mut overlay = Vec::new();
    let mut a = Args {
        request: ScanRequest::dirs(Vec::new(), false),
        json: false,
        color: std::io::stdout().is_terminal(),
        diagnostics: true,
        quiet: false,
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-r" | "--recursive" => recursive = true,
            "-f" | "--format" => match it.next().as_deref() {
                Some("json") => a.json = true,
                Some("text") => a.json = false,
                other => return Err(format!("unknown format {other:?}")),
            },
            "--var-file" => var_files.push(it.next().ok_or("--var-file needs a value")?.into()),
            "--rule" => selection
                .get_or_insert_with(Vec::new)
                .push(it.next().ok_or("--rule needs a value")?),
            "--rule-file" => catalog
                .rule_files
                .push(it.next().ok_or("--rule-file needs a value")?.into()),
            "--rego-native" => catalog.policies.native = true,
            "--policy" => catalog
                .policies
                .foreign
                .push(it.next().ok_or("--policy needs a value")?.into()),
            "--policy-shape" => {
                catalog.policies.shape =
                    Some(it.next().ok_or("--policy-shape needs a value")?.parse()?)
            }
            "--policy-entry" => catalog
                .policies
                .entries
                .push(it.next().ok_or("--policy-entry needs a value")?),
            "--rego-v0" => catalog.policies.rego_v0 = true,
            "--plan" => plan = Some(it.next().ok_or("--plan needs a value")?.into()),
            "--source" => source = Some(it.next().ok_or("--source needs a value")?.into()),
            "--overlay" => {
                let spec = it.next().ok_or("--overlay needs PATH=FILE")?;
                let (path, file) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("--overlay {spec:?}: expected PATH=FILE"))?;
                let text = if file == "-" {
                    let mut s = String::new();
                    std::io::stdin()
                        .read_to_string(&mut s)
                        .map_err(|e| format!("--overlay {path}: stdin: {e}"))?;
                    s
                } else {
                    std::fs::read_to_string(file)
                        .map_err(|e| format!("--overlay {path}: {file}: {e}"))?
                };
                overlay.push((PathBuf::from(path), std::sync::Arc::from(text)));
            }
            "--threads" => {
                threads = Some(
                    it.next()
                        .and_then(|n| n.parse().ok())
                        .ok_or("--threads needs a number")?,
                )
            }
            "--color" => a.color = true,
            "--no-color" => a.color = false,
            "--no-diagnostics" => a.diagnostics = false,
            "-q" | "--quiet" => a.quiet = true,
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            p => paths.push(p.into()),
        }
    }
    let input = match plan {
        Some(plan) => {
            if !paths.is_empty() || recursive || !var_files.is_empty() {
                return Err("--plan takes no PATH, --recursive or --var-file".into());
            }
            ScanInput::Plan { plan, source }
        }
        None => {
            if source.is_some() {
                return Err("--source needs --plan".into());
            }
            if paths.is_empty() {
                paths.push(".".into());
            }
            ScanInput::Dirs { paths, recursive }
        }
    };
    a.request = ScanRequest {
        input,
        catalog,
        selection,
        var_files,
        threads,
        overlay,
        // The CLI prints findings; it never reads the models.
        keep_models: false,
    };
    Ok(a)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("scan") => match parse_args(args) {
            Ok(a) => scan(a),
            Err(e) => {
                eprintln!("error: {e}\n\n{USAGE}");
                ExitCode::from(2)
            }
        },
        Some("rules") => {
            let rules = match parse_args(args)
                .and_then(|a| a.request.catalog.resolve().map_err(|e| e.to_string()))
            {
                Ok(resolved) => {
                    for w in &resolved.warnings {
                        eprintln!("warning: {w}");
                    }
                    resolved.rules
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            for r in Linter::new(rules).rules() {
                let types = if r.runs_on_module {
                    "(module rule)".to_string()
                } else {
                    r.resource_types.join(", ")
                };
                println!(
                    "{:<28} {:<9} {:<11} {}  [{}]",
                    r.name,
                    r.level.as_str(),
                    r.category.as_str(),
                    r.description,
                    types
                );
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Exit codes: 0 clean run, 1 a rule failed on some resource (the output
/// is still printed and carries the rule errors), 2 the scan could not run.
fn scan(a: Args) -> ExitCode {
    let Args {
        request,
        json,
        color,
        diagnostics,
        quiet,
    } = a;
    let output = match tf_scan::scan(request) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let r = &output.result;
    // Skipped rule files are shown even with --no-diagnostics: they change
    // what an empty result means.
    for d in r.diagnostics.iter().filter(|d| d.code == "rule-skipped") {
        eprintln!("warning: {}", d.message);
    }
    for e in &r.rule_errors {
        match &e.resource {
            Some(res) => eprintln!("rule error: {} on {res}: {}", e.rule, e.message),
            None => eprintln!("rule error: {}: {}", e.rule, e.message),
        }
    }
    print_result(r, json, color, diagnostics, quiet);
    if r.rule_errors.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn print_result(
    r: &tf_linter::ScanResult,
    json: bool,
    color: bool,
    diagnostics: bool,
    quiet: bool,
) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if json {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&result_json(r)).unwrap()
        );
        return;
    }
    if !quiet {
        for f in &r.findings {
            let _ = writeln!(out, "{}", render_finding(&r.files, f, color));
        }
        if diagnostics {
            // Skipped rule files were already printed to stderr.
            for d in r.diagnostics.iter().filter(|d| d.code != "rule-skipped") {
                let at =
                    d.at.map(|x| format!("{}: ", location(&r.files, x)))
                        .unwrap_or_default();
                let _ = writeln!(out, "{:?} [{}] {at}{}", d.severity, d.code, d.message);
            }
        }
    }
    let s = &r.stats;
    let by_rule: Vec<String> = s
        .findings_by_rule
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    let _ = writeln!(
        out,
        "{} findings ({} definite, {} conditional, {} indeterminate) in {} root modules, {} module instances, {} files, {} resources; {} diagnostics; {} rule errors; {:.1} ms{}",
        s.findings,
        s.definite,
        s.conditional,
        s.indeterminate,
        s.roots,
        s.module_instances,
        s.files,
        s.resources,
        r.diagnostics.len(),
        r.rule_errors.len(),
        s.elapsed.as_secs_f64() * 1000.0,
        if by_rule.is_empty() {
            String::new()
        } else {
            format!("\n  by rule: {}", by_rule.join(", "))
        }
    );
}

//! `oxtf`: Terraform security scanner (spike).
//!
//! ```text
//! oxtf scan [PATH...] [-r|--recursive] [--format text|json] [--var-file FILE]...
//!           [--rule ID]... [--rule-file FILE]... [--threads N] [--color] [--no-diagnostics] [--quiet]
//! oxtf scan --plan PLAN.json [--source DIR] [options]
//! oxtf rules
//! ```
//!
//! Exit codes: 0 clean, 1 some rule failed on some resource (output is
//! still printed; see `rule_errors`), 2 the scan could not run.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use tf_linter::Linter;
use tf_linter::render::{location, render_finding, result_json};
use tf_scan::{Catalog, ScanInput, ScanRequest};

const USAGE: &str = "usage:
  oxtf scan [PATH...] [options]   scan Terraform module directories (default: .)
  oxtf scan --plan PLAN.json [--source DIR] [options]
                                  scan `terraform show -json` output; findings are mapped
                                  back to .tf spans in DIR (default: the plan's directory
                                  if it has .tf files, else locations point into the JSON)
  oxtf rules                      list rules

scan options:
  -r, --recursive         every directory under PATH containing .tf files is a root module
  -f, --format FMT        text (default) or json
      --var-file FILE     extra .tfvars for the root module(s) (repeatable)
      --rule ID           only run this rule (repeatable); ids come from the whole
                          catalog: seed rules, --rule-file rules and Rego policies
      --rule-file FILE    also run rules from a JSON rule-IR file (repeatable; e.g. written
                          by the tfscan Python expression API)
      --rego-native       run the seed rules that have a bundled native-tier Rego
                          policy (RDS encryption, GCS uniform access) as Rego
      --policy FILE       also run a foreign Rego policy over every resource
                          (repeatable; Conftest / OPA style, unchanged)
      --policy-shape S    input document shape for --policy: plan (default) or hcl
      --policy-entry R    rule path read for violations (default: data.main.deny)
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
            "--policy-entry" => {
                catalog.policies.entry = Some(it.next().ok_or("--policy-entry needs a value")?)
            }
            "--plan" => plan = Some(it.next().ok_or("--plan needs a value")?.into()),
            "--source" => source = Some(it.next().ok_or("--source needs a value")?.into()),
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
            for r in Linter::with_seed_rules().rules() {
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
            for d in &r.diagnostics {
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

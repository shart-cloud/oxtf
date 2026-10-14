//! `oxtf`: Terraform security scanner (spike).
//!
//! ```text
//! oxtf scan [PATH...] [-r|--recursive] [--format text|json] [--var-file FILE]...
//!           [--rule ID]... [--rule-file FILE]... [--threads N] [--color] [--no-diagnostics] [--quiet]
//! oxtf scan --plan PLAN.json [--source DIR] [options]
//! oxtf rules
//! ```

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use tf_linter::render::{location, render_finding, result_json};
use tf_linter::{Linter, ScanOptions, discover_roots, scan_with};

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
      --rule ID           only run this rule (repeatable)
      --rule-file FILE    also run rules from a JSON rule-IR file (repeatable; e.g. written
                          by the tfscan Python expression API)
      --threads N         worker threads (default: all CPUs)
      --color             force colored output
      --no-diagnostics    do not print parse / strict-bool / module diagnostics
  -q, --quiet             text format: print only the summary";

struct Args {
    paths: Vec<PathBuf>,
    plan: Option<PathBuf>,
    source: Option<PathBuf>,
    rule_files: Vec<PathBuf>,
    opts: ScanOptions,
    json: bool,
    color: bool,
    diagnostics: bool,
    quiet: bool,
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut a = Args {
        paths: Vec::new(),
        plan: None,
        source: None,
        rule_files: Vec::new(),
        opts: ScanOptions::default(),
        json: false,
        color: std::io::stdout().is_terminal(),
        diagnostics: true,
        quiet: false,
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-r" | "--recursive" => a.opts.recursive = true,
            "-f" | "--format" => match it.next().as_deref() {
                Some("json") => a.json = true,
                Some("text") => a.json = false,
                other => return Err(format!("unknown format {other:?}")),
            },
            "--var-file" => a
                .opts
                .var_files
                .push(it.next().ok_or("--var-file needs a value")?.into()),
            "--rule" => a
                .opts
                .rules
                .get_or_insert_with(Vec::new)
                .push(it.next().ok_or("--rule needs a value")?),
            "--rule-file" => a
                .rule_files
                .push(it.next().ok_or("--rule-file needs a value")?.into()),
            "--plan" => a.plan = Some(it.next().ok_or("--plan needs a value")?.into()),
            "--source" => a.source = Some(it.next().ok_or("--source needs a value")?.into()),
            "--threads" => {
                a.opts.threads = Some(
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
            p => a.paths.push(p.into()),
        }
    }
    if a.plan.is_some() {
        if !a.paths.is_empty() || a.opts.recursive || !a.opts.var_files.is_empty() {
            return Err("--plan takes no PATH, --recursive or --var-file".into());
        }
    } else if a.source.is_some() {
        return Err("--source needs --plan".into());
    }
    if a.paths.is_empty() {
        a.paths.push(".".into());
    }
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

fn scan(a: Args) -> ExitCode {
    let mut rules = tf_linter::rules::all();
    for f in &a.rule_files {
        match tf_rule_ir::load_rules_file(f).and_then(|specs| {
            specs
                .into_iter()
                .map(tf_rule_ir::compile)
                .collect::<Result<Vec<_>, _>>()
        }) {
            Ok(rs) => rules.extend(rs.into_iter().map(|r| Box::new(r) as _)),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let run = |rules| scan_rules(&a, rules);
    let result = run(rules);
    match result {
        Ok(r) => print_result(&r, &a),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn scan_rules(
    a: &Args,
    rules: Vec<Box<dyn tf_linter::rule::DynRule>>,
) -> Result<tf_linter::ScanResult, String> {
    let linter = match &a.opts.rules {
        Some(ids) => Linter::filtered(rules, ids).map_err(|e| e.to_string())?,
        None => Linter::new(rules),
    };
    if let Some(plan) = &a.plan {
        tf_plan::scan_plan(
            &linter,
            plan,
            &tf_plan::PlanOptions {
                source: a.source.clone(),
            },
        )
        .map_err(|e| e.to_string())
    } else {
        scan_dirs(&linter, a)
    }
}

fn scan_dirs(linter: &Linter, a: &Args) -> Result<tf_linter::ScanResult, String> {
    let mut roots = Vec::new();
    for p in &a.paths {
        if !p.is_dir() {
            return Err(format!("{} is not a directory", p.display()));
        }
        roots.extend(discover_roots(p, a.opts.recursive));
    }
    Ok(scan_with(linter, &roots, &a.opts).0)
}

fn print_result(r: &tf_linter::ScanResult, a: &Args) -> ExitCode {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if a.json {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&result_json(r)).unwrap()
        );
        return ExitCode::SUCCESS;
    }
    if !a.quiet {
        for f in &r.findings {
            let _ = writeln!(out, "{}", render_finding(&r.files, f, a.color));
        }
        if a.diagnostics {
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
        "{} findings ({} definite, {} conditional) in {} root modules, {} module instances, {} files, {} resources; {} diagnostics; {:.1} ms{}",
        s.findings,
        s.definite,
        s.conditional,
        s.roots,
        s.module_instances,
        s.files,
        s.resources,
        r.diagnostics.len(),
        s.elapsed.as_secs_f64() * 1000.0,
        if by_rule.is_empty() {
            String::new()
        } else {
            format!("\n  by rule: {}", by_rule.join(", "))
        }
    );
    ExitCode::SUCCESS
}

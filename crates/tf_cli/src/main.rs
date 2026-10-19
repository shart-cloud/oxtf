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
  oxtf rules [--rule-file PATH]... [-f json]
                                  list built-in and loaded rules: level, category, engine,
                                  description, resource types and source file:line
  oxtf rules test --policy PATH... [--data PATH]... [--namespace NS]... [--rego-v0]
                                  run the policies' test_* rules (as `conftest verify`)

Built in are the seed rules and the bundled Checkov catalog: Checkov 3.2.328's Terraform
value checks, graph policies and Python resource checks (1073 rules), run natively.

scan options:
  -r, --recursive         every directory under PATH containing .tf files is a root module
  -f, --format FMT        text (default) or json
      --var-file FILE     extra .tfvars for the root module(s) (repeatable)
      --rule ID           only run this rule (repeatable); ids come from the whole
                          catalog: bundled Checkov rules, seed rules, --rule-file rules
                          and Rego policies
      --no-bundled        do not run the bundled Checkov catalog
      --no-builtin        run neither the bundled catalog nor the seed rules, only
                          --rule-file / --policy rules
      --rule-file PATH    also run rules from PATH (repeatable), each file by its format:
                          rule-IR JSON (e.g. from the tfscan Python expression API),
                          Checkov YAML/JSON policies, Rego (.rego), or a directory of any
                          mix of them (searched recursively)
      --rego-native       run the seed rules that have a bundled native-tier Rego
                          policy (RDS encryption, GCS uniform access) as Rego
      --policy PATH       the same as --rule-file. Rego files load as one bundle and run
                          unchanged; by default they follow Conftest: every
                          deny/violation/warn rule (and deny_*, ...) in the selected
                          namespaces is a rule, and `exception` sets suppress them
      --namespace NS      Conftest namespace to run (repeatable; default: main)
      --all-namespaces    run every namespace
      --data PATH         .json/.yaml data documents for --policy (repeatable)
      --policy-entry R    OPA mode instead: run these entry rules (repeatable), and load
                          data next to the policies as `opa eval -d PATH` does
      --policy-shape S    input document shape for --policy: plan (default) or hcl
      --rego-v0           parse --policy files as Rego v0 (`--v0-compatible`)
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
    let mut catalog = Catalog::standard();
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
            "--no-bundled" => catalog.bundled = false,
            "--no-builtin" => {
                catalog.bundled = false;
                catalog.builtin = false;
            }
            // An alias: every format is detected.
            "--policy" => catalog
                .rule_files
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
            "--namespace" => catalog
                .policies
                .namespaces
                .push(it.next().ok_or("--namespace needs a value")?),
            "--all-namespaces" => catalog.policies.all_namespaces = true,
            "--data" => catalog
                .policies
                .data
                .push(it.next().ok_or("--data needs a value")?.into()),
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
            let mut args = args.peekable();
            if args.peek().map(String::as_str) == Some("test") {
                args.next();
                return rules_test(args);
            }
            let (rules, json) = match parse_args(args).and_then(|a| {
                let json = a.json;
                a.request
                    .catalog
                    .resolve()
                    .map(|r| (r, json))
                    .map_err(|e| e.to_string())
            }) {
                Ok((resolved, json)) => {
                    for w in &resolved.warnings {
                        eprintln!("warning: {w}");
                    }
                    (resolved.rules, json)
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let linter = Linter::new(rules);
            if json {
                let list: Vec<serde_json::Value> = linter
                    .rules()
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": &*r.name,
                            "level": r.level.as_str(),
                            "category": r.category.as_str(),
                            "description": &*r.description,
                            "resource_types": r.resource_types.iter().map(|t| &**t).collect::<Vec<_>>(),
                            "runs_on_module": r.runs_on_module,
                            "guideline": r.guideline.as_deref(),
                            "source": tf_linter::record::SourceRef::from(&r.source),
                            "aliases": r.aliases.iter().map(|a| &**a).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                println!("{}", serde_json::Value::Array(list));
                return ExitCode::SUCCESS;
            }
            for r in linter.rules() {
                let types = if r.runs_on_module {
                    "(module rule)".to_string()
                } else {
                    r.resource_types.join(", ")
                };
                let mut source = match (&r.source.file, r.source.line) {
                    (Some(f), Some(l)) => format!("  {}:{l}", f.display()),
                    (Some(f), None) => format!("  {}", f.display()),
                    _ => String::new(),
                };
                if !r.aliases.is_empty() {
                    source = format!("  (also {}){source}", r.aliases.join(", "));
                }
                println!(
                    "{:<28} {:<9} {:<11} {:<9} {}  [{}]{source}",
                    r.name,
                    r.level.as_str(),
                    r.category.as_str(),
                    r.source.engine.as_str(),
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

/// `oxtf rules test`: run the policies' `test_*` rules as `conftest
/// verify` does. Exit codes: 0 all passed, 1 a test failed or errored,
/// 2 the policies could not load.
fn rules_test(args: impl Iterator<Item = String>) -> ExitCode {
    let catalog = match parse_args(args) {
        Ok(a) => a.request.catalog,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let outcomes = match tf_scan::verify_policies(&catalog) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    use tf_scan::TestResult;
    let (mut passed, mut failed, mut skipped, mut errors) = (0, 0, 0, 0);
    for o in &outcomes {
        let (tag, detail) = match &o.result {
            TestResult::Pass => {
                passed += 1;
                ("PASS", String::new())
            }
            TestResult::Fail => {
                failed += 1;
                ("FAIL", String::new())
            }
            TestResult::Skip => {
                skipped += 1;
                ("SKIP", String::new())
            }
            TestResult::Error(e) => {
                errors += 1;
                ("ERROR", format!("\n{e}"))
            }
        };
        println!("{tag} - {} - {}{detail}", o.file.display(), o.rule);
    }
    println!(
        "\n{} tests, {passed} passed, {failed} failures, {skipped} skipped, {errors} errors",
        outcomes.len()
    );
    if failed + errors > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// A rule-loading message, with each `file:line:col: ` line drawn as a
/// snippet of the rule file.
fn load_message(message: &str, severity: miette::Severity, color: bool) -> String {
    let rendered = tf_linter::render::render_load_message(message, severity, color);
    if rendered.ends_with('\n') {
        rendered
    } else {
        format!("{rendered}\n")
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
            eprint!(
                "error: {}",
                load_message(&e.to_string(), miette::Severity::Error, color)
            );
            return ExitCode::from(2);
        }
    };
    let r = &output.result;
    // Skipped rule files are shown even with --no-diagnostics: they change
    // what an empty result means.
    for d in r.diagnostics.iter().filter(|d| d.code == "rule-skipped") {
        eprint!(
            "warning: {}",
            load_message(&d.message, miette::Severity::Warning, color)
        );
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
    if !r.suppressed.is_empty() {
        let _ = writeln!(out, "  suppressed by checkov:skip: {}", r.suppressed.len());
    }
}

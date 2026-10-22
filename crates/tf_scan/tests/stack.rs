//! Guarded recursion must fit the production worker stack. Every construct that
//! nests runs at its ceiling, one past it and far past it, through the real scan
//! with every shipped profile. Debug frames are larger than release frames, so a
//! passing debug run leaves release more margin. Measured worst cases are in
//! docs/LIMITS.md; a stack abort runs in a timed child with core dumps disabled.
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tf_scan::{ALL_PROFILES, Catalog, ScanRequest, scan};

const DEPTHS: [usize; 3] = [63, 64, 1000];

fn nested(open: &str, inner: &str, close: &str, n: usize) -> String {
    format!("{}{inner}{}", open.repeat(n), close.repeat(n))
}

fn chain(n: usize, first: &str, next: impl Fn(usize) -> String) -> String {
    let mut text = format!("locals {{\nx0 = {first}\n");
    for i in 1..n {
        text.push_str(&format!("x{i} = {}\n", next(i - 1)));
    }
    text + "}\n"
}

type Root = (String, Vec<(String, String)>);

fn bucket(value: &str) -> String {
    format!("resource \"aws_s3_bucket\" \"b\" {{ bucket = {value} }}\n")
}

fn main_tf(name: &str, text: String) -> Root {
    (name.into(), vec![("main.tf".into(), text)])
}

/// Constructs that nest within one attribute expression.
fn expression_roots(n: usize) -> Vec<Root> {
    [
        ("unary", format!("{}true", "!".repeat(n))),
        ("parens", nested("(", "1", ")", n)),
        ("lists", nested("[", "1", "]", n)),
        ("objects", nested("{a = ", "1", "}", n)),
        ("calls", nested("upper(", "\"x\"", ")", n)),
        ("templates", nested("\"${", "1", "}\"", n)),
        ("binary", vec!["1"; n].join(" + ")),
        (
            "json",
            format!("jsonencode(jsondecode(\"{}\"))", nested("[", "1", "]", n)),
        ),
    ]
    .into_iter()
    .map(|(name, value)| main_tf(name, bucket(&value)))
    .collect()
}

/// Constructs that nest through blocks, declarations or input files.
fn declaration_roots(n: usize) -> Vec<Root> {
    let last = n - 1;
    let blocks = nested("x {\n", "", "}\n", n);
    let conditional = format!("{}0", "var.v ? 1 : ".repeat(n));
    let locals = chain(n, "aws_s3_bucket.n.id", |i| format!("local.x{i}"));
    let wrapped = chain(n, "\"a\"", |i| format!("[local.x{i}]"));
    let tfvars = "variable \"v\" {}\nresource \"aws_s3_bucket\" \"b\" { tags = var.v }\n";
    vec![
        main_tf(
            "blocks",
            format!("resource \"aws_s3_bucket\" \"b\" {{\n{blocks}}}\n"),
        ),
        main_tf(
            "conditionals",
            format!("variable \"v\" {{}}\n{}", bucket(&conditional)),
        ),
        main_tf(
            "locals",
            format!(
                "resource \"aws_s3_bucket\" \"n\" {{}}\n{locals}{}",
                bucket(&format!("local.x{last}"))
            ),
        ),
        main_tf(
            "wrapped",
            format!(
                "{wrapped}resource \"aws_security_group\" \"b\" {{ tags = {{ a = local.x{last} }} }}\n"
            ),
        ),
        (
            "tfvars".into(),
            vec![
                ("main.tf".into(), tfvars.into()),
                (
                    "terraform.tfvars.json".into(),
                    format!("{{\"v\": {}}}", nested("[", "1", "]", n)),
                ),
            ],
        ),
    ]
}

/// A chain of `depth` child modules passing one value down.
fn module_chain(depth: usize) -> Vec<(String, String)> {
    (0..=depth)
        .map(|i| {
            let dir = vec!["m"; i].join("/");
            let input = if i == 0 {
                "locals { v = \"x\" }\n"
            } else {
                "variable \"v\" {}\n"
            };
            let value = if i == 0 { "local.v" } else { "var.v" };
            let body = if i < depth {
                format!("module \"m\" {{\n  source = \"./m\"\n  v = {value}\n}}\n")
            } else {
                format!("resource \"aws_s3_bucket\" \"b\" {{ bucket = {value} }}\n")
            };
            (
                format!("{dir}/main.tf").trim_start_matches('/').to_string(),
                format!("{input}{body}"),
            )
        })
        .collect()
}

fn request() -> ScanRequest {
    let base = PathBuf::from("/nonexistent/stack");
    let mut roots = Vec::new();
    let mut overlay = Vec::new();
    let mut add = |name: String, files: Vec<(String, String)>| {
        roots.push(base.join(&name));
        for (path, text) in files {
            overlay.push((base.join(&name).join(path), text.into()));
        }
    };
    for n in DEPTHS {
        for (construct, files) in expression_roots(n).into_iter().chain(declaration_roots(n)) {
            add(format!("{construct}{n}"), files);
        }
    }
    for depth in [tf_limits::MODULE_DEPTH_MAX, tf_limits::MODULE_DEPTH_MAX + 1] {
        add(format!("modules{depth}"), module_chain(depth));
    }
    let mut request = ScanRequest::dirs(roots, false);
    request.catalog = Catalog {
        profiles: Some(ALL_PROFILES.to_vec()),
        ..Catalog::standard()
    };
    request.overlay = overlay;
    request.threads = Some(2);
    request
}

#[test]
fn hostile_nesting_fits_the_production_worker_stack() {
    if std::env::var_os("OXTF_STACK_CHILD").is_some() {
        let out = scan(request()).unwrap();
        let codes: Vec<_> = out.result.diagnostics.iter().map(|d| d.code).collect();
        // Past every ceiling the scan reports limits instead of aborting.
        for code in [
            "coverage-parse-limit",
            "coverage-evaluation",
            "module-depth",
        ] {
            assert!(codes.contains(&code), "{code} missing from {codes:?}");
        }
        assert!(!out.result.findings.is_empty());
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new("sh")
        .args(["-c", "ulimit -c 0; exec \"$@\"", "stack-test"])
        .arg(exe)
        .args([
            "--exact",
            "hostile_nesting_fits_the_production_worker_stack",
        ])
        .env("OXTF_STACK_CHILD", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("stack probe timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

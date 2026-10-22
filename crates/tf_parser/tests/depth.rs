//! Stack-abort regressions run in a timed child with core dumps disabled.
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tf_allocator::Allocator;
use tf_parser::{AST_DEPTH_MAX, Diagnostic, DiagnosticKind, PARSE_DEPTH_MAX, ParseLimit};

fn assert_limit(errors: &[Diagnostic]) {
    assert!(
        errors
            .iter()
            .any(|e| matches!(e.kind, DiagnosticKind::Limit(_))),
        "{errors:?}"
    );
    assert!(
        errors.iter().all(|e| e.kind != DiagnosticKind::Syntax),
        "{errors:?}"
    );
}

#[test]
fn deep_inputs_return_limits_without_aborting() {
    if std::env::var_os("OXTF_PARSER_DEPTH_CHILD").is_some() {
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(probe_inputs)
            .unwrap()
            .join()
            .unwrap();
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new("sh")
        .args(["-c", "ulimit -c 0; exec \"$@\"", "depth-test"])
        .arg(exe)
        .args([
            "--exact",
            "deep_inputs_return_limits_without_aborting",
            "--nocapture",
        ])
        .env("OXTF_PARSER_DEPTH_CHILD", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("parser depth probe timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn probe_inputs() {
    for source in [
        format!("{}true", "!".repeat(100_000)),
        std::iter::repeat_n("1", 30_000)
            .collect::<Vec<_>>()
            .join("+"),
        format!("{}0{}", "(".repeat(10_000), ")".repeat(10_000)),
        format!("{}0{}", "[".repeat(10_000), "]".repeat(10_000)),
        format!("{}0{}", "{x=".repeat(10_000), "}".repeat(10_000)),
        format!("{}0", "true ? 0 : ".repeat(10_000)),
        format!("{}0{}", "length(".repeat(1000), ")".repeat(1000)),
        format!(
            "{}0{}",
            "true || false && 1 == 2 < 3 + 4 * (".repeat(1000),
            ")".repeat(1000)
        ),
    ] {
        let allocator = Allocator::new();
        let (value, errors) = tf_parser::parse_expression(&allocator, &source);
        assert_limit(&errors);
        assert!(value.is_none());
        let file = format!("v = {source}\n");
        let result = tf_parser::parse(&allocator, &file);
        assert_limit(&result.errors);
        assert!(result.file.body.items.is_empty());
    }
    let blocks = format!("{}{}", "b {\n".repeat(1000), "}\n".repeat(1000));
    let template = format!(
        "{}text{}",
        "%{ if true }".repeat(1000),
        "%{ endif }".repeat(1000)
    );
    let heredoc = format!("v = <<-EOT\n{template}\nEOT\n");
    for file in [&blocks, &heredoc] {
        let allocator = Allocator::new();
        let result = tf_parser::parse(&allocator, file);
        assert_limit(&result.errors);
        assert!(result.file.body.items.is_empty());
    }
    let allocator = Allocator::new();
    assert_limit(&tf_parser::parse_template(&allocator, &template).1);
    let json = format!("{{\"v\":{}0{}}}", "[".repeat(10_000), "]".repeat(10_000));
    assert_limit(&tf_parser::parse_json_vars(&allocator, &json).errors);
    assert_limit(&tf_parser::parse_json_value(&allocator, &json).1);
}

#[test]
fn parser_and_ast_depth_boundaries_are_independent() {
    for unary in [
        PARSE_DEPTH_MAX - 3,
        PARSE_DEPTH_MAX - 2,
        PARSE_DEPTH_MAX - 1,
    ] {
        let source = format!("{}true", "!".repeat(unary));
        let allocator = Allocator::new();
        let (_, errors) = tf_parser::parse_expression(&allocator, &source);
        if unary <= PARSE_DEPTH_MAX - 2 {
            assert!(errors.is_empty(), "{errors:?}");
        } else {
            assert!(
                errors
                    .iter()
                    .any(|e| e.kind == DiagnosticKind::Limit(ParseLimit::ParserDepth))
            );
        }
    }
    for terms in [AST_DEPTH_MAX - 1, AST_DEPTH_MAX, AST_DEPTH_MAX + 1] {
        let source = std::iter::repeat_n("1", terms)
            .collect::<Vec<_>>()
            .join("+");
        let allocator = Allocator::new();
        let (_, errors) = tf_parser::parse_expression(&allocator, &source);
        if terms <= AST_DEPTH_MAX {
            assert!(errors.is_empty(), "{errors:?}");
        } else {
            assert_eq!(errors[0].kind, DiagnosticKind::Limit(ParseLimit::AstDepth));
        }
    }
}

#[test]
fn quoted_json_brackets_and_escapes_do_not_consume_nesting() {
    let source = serde_json::json!({"v": "[\\\"{".repeat(1000)}).to_string();
    let allocator = Allocator::new();
    assert!(
        tf_parser::parse_json_vars(&allocator, &source)
            .errors
            .is_empty()
    );
    let malformed = tf_parser::parse(&allocator, "v = ]\n");
    assert_eq!(malformed.errors[0].kind, DiagnosticKind::Syntax);
}

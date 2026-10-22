use std::sync::Arc;
use tf_allocator::Allocator;
use tf_limits::{Limits, Resource, input::InputBudget};
use tf_parser::{DiagnosticKind, ParseLimit};

fn arena(nodes: u64) -> Allocator {
    Allocator::with_budget(Arc::new(InputBudget::new(
        Limits::default().with_ast_nodes(nodes).unwrap(),
    )))
}

fn storage(errors: &[tf_parser::Diagnostic], resource: Resource) {
    assert!(
        errors.iter().any(|error| matches!(error.kind,
        DiagnosticKind::Limit(ParseLimit::Storage(e)) if e.resource == resource)),
        "{errors:?}"
    );
}

#[test]
fn native_construction_has_an_inclusive_node_boundary() {
    for source in [
        "a = 1\n",
        "block \"label\" { a = [1, 2, 3] }",
        "a = { for k, v in { a = 1 } : k => v }",
        "a = provider::test::f(1, 2)[0].x",
        "a = \"hello\\n${true ? 1 : 2}\"",
        "a = <<-EOT\n  %{ if true }hello%{ else }world%{ endif }\nEOT\n",
    ] {
        let baseline = Allocator::new();
        assert!(
            tf_parser::parse(&baseline, source).errors.is_empty(),
            "{source}"
        );
        let count = baseline.budget().stats().ast_nodes;
        for allowance in [count - 1, count, count + 1] {
            let alloc = arena(allowance);
            let parsed = tf_parser::parse(&alloc, source);
            if allowance < count {
                storage(&parsed.errors, Resource::AstNodes);
                assert!(parsed.file.body.items.is_empty());
            } else {
                assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
                assert_eq!(parsed.file.body.items.len(), 1);
            }
            assert!(alloc.budget().stats().ast_nodes <= allowance);
        }
    }
}

#[test]
fn json_vars_and_values_do_not_expose_a_successful_prefix() {
    let source = r#"{"a":[1,2,3],"b":{"escaped":"hello\nworld"}}"#;
    for variable_file in [false, true] {
        let probe = Allocator::new();
        if variable_file {
            tf_parser::parse_json_vars(&probe, source);
        } else {
            tf_parser::parse_json_value(&probe, source);
        }
        let count = probe.budget().stats().ast_nodes;
        for allowance in [count - 1, count, count + 1] {
            let alloc = arena(allowance);
            let (present, errors) = if variable_file {
                let parsed = tf_parser::parse_json_vars(&alloc, source);
                (!parsed.file.body.items.is_empty(), parsed.errors)
            } else {
                let (value, errors) = tf_parser::parse_json_value(&alloc, source);
                (value.is_some(), errors)
            };
            assert_eq!(present, allowance >= count);
            if allowance < count {
                storage(&errors, Resource::AstNodes);
            } else {
                assert!(errors.is_empty());
            }
        }
    }
}

#[test]
fn expression_and_template_refusal_needs_no_arena_placeholder() {
    for template in [false, true] {
        let alloc = Allocator::with_budget(Arc::new(InputBudget::new(
            Limits::default().with_arena_bytes(1).unwrap(),
        )));
        let (value, errors) = if template {
            tf_parser::parse_template(&alloc, "hello ${1}")
        } else {
            tf_parser::parse_expression(&alloc, "1")
        };
        assert!(value.is_none());
        storage(&errors, Resource::ArenaBytes);
        assert_eq!(alloc.allocated_bytes(), 0);
    }
}

#[test]
fn syntax_errors_preceding_exhaustion_remain_visible() {
    let alloc = arena(1);
    let parsed = tf_parser::parse(&alloc, "@\na = [1, 2, 3]");
    assert!(
        parsed
            .errors
            .iter()
            .any(|e| e.kind == DiagnosticKind::Syntax)
    );
    storage(&parsed.errors, Resource::AstNodes);
    assert!(parsed.file.body.items.is_empty());
}

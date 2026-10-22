//! Parser-independent ASTs and resolver re-entry must share the stack guard.
use std::cell::Cell;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tf_allocator::{Allocator, Box as ArenaBox, Vec as ArenaVec};
use tf_ast::{BinaryExpr, BinaryOperator, Expression, NumberLiteral, Span, TraversalOperator};
use tf_eval::eval::{EVALUATION_DEPTH_MAX, Resolver};
use tf_eval::{Evaluator, NoResolver, Origin, Scope, Value};
use tf_span::FileId;

fn number(allocator: &Allocator) -> Expression<'_> {
    Expression::Number(
        ArenaBox::new_in(
            NumberLiteral {
                span: Span::EMPTY,
                raw: "1".into(),
                value: 1.0,
            },
            allocator,
        )
        .unwrap(),
    )
}

fn assert_limit(value: &Value) {
    assert!(
        matches!(value.origin(), Some(Origin::Limit(_))),
        "{value:?}"
    );
    assert!(!value.is_error());
}

#[test]
fn deep_evaluation_returns_limits_without_aborting() {
    if std::env::var_os("OXTF_EVAL_DEPTH_CHILD").is_some() {
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(probe_inputs)
            .unwrap()
            .join()
            .unwrap();
        return;
    }
    let mut child = Command::new("sh")
        .args(["-c", "ulimit -c 0; exec \"$@\"", "depth-test"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "deep_evaluation_returns_limits_without_aborting",
            "--nocapture",
        ])
        .env("OXTF_EVAL_DEPTH_CHILD", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("evaluation depth probe timed out");
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
    let allocator = Allocator::new();
    probe_templates(&allocator);
    let mut expression = number(&allocator);
    for _ in 0..30_000 {
        expression = Expression::Binary(
            ArenaBox::new_in(
                BinaryExpr {
                    span: Span::EMPTY,
                    operator: BinaryOperator::Add,
                    left: expression,
                    right: number(&allocator),
                },
                &allocator,
            )
            .unwrap(),
        );
    }
    let evaluator = Evaluator::new(&NoResolver, FileId(0));
    assert_limit(&evaluator.eval(&expression, Scope::EMPTY));
    let mut nested = number(&allocator);
    for _ in 0..10_000 {
        let mut elements = ArenaVec::new_in(&allocator);
        elements.push(nested).unwrap();
        nested = Expression::Tuple(
            ArenaBox::new_in(
                tf_ast::Tuple {
                    span: Span::EMPTY,
                    elements,
                },
                &allocator,
            )
            .unwrap(),
        );
    }
    assert_limit(&evaluator.eval_static(&nested));
    // Returning just the list length must not erase the exhausted child evaluation.
    let mut args = ArenaVec::new_in(&allocator);
    args.push(nested).unwrap();
    let call = Expression::FunctionCall(
        ArenaBox::new_in(
            tf_ast::FunctionCall {
                span: Span::EMPTY,
                namespace: ArenaVec::new_in(&allocator),
                name: tf_ast::Identifier {
                    span: Span::EMPTY,
                    name: "length".into(),
                },
                arguments: args,
                expand_final: false,
            },
            &allocator,
        )
        .unwrap(),
    );
    assert_limit(&evaluator.eval(&call, Scope::EMPTY));
    assert_eq!(
        evaluator
            .eval(&number(&allocator), Scope::EMPTY)
            .as_number(),
        Some(1.0)
    );
}

struct Reenter<'a> {
    expression: &'a Expression<'a>,
    calls: Cell<usize>,
}

impl<'a> Resolver<'a> for Reenter<'a> {
    fn resolve(
        &self,
        _: &Evaluator<'_, 'a>,
        scope: Scope<'_>,
        _: &'a str,
        _: Span,
        _: &'a [TraversalOperator<'a>],
    ) -> (Value, usize) {
        self.calls.set(self.calls.get() + 1);
        (
            Evaluator::new(self, FileId(0)).eval(self.expression, scope),
            0,
        )
    }
}

#[test]
fn fresh_evaluators_cannot_reset_active_depth() {
    let allocator = Allocator::new();
    let (expression, errors) = tf_parser::parse_expression(&allocator, "x");
    let expression = expression.unwrap();
    assert!(errors.is_empty());
    let resolver = Reenter {
        expression: &expression,
        calls: Cell::new(0),
    };
    assert_limit(&Evaluator::new(&resolver, FileId(0)).eval(&expression, Scope::EMPTY));
    assert_eq!(resolver.calls.get(), EVALUATION_DEPTH_MAX);
    assert_eq!(
        Evaluator::new(&NoResolver, FileId(0))
            .eval(&number(&allocator), Scope::EMPTY)
            .as_number(),
        Some(1.0)
    );
}

#[test]
fn evaluation_depth_accepts_the_boundary() {
    for depth in [
        EVALUATION_DEPTH_MAX - 1,
        EVALUATION_DEPTH_MAX,
        EVALUATION_DEPTH_MAX + 1,
    ] {
        let allocator = Allocator::new();
        let mut expression = number(&allocator);
        for _ in 1..depth {
            expression = Expression::Binary(
                ArenaBox::new_in(
                    BinaryExpr {
                        span: Span::EMPTY,
                        operator: BinaryOperator::Add,
                        left: expression,
                        right: number(&allocator),
                    },
                    &allocator,
                )
                .unwrap(),
            );
        }
        let result = Evaluator::new(&NoResolver, FileId(0)).eval(&expression, Scope::EMPTY);
        if depth <= EVALUATION_DEPTH_MAX {
            assert_eq!(result.as_number(), Some(depth as f64));
        } else {
            assert_limit(&result);
        }
    }
}

fn probe_templates(allocator: &Allocator) {
    use tf_ast::{BooleanLiteral, Strip, Template, TemplateElement, TemplateIf};
    let mut template = Template {
        span: Span::EMPTY,
        elements: ArenaVec::new_in(allocator),
    };
    for _ in 0..10_000 {
        let condition = Expression::Bool(
            ArenaBox::new_in(
                BooleanLiteral {
                    span: Span::EMPTY,
                    value: true,
                },
                allocator,
            )
            .unwrap(),
        );
        let mut elements = ArenaVec::new_in(allocator);
        elements
            .push(TemplateElement::If(
                ArenaBox::new_in(
                    TemplateIf {
                        span: Span::EMPTY,
                        condition,
                        if_strip: Strip::default(),
                        then_template: template,
                        else_strip: None,
                        else_template: None,
                        endif_strip: Strip::default(),
                    },
                    allocator,
                )
                .unwrap(),
            ))
            .unwrap();
        template = Template {
            span: Span::EMPTY,
            elements,
        };
    }
    assert_limit(
        &Evaluator::new(&NoResolver, FileId(0))
            .eval_template(allocator.alloc(template).unwrap(), Scope::EMPTY),
    );
}

struct PanickingResolver;

impl<'a> Resolver<'a> for PanickingResolver {
    fn resolve(
        &self,
        _: &Evaluator<'_, 'a>,
        _: Scope<'_>,
        _: &'a str,
        _: Span,
        _: &'a [TraversalOperator<'a>],
    ) -> (Value, usize) {
        panic!("injected resolver failure")
    }
}

#[test]
fn unwinding_releases_the_active_depth_guard() {
    let allocator = Allocator::new();
    let (expression, errors) = tf_parser::parse_expression(&allocator, "x");
    let expression = expression.unwrap();
    assert!(errors.is_empty());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Evaluator::new(&PanickingResolver, FileId(0)).eval(&expression, Scope::EMPTY)
    }));
    assert!(panic.is_err());
    evaluation_depth_accepts_the_boundary();
}

#[test]
fn existing_errors_keep_precedence_and_cannot_make_depth_exhaustion_catchable() {
    for name in ["direct", "try", "can"] {
        let allocator = Allocator::new();
        let mut deep = number(&allocator);
        for _ in 0..EVALUATION_DEPTH_MAX {
            deep = Expression::Binary(
                ArenaBox::new_in(
                    BinaryExpr {
                        span: Span::EMPTY,
                        operator: BinaryOperator::Add,
                        left: deep,
                        right: number(&allocator),
                    },
                    &allocator,
                )
                .unwrap(),
            );
        }
        let (missing, errors) = tf_parser::parse_expression(&allocator, "missing");
        let missing = missing.unwrap();
        assert!(errors.is_empty());
        let mut expression = Expression::Binary(
            ArenaBox::new_in(
                BinaryExpr {
                    span: Span::EMPTY,
                    operator: BinaryOperator::Add,
                    left: missing,
                    right: deep,
                },
                &allocator,
            )
            .unwrap(),
        );
        if name != "direct" {
            let mut arguments = ArenaVec::new_in(&allocator);
            arguments.push(expression).unwrap();
            if name == "try" {
                arguments.push(number(&allocator)).unwrap();
            }
            expression = Expression::FunctionCall(
                ArenaBox::new_in(
                    tf_ast::FunctionCall {
                        span: Span::EMPTY,
                        namespace: ArenaVec::new_in(&allocator),
                        name: tf_ast::Identifier {
                            span: Span::EMPTY,
                            name: name.into(),
                        },
                        arguments,
                        expand_final: false,
                    },
                    &allocator,
                )
                .unwrap(),
            );
        }
        let value = Evaluator::new(&NoResolver, FileId(0)).eval(&expression, Scope::EMPTY);
        if name == "direct" {
            assert!(value.is_error(), "{value:?}");
        } else {
            assert_limit(&value);
        }
    }
}

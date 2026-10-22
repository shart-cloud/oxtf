use std::cell::Cell;

use tf_allocator::Allocator;
use tf_ast::{Expression, TraversalOperator};
use tf_eval::{EvaluationBudget, Evaluator, NoResolver, Origin, Resolver, Scope, Value};
use tf_limits::Limits;
use tf_span::{FileId, Span};

fn evaluate(source: &str, budget: &EvaluationBudget) -> Value {
    let allocator = Allocator::new();
    let (expression, errors) = tf_parser::parse_expression(&allocator, source);
    let expression = expression.unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    Evaluator::with_budget(&NoResolver, FileId(0), budget).eval(&expression, Scope::EMPTY)
}

#[test]
fn independently_created_evaluators_share_the_exact_allowance() {
    for allowance in [5, 6, 7] {
        let budget = EvaluationBudget::new(Limits::new(allowance).unwrap());
        assert_eq!(evaluate("1 + 2", &budget).as_number(), Some(3.0));
        let value = evaluate("3 + 4", &budget);
        if allowance >= 6 {
            assert_eq!(value.as_number(), Some(7.0));
            assert_eq!(budget.used(), 6);
            assert!(budget.first_limit().is_none());
        } else {
            assert!(matches!(value.origin(), Some(Origin::Limit(_))));
            assert_eq!(budget.used(), allowance);
            assert!(matches!(
                evaluate("1", &budget).origin(),
                Some(Origin::Limit(_))
            ));
        }
    }
}

#[test]
fn discarded_limit_values_still_qualify_the_root() {
    let budget = EvaluationBudget::new(Limits::default());
    let value = evaluate("length([indent(1e100, \"a\\nb\")])", &budget);
    assert_eq!(value.as_number(), Some(1.0));
    assert!(budget.first_limit().is_some());
    assert_eq!(evaluate("1", &budget).as_number(), Some(1.0));
    assert!(budget.first_limit().is_some());
}

#[test]
fn a_later_work_limit_reports_the_configured_allowance() {
    let budget = EvaluationBudget::new(Limits::new(6).unwrap());
    evaluate("length([indent(1e100, \"a\\nb\")])", &budget);
    assert!(matches!(
        budget.first_limit().unwrap().reason,
        tf_eval::budget::LimitReason::Evaluation
    ));
    evaluate("1 + 2", &budget);
    assert!(matches!(
        budget.first_limit().unwrap().reason,
        tf_eval::budget::LimitReason::Work(tf_limits::Exhaustion { allowance: 6, .. })
    ));
}

#[test]
fn exhaustion_retains_sensitive_evidence() {
    let budget = EvaluationBudget::new(Limits::new(3).unwrap());
    let value = evaluate("sensitive(1) + 2", &budget);
    assert!(matches!(value.origin(), Some(Origin::Limit(_))));
    assert!(value.is_sensitive());
}

#[test]
fn try_can_and_conditions_cannot_hide_exhausted_work() {
    for expression in [
        "try(length([1, 2, 3, 4]), 0)",
        "can([1, 2, 3]) ? 20 : 20",
        "length([1, 2, 3]) == 0 || true",
    ] {
        let budget = EvaluationBudget::new(Limits::new(3).unwrap());
        let value = evaluate(expression, &budget);
        assert!(
            matches!(value.origin(), Some(Origin::Limit(_))),
            "{expression}: {value:?}"
        );
        assert!(budget.is_exhausted());
        assert!(budget.first_limit().is_some());
    }
}

struct Reenter<'a> {
    expression: &'a Expression<'a>,
    calls: Cell<u64>,
}

impl<'a> Resolver<'a> for Reenter<'a> {
    fn resolve(
        &self,
        ev: &Evaluator<'_, 'a>,
        scope: Scope<'_>,
        _: &'a str,
        _: Span,
        _: &'a [TraversalOperator<'a>],
    ) -> (Value, usize) {
        self.calls.set(self.calls.get() + 1);
        let nested = Evaluator::with_budget(self, ev.file, ev.budget());
        (nested.eval(self.expression, scope), 0)
    }
}

#[test]
fn resolver_reentry_cannot_reset_shared_work() {
    let allocator = Allocator::new();
    let (expression, errors) = tf_parser::parse_expression(&allocator, "x");
    let expression = expression.unwrap();
    assert!(errors.is_empty());
    let resolver = Reenter {
        expression: &expression,
        calls: Cell::new(0),
    };
    let budget = EvaluationBudget::new(Limits::new(4).unwrap());
    let result =
        Evaluator::with_budget(&resolver, FileId(0), &budget).eval(&expression, Scope::EMPTY);
    assert!(matches!(result.origin(), Some(Origin::Limit(_))));
    assert_eq!(resolver.calls.get(), 4);
    assert_eq!(budget.used(), 4);
}

#[test]
fn template_work_and_static_defaults_cannot_reset_the_budget() {
    let allocator = Allocator::new();
    let (expression, errors) = tf_parser::parse_template(&allocator, "literal ${1} text ${2}");
    let expression = expression.unwrap();
    assert!(errors.is_empty());
    let budget = EvaluationBudget::new(Limits::new(4).unwrap());
    let evaluator = Evaluator::with_budget(&NoResolver, FileId(0), &budget);
    let result = evaluator.eval(&expression, Scope::EMPTY);
    assert!(matches!(result.origin(), Some(Origin::Limit(_))));
    let (constant, errors) = tf_parser::parse_expression(&allocator, "1");
    let constant = constant.unwrap();
    assert!(errors.is_empty());
    assert!(matches!(
        evaluator.eval_static(&constant).origin(),
        Some(Origin::Limit(_))
    ));
}

#[test]
fn established_error_precedes_work_exhaustion() {
    for expression in [
        "missing + (1 + 2)",
        "length([missing, 1 + 2])",
        "[missing, 1 + 2]",
    ] {
        let budget = EvaluationBudget::new(Limits::new(3).unwrap());
        let value = evaluate(expression, &budget);
        assert!(
            tf_eval::eval::contains_error(&value),
            "{expression}: {value:?}"
        );
        assert!(budget.first_limit().is_some());
    }
}

#[test]
fn cached_exhaustion_cannot_reset_the_root_allowance() {
    use tf_limits::Resource;
    use tf_span::FileSpan;
    let limits = Limits::default().with_loader_steps(3).unwrap();
    let module = EvaluationBudget::for_resource(limits, Resource::LoaderSteps);
    let at = FileSpan::new(FileId(0), Span::EMPTY);
    module.charge(at, 2).unwrap();
    assert!(module.charge(at, 2).is_err());
    let root = EvaluationBudget::for_resource(limits, Resource::LoaderSteps);
    root.import(at, module.used(), module.first_limit());
    assert_eq!(root.used(), 2);
    assert!(root.is_exhausted());
    assert!(root.charge(at, 0).is_err());
    assert!(matches!(
        evaluate("1", &root).origin(),
        Some(Origin::Limit(_))
    ));
}

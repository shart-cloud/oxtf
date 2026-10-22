use std::path::Path;
use std::sync::{Arc, Mutex};

use tf_linter::{ConfigFile, DynRule, Judgement, Linter, RuleBudget, RuleInfo, Subject};
use tf_semantic::{Analysis, AnalyzeOptions, FileTable, Module, Resource, graph::ResourceGraph};

#[test]
fn rego_time_is_cumulative_sticky_and_independent_of_counted_work() {
    use std::time::Duration;
    let limits = tf_limits::Limits::default().with_rego_time_ms(3).unwrap();
    let budget = RuleBudget::new(limits);
    budget
        .record_rego_elapsed(Duration::from_millis(2))
        .unwrap();
    assert_eq!(budget.rego_remaining().unwrap(), Duration::from_millis(1));
    budget
        .record_rego_elapsed(Duration::from_millis(1))
        .unwrap();
    assert!(budget.rego_remaining().is_err());
    let limit = budget.exhaustion().unwrap();
    assert_eq!(limit.resource, tf_limits::Resource::RegoTimeMs);
    assert_eq!(limit.allowance, 3);
    assert!(budget.charge(0).is_err());
    assert!(budget.finish(Ok(())).is_err());
    assert_eq!(budget.used(), 0);
    assert!(RuleBudget::new(limits).rego_remaining().is_ok());
    assert!(tf_limits::Limits::default().with_rego_time_ms(0).is_err());
}

#[test]
fn backend_scratch_is_owned_by_each_root_and_released_on_unwind() {
    #[derive(Default)]
    struct Scratch(Arc<()>);
    let outer = RuleBudget::default();
    let weak = outer.with_cache(|cache: &mut Scratch| Arc::downgrade(&cache.0));
    let inner = RuleBudget::default();
    inner.with_cache(|cache: &mut Scratch| assert!(!weak.ptr_eq(&Arc::downgrade(&cache.0))));
    drop(inner);
    assert!(weak.upgrade().is_some());
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _root = outer;
        panic!("fixture callback failure");
    }));
    assert!(outcome.is_err());
    assert!(weak.upgrade().is_none());
}

struct Hooks {
    calls: Arc<Mutex<Vec<&'static str>>>,
    discard_failure: bool,
}

impl DynRule for Hooks {
    fn info(&self) -> RuleInfo {
        let mut info = tf_linter::rules::all()[0].info();
        info.name = "test-hooks".into();
        info.resource_types = vec!["*".into()];
        info.runs_on_module = !self.discard_failure;
        info
    }
    fn needs_graph(&self) -> bool {
        !self.discard_failure
    }
    fn needs_files(&self) -> bool {
        !self.discard_failure
    }
    fn judge_graph<'a>(
        &self,
        _: &ResourceGraph<'a>,
    ) -> Result<Vec<(&'a Resource, Judgement)>, String> {
        self.calls.lock().unwrap().push("graph");
        Ok(Vec::new())
    }
    fn judge_files<'a>(
        &self,
        _: &'a Analysis,
        _: &[ConfigFile<'a>],
    ) -> Result<Vec<(Subject<'a>, Judgement)>, String> {
        self.calls.lock().unwrap().push("files");
        Ok(Vec::new())
    }
    fn judge_module<'m>(&self, _: &'m Module) -> Result<Vec<(&'m Resource, Judgement)>, String> {
        self.calls.lock().unwrap().push("module");
        Ok(Vec::new())
    }
    fn judge_resource(&self, _: &Resource) -> Result<Vec<Judgement>, String> {
        self.calls.lock().unwrap().push("resource");
        Ok(Vec::new())
    }
    fn judge_resource_with_budget(
        &self,
        r: &Resource,
        budget: &RuleBudget,
    ) -> Result<Vec<Judgement>, String> {
        if self.discard_failure {
            let _ = budget.charge(u64::MAX);
        }
        self.judge_resource(r)
    }
}

fn analysis() -> Analysis {
    let files = FileTable::with_overlay([(
        "/nonexistent/hooks/main.tf".into(),
        Arc::from("resource \"test_resource\" \"r\" { value = sensitive(\"private\") }"),
    )]);
    tf_semantic::analyze_module(
        Path::new("/nonexistent/hooks"),
        &AnalyzeOptions::default(),
        &files,
    )
}

#[test]
fn all_hook_passes_share_one_allowance_and_stop_at_the_boundary() {
    // Graph construction charges its one resource before the graph hook runs.
    const GRAPH_STEPS: u64 = 1;
    const HOOKS: [&str; 4] = ["graph", "files", "module", "resource"];
    let total = GRAPH_STEPS + HOOKS.len() as u64;
    for allowance in 1..=total + 1 {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let linter = Linter::new(vec![Box::new(Hooks {
            calls: calls.clone(),
            discard_failure: false,
        })]);
        let limits = tf_limits::Limits::default()
            .with_rule_steps(allowance)
            .unwrap();
        let out = linter.run_with_limits(&analysis(), None, limits);
        assert_eq!(out.rule_steps, allowance.min(total));
        let ran = (allowance.min(total) - GRAPH_STEPS) as usize;
        assert_eq!(*calls.lock().unwrap(), HOOKS[..ran]);
        assert_eq!(out.rule_errors.len(), usize::from(allowance < total));
        if allowance < total {
            assert!(out.rule_errors[0].message.contains("rule_steps"));
            assert!(
                out.rule_errors[0]
                    .message
                    .contains(&format!("allowance {allowance}"))
            );
            assert!(!out.rule_errors[0].message.contains("private"));
        }
    }
}

#[test]
fn discarded_charge_failure_cannot_be_reported_as_success() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let linter = Linter::new(vec![Box::new(Hooks {
        calls: calls.clone(),
        discard_failure: true,
    })]);
    let limits = tf_limits::Limits::default().with_rule_steps(10).unwrap();
    for _ in 0..2 {
        let out = linter.run_with_limits(&analysis(), None, limits);
        assert_eq!(out.rule_steps, 1);
        assert_eq!(out.rule_errors.len(), 1);
        assert!(out.rule_errors[0].message.contains("rule_steps"));
        assert!(out.findings.is_empty());
    }
    assert_eq!(*calls.lock().unwrap(), ["resource", "resource"]);
}

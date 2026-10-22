//! Module-instance tree, reference resolution and schema-aware evaluation of
//! resource bodies into the owned [`crate::model`].

use rustc_hash::FxHashMap as HashMap;
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use crate::model_budget::{self as storage, Build};
use tf_eval::collections::{self, Buffer, failure};

mod body;
mod build;
mod expansion;
mod policy;
#[cfg(test)]
mod tests;
use body::body_failure;

use tf_ast::{Attribute, Body, Expression, TraversalOperator};
use tf_eval::{
    Evaluator, Kind, Known, Map, NoResolver, Origin, Resolver, Scope, Step, StepKind, Truth, Value,
};
use tf_schema::Member;
use tf_span::{FileId, FileSpan, Span};

use crate::address::{Address, InstanceKey};
use crate::installed::{InstalledModules, InstalledPackage};
use crate::model::{self, AnalysisStats, Attr, DiagSeverity, Diagnostic};
use crate::module::{
    Mode, ModuleDef, ModuleSource, ResourceDecl, SymbolRef, auto_tfvars, has_module_files,
};
use crate::source::{FileTable, SourceFile, normalize};
use crate::store::ModuleStore;

/// Options for [`analyze_module`].
#[derive(Clone, Debug)]
pub struct AnalyzeOptions {
    /// Cumulative runtime evaluation work per root, shared with every child module.
    pub limits: tf_limits::Limits,
    /// Extra `-var-file`s, applied after default and auto HCL/JSON
    /// variable files (later wins).
    pub var_files: Vec<PathBuf>,
    /// Terraform data directory, relative to each root unless absolute.
    pub data_dir: Option<PathBuf>,
    /// Maximum depth of local and installed child modules followed.
    pub max_module_depth: usize,
    /// `count` / `for_each` / `dynamic` collections larger than this are evaluated as
    /// one abstract instance instead of being expanded.
    pub max_expand: usize,
    /// Total resource and child-module instances per root. Bounds products of
    /// nested expansions independently of the per-declaration limit.
    pub max_instances: usize,
    /// Also evaluate what only whole-file rules read: every `locals`
    /// entry ([`model::Module::locals`]) and every module-call argument
    /// ([`model::ModuleCallInfo::arguments`]). Off by default: unused
    /// locals cost time.
    pub whole_files: bool,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        AnalyzeOptions {
            limits: tf_limits::Limits::default(),
            var_files: Vec::new(),
            data_dir: None,
            max_module_depth: tf_limits::MODULE_DEPTH_MAX,
            max_expand: tf_limits::EXPANSION_MAX,
            max_instances: tf_limits::INSTANCES_MAX,
            whole_files: false,
        }
    }
}

/// Handed to an observer for every attribute evaluated in a resource /
/// data-source body (used by the Q6 corpus analysis).
pub struct ObservedAttr<'x, 'e> {
    pub mode: Mode,
    pub resource_type: &'x str,
    /// Dotted path from the resource body, e.g. `ingress.cidr_blocks`.
    pub path: &'x str,
    pub name: &'x str,
    /// File of `expr` (its span is `expr.span()`).
    pub file: FileId,
    pub expr: &'x Expression<'e>,
    pub value: &'x Value,
}

pub type Observer<'o> = &'o mut dyn FnMut(&ObservedAttr<'_, '_>);

/// Analyse the root module in `dir` (and every available child module it
/// calls).
pub fn analyze_module(dir: &Path, opts: &AnalyzeOptions, files: &FileTable) -> model::Analysis {
    analyze_module_observed(dir, opts, files, None)
}

pub fn analyze_module_observed(
    dir: &Path,
    opts: &AnalyzeOptions,
    files: &FileTable,
    observer: Option<Observer<'_>>,
) -> model::Analysis {
    let store = ModuleStore::new();
    let an = Analyzer::new(&store, files, opts, observer, dir);
    an.run()
}

/// Analyse `dir` with parsed modules taken from (and added to) `store`, so
/// a scan of many roots parses each module directory once.
pub fn analyze_module_shared(
    dir: &Path,
    opts: &AnalyzeOptions,
    files: &FileTable,
    store: &ModuleStore,
) -> model::Analysis {
    Analyzer::new(store, files, opts, None, dir).run()
}

// ---------------------------------------------------------------------------

const META_ATTRS: &[&str] = &["count", "for_each", "provider", "depends_on"];
const META_BLOCKS: &[&str] = &["lifecycle", "provisioner", "connection"];
const MAX_DEPTH: u32 = 400;

#[derive(Clone)]
enum Slot {
    Busy,
    Done(Value),
}

#[derive(Clone)]
struct InstBind {
    key: Option<InstanceKey>,
    binds: Option<(&'static str, Value)>,
    existence: Truth,
}

type ChildInstances = Rc<Vec<(Option<InstanceKey>, usize)>>;
type Children = Option<ChildInstances>;
type ResAttrKey = (usize, Option<InstanceKey>, String);
type Expansion = (Vec<InstBind>, Option<Value>, Option<Value>, bool);

struct Instance<'a> {
    def: &'a ModuleDef<'a>,
    address: Arc<str>,
    parent: Option<(usize, usize)>,
    binds: Option<(&'static str, Value)>,
    existence: Truth,
    ancestors: Vec<PathBuf>,
    package: Option<InstalledPackage>,
    children: RefCell<HashMap<usize, Children>>,
    limited_children: RefCell<Vec<usize>>,
    vars: RefCell<HashMap<String, Slot>>,
    locals: RefCell<HashMap<String, Slot>>,
    outputs: RefCell<HashMap<String, Slot>>,
    res_attrs: RefCell<HashMap<ResAttrKey, Slot>>,
    res_insts: RefCell<HashMap<usize, Option<Rc<Expansion>>>>,
}

impl Instance<'_> {
    fn prefix(&self) -> String {
        if self.address.is_empty() {
            String::new()
        } else {
            format!("{}.", self.address)
        }
    }
}

struct TfvarsBinding<'a> {
    name: &'a str,
    attr: &'a Attribute<'a>,
    file: Arc<SourceFile>,
}

struct Analyzer<'a, 'o> {
    budget: tf_eval::EvaluationBudget,
    loader_budget: tf_eval::EvaluationBudget,
    store: &'a ModuleStore,
    files: &'a FileTable,
    opts: &'a AnalyzeOptions,
    root_dir: PathBuf,
    installed: InstalledModules<'a>,
    /// Definitions this root has taken from the store, by directory; the
    /// store's lookup is a lock and a hash, this one is a hash.
    defs: RefCell<HashMap<PathBuf, &'a ModuleDef<'a>>>,
    insts: RefCell<Vec<Rc<Instance<'a>>>>,
    tfvars: Vec<TfvarsBinding<'a>>,
    diags: RefCell<Vec<Diagnostic>>,
    depth: Cell<u32>,
    observer: RefCell<Option<Observer<'o>>>,
    attr_count: Cell<usize>,
    expanded: Cell<usize>,
    observed_error: Cell<Option<FileSpan>>,
}

fn header_span(b: &tf_ast::Block<'_>) -> Span {
    let end = b
        .labels
        .last()
        .map(|l| l.span.end)
        .unwrap_or(b.ident.span.end);
    Span::new(b.span.start, end)
}

fn snippet(text: &str, span: Span, max: usize) -> String {
    let s = span
        .source_text(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if s.chars().count() > max {
        let t: String = s.chars().take(max).collect();
        format!("{t}...")
    } else {
        s
    }
}

fn instance_key(value: &Value, counted: bool) -> Option<InstanceKey> {
    if counted {
        let n = value.as_number()?;
        (n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n < u64::MAX as f64)
            .then_some(InstanceKey::Index(n as u64))
    } else {
        value.to_str().map(InstanceKey::Key)
    }
}

fn reference_value(
    value: Value,
    dependencies: &[tf_eval::prov::ResourceDependency],
    budget: &tf_limits::input::InputBudget,
) -> Value {
    match collections::admit_tree_copy(&value, budget) {
        Ok(()) => reference_value_unchecked(value, dependencies),
        Err(stopped) => {
            let prov = value.prov.clone().referencing(dependencies.to_vec());
            let value = value.with_prov(prov);
            failure(stopped, [&value])
        }
    }
}

fn reference_value_unchecked(
    mut value: Value,
    dependencies: &[tf_eval::prov::ResourceDependency],
) -> Value {
    // A resource traversal refers to this instance even when its configured
    // attribute was computed from another resource or contains nested values.
    value.kind = match value.kind {
        Kind::Known(Known::List(items)) => Kind::Known(Known::List(Arc::new(
            items
                .iter()
                .map(|v| reference_value_unchecked(v.clone(), dependencies))
                .collect(),
        ))),
        Kind::Known(Known::Object(items)) => Kind::Known(Known::Object(Arc::new(
            items
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        reference_value_unchecked(v.clone(), dependencies),
                    )
                })
                .collect(),
        ))),
        Kind::Known(Known::Json(inner)) => Kind::Known(Known::Json(Arc::new(
            reference_value_unchecked((*inner).clone(), dependencies),
        ))),
        Kind::OneOf(one) => Kind::OneOf(Arc::new(tf_eval::value::OneOf {
            alternatives: one
                .alternatives
                .iter()
                .map(|v| reference_value_unchecked(v.clone(), dependencies))
                .collect(),
            tainted: one.tainted,
        })),
        other => other,
    };
    value.prov = value.prov.referencing(dependencies.to_vec());
    value
}

impl<'a, 'o> Analyzer<'a, 'o> {
    #[expect(clippy::too_many_lines)]
    fn new(
        store: &'a ModuleStore,
        files: &'a FileTable,
        opts: &'a AnalyzeOptions,
        observer: Option<Observer<'o>>,
        dir: &Path,
    ) -> Self {
        let root_dir = normalize(dir);
        let mut diags = Vec::new();
        let mut tfvars = Vec::new();
        let mut var_files = auto_tfvars(files, &root_dir);
        var_files.extend(opts.var_files.iter().cloned());
        for p in var_files {
            match files.load(&p) {
                Ok(sf) => {
                    let Ok(parsed) = store.variable_file(&sf) else {
                        break;
                    };
                    for (at, m) in &parsed.errors {
                        diags.push(Diagnostic {
                            severity: DiagSeverity::Error,
                            code: "parse-error",
                            message: m.clone(),
                            at: Some(*at),
                        });
                    }
                    for (at, limit) in &parsed.limits {
                        diags.push(Diagnostic {
                            severity: DiagSeverity::Warning,
                            code: "coverage-parse-limit",
                            message: limit.message.clone(),
                            at: Some(*at),
                        });
                    }
                    for a in parsed.file.body.attributes() {
                        if storage::reserve(&mut tfvars, 1, files.input_budget()).is_err() {
                            break;
                        }
                        tfvars.push(TfvarsBinding {
                            name: a.key.name.as_str(),
                            attr: a,
                            file: sf.clone(),
                        });
                    }
                }
                Err(e) if tf_limits::input::exhaustion(&e).is_some() => break,
                Err(e) => diags.push(Diagnostic {
                    severity: DiagSeverity::Error,
                    code: "var-file",
                    message: format!("cannot read {}: {e}", p.display()),
                    at: None,
                }),
            }
        }
        Analyzer {
            budget: tf_eval::EvaluationBudget::with_storage(
                opts.limits,
                tf_limits::Resource::EvaluationSteps,
                files.shared_input_budget(),
            ),
            loader_budget: tf_eval::EvaluationBudget::with_storage(
                opts.limits,
                tf_limits::Resource::LoaderSteps,
                files.shared_input_budget(),
            ),
            store,
            files,
            opts,
            installed: InstalledModules::new(&root_dir, opts.data_dir.as_deref(), files),
            root_dir,
            defs: RefCell::new(HashMap::default()),
            insts: RefCell::new(Vec::new()),
            tfvars,
            diags: RefCell::new(diags),
            depth: Cell::new(0),
            observer: RefCell::new(observer),
            attr_count: Cell::new(0),
            expanded: Cell::new(0),
            observed_error: Cell::new(None),
        }
    }

    fn diag(
        &self,
        severity: DiagSeverity,
        code: &'static str,
        message: String,
        at: Option<FileSpan>,
    ) {
        self.diags.borrow_mut().push(Diagnostic {
            severity,
            code,
            message,
            at,
        });
    }

    fn load_def(&self, dir: &Path) -> Build<&'a ModuleDef<'a>> {
        if let Some(d) = self.defs.borrow().get(dir) {
            return Ok(d);
        }
        let d = self
            .store
            .module_with_limits(self.files, dir, self.opts.limits)
            .map_err(|error| Value::limit(error.to_string()))?;
        if let Some((file, ast)) = d.files.first() {
            self.loader_budget.import(
                FileSpan::new(file.id, ast.span),
                d.loader_steps,
                d.loader_limit,
            );
        }
        for (at, m) in &d.parse_errors {
            self.diag(DiagSeverity::Error, "parse-error", m.clone(), Some(*at));
        }
        for (at, limit) in &d.parse_limits {
            self.diag(
                DiagSeverity::Warning,
                "coverage-parse-limit",
                limit.message.clone(),
                Some(*at),
            );
        }
        for message in &d.load_errors {
            self.diag(DiagSeverity::Error, "read-error", message.clone(), None);
        }
        if d.files.is_empty() {
            self.diag(
                DiagSeverity::Warning,
                "coverage-no-input",
                format!("no supported Terraform configuration in {}", dir.display()),
                None,
            );
        }
        if let Some(error) = self.files.listing_error(dir) {
            self.diag(
                DiagSeverity::Error,
                "read-error",
                format!("{}: {error}", dir.display()),
                None,
            );
        }
        storage::hash_slot(&mut self.defs.borrow_mut(), self.budget.storage())?;
        self.defs.borrow_mut().insert(dir.to_path_buf(), d);
        Ok(d)
    }

    fn inst(&self, id: usize) -> Rc<Instance<'a>> {
        self.insts.borrow()[id].clone()
    }

    fn new_instance(
        &self,
        def: &'a ModuleDef<'a>,
        address: Arc<str>,
        parent: Option<(usize, usize)>,
        bind: InstBind,
        ancestors: Vec<PathBuf>,
        package: Option<InstalledPackage>,
    ) -> Build<usize> {
        storage::reserve(&mut self.insts.borrow_mut(), 1, self.budget.storage())?;
        collections::admit::<Instance<'_>>(1, self.budget.storage())?;
        let inst = Instance {
            def,
            address,
            parent,
            binds: bind.binds,
            existence: bind.existence,
            ancestors,
            package,
            children: RefCell::new(HashMap::default()),
            limited_children: RefCell::new(Vec::new()),
            vars: RefCell::new(HashMap::default()),
            locals: RefCell::new(HashMap::default()),
            outputs: RefCell::new(HashMap::default()),
            res_attrs: RefCell::new(HashMap::default()),
            res_insts: RefCell::new(HashMap::default()),
        };
        let mut v = self.insts.borrow_mut();
        v.push(Rc::new(inst));
        Ok(v.len() - 1)
    }

    fn run(self) -> model::Analysis {
        let modules = self.build_analysis().unwrap_or_else(|stopped| {
            self.mark_sensitive(&stopped);
            Vec::new()
        });
        self.report_budget();
        if self.budget.storage().exhaustion().is_some()
            && let Some(at) = self.observed_error.get()
        {
            self.report_limits(&Value::error("previous evaluation failed"), at);
        }
        let stats = AnalysisStats {
            loader_steps: self.loader_budget.used(),
            evaluation_steps: self.budget.used(),
            files: self
                .defs
                .borrow()
                .values()
                .map(|d| d.files.len())
                .sum::<usize>(),
            module_instances: modules.len(),
            resources: modules.iter().map(|m| m.resources.len()).sum(),
            attributes: self.attr_count.get(),
        };
        model::Analysis {
            root_dir: self.root_dir.clone(),
            modules,
            diagnostics: {
                let mut diagnostics = self.diags.take();
                diagnostics.extend(self.files.limit_diagnostic());
                diagnostics
            },
            stats,
        }
    }

    fn build_analysis(&self) -> Build<Vec<model::Module>> {
        let def = self.load_def(&self.root_dir)?;
        let root = self.new_instance(
            def,
            Arc::from(""),
            None,
            InstBind {
                key: None,
                binds: None,
                existence: Truth::True,
            },
            collections::collect(
                std::iter::once(self.root_dir.clone()),
                self.budget.storage(),
            )?,
            None,
        )?;
        let mut i = root;
        while i < self.insts.borrow().len() {
            let n = self.inst(i).def.module_calls.len();
            for ci in 0..n {
                self.children_of(i, ci)?;
            }
            i += 1;
        }
        let n = self.insts.borrow().len();
        let mut modules = Vec::new();
        storage::reserve(&mut modules, n, self.budget.storage())?;
        for id in 0..n {
            let mut module = match self.new_model(id) {
                Ok(module) => module,
                Err(stopped) => {
                    self.mark_sensitive(&stopped);
                    break;
                }
            };
            let result = self.build_module(id, &mut module);
            // This slot is already reserved. Keep complete resources when a later
            // field stops; the terminal diagnostic marks the analysis incomplete.
            modules.push(module);
            if let Err(stopped) = result {
                self.mark_sensitive(&stopped);
                break;
            }
        }
        Ok(modules)
    }

    fn new_model(&self, id: usize) -> Build<model::Module> {
        let inst = self.inst(id);
        Ok(model::Module {
            address: inst.address.clone(),
            dir: inst.def.dir.clone(),
            parent: inst.parent.map(|p| p.0),
            package: self.copy_package(inst.package.as_ref())?,
            resources: Vec::new(),
            variables: Vec::new(),
            outputs: Vec::new(),
            locals: Vec::new(),
            block_values: std::collections::HashMap::new(),
            module_calls: Vec::new(),
            symbols: Vec::new(),
            references: inst.def.references.clone(),
        })
    }

    // ---- evaluation entry points ----------------------------------------

    fn report_budget(&self) {
        self.report_loader_budget();
        let Some(limit) = self.budget.first_limit() else {
            return;
        };
        let (code, message) = match limit.reason {
            tf_eval::budget::LimitReason::Storage(_) => return,
            tf_eval::budget::LimitReason::Work(exhaustion) => {
                ("coverage-budget", exhaustion.to_string())
            }
            tf_eval::budget::LimitReason::Evaluation => (
                "coverage-evaluation",
                "evaluation reached a fixed expansion or nesting limit".to_string(),
            ),
        };
        self.diag(DiagSeverity::Warning, code, message, Some(limit.at));
    }

    fn report_loader_budget(&self) {
        let Some(limit) = self.loader_budget.first_limit() else {
            return;
        };
        let (code, message) = match limit.reason {
            tf_eval::budget::LimitReason::Storage(_) => return,
            tf_eval::budget::LimitReason::Work(exhaustion) => {
                ("coverage-budget", exhaustion.to_string())
            }
            tf_eval::budget::LimitReason::Evaluation => (
                "coverage-loader",
                "module defaults reached a fixed expansion or nesting limit".to_string(),
            ),
        };
        self.diag(DiagSeverity::Warning, code, message, Some(limit.at));
    }

    fn loading_exhausted(&self) -> bool {
        self.loader_budget.first_limit().is_some()
            || self.files.input_budget().exhaustion().is_some()
    }

    fn eval(&self, inst: usize, file: FileId, e: &'a Expression<'a>, sc: Scope<'_>) -> Value {
        if self.loading_exhausted() {
            return Value::other("module inputs unavailable after loader exhaustion");
        }
        let r = InstResolver { an: self, inst };
        Evaluator::with_budget(&r, file, &self.budget).eval(e, sc)
    }

    fn eval_const(&self, file: FileId, e: &'a Expression<'a>) -> Value {
        if self.loading_exhausted() {
            return Value::other("module inputs unavailable after loader exhaustion");
        }
        Evaluator::with_budget(&NoResolver, file, &self.budget).eval(e, Scope::EMPTY)
    }

    /// Memoised evaluation. The lookup is by the borrowed form `k`; the
    /// owned key is only built (`key`) on a miss, so a hit allocates
    /// nothing.
    fn memo<K, Q>(
        &self,
        map: &RefCell<HashMap<K, Slot>>,
        k: &Q,
        key: impl FnOnce() -> K,
        what: impl FnOnce() -> String,
        compute: impl FnOnce() -> Value,
    ) -> Value
    where
        K: std::hash::Hash + Eq + std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        if let Some(s) = map.borrow().get(k) {
            return match s {
                Slot::Busy => Value::error(format!("cycle while evaluating {}", what())),
                Slot::Done(v) => v.clone(),
            };
        }
        if self.depth.get() > MAX_DEPTH {
            return Value::limit(format!("evaluation too deep at {}", what()));
        }
        if let Err(stopped) = storage::hash_slot(&mut map.borrow_mut(), self.budget.storage()) {
            return stopped;
        }
        map.borrow_mut().insert(key(), Slot::Busy);
        self.depth.set(self.depth.get() + 1);
        let v = compute();
        self.depth.set(self.depth.get() - 1);
        if let Some(slot) = map.borrow_mut().get_mut(k) {
            *slot = Slot::Done(v.clone());
        }
        v
    }

    // ---- variables, locals, outputs -------------------------------------

    #[expect(clippy::too_many_lines)]
    fn var_value(&self, inst_id: usize, name: &str) -> Value {
        if self.loading_exhausted() {
            return Value::other("module inputs unavailable after loader exhaustion");
        }
        let inst = self.inst(inst_id);
        self.memo(
            &inst.vars,
            name,
            || name.to_string(),
            || format!("var.{name}"),
            || {
                let Some(decl) = inst.def.variable(name) else {
                    return Value::error(format!(
                        "reference to undeclared input variable \"{name}\""
                    ));
                };
                let header = FileSpan::new(decl.file, header_span(decl.block));
                let var_step = |label: String| Step::new(StepKind::Variable, header, label);
                let from_default = || -> Option<Value> {
                    let d = decl.default?;
                    let file = inst.def.origins.file(d, decl.file);
                    let v = decl
                        .default_value
                        .clone()
                        .unwrap_or_else(|| self.eval_const(file, &d.value));
                    Some(v.push(Step::new(
                        StepKind::VariableDefault,
                        FileSpan::new(file, d.span),
                        format!("variable {name} default"),
                    )))
                };
                let v = match inst.parent {
                    None => {
                        if let Some(tb) = self.tfvars.iter().rev().find(|t| t.name == name) {
                            let v = self.eval_const(tb.file.id, &tb.attr.value);
                            let fname = tb
                                .file
                                .path
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();
                            v.push(Step::new(
                                StepKind::Tfvars,
                                FileSpan::new(tb.file.id, tb.attr.span),
                                format!("{fname}: {}", snippet(&tb.file.text, tb.attr.span, 60)),
                            ))
                            .push(var_step(format!("variable {name}")))
                        } else if let Some(v) = from_default() {
                            v
                        } else {
                            Value::tainted(name).push(var_step(format!(
                                "variable {name} (no default, no tfvars value: unconstrained)"
                            )))
                        }
                    }
                    Some((pid, ci)) => {
                        let parent = self.inst(pid);
                        let call = &parent.def.module_calls[ci];
                        match call.block.body.find_attribute(name) {
                            Some(arg) => {
                                let file = parent.def.origins.file(arg, call.file);
                                let v = Scope::EMPTY.with_all(inst.binds.as_slice(), |sc| {
                                    self.eval(pid, file, &arg.value, sc)
                                });
                                v.push(Step::new(
                                    StepKind::ModuleArgument,
                                    FileSpan::new(file, arg.span),
                                    format!(
                                        "{}module.{} argument {name}",
                                        parent.prefix(),
                                        call.name
                                    ),
                                ))
                                .push(var_step(format!("variable {name}")))
                            }
                            None => match from_default() {
                                Some(v) => v,
                                None => Value::tainted(name).push(var_step(format!(
                                    "variable {name} (not set by module.{}, no default)",
                                    call.name
                                ))),
                            },
                        }
                    }
                };
                let v = if decl.non_nullable && v.is_null() {
                    from_default().unwrap_or(v)
                } else {
                    v
                };
                // Overrides replace the constraint but retain the original
                // declaration's optional defaults for all runtime inputs.
                let mut v = crate::input_conversion::convert_input(
                    v,
                    decl.ty,
                    inst.def.origins.type_defaults(decl.block),
                    crate::input_conversion::InputContext {
                        budget: &self.budget,
                        at: header,
                    },
                );
                if declared_sensitive(&decl.block.body) {
                    v = v.sensitive();
                }
                self.mark_sensitive(&v);
                v
            },
        )
    }

    fn local_value(&self, inst_id: usize, name: &str) -> Value {
        let inst = self.inst(inst_id);
        self.memo(
            &inst.locals,
            name,
            || name.to_string(),
            || format!("local.{name}"),
            || {
                let Some(decl) = inst.def.local(name) else {
                    return Value::error(format!("reference to undeclared local value \"{name}\""));
                };
                let v = self.eval(inst_id, decl.file, &decl.attr.value, Scope::EMPTY);
                let v = v.push(Step::new(
                    StepKind::Local,
                    FileSpan::new(decl.file, decl.attr.span),
                    format!("local.{name}"),
                ));
                self.mark_sensitive(&v);
                v
            },
        )
    }

    fn output_value(&self, inst_id: usize, name: &str) -> Value {
        let inst = self.inst(inst_id);
        self.memo(
            &inst.outputs,
            name,
            || name.to_string(),
            || format!("output {name}"),
            || {
                let Some(decl) = inst.def.output(name) else {
                    return Value::error(format!("module has no output \"{name}\""));
                };
                let Some(va) = decl.value else {
                    return Value::error("output without value");
                };
                let file = inst.def.origins.file(va, decl.file);
                let mut v = self.eval(inst_id, file, &va.value, Scope::EMPTY);
                if declared_sensitive(&decl.block.body) {
                    v = v.sensitive();
                }
                if v.is_sensitive() {
                    self.files.mark_sensitive(FileSpan::new(file, va.span));
                    self.mark_sensitive(&v);
                }
                v.push(Step::new(
                    StepKind::Output,
                    FileSpan::new(file, va.span),
                    format!(
                        "{}output {name}",
                        if inst.address.is_empty() {
                            String::new()
                        } else {
                            format!("{} ", inst.address)
                        }
                    ),
                ))
            },
        )
    }

    // ---- references -----------------------------------------------------

    #[expect(clippy::too_many_lines)]
    fn resource_ref(
        &self,
        inst_id: usize,
        mode: Mode,
        ty: &'a str,
        ops: &'a [TraversalOperator<'a>],
        ev: &Evaluator<'_, 'a>,
        sc: Scope<'_>,
    ) -> Build<(Value, usize)> {
        let inst = self.inst(inst_id);
        let Some(name) = ops.first().and_then(|o| o.attr_name()) else {
            return Ok((Value::error(format!("invalid reference to {ty}")), 0));
        };
        let Some(ri) = inst.def.resource_index(mode, ty, name) else {
            let what = if mode == Mode::Data {
                format!("data.{ty}.{name}")
            } else {
                format!("{ty}.{name}")
            };
            return Ok((
                Value::error(format!("reference to undeclared resource {what}")),
                1,
            ));
        };
        let mut i = 1;
        let mut key: Option<InstanceKey> = None;
        let mut certainty = Truth::True;
        let mut splat = false;
        let selected = match ops.get(1) {
            Some(TraversalOperator::Index(ix)) => Some(ev.eval(&ix.index, sc)),
            _ => None,
        };
        if let Some(index) = &selected {
            self.mark_sensitive(index);
        }
        let attempt = (|| {
            let indexed = |value: Value| match &selected {
                Some(index) => value.inherit_sensitive(index),
                None => value,
            };
            match ops.get(1) {
                Some(TraversalOperator::Index(_)) => {
                    let index = selected.as_ref().unwrap();
                    key = instance_key(
                        index,
                        inst.def.resources[ri]
                            .block
                            .body
                            .find_attribute("count")
                            .is_some(),
                    );
                    if key.is_none() {
                        if matches!(index.kind, Kind::Known(_)) {
                            return Ok((
                                indexed(Value::error("invalid resource instance index")),
                                2,
                            ));
                        }
                        certainty = tf_eval::truth::uncertainty(index);
                    }
                    i = 2;
                }
                Some(TraversalOperator::LegacyIndex(l)) => {
                    key = Some(InstanceKey::Index(l.index));
                    i = 2;
                }
                Some(TraversalOperator::FullSplat(_) | TraversalOperator::AttrSplat(_)) => {
                    splat = true;
                    i = 2;
                }
                _ => {}
            }
            let base = Address::new(inst.address.clone(), mode, ty, name, None);
            let insts = self.res_instances(inst_id, ri)?;
            if insts.3 {
                return Ok((
                    indexed(Value::unknown(Origin::Limit(
                        "root instance budget exceeded".into(),
                    ))),
                    ops.len(),
                ));
            }
            if splat {
                if insts.0.iter().any(|b| b.key.is_none())
                    && (insts.1.is_some() || insts.2.is_some())
                {
                    return Ok((Value::other("resource instances not expanded"), ops.len()));
                }
                let attr = ops.get(i).and_then(|op| op.attr_name());
                let values = storage::values(
                    insts.0.iter().map(|b| {
                        let mut value = if let Some(attr) = attr {
                            self.resource_attr(inst_id, ri, b.key.clone(), attr, &base)
                        } else {
                            self.resource_object(inst_id, ri, b.key.clone(), &base)
                        };
                        value = reference_value(
                            value,
                            &[tf_eval::prov::ResourceDependency {
                                resource: base.base_string().into(),
                                key: b.key.as_ref().map(InstanceKey::as_str),
                                certainty: b.existence,
                            }],
                            self.budget.storage(),
                        );
                        value
                    }),
                    self.budget.storage(),
                )?;
                let rest = &ops[i + usize::from(attr.is_some())..];
                let mut values = values;
                let result = if matches!(ops.get(1), Some(TraversalOperator::FullSplat(_))) {
                    for value in &mut values {
                        *value = ev.apply_ops(value.clone(), rest, sc);
                    }
                    Value::list(values)
                } else {
                    let n = rest
                        .iter()
                        .take_while(|op| {
                            matches!(
                                op,
                                TraversalOperator::GetAttr(_) | TraversalOperator::LegacyIndex(_)
                            )
                        })
                        .count();
                    for value in &mut values {
                        *value = ev.apply_ops(value.clone(), &rest[..n], sc);
                    }
                    ev.apply_ops(Value::list(values), &rest[n..], sc)
                };
                return Ok((result, ops.len()));
            }
            if i == 2 && key.is_some() && !insts.0.iter().any(|b| b.key == key || b.key.is_none()) {
                return Ok((
                    indexed(Value::error("resource instance index is out of range")),
                    i,
                ));
            }
            let whole = ops.get(i).and_then(|o| o.attr_name()).is_none();
            let dependencies = if splat || (whole && key.is_none() && certainty == Truth::True) {
                insts
                    .0
                    .iter()
                    .map(|b| tf_eval::prov::ResourceDependency {
                        resource: base.base_string().into(),
                        key: b.key.as_ref().map(InstanceKey::as_str),
                        certainty: b.existence,
                    })
                    .collect()
            } else {
                vec![tf_eval::prov::ResourceDependency {
                    resource: base.base_string().into(),
                    key: key.as_ref().map(InstanceKey::as_str),
                    certainty,
                }]
            };
            let referenced = |value: Value| {
                indexed(reference_value(value, &dependencies, self.budget.storage()))
            };
            let Some(attr) = ops.get(i).and_then(|o| o.attr_name()) else {
                let object = |key| self.resource_object(inst_id, ri, key, &base);
                if i == 1 && insts.0.iter().all(|b| b.key.is_some()) {
                    let value = if insts.1.is_some() {
                        Value::list(storage::values(
                            insts.0.iter().map(|b| object(b.key.clone())),
                            self.budget.storage(),
                        )?)
                    } else {
                        storage::object(
                            insts
                                .0
                                .iter()
                                .map(|b| (b.key.as_ref().unwrap().as_str(), object(b.key.clone()))),
                            self.budget.storage(),
                        )?
                    };
                    return Ok((value, i));
                }
                if insts.0.iter().any(|b| b.key == key)
                    && (key.is_some() || (insts.1.is_none() && insts.2.is_none()))
                {
                    return Ok((referenced(object(key)), i));
                }
                let instance = base.with_key(key);
                return Ok((
                    referenced(Value::unknown(instance.computed("(whole object)"))),
                    i,
                ));
            };
            if i == 1 && (insts.1.is_some() || insts.2.is_some()) {
                return Ok((Value::error("resource instance key is required"), i + 1));
            }
            let v = if key.is_none() && i == 2 && !insts.0.is_empty() {
                let choices = storage::values(
                    insts
                        .0
                        .iter()
                        .map(|b| self.resource_attr(inst_id, ri, b.key.clone(), attr, &base)),
                    self.budget.storage(),
                )?;
                storage::alternatives(choices, certainty == Truth::Tainted, self.budget.storage())?
            } else {
                self.resource_attr(inst_id, ri, key, attr, &base)
            };
            Ok((referenced(v), i + 1))
        })();
        attempt.map_err(|stopped| failure(stopped, selected.iter()))
    }

    fn resource_object(
        &self,
        inst_id: usize,
        ri: usize,
        key: Option<InstanceKey>,
        base: &Address,
    ) -> Value {
        let inst = self.inst(inst_id);
        let decl = &inst.def.resources[ri];
        let dependency = tf_eval::prov::ResourceDependency {
            resource: base.base_string().into(),
            key: key.as_ref().map(InstanceKey::as_str),
            certainty: Truth::True,
        };
        let attempt = (|| -> Build<Value> {
            let mut names = Buffer::new(self.budget.storage());
            for name in decl
                .block
                .body
                .attributes()
                .map(|a| a.key.name.as_str())
                .filter(|n| !META_ATTRS.contains(n))
            {
                names.push(name)?;
            }
            for block in decl.block.body.blocks() {
                let name = block.block_type();
                if name == "dynamic" {
                    if let Some(label) = block.labels.first() {
                        names.push(label.value.as_str())?;
                    }
                } else if !META_BLOCKS.contains(&name) {
                    names.push(name)?;
                }
            }
            if let Some(schema) = decl.schema {
                for attr in &schema.attributes {
                    names.push(attr.name)?;
                }
                for block in &schema.block_types {
                    names.push(block.name)?;
                }
            }
            let mut names = names.finish();
            names.sort_unstable();
            names.dedup();
            let value = storage::object(
                names.into_iter().map(|name| {
                    (
                        Arc::from(name),
                        self.resource_attr(inst_id, ri, key.clone(), name, base),
                    )
                }),
                self.budget.storage(),
            )?;
            Ok(reference_value(value, &[dependency], self.budget.storage()))
        })();
        attempt.unwrap_or_else(|stopped| stopped)
    }

    #[expect(clippy::too_many_lines)]
    fn resource_attr(
        &self,
        inst_id: usize,
        ri: usize,
        key: Option<InstanceKey>,
        attr: &str,
        base: &Address,
    ) -> Value {
        let inst = self.inst(inst_id);
        let k = (ri, key.clone(), attr.to_string());
        let instance = base.clone().with_key(key.clone());
        let base_str = base.base_string();
        self.memo(
            &inst.res_attrs,
            &k,
            || k.clone(),
            || format!("{base}.{attr}"),
            || {
                let decl: &ResourceDecl<'a> = &inst.def.resources[ri];
                if decl.mode == Mode::Data
                    && decl.ty == "aws_iam_policy_document"
                    && (attr == "json" || attr == "minified_json")
                {
                    return self.iam_policy_document(inst_id, ri, key.as_ref(), &base_str);
                }
                if let Some(a) = decl
                    .block
                    .body
                    .find_attribute(attr)
                    .filter(|_| !META_ATTRS.contains(&attr))
                {
                    let insts = match self.res_instances(inst_id, ri) {
                        Ok(insts) => insts,
                        Err(stopped) => return stopped,
                    };
                    let chosen = match &key {
                        Some(k) => insts.0.iter().find(|b| b.key.as_ref() == Some(k)),
                        None => None,
                    }
                    .or(if insts.0.len() == 1 {
                        insts.0.first()
                    } else {
                        None
                    });
                    let fallback;
                    let binds = match chosen {
                        Some(binding) => binding.binds.as_slice(),
                        None => {
                            let count = match self
                                .obj1("index", Value::other("count.index (instance not selected)"))
                            {
                                Ok(value) => value,
                                Err(stopped) => return stopped,
                            };
                            fallback = [
                                ("count", count),
                                ("each", Value::other("each (instance not selected)")),
                            ];
                            &fallback
                        }
                    };
                    let file = inst.def.origins.file(a, decl.file);
                    let mut v =
                        Scope::EMPTY.with_all(binds, |sc| self.eval(inst_id, file, &a.value, sc));
                    if decl
                        .schema
                        .and_then(|s| s.attribute(attr))
                        .is_some_and(|a| a.is_sensitive())
                    {
                        v = v.sensitive();
                        self.files.mark_sensitive(FileSpan::new(file, a.span));
                        self.mark_sensitive(&v);
                    }
                    // A null in configuration leaves a computed attribute to
                    // the provider.
                    let is_computed = decl
                        .schema
                        .and_then(|s| s.attribute(attr))
                        .is_some_and(|at| at.is_computed());
                    if v.is_null() && is_computed {
                        return Value::unknown(instance.computed(attr));
                    }
                    return v.push(
                        Step::new(
                            StepKind::Attribute,
                            FileSpan::new(file, a.span),
                            format!("{base_str} {attr}"),
                        )
                        .with_resource(base_str.clone().into())
                        .with_attribute(attr),
                    );
                }
                let computed = || Value::unknown(instance.computed(attr));
                match decl.schema {
                    Some(s) => match s.member(attr) {
                        Some(Member::Attribute(at)) if at.is_computed() => computed(),
                        Some(Member::Attribute(_)) => tf_schema::default_for(decl.ty, attr)
                            .map(model::default_value)
                            .unwrap_or_else(Value::null),
                        Some(Member::Block(_)) => {
                            Value::other(format!("nested block reference {base_str}.{attr}"))
                        }
                        None => {
                            Value::error(format!("unsupported attribute \"{attr}\" on {}", decl.ty))
                        }
                    },
                    None => computed(),
                }
            },
        )
    }

    #[expect(clippy::too_many_lines)]
    fn module_ref(
        &self,
        inst_id: usize,
        ops: &'a [TraversalOperator<'a>],
        ev: &Evaluator<'_, 'a>,
        sc: Scope<'_>,
    ) -> Build<(Value, usize)> {
        let inst = self.inst(inst_id);
        let Some(name) = ops.first().and_then(|o| o.attr_name()) else {
            return Ok((Value::error("invalid module reference"), 0));
        };
        let Some(ci) = inst.def.module_call(name) else {
            return Ok((
                Value::error(format!("reference to undeclared module \"{name}\"")),
                1,
            ));
        };
        let call = &inst.def.module_calls[ci];
        let maddr = format!("{}module.{name}", inst.prefix());
        let selected = match ops.get(1) {
            Some(TraversalOperator::Index(ix)) => Some(ev.eval(&ix.index, sc)),
            Some(TraversalOperator::LegacyIndex(ix)) => Some(Value::number(ix.index as f64)),
            _ => None,
        };
        if let Some(index) = &selected {
            self.mark_sensitive(index);
        }
        let attempt = (|| {
            let indexed = |value: Value| match &selected {
                Some(index) => value.inherit_sensitive(index),
                None => value,
            };
            if matches!(call.source, ModuleSource::Invalid) {
                return Ok((
                    indexed(Value::other(format!(
                        "{maddr}: module source not a literal"
                    ))),
                    1,
                ));
            }
            let kids = self.children_of(inst_id, ci)?;
            if inst.limited_children.borrow().contains(&ci) {
                return Ok((
                    indexed(Value::unknown(Origin::Limit(
                        "root instance budget exceeded".into(),
                    ))),
                    ops.len(),
                ));
            }
            let counted = call.block.body.find_attribute("count").is_some();
            let repeated = counted || call.block.body.find_attribute("for_each").is_some();
            // No selected instance is not the same as an unavailable package.
            if kids.is_empty() && matches!(call.source, ModuleSource::Remote(_)) {
                let (binds, _, _) =
                    self.expand_inner(inst_id, call.file, &call.block.body, Scope::EMPTY)?;
                if !binds.is_empty() {
                    return Ok((
                        indexed(Value::unknown(Origin::RemoteModule {
                            module: maddr.into(),
                            output: "(unavailable module)".into(),
                        })),
                        ops.len(),
                    ));
                }
            }
            let object = |kid: usize| {
                let child = self.inst(kid);
                storage::object(
                    child
                        .def
                        .outputs
                        .iter()
                        .map(|o| (Arc::from(o.name), self.output_value(kid, o.name))),
                    self.budget.storage(),
                )
                .unwrap_or_else(|stopped| stopped)
            };
            if let Some(index) = &selected {
                let key = instance_key(index, counted);
                let kid = key
                    .as_ref()
                    .and_then(|key| kids.iter().find(|(k, _)| k.as_ref() == Some(key)))
                    .or_else(|| kids.iter().find(|(k, _)| k.is_none() && repeated));
                if let Some((_, kid)) = kid {
                    if let Some(out) = ops.get(2).and_then(|op| op.attr_name()) {
                        return Ok((indexed(self.output_value(*kid, out)), 3));
                    }
                    return Ok((indexed(object(*kid)), 2));
                }
                if matches!(index.kind, Kind::Known(_)) {
                    return Ok((
                        indexed(Value::error(
                            "module instance index is out of range or invalid",
                        )),
                        2,
                    ));
                }
                let choices =
                    storage::values(kids.iter().map(|(_, k)| object(*k)), self.budget.storage())?;
                let value = storage::alternatives(
                    choices,
                    tf_eval::truth::uncertainty(index) == Truth::Tainted,
                    self.budget.storage(),
                )?;
                return Ok((indexed(value), 2));
            }
            if !repeated {
                if let Some((_, kid)) = kids.first() {
                    if let Some(out) = ops.get(1).and_then(|op| op.attr_name()) {
                        return Ok((self.output_value(*kid, out), 2));
                    }
                    return Ok((object(*kid), 1));
                }
                return Ok((Value::other(format!("{maddr}: module not instantiated")), 1));
            }
            if kids.iter().any(|(k, _)| k.is_none()) {
                return Ok((
                    Value::other(format!("{maddr}: module instances not expanded")),
                    ops.len(),
                ));
            }
            let value = if counted {
                Value::list(storage::values(
                    kids.iter().map(|(_, k)| object(*k)),
                    self.budget.storage(),
                )?)
            } else {
                storage::object(
                    kids.iter()
                        .map(|(key, k)| (key.as_ref().unwrap().as_str(), object(*k))),
                    self.budget.storage(),
                )?
            };
            Ok((value, 1))
        })();
        attempt.map_err(|stopped| failure(stopped, selected.iter()))
    }

    fn model_value(&self, value: Value, at: FileSpan) -> Value {
        self.mark_sensitive(&value);
        if self.observed_error.get().is_none() && tf_eval::eval::contains_error(&value) {
            self.observed_error.set(Some(at));
        }
        value
    }

    fn report_limits(&self, value: &Value, at: FileSpan) {
        if let Some(Origin::Error(_)) = value.origin() {
            // Avoid echoing value-bearing error details into unredacted diagnostics.
            self.diag(
                DiagSeverity::Error,
                "evaluation-error",
                "expression evaluation failed".into(),
                Some(at),
            );
        }
        if let Some(o @ (Origin::UnsupportedFunction(_) | Origin::Limit(_))) = value.origin() {
            // One located root diagnostic suffices for the shared allowance. Emitting
            // a duplicate for every unevaluated attribute would itself grow without bound.
            if matches!(o, Origin::Limit(_)) && self.budget.is_exhausted() {
                return;
            }
            self.diag(
                DiagSeverity::Warning,
                "coverage-evaluation",
                o.to_string(),
                Some(at),
            );
        }
        match &value.kind {
            Kind::Known(Known::List(v)) => v.iter().for_each(|v| self.report_limits(v, at)),
            Kind::Known(Known::Object(v)) => v.values().for_each(|v| self.report_limits(v, at)),
            Kind::Known(Known::Json(v)) => self.report_limits(v, at),
            Kind::OneOf(o) => o
                .alternatives
                .iter()
                .for_each(|v| self.report_limits(v, at)),
            _ => {}
        }
    }

    fn mark_sensitive(&self, value: &Value) {
        if value.is_sensitive() {
            for step in value.prov.steps() {
                self.files.mark_sensitive(step.at);
            }
        }
        match &value.kind {
            Kind::Known(Known::List(items)) => items.iter().for_each(|v| self.mark_sensitive(v)),
            Kind::Known(Known::Object(items)) => {
                items.values().for_each(|v| self.mark_sensitive(v))
            }
            Kind::Known(Known::Json(inner)) => self.mark_sensitive(inner),
            Kind::OneOf(o) => o.alternatives.iter().for_each(|v| self.mark_sensitive(v)),
            _ => {}
        }
    }

    fn observe(
        &self,
        ctx: &BodyCtx<'a>,
        file: FileId,
        path: &str,
        name: &str,
        expr: &'a Expression<'a>,
        v: &Value,
    ) {
        if !ctx.observe {
            return;
        }
        self.attr_count.set(self.attr_count.get() + 1);
        if let Some(obs) = self.observer.borrow_mut().as_mut() {
            let full = format!("{path}{name}");
            obs(&ObservedAttr {
                mode: ctx.mode,
                resource_type: ctx.ty,
                path: &full,
                name,
                file,
                expr,
                value: v,
            });
        }
    }
}

fn declared_sensitive(body: &Body<'_>) -> bool {
    body.find_attribute("sensitive")
        .is_some_and(|a| matches!(a.value.without_parens(), Expression::Bool(b) if b.value))
}

struct BodyCtx<'a> {
    inst: usize,
    origins: &'a crate::compose::Origins,
    file: FileId,
    addr: Arc<str>,
    base: Arc<str>,
    ty: &'a str,
    mode: Mode,
    strict_bool: bool,
    /// Report attributes to the observer (off for internal re-evaluation).
    observe: bool,
}

fn nested_schema(
    schema: Option<&'static tf_schema::Block<'static>>,
    name: &str,
) -> (Option<&'static tf_schema::Block<'static>>, bool) {
    match schema.and_then(|s| s.member(name)) {
        Some(Member::Block(nb)) => (Some(nb.block()), false),
        Some(Member::Attribute(_)) => (None, true),
        None => (None, false),
    }
}

fn body_to_object(body: &model::Body, budget: &tf_limits::input::InputBudget) -> Build<Value> {
    let mut map = Map::new();
    for attr in &body.attrs {
        collections::insert(&mut map, attr.name.clone(), attr.value.clone(), budget)?;
    }
    let mut lists: Buffer<'_, (Arc<str>, Vec<Value>)> = Buffer::new(budget);
    for block in &body.blocks {
        let group = lists.iter().position(|list| list.0 == block.ty);
        if let Some(index) = group {
            storage::reserve(&mut lists[index].1, 1, budget)?;
            let value = body_to_object(&block.body, budget)?;
            lists[index].1.push(value);
        } else {
            lists.reserve(1)?;
            let values = collections::try_collect(
                std::iter::once_with(|| body_to_object(&block.body, budget)),
                budget,
            )?;
            lists.push((block.ty.clone(), values))?;
        }
    }
    for (key, values) in lists.finish() {
        if !map.contains_key(&key) {
            collections::insert(&mut map, key, Value::list(values), budget)?;
        }
    }
    Ok(Value::object(map))
}

impl Analyzer<'_, '_> {
    fn obj1(&self, key: &str, value: Value) -> Build<Value> {
        storage::object(std::iter::once((key.into(), value)), self.budget.storage())
    }

    fn obj2(&self, key: Value, value: Value) -> Build<Value> {
        storage::object(
            [("key".into(), key), ("value".into(), value)].into_iter(),
            self.budget.storage(),
        )
    }
}

enum CollectionItems<'v> {
    List(&'v Value, std::iter::Enumerate<std::slice::Iter<'v, Value>>),
    Object(
        &'v Value,
        std::collections::btree_map::Iter<'v, Arc<str>, Value>,
    ),
}

impl Iterator for CollectionItems<'_> {
    type Item = (Value, Value);
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::List(parent, items) => items.next().map(|(index, value)| {
                let value = value.child_of(parent);
                let key = if value.as_str().is_some() {
                    value.clone()
                } else {
                    Value::number(index as f64).inherit_sensitive(parent)
                };
                (key, value)
            }),
            Self::Object(parent, items) => items.next().map(|(key, value)| {
                (
                    Value::string(key.clone()).inherit_sensitive(parent),
                    value.child_of(parent),
                )
            }),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for CollectionItems<'_> {
    fn len(&self) -> usize {
        match self {
            Self::List(_, items) => items.len(),
            Self::Object(_, items) => items.len(),
        }
    }
}

fn collection_items(value: &Value) -> Option<CollectionItems<'_>> {
    match &value.kind {
        Kind::Known(Known::List(items)) => {
            Some(CollectionItems::List(value, items.iter().enumerate()))
        }
        Kind::Known(Known::Object(items)) => Some(CollectionItems::Object(value, items.iter())),
        _ => None,
    }
}

struct InstResolver<'x, 'a, 'o> {
    an: &'x Analyzer<'a, 'o>,
    inst: usize,
}

impl<'a> Resolver<'a> for InstResolver<'_, 'a, '_> {
    fn call(&self, name: &str, args: Vec<Value>, budget: &tf_eval::EvaluationBudget) -> Value {
        let inst = self.an.inst(self.inst);
        let boundary = inst
            .package
            .as_ref()
            .and_then(|p| p.package_root.as_deref());
        crate::file_functions::call(
            self.an.files,
            &self.an.root_dir,
            boundary,
            name,
            args,
            false,
            budget,
        )
    }

    fn resolve(
        &self,
        ev: &Evaluator<'_, 'a>,
        sc: Scope<'_>,
        root: &'a str,
        _span: Span,
        ops: &'a [TraversalOperator<'a>],
    ) -> (Value, usize) {
        let an = self.an;
        let a0 = ops.first().and_then(|o| o.attr_name());
        match root {
            "var" => match a0 {
                Some(n) => (an.var_value(self.inst, n), 1),
                None => (Value::error("invalid reference to var"), 0),
            },
            "local" => match a0 {
                Some(n) => (an.local_value(self.inst, n), 1),
                None => (Value::error("invalid reference to local"), 0),
            },
            "path" => {
                let inst = an.inst(self.inst);
                let rel = |p: &Path| {
                    crate::source::relative_to(p, &an.root_dir)
                        .display()
                        .to_string()
                };
                match a0 {
                    Some("module") => (Value::string(rel(&inst.def.dir)), 1),
                    Some("root") | Some("cwd") => (Value::string("."), 1),
                    _ => (Value::error("invalid path reference"), 0),
                }
            }
            "terraform" => (Value::other("terraform.workspace"), ops.len().min(1)),
            "count" | "each" | "self" => (
                Value::other(format!("{root} (outside its context)")),
                ops.len().min(1),
            ),
            "module" => an
                .module_ref(self.inst, ops, ev, sc)
                .unwrap_or_else(|v| (v, ops.len())),
            "data" => match a0 {
                Some(ty) => {
                    let (v, used) = an
                        .resource_ref(self.inst, Mode::Data, ty, &ops[1..], ev, sc)
                        .unwrap_or_else(|v| (v, ops.len() - 1));
                    (v, used + 1)
                }
                None => (Value::error("invalid data reference"), 0),
            },
            ty => an
                .resource_ref(self.inst, Mode::Managed, ty, ops, ev, sc)
                .unwrap_or_else(|v| (v, ops.len())),
        }
    }
}

//! Module-instance tree, reference resolution and schema-aware evaluation of
//! resource bodies into the owned [`crate::model`].

use rustc_hash::FxHashMap as HashMap;
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

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
    Mode, ModuleDef, ModuleSource, ResourceDecl, SymbolRef, auto_tfvars, module_files,
};
use crate::source::{FileTable, SourceFile, normalize};
use crate::store::ModuleStore;

/// Options for [`analyze_module`].
#[derive(Clone, Debug)]
pub struct AnalyzeOptions {
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
            var_files: Vec::new(),
            data_dir: None,
            max_module_depth: 10,
            max_expand: 64,
            max_instances: 16_384,
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
    binds: Vec<(&'static str, Value)>,
    existence: Truth,
}

type Children = Option<Rc<Vec<(Option<InstanceKey>, usize)>>>;
type ResAttrKey = (usize, Option<InstanceKey>, String);
type Expansion = (Vec<InstBind>, Option<Value>, Option<Value>, bool);

struct Instance<'a> {
    def: &'a ModuleDef<'a>,
    address: Arc<str>,
    parent: Option<(usize, usize)>,
    binds: Vec<(&'static str, Value)>,
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

fn reference_value(mut value: Value, dependencies: &[tf_eval::prov::ResourceDependency]) -> Value {
    // A resource traversal refers to this instance even when its configured
    // attribute was computed from another resource or contains nested values.
    value.kind = match value.kind {
        Kind::Known(Known::List(items)) => Kind::Known(Known::List(Arc::new(
            items
                .iter()
                .map(|v| reference_value(v.clone(), dependencies))
                .collect(),
        ))),
        Kind::Known(Known::Object(items)) => Kind::Known(Known::Object(Arc::new(
            items
                .iter()
                .map(|(k, v)| (k.clone(), reference_value(v.clone(), dependencies)))
                .collect(),
        ))),
        Kind::Known(Known::Json(inner)) => Kind::Known(Known::Json(Arc::new(reference_value(
            (*inner).clone(),
            dependencies,
        )))),
        Kind::OneOf(one) => Kind::OneOf(Arc::new(tf_eval::value::OneOf {
            alternatives: one
                .alternatives
                .iter()
                .map(|v| reference_value(v.clone(), dependencies))
                .collect(),
            tainted: one.tainted,
        })),
        other => other,
    };
    value.prov = value.prov.referencing(dependencies.to_vec());
    value
}

impl<'a, 'o> Analyzer<'a, 'o> {
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
                    let parsed = store.variable_file(&sf);
                    for (at, m) in &parsed.errors {
                        diags.push(Diagnostic {
                            severity: DiagSeverity::Error,
                            code: "parse-error",
                            message: m.clone(),
                            at: Some(*at),
                        });
                    }
                    for a in parsed.file.body.attributes() {
                        tfvars.push(TfvarsBinding {
                            name: a.key.name.as_str(),
                            attr: a,
                            file: sf.clone(),
                        });
                    }
                }
                Err(e) => diags.push(Diagnostic {
                    severity: DiagSeverity::Error,
                    code: "var-file",
                    message: format!("cannot read {}: {e}", p.display()),
                    at: None,
                }),
            }
        }
        Analyzer {
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

    fn load_def(&self, dir: &Path) -> &'a ModuleDef<'a> {
        if let Some(d) = self.defs.borrow().get(dir) {
            return d;
        }
        let d = self.store.module(self.files, dir);
        for (at, m) in &d.parse_errors {
            self.diag(DiagSeverity::Error, "parse-error", m.clone(), Some(*at));
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
        self.defs.borrow_mut().insert(dir.to_path_buf(), d);
        d
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
    ) -> usize {
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
        v.len() - 1
    }

    fn run(self) -> model::Analysis {
        let def = self.load_def(&self.root_dir.clone());
        let root = self.new_instance(
            def,
            Arc::from(""),
            None,
            InstBind {
                key: None,
                binds: vec![],
                existence: Truth::True,
            },
            vec![self.root_dir.clone()],
            None,
        );
        // Instantiate the whole tree (children are created lazily, so force
        // them breadth-first).
        let mut i = root;
        while i < self.insts.borrow().len() {
            let n = self.inst(i).def.module_calls.len();
            for ci in 0..n {
                self.children_of(i, ci);
            }
            i += 1;
        }
        let n = self.insts.borrow().len();
        let modules: Vec<model::Module> = (0..n).map(|i| self.build_module(i)).collect();
        let stats = AnalysisStats {
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
            diagnostics: self.diags.take(),
            stats,
        }
    }

    // ---- evaluation entry points ----------------------------------------

    fn eval(&self, inst: usize, file: FileId, e: &'a Expression<'a>, sc: Scope<'_>) -> Value {
        let r = InstResolver { an: self, inst };
        Evaluator::new(&r, file).eval(e, sc)
    }

    fn eval_const(&self, file: FileId, e: &'a Expression<'a>) -> Value {
        Evaluator::new(&NoResolver, file).eval(e, Scope::EMPTY)
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

    fn var_value(&self, inst_id: usize, name: &str) -> Value {
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
                                let v = Scope::EMPTY.with_all(&inst.binds, |sc| {
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
                let mut v = if let Some(defaults) = inst.def.origins.type_defaults(decl.block) {
                    convert_to_type(defaults.apply(v), decl.ty, false)
                } else {
                    convert_to_type(v, decl.ty, true)
                };
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

    // ---- count / for_each -----------------------------------------------

    fn expand(&self, inst_id: usize, file: FileId, body: &'a Body<'a>, sc: Scope<'_>) -> Expansion {
        let (mut binds, count, each) = self.expand_inner(inst_id, file, body, sc);
        let limited = binds.len() > self.opts.max_instances.saturating_sub(self.expanded.get());
        if limited {
            self.diag(
                DiagSeverity::Warning,
                "coverage-expansion",
                format!(
                    "root exceeds the {} total instance limit",
                    self.opts.max_instances
                ),
                Some(FileSpan::new(file, body.span)),
            );
            binds.clear();
        } else {
            self.expanded.set(self.expanded.get() + binds.len());
        }
        (binds, count, each, limited)
    }

    fn expand_inner(
        &self,
        inst_id: usize,
        file: FileId,
        body: &'a Body<'a>,
        sc: Scope<'_>,
    ) -> (Vec<InstBind>, Option<Value>, Option<Value>) {
        let single = || InstBind {
            key: None,
            binds: vec![],
            existence: Truth::True,
        };
        if let Some(c) = body.find_attribute("count") {
            let file = self.inst(inst_id).def.origins.file(c, file);
            let v = self.eval(inst_id, file, &c.value, sc);
            let abstract_count = |existence: Truth| InstBind {
                key: None,
                binds: vec![(
                    "count",
                    obj1(
                        "index",
                        Value::other("count.index (instances not expanded)"),
                    ),
                )],
                existence,
            };
            let r = match &v.kind {
                Kind::Known(_) => match v.as_number() {
                    Some(n) if n.is_finite() && n >= 0.0 && n.fract() == 0.0 => {
                        if n <= self.opts.max_expand as f64 {
                            (0..n as u64)
                                .map(|index| InstBind {
                                    key: Some(InstanceKey::Index(index)),
                                    binds: vec![(
                                        "count",
                                        obj1("index", Value::number(index as f64)),
                                    )],
                                    existence: Truth::True,
                                })
                                .collect()
                        } else {
                            self.diag(
                                DiagSeverity::Warning,
                                "coverage-count",
                                format!(
                                    "count exceeds the {} instance limit",
                                    self.opts.max_expand
                                ),
                                Some(FileSpan::new(file, c.span)),
                            );
                            vec![abstract_count(Truth::True)]
                        }
                    }
                    _ => {
                        self.diag(
                            DiagSeverity::Error,
                            "invalid-count",
                            "count must be a nonnegative whole number".into(),
                            Some(FileSpan::new(file, c.span)),
                        );
                        vec![abstract_count(Truth::Unknown)]
                    }
                },
                Kind::Tainted(_) => vec![abstract_count(Truth::Tainted)],
                Kind::Unknown(_) => vec![abstract_count(Truth::Unknown)],
                Kind::OneOf(o) => {
                    let ns: Vec<Option<f64>> =
                        o.alternatives.iter().map(|a| a.as_number()).collect();
                    if ns.iter().all(|n| n.is_some_and(|n| n <= 0.0)) {
                        vec![]
                    } else if ns.iter().all(|n| n.is_some_and(|n| n >= 1.0)) {
                        vec![abstract_count(Truth::True)]
                    } else {
                        vec![abstract_count(tf_eval::truth::uncertainty(&v))]
                    }
                }
            };
            self.report_limits(&v, FileSpan::new(file, c.span));
            return (r, Some(v), None);
        }
        if let Some(fe) = body.find_attribute("for_each") {
            let file = self.inst(inst_id).def.origins.file(fe, file);
            let v = self.eval(inst_id, file, &fe.value, sc).push(Step::new(
                StepKind::Iteration,
                FileSpan::new(file, fe.span),
                "for_each",
            ));
            let abstract_each = |each: Value, existence: Truth| InstBind {
                key: None,
                binds: vec![("each", each)],
                existence,
            };
            if v.is_sensitive() {
                self.files.mark_sensitive(FileSpan::new(file, fe.span));
                self.mark_sensitive(&v);
                self.diag(
                    DiagSeverity::Error,
                    "sensitive-for-each",
                    "sensitive values cannot determine resource or module instance keys".into(),
                    Some(FileSpan::new(file, fe.span)),
                );
                let unknown = Value::other("sensitive for_each").sensitive();
                return (
                    vec![abstract_each(
                        obj2(unknown.clone(), unknown),
                        Truth::Unknown,
                    )],
                    None,
                    Some(v),
                );
            }
            let items = collection_items(&v);
            let r = match items {
                Some(items) if items.len() <= self.opts.max_expand => items
                    .into_iter()
                    .map(|(k, val)| {
                        let key = match k.to_str() {
                            Some(s) => s,
                            None => Arc::from("?"),
                        };
                        let mut m = Map::new();
                        m.insert("key".into(), Value::string(key.clone()));
                        m.insert("value".into(), val);
                        InstBind {
                            key: Some(InstanceKey::Key(key)),
                            binds: vec![("each", Value::object(m))],
                            existence: Truth::True,
                        }
                    })
                    .collect(),
                Some(_) => {
                    self.diag(
                        DiagSeverity::Warning,
                        "coverage-expansion",
                        format!(
                            "for_each exceeds the {} instance limit",
                            self.opts.max_expand
                        ),
                        Some(FileSpan::new(file, fe.span)),
                    );
                    let u = Value::other("each (for_each too large to expand)");
                    vec![abstract_each(obj2(u.clone(), u), Truth::True)]
                }
                None => match (&v.kind, tf_eval::truth::uncertainty(&v)) {
                    (Kind::Known(Known::Null), _) => vec![],
                    (Kind::Tainted(_), _) => vec![abstract_each(v.clone(), Truth::Tainted)],
                    (_, Truth::Tainted) => vec![abstract_each(
                        Value::tainted("(conditional for_each)").with_prov(v.prov.clone()),
                        Truth::Tainted,
                    )],
                    _ => {
                        let u = Value::other("each (for_each not known)").with_prov(v.prov.clone());
                        vec![abstract_each(u, Truth::Unknown)]
                    }
                },
            };
            self.report_limits(&v, FileSpan::new(file, fe.span));
            return (r, None, Some(v));
        }
        (vec![single()], None, None)
    }

    fn res_instances(&self, inst_id: usize, ri: usize) -> Rc<Expansion> {
        let inst = self.inst(inst_id);
        if let Some(s) = inst.res_insts.borrow().get(&ri) {
            return match s {
                Some(v) => v.clone(),
                None => Rc::new((
                    vec![InstBind {
                        key: None,
                        binds: vec![],
                        existence: Truth::Unknown,
                    }],
                    None,
                    None,
                    false,
                )),
            };
        }
        inst.res_insts.borrow_mut().insert(ri, None);
        let decl = &inst.def.resources[ri];
        let r = Rc::new(self.expand(inst_id, decl.file, &decl.block.body, Scope::EMPTY));
        inst.res_insts.borrow_mut().insert(ri, Some(r.clone()));
        r
    }

    fn children_of(&self, inst_id: usize, ci: usize) -> Rc<Vec<(Option<InstanceKey>, usize)>> {
        let inst = self.inst(inst_id);
        if let Some(s) = inst.children.borrow().get(&ci) {
            return s.clone().unwrap_or_default();
        }
        inst.children.borrow_mut().insert(ci, None);
        let call = &inst.def.module_calls[ci];
        let mut out = Vec::new();
        let (binds, _, _, limited) =
            self.expand(inst_id, call.file, &call.block.body, Scope::EMPTY);
        if limited {
            inst.limited_children.borrow_mut().push(ci);
        }
        if !binds.is_empty() {
            let at = FileSpan::new(call.file, header_span(call.block));
            let resolved = match &call.source {
                ModuleSource::Local(dir) => {
                    let mut package = inst.package.clone();
                    if let Some(p) = &mut package {
                        p.calls.push(at);
                        self.files.protect_dir(dir);
                    }
                    Ok((dir.clone(), package))
                }
                ModuleSource::Remote(_) => {
                    let mut calls = vec![call];
                    let mut parent = inst.parent;
                    while let Some((pid, pci)) = parent {
                        let p = self.inst(pid);
                        calls.push(&p.def.module_calls[pci]);
                        parent = p.parent;
                    }
                    calls.reverse();
                    self.installed
                        .resolve(&calls)
                        .map(|p| (p.dir.clone(), Some(p)))
                }
                ModuleSource::Invalid => Err("source is missing or not a literal string".into()),
            };
            match resolved {
                Err(message) => self.diag(
                    DiagSeverity::Warning,
                    "coverage-remote-module",
                    format!("module.{}: {message}; source was not evaluated", call.name),
                    Some(at),
                ),
                Ok((dir, package)) => {
                    let canonical = self.files.canonical_path(&dir);
                    if inst
                        .ancestors
                        .iter()
                        .any(|p| self.files.canonical_path(p) == canonical)
                    {
                        self.diag(
                            DiagSeverity::Warning,
                            "module-cycle",
                            format!(
                                "module.{} calls an ancestor module ({})",
                                call.name,
                                dir.display()
                            ),
                            Some(at),
                        );
                    } else if inst.ancestors.len() > self.opts.max_module_depth {
                        self.diag(
                            DiagSeverity::Warning,
                            "module-depth",
                            format!(
                                "module.{}: nesting deeper than {}",
                                call.name, self.opts.max_module_depth
                            ),
                            Some(at),
                        );
                    } else if module_files(self.files, &dir).is_empty() {
                        self.diag(
                            DiagSeverity::Warning,
                            "module-missing",
                            format!(
                                "module.{}: no supported .tf files in {}",
                                call.name,
                                dir.display()
                            ),
                            Some(at),
                        );
                    } else {
                        let def = self.load_def(&dir);
                        let mut anc = inst.ancestors.clone();
                        anc.push(dir);
                        for b in binds {
                            let addr = match &b.key {
                                Some(k) => format!("{}module.{}{}", inst.prefix(), call.name, k),
                                None => format!("{}module.{}", inst.prefix(), call.name),
                            };
                            let key = b.key.clone();
                            let b = InstBind {
                                existence: b.existence.min(inst.existence),
                                ..b
                            };
                            let id = self.new_instance(
                                def,
                                addr.into(),
                                Some((inst_id, ci)),
                                b,
                                anc.clone(),
                                package.clone(),
                            );
                            out.push((key, id));
                        }
                    }
                }
            }
        }
        let rc = Rc::new(out);
        inst.children.borrow_mut().insert(ci, Some(rc.clone()));
        rc
    }

    // ---- references -----------------------------------------------------

    fn resource_ref(
        &self,
        inst_id: usize,
        mode: Mode,
        ty: &'a str,
        ops: &'a [TraversalOperator<'a>],
        ev: &Evaluator<'_, 'a>,
        sc: Scope<'_>,
    ) -> (Value, usize) {
        let inst = self.inst(inst_id);
        let Some(name) = ops.first().and_then(|o| o.attr_name()) else {
            return (Value::error(format!("invalid reference to {ty}")), 0);
        };
        let Some(ri) = inst.def.resource_index(mode, ty, name) else {
            let what = if mode == Mode::Data {
                format!("data.{ty}.{name}")
            } else {
                format!("{ty}.{name}")
            };
            return (
                Value::error(format!("reference to undeclared resource {what}")),
                1,
            );
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
                        return (indexed(Value::error("invalid resource instance index")), 2);
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
        let insts = self.res_instances(inst_id, ri);
        if insts.3 {
            return (
                indexed(Value::unknown(Origin::Limit(
                    "root instance budget exceeded".into(),
                ))),
                ops.len(),
            );
        }
        if splat {
            if insts.0.iter().any(|b| b.key.is_none()) && (insts.1.is_some() || insts.2.is_some()) {
                return (Value::other("resource instances not expanded"), ops.len());
            }
            let attr = ops.get(i).and_then(|op| op.attr_name());
            let values = insts
                .0
                .iter()
                .map(|b| {
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
                    );
                    value
                })
                .collect();
            let rest = &ops[i + usize::from(attr.is_some())..];
            let result = if matches!(ops.get(1), Some(TraversalOperator::FullSplat(_))) {
                let value = Value::list(values);
                // Full splats apply every remaining operator per instance.
                Value::list(
                    value
                        .as_list()
                        .unwrap()
                        .iter()
                        .map(|v| ev.apply_ops(v.clone(), rest, sc))
                        .collect(),
                )
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
                let values = values
                    .into_iter()
                    .map(|v| ev.apply_ops(v, &rest[..n], sc))
                    .collect();
                ev.apply_ops(Value::list(values), &rest[n..], sc)
            };
            return (result, ops.len());
        }
        if i == 2 && key.is_some() && !insts.0.iter().any(|b| b.key == key || b.key.is_none()) {
            return (
                indexed(Value::error("resource instance index is out of range")),
                i,
            );
        }
        let whole = ops.get(i).and_then(|o| o.attr_name()).is_none();
        let dependencies = if splat || (whole && key.is_none() && certainty == Truth::True) {
            self.res_instances(inst_id, ri)
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
        let referenced = |value: Value| indexed(reference_value(value, &dependencies));
        let Some(attr) = ops.get(i).and_then(|o| o.attr_name()) else {
            let object = |key| self.resource_object(inst_id, ri, key, &base);
            if i == 1 && insts.0.iter().all(|b| b.key.is_some()) {
                let value = if insts.1.is_some() {
                    Value::list(insts.0.iter().map(|b| object(b.key.clone())).collect())
                } else {
                    Value::object(
                        insts
                            .0
                            .iter()
                            .map(|b| (b.key.as_ref().unwrap().as_str(), object(b.key.clone())))
                            .collect(),
                    )
                };
                return (value, i);
            }
            if insts.0.iter().any(|b| b.key == key)
                && (key.is_some() || (insts.1.is_none() && insts.2.is_none()))
            {
                return (referenced(object(key)), i);
            }
            let instance = base.with_key(key);
            return (
                referenced(Value::unknown(instance.computed("(whole object)"))),
                i,
            );
        };
        if i == 1 && (insts.1.is_some() || insts.2.is_some()) {
            return (Value::error("resource instance key is required"), i + 1);
        }
        let v = if key.is_none() && i == 2 && !insts.0.is_empty() {
            Value::one_of(
                insts
                    .0
                    .iter()
                    .map(|b| self.resource_attr(inst_id, ri, b.key.clone(), attr, &base))
                    .collect(),
                certainty == Truth::Tainted,
            )
        } else {
            self.resource_attr(inst_id, ri, key, attr, &base)
        };
        (
            referenced(if splat { Value::list(vec![v]) } else { v }),
            i + 1,
        )
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
        let mut names: Vec<&str> = decl
            .block
            .body
            .attributes()
            .map(|a| a.key.name.as_str())
            .filter(|n| !META_ATTRS.contains(n))
            .collect();
        names.extend(decl.block.body.blocks().filter_map(|b| {
            let name = b.block_type();
            if name == "dynamic" {
                b.labels.first().map(|label| label.value.as_str())
            } else if META_BLOCKS.contains(&name) {
                None
            } else {
                Some(name)
            }
        }));
        if let Some(schema) = decl.schema {
            names.extend(schema.attributes.iter().map(|a| a.name));
            names.extend(schema.block_types.iter().map(|b| b.name));
        }
        names.sort_unstable();
        names.dedup();
        let value = Value::object(
            names
                .into_iter()
                .map(|name| {
                    (
                        Arc::from(name),
                        self.resource_attr(inst_id, ri, key.clone(), name, base),
                    )
                })
                .collect(),
        );
        reference_value(value, &[dependency])
    }

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
                    let insts = self.res_instances(inst_id, ri);
                    let chosen = match &key {
                        Some(k) => insts.0.iter().find(|b| b.key.as_ref() == Some(k)),
                        None => None,
                    }
                    .or(if insts.0.len() == 1 {
                        insts.0.first()
                    } else {
                        None
                    });
                    let binds: Vec<(&str, Value)> = match chosen {
                        Some(b) => b.binds.clone(),
                        None => vec![
                            (
                                "count",
                                obj1("index", Value::other("count.index (instance not selected)")),
                            ),
                            ("each", Value::other("each (instance not selected)")),
                        ],
                    };
                    let file = inst.def.origins.file(a, decl.file);
                    let mut v =
                        Scope::EMPTY.with_all(&binds, |sc| self.eval(inst_id, file, &a.value, sc));
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

    fn module_ref(
        &self,
        inst_id: usize,
        ops: &'a [TraversalOperator<'a>],
        ev: &Evaluator<'_, 'a>,
        sc: Scope<'_>,
    ) -> (Value, usize) {
        let inst = self.inst(inst_id);
        let Some(name) = ops.first().and_then(|o| o.attr_name()) else {
            return (Value::error("invalid module reference"), 0);
        };
        let Some(ci) = inst.def.module_call(name) else {
            return (
                Value::error(format!("reference to undeclared module \"{name}\"")),
                1,
            );
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
        let indexed = |value: Value| match &selected {
            Some(index) => value.inherit_sensitive(index),
            None => value,
        };
        if matches!(call.source, ModuleSource::Invalid) {
            return (
                indexed(Value::other(format!(
                    "{maddr}: module source not a literal"
                ))),
                1,
            );
        }
        let kids = self.children_of(inst_id, ci);
        if inst.limited_children.borrow().contains(&ci) {
            return (
                indexed(Value::unknown(Origin::Limit(
                    "root instance budget exceeded".into(),
                ))),
                ops.len(),
            );
        }
        let counted = call.block.body.find_attribute("count").is_some();
        let repeated = counted || call.block.body.find_attribute("for_each").is_some();
        // No selected instance is not the same as an unavailable package.
        if kids.is_empty() && matches!(call.source, ModuleSource::Remote(_)) {
            let (binds, _, _) =
                self.expand_inner(inst_id, call.file, &call.block.body, Scope::EMPTY);
            if !binds.is_empty() {
                return (
                    indexed(Value::unknown(Origin::RemoteModule {
                        module: maddr.into(),
                        output: "(unavailable module)".into(),
                    })),
                    ops.len(),
                );
            }
        }
        let object = |kid: usize| {
            let child = self.inst(kid);
            Value::object(
                child
                    .def
                    .outputs
                    .iter()
                    .map(|o| (Arc::from(o.name), self.output_value(kid, o.name)))
                    .collect(),
            )
        };
        if let Some(index) = &selected {
            let key = instance_key(index, counted);
            let kid = key
                .as_ref()
                .and_then(|key| kids.iter().find(|(k, _)| k.as_ref() == Some(key)))
                .or_else(|| kids.iter().find(|(k, _)| k.is_none() && repeated));
            if let Some((_, kid)) = kid {
                if let Some(out) = ops.get(2).and_then(|op| op.attr_name()) {
                    return (indexed(self.output_value(*kid, out)), 3);
                }
                return (indexed(object(*kid)), 2);
            }
            if matches!(index.kind, Kind::Known(_)) {
                return (
                    indexed(Value::error(
                        "module instance index is out of range or invalid",
                    )),
                    2,
                );
            }
            let value = Value::one_of(
                kids.iter().map(|(_, k)| object(*k)).collect(),
                tf_eval::truth::uncertainty(index) == Truth::Tainted,
            );
            return (indexed(value), 2);
        }
        if !repeated {
            if let Some((_, kid)) = kids.first() {
                if let Some(out) = ops.get(1).and_then(|op| op.attr_name()) {
                    return (self.output_value(*kid, out), 2);
                }
                return (object(*kid), 1);
            }
            return (Value::other(format!("{maddr}: module not instantiated")), 1);
        }
        if kids.iter().any(|(k, _)| k.is_none()) {
            return (
                Value::other(format!("{maddr}: module instances not expanded")),
                ops.len(),
            );
        }
        let value = if counted {
            Value::list(kids.iter().map(|(_, k)| object(*k)).collect())
        } else {
            Value::object(
                kids.iter()
                    .map(|(key, k)| (key.as_ref().unwrap().as_str(), object(*k)))
                    .collect(),
            )
        };
        (value, 1)
    }

    // ---- data sources evaluated statically ------------------------------

    /// `data.aws_iam_policy_document.x.json`: the provider renders the
    /// `statement` blocks (and `source_policy_documents` /
    /// `override_policy_documents`) to JSON deterministically, so it is
    /// evaluated here instead of being left Unknown. `condition` blocks are
    /// not rendered; override documents are appended (not merged by Sid).
    fn iam_policy_document(
        &self,
        inst_id: usize,
        ri: usize,
        key: Option<&InstanceKey>,
        base: &str,
    ) -> Value {
        let inst = self.inst(inst_id);
        let decl = &inst.def.resources[ri];
        let insts = self.res_instances(inst_id, ri);
        let binds: Vec<(&str, Value)> = key
            .and_then(|k| insts.0.iter().find(|b| b.key.as_ref() == Some(k)))
            .or(if insts.0.len() == 1 {
                insts.0.first()
            } else {
                None
            })
            .map(|b| b.binds.clone())
            .unwrap_or_default();
        let ctx = BodyCtx {
            inst: inst_id,
            file: decl.file,
            origins: &inst.def.origins,
            addr: base.into(),
            base: base.into(),
            ty: decl.ty,
            mode: decl.mode,
            strict_bool: false,
            observe: false,
        };
        let body = Scope::EMPTY.with_all(&binds, |sc| {
            self.eval_body(
                &ctx,
                &decl.block.body,
                decl.schema.map(|s| s.block()),
                sc,
                "",
                true,
            )
        });
        let mut statements: Vec<Value> = Vec::new();
        for src in ["source_policy_documents", "override_policy_documents"] {
            let Some(docs) = body.value(src) else {
                continue;
            };
            match docs.as_list() {
                Some(l) => {
                    for d in l {
                        let d = d.child_of(docs);
                        let parsed = match &d.kind {
                            Kind::Known(Known::Json(j)) => (**j).clone(),
                            Kind::Known(Known::String(_)) => {
                                tf_eval::functions::call("jsondecode", vec![d.clone()])
                            }
                            _ => {
                                return Value::other(format!("{base}.json: {src} not known"))
                                    .with_prov(d.prov.clone());
                            }
                        };
                        let st = parsed.get_attr("Statement");
                        match st.as_list() {
                            Some(sl) => statements.extend(sl.iter().map(|x| x.child_of(&st))),
                            None if st.is_known() => statements.push(st),
                            None => return st,
                        }
                    }
                }
                None if docs.is_null() => {}
                None => return docs.clone(),
            }
        }
        let rename = [
            ("sid", "Sid"),
            ("effect", "Effect"),
            ("actions", "Action"),
            ("not_actions", "NotAction"),
            ("resources", "Resource"),
            ("not_resources", "NotResource"),
        ];
        for b in body.blocks_of("statement") {
            let mut m = Map::new();
            for (from, to) in rename {
                if let Some(v) = b.body.value(from)
                    && !v.is_null()
                {
                    m.insert(to.into(), v.clone());
                }
            }
            m.entry("Effect".into())
                .or_insert_with(|| Value::string("Allow"));
            for (blk, key) in [
                ("principals", "Principal"),
                ("not_principals", "NotPrincipal"),
            ] {
                let mut p = Map::new();
                for pb in b.body.blocks_of(blk) {
                    if let (Some(t), Some(ids)) = (
                        pb.body.value("type").and_then(|t| t.to_str()),
                        pb.body.value("identifiers"),
                    ) {
                        p.insert(t, ids.clone());
                    }
                }
                if !p.is_empty() {
                    m.insert(key.into(), Value::object(p));
                }
            }
            let st = Value::object(m);
            statements.push(match b.existence {
                Truth::True => st,
                e => Value::one_of(vec![st, Value::null()], e == Truth::Tainted),
            });
        }
        let mut doc = Map::new();
        doc.insert(
            "Version".into(),
            body.value("version")
                .filter(|v| !v.is_null())
                .cloned()
                .unwrap_or_else(|| Value::string("2012-10-17")),
        );
        doc.insert("Statement".into(), Value::list(statements));
        Value::json(Value::object(doc)).push(
            Step::new(
                StepKind::Attribute,
                FileSpan::new(decl.file, header_span(decl.block)),
                format!("{base}.json (rendered from statement blocks)"),
            )
            .with_resource(base.into()),
        )
    }

    // ---- model building -------------------------------------------------

    fn build_module(&self, inst_id: usize) -> model::Module {
        let inst = self.inst(inst_id);
        let def = inst.def;
        let mut resources = Vec::new();
        for (ri, decl) in def.resources.iter().enumerate() {
            let insts = self.res_instances(inst_id, ri);
            let decl_id = Address::new(inst.address.clone(), decl.mode, decl.ty, decl.name, None);
            let base: Arc<str> = decl_id.base_string().into();
            for b in insts.0.iter() {
                let id = decl_id.clone().with_key(b.key.clone());
                let address: Arc<str> = id.to_string().into();
                let ctx = BodyCtx {
                    inst: inst_id,
                    file: decl.file,
                    origins: &def.origins,
                    addr: address.clone(),
                    base: base.clone(),
                    ty: decl.ty,
                    mode: decl.mode,
                    strict_bool: decl
                        .schema
                        .is_some_and(|s| s.provider == tf_schema::Provider::Aws),
                    observe: true,
                };
                let body = Scope::EMPTY.with_all(&b.binds, |sc| {
                    self.eval_body(
                        &ctx,
                        &decl.block.body,
                        decl.schema.map(|s| s.block()),
                        sc,
                        "",
                        true,
                    )
                });
                let mut resource = model::Resource::new(
                    id,
                    FileSpan::new(decl.file, header_span(decl.block)),
                    body,
                    b.existence.min(inst.existence),
                    insts.1.clone(),
                    insts.2.clone(),
                    decl.schema.map(|s| s.provider),
                );
                if let Some(a) = decl.block.body.find_attribute("depends_on") {
                    let file = def.origins.file(a, decl.file);
                    let value = Scope::EMPTY
                        .with_all(&b.binds, |sc| self.eval(inst_id, file, &a.value, sc));
                    crate::graph::value_dependencies(&value, &mut resource.dependencies);
                }
                resources.push(resource);
            }
        }
        let variables = def
            .variables
            .iter()
            .map(|v| model::VariableInfo {
                name: v.name.into(),
                value: self.var_value(inst_id, v.name),
                span: FileSpan::new(v.file, header_span(v.block)),
            })
            .collect();
        let outputs = def
            .outputs
            .iter()
            .map(|o| model::VariableInfo {
                name: o.name.into(),
                value: self.output_value(inst_id, o.name),
                span: FileSpan::new(o.file, header_span(o.block)),
            })
            .collect();
        let module_calls = def
            .module_calls
            .iter()
            .map(|c| model::ModuleCallInfo {
                name: c.name.into(),
                source: match &c.source {
                    ModuleSource::Local(p) => p.display().to_string(),
                    ModuleSource::Remote(s) => s.clone(),
                    ModuleSource::Invalid => String::new(),
                },
                remote: matches!(c.source, ModuleSource::Remote(_)),
                span: FileSpan::new(c.file, header_span(c.block)),
                // Evaluated in the caller, outside any `count`/`for_each`
                // instance: an argument that reads `count.index` or
                // `each` is not known here.
                arguments: if self.opts.whole_files {
                    c.block
                        .body
                        .attributes()
                        .filter(|a| !matches!(&*a.key.name, "providers" | "depends_on"))
                        .map(|a| {
                            let file = def.origins.file(a, c.file);
                            let v = self.eval(inst_id, file, &a.value, Scope::EMPTY);
                            (Arc::from(&*a.key.name), v)
                        })
                        .collect()
                } else {
                    Vec::new()
                },
            })
            .collect();
        let mut symbols = Vec::new();
        for v in &def.variables {
            symbols.push(model::SymbolInfo {
                symbol: SymbolRef::Variable(v.name.into()),
                span: FileSpan::new(v.file, header_span(v.block)),
            });
        }
        for l in &def.locals {
            symbols.push(model::SymbolInfo {
                symbol: SymbolRef::Local(l.name.into()),
                span: FileSpan::new(l.file, l.attr.span),
            });
        }
        for r in &def.resources {
            let s = match r.mode {
                Mode::Managed => SymbolRef::Resource(r.ty.into(), r.name.into()),
                Mode::Data => SymbolRef::Data(r.ty.into(), r.name.into()),
            };
            symbols.push(model::SymbolInfo {
                symbol: s,
                span: FileSpan::new(r.file, header_span(r.block)),
            });
        }
        for c in &def.module_calls {
            symbols.push(model::SymbolInfo {
                symbol: SymbolRef::Module(c.name.into()),
                span: FileSpan::new(c.file, header_span(c.block)),
            });
        }
        for o in &def.outputs {
            symbols.push(model::SymbolInfo {
                symbol: SymbolRef::Output(o.name.into()),
                span: FileSpan::new(o.file, header_span(o.block)),
            });
        }
        // Every attribute of the other top-level blocks (`provider`,
        // `terraform`, `check`, `import`, ...), evaluated in this instance,
        // by expression span: what a whole-file rule renders.
        let mut block_values = std::collections::HashMap::new();
        if self.opts.whole_files {
            for (sf, file) in &def.files {
                for b in file.body.blocks() {
                    if !matches!(
                        &*b.ident.name,
                        "resource" | "data" | "module" | "variable" | "locals" | "output"
                    ) {
                        self.block_values(inst_id, sf.id, &b.body, &mut block_values);
                    }
                }
            }
        }
        // Register sensitive local sources even when no remaining resource
        // refers to them (for example, after a verified edit).
        let locals = def
            .locals
            .iter()
            .filter_map(|l| {
                let value = self.local_value(inst_id, l.name);
                self.opts.whole_files.then(|| model::VariableInfo {
                    name: l.name.into(),
                    value,
                    span: FileSpan::new(l.file, l.attr.span),
                })
            })
            .collect();
        model::Module {
            address: inst.address.clone(),
            dir: def.dir.clone(),
            parent: inst.parent.map(|p| p.0),
            package: inst.package.clone(),
            resources,
            variables,
            outputs,
            locals,
            block_values,
            module_calls,
            symbols,
            references: def.references.clone(),
        }
    }

    fn block_values(
        &self,
        inst_id: usize,
        file: FileId,
        body: &'a Body<'a>,
        out: &mut std::collections::HashMap<FileSpan, Value>,
    ) {
        for a in body.attributes() {
            let file = self.inst(inst_id).def.origins.file(a, file);
            let v = self.eval(inst_id, file, &a.value, Scope::EMPTY);
            out.insert(FileSpan::new(file, tf_span::GetSpan::span(&a.value)), v);
        }
        for b in body.blocks() {
            if &*b.ident.name != "dynamic" {
                self.block_values(inst_id, file, &b.body, out);
            }
        }
    }

    fn eval_body(
        &self,
        ctx: &BodyCtx<'a>,
        body: &'a Body<'a>,
        schema: Option<&'static tf_schema::Block<'static>>,
        sc: Scope<'_>,
        path: &str,
        top: bool,
    ) -> model::Body {
        let mut out = model::Body {
            span: FileSpan::new(ctx.origins.file(body, ctx.file), body.span),
            attrs: Vec::new(),
            blocks: Vec::new(),
        };
        // (name, body, dynamic, existence, span, attribute-as-blocks)
        let mut raw: Vec<(&'a str, model::Body, bool, Truth, FileSpan, bool)> = Vec::new();
        for a in body.attributes() {
            let file = ctx.origins.file(a, ctx.file);
            let name = a.key.name.as_str();
            if top && META_ATTRS.contains(&name) {
                continue;
            }
            let mut v = self.eval(ctx.inst, file, &a.value, sc).push(
                Step::new(
                    StepKind::Attribute,
                    FileSpan::new(file, a.span),
                    format!("{} {path}{name}", ctx.addr),
                )
                .with_resource(ctx.base.clone())
                .with_attribute(format!("{path}{name}")),
            );
            if schema
                .and_then(|s| s.attribute(name))
                .is_some_and(|a| a.is_sensitive())
            {
                v = v.sensitive();
            }
            self.mark_sensitive(&v);
            self.report_limits(&v, FileSpan::new(file, a.span));
            if ctx.strict_bool
                && let Some(at) = schema.and_then(|s| s.attribute(name))
                && at.is_bool()
                && let Some(s) = v.as_str()
                && (s == "true" || s == "false")
            {
                self.diag(
                                    DiagSeverity::Warning,
                                    "strict-bool",
                                    if v.is_sensitive() {
                                        format!("{} {path}{name}: sensitive string where the AWS provider schema requires a bool", ctx.addr)
                                    } else {
                                        format!("{} {path}{name}: string \"{s}\" where the AWS provider schema requires a bool; Terraform converts it, but write {s} without quotes", ctx.addr)
                                    },
                                    Some(FileSpan::new(file, a.span)),
                                );
                v = Value::bool(s == "true").with_prov(v.prov.clone());
            }
            self.observe(ctx, file, path, name, &a.value, &v);
            out.attrs.push(Attr {
                name: name.into(),
                value: v,
                span: FileSpan::new(file, a.span),
                from_blocks: false,
            });
        }
        for b in body.blocks() {
            let at = FileSpan::new(ctx.origins.file(b, ctx.file), b.span);
            let ty = b.block_type();
            if top && META_BLOCKS.contains(&ty) {
                continue;
            }
            if ty == "dynamic" {
                let Some(label) = b.label(0) else { continue };
                let Some(content) = b.body.find_block("content") else {
                    continue;
                };
                let (nested, as_attr) = nested_schema(schema, label);
                let it_name: &str = b
                    .body
                    .find_attribute("iterator")
                    .and_then(|a| match &a.value {
                        Expression::Variable(v) => Some(v.name.as_str()),
                        _ => None,
                    })
                    .unwrap_or(label);
                let Some(fe) = b.body.find_attribute("for_each") else {
                    continue;
                };
                let file = ctx.origins.file(fe, ctx.file);
                let fv = self.eval(ctx.inst, file, &fe.value, sc).push(Step::new(
                    StepKind::Iteration,
                    FileSpan::new(file, fe.span),
                    format!("{} dynamic \"{label}\" for_each", ctx.addr),
                ));
                let sub = format!("{path}{label}.");
                self.report_limits(&fv, FileSpan::new(file, fe.span));
                match collection_items(&fv) {
                    Some(items) if items.len() <= self.opts.max_expand => {
                        for (k, v) in items {
                            let it = obj2(k, v);
                            let bd = sc.with(it_name, &it, |s| {
                                self.eval_body(ctx, &content.body, nested, s, &sub, false)
                            });
                            raw.push((label, bd, true, Truth::True, at, as_attr));
                        }
                    }
                    other => {
                        if other.is_some() {
                            self.diag(
                                DiagSeverity::Warning,
                                "coverage-expansion",
                                format!(
                                    "dynamic block exceeds the {} instance limit",
                                    self.opts.max_expand
                                ),
                                Some(FileSpan::new(file, fe.span)),
                            );
                        }
                        if other.is_none() && fv.is_null() {
                            continue;
                        }
                        let (it, ex) = match (&fv.kind, tf_eval::truth::uncertainty(&fv)) {
                            (Kind::Tainted(_), _) => (fv.clone(), Truth::Tainted),
                            (_, Truth::Tainted) => (
                                Value::tainted("(conditional for_each)").with_prov(fv.prov.clone()),
                                Truth::Tainted,
                            ),
                            _ if other.is_some() => (
                                Value::other("dynamic iterator (too many elements)"),
                                Truth::True,
                            ),
                            _ => (
                                Value::other("dynamic iterator (for_each not known)")
                                    .with_prov(fv.prov.clone()),
                                Truth::Unknown,
                            ),
                        };
                        let it = obj2(it.clone(), it);
                        let bd = sc.with(it_name, &it, |s| {
                            self.eval_body(ctx, &content.body, nested, s, &sub, false)
                        });
                        raw.push((label, bd, true, ex, at, as_attr));
                    }
                }
            } else {
                let (nested, as_attr) = nested_schema(schema, ty);
                let sub = format!("{path}{ty}.");
                let bd = self.eval_body(ctx, &b.body, nested, sc, &sub, false);
                raw.push((ty, bd, false, Truth::True, at, as_attr));
            }
        }
        // Group: attributes written as blocks become list-of-object values.
        let mut grouped: Vec<(&'a str, Vec<Value>, FileSpan)> = Vec::new();
        for (name, bd, dynamic, existence, span, as_attr) in raw {
            if as_attr {
                let mut obj = body_to_object(&bd);
                if existence != Truth::True {
                    obj = Value::one_of(vec![obj, Value::null()], existence == Truth::Tainted);
                }
                match grouped.iter_mut().find(|g| g.0 == name) {
                    Some(g) => g.1.push(obj),
                    None => grouped.push((name, vec![obj], span)),
                }
            } else {
                out.blocks.push(model::Block {
                    ty: name.into(),
                    body: bd,
                    dynamic,
                    existence,
                });
            }
        }
        for (name, elems, span) in grouped {
            if out.attrs.iter().any(|a| &*a.name == name) {
                continue;
            }
            out.attrs.push(Attr {
                name: name.into(),
                value: Value::list(elems),
                span,
                from_blocks: true,
            });
        }
        out
    }

    fn report_limits(&self, value: &Value, at: FileSpan) {
        if let Some(o @ (Origin::UnsupportedFunction(_) | Origin::Limit(_))) = value.origin() {
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

fn body_to_object(b: &model::Body) -> Value {
    let mut m = Map::new();
    for a in &b.attrs {
        m.insert(a.name.clone(), a.value.clone());
    }
    let mut lists: Vec<(Arc<str>, Vec<Value>)> = Vec::new();
    for blk in &b.blocks {
        let o = body_to_object(&blk.body);
        match lists.iter_mut().find(|l| l.0 == blk.ty) {
            Some(l) => l.1.push(o),
            None => lists.push((blk.ty.clone(), vec![o])),
        }
    }
    for (k, v) in lists {
        m.entry(k).or_insert_with(|| Value::list(v));
    }
    Value::object(m)
}

fn obj1(k: &str, v: Value) -> Value {
    let mut m = Map::new();
    m.insert(k.into(), v);
    Value::object(m)
}

fn obj2(key: Value, value: Value) -> Value {
    let mut m = Map::new();
    m.insert("key".into(), key);
    m.insert("value".into(), value);
    Value::object(m)
}

/// (key, value) pairs of a Known list (index keys; for sets of strings the
/// element is also the key) or object.
fn collection_items(v: &Value) -> Option<Vec<(Value, Value)>> {
    match &v.kind {
        Kind::Known(Known::List(l)) => Some(
            l.iter()
                .enumerate()
                .map(|(i, x)| {
                    let x = x.child_of(v);
                    let k = if x.as_str().is_some() {
                        x.clone()
                    } else {
                        Value::number(i as f64).inherit_sensitive(v)
                    };
                    (k, x)
                })
                .collect(),
        ),
        Kind::Known(Known::Object(m)) => Some(
            m.iter()
                .map(|(k, x)| (Value::string(k.clone()).inherit_sensitive(v), x.child_of(v)))
                .collect(),
        ),
        _ => None,
    }
}

/// Apply a variable's primitive `type` constraint (bool / number / string).
/// Apply a variable's `type` constraint: primitive conversions
/// (string <-> bool / number), recursively through `list` / `set` / `map` /
/// `tuple` / `object`, and `optional(T, default)` object attributes (absent or
/// null optional attributes become the default, or null).
fn convert_to_type(v: Value, ty: Option<&Expression<'_>>, apply_defaults: bool) -> Value {
    match ty {
        Some(t) => apply_type(v, t, apply_defaults),
        None => v,
    }
}

fn apply_type(v: Value, ty: &Expression<'_>, apply_defaults: bool) -> Value {
    let prov = v.prov.clone();
    match ty.without_parens() {
        Expression::Variable(t) => {
            let out = match (&*t.name, &v.kind) {
                ("bool", Kind::Known(Known::String(s))) if &**s == "true" || &**s == "false" => {
                    Value::bool(&**s == "true")
                }
                ("number", Kind::Known(Known::String(s))) => match s.trim().parse::<f64>() {
                    Ok(n) => Value::number(n),
                    Err(_) => return v,
                },
                ("string", Kind::Known(Known::Number(_) | Known::Bool(_))) => {
                    Value::string(v.to_str().unwrap())
                }
                _ => return v,
            };
            out.with_prov(prov)
        }
        Expression::FunctionCall(f) => {
            let name = f.name.name.as_str();
            let arg = f.arguments.first();
            match (name, &v.kind, arg) {
                ("list" | "set", Kind::Known(Known::List(l)), Some(et)) => Value::list(
                    l.iter()
                        .map(|e| apply_type(e.clone(), et, apply_defaults))
                        .collect(),
                )
                .with_prov(prov),
                ("map", Kind::Known(Known::Object(m)), Some(et)) => Value::object(
                    m.iter()
                        .map(|(k, e)| (k.clone(), apply_type(e.clone(), et, apply_defaults)))
                        .collect(),
                )
                .with_prov(prov),
                ("tuple", Kind::Known(Known::List(l)), Some(Expression::Tuple(ts))) => Value::list(
                    l.iter()
                        .enumerate()
                        .map(|(i, e)| match ts.elements.get(i) {
                            Some(t) => apply_type(e.clone(), t, apply_defaults),
                            None => e.clone(),
                        })
                        .collect(),
                )
                .with_prov(prov),
                ("object", Kind::Known(Known::Object(m)), Some(Expression::Object(o))) => {
                    let mut out = Map::new();
                    for item in o.items.iter() {
                        let Some(k) = item.key.as_static_str() else {
                            continue;
                        };
                        let (inner, default, optional) = match item.value.without_parens() {
                            Expression::FunctionCall(c) if c.name.name.as_str() == "optional" => {
                                (c.arguments.first(), c.arguments.get(1), true)
                            }
                            other => (Some(other), None, false),
                        };
                        let cur = m.get(k).cloned();
                        let val = match cur {
                            Some(x) if !(optional && x.is_null() && apply_defaults) => {
                                match inner {
                                    Some(t) => apply_type(x, t, apply_defaults),
                                    None => x,
                                }
                            }
                            _ if optional => match default.filter(|_| apply_defaults) {
                                Some(d) => {
                                    let dv = Evaluator::new(&NoResolver, FileId(0)).eval_static(d);
                                    match inner {
                                        Some(t) => apply_type(dv, t, apply_defaults),
                                        None => dv,
                                    }
                                }
                                None => Value::null(),
                            },
                            _ => continue,
                        };
                        out.insert(Arc::from(k), val);
                    }
                    Value::object(out).with_prov(prov)
                }
                _ => v,
            }
        }
        _ => v,
    }
}

struct InstResolver<'x, 'a, 'o> {
    an: &'x Analyzer<'a, 'o>,
    inst: usize,
}

impl<'a> Resolver<'a> for InstResolver<'_, 'a, '_> {
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
                let rel = |p: &Path| -> String {
                    match p.strip_prefix(&an.root_dir) {
                        Ok(r) if r.as_os_str().is_empty() => ".".to_string(),
                        Ok(r) => r.display().to_string(),
                        Err(_) => p.display().to_string(),
                    }
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
            "module" => an.module_ref(self.inst, ops, ev, sc),
            "data" => match a0 {
                Some(ty) => {
                    let (v, used) = an.resource_ref(self.inst, Mode::Data, ty, &ops[1..], ev, sc);
                    (v, used + 1)
                }
                None => (Value::error("invalid data reference"), 0),
            },
            ty => an.resource_ref(self.inst, Mode::Managed, ty, ops, ev, sc),
        }
    }
}

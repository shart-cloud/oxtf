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
use crate::model::{self, AnalysisStats, Attr, DiagSeverity, Diagnostic};
use crate::module::{
    Mode, ModuleDef, ModuleSource, ResourceDecl, SymbolRef, auto_tfvars, module_files,
};
use crate::source::{FileTable, SourceFile, normalize};
use crate::store::ModuleStore;

/// Options for [`analyze_module`].
#[derive(Clone, Debug)]
pub struct AnalyzeOptions {
    /// Extra `-var-file`s, applied after `terraform.tfvars` and
    /// `*.auto.tfvars` (later wins).
    pub var_files: Vec<PathBuf>,
    /// Maximum depth of local child modules followed.
    pub max_module_depth: usize,
    /// `for_each` / `dynamic` collections larger than this are evaluated as
    /// one abstract instance instead of being expanded.
    pub max_expand: usize,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        AnalyzeOptions {
            var_files: Vec::new(),
            max_module_depth: 10,
            max_expand: 64,
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

/// Analyse the root module in `dir` (and every local child module it
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
    key: Option<Arc<str>>,
    binds: Vec<(&'static str, Value)>,
    existence: Truth,
}

type Children = Option<Rc<Vec<(Option<Arc<str>>, usize)>>>;
type ResAttrKey = (usize, Option<Arc<str>>, String);
type Expansion = (Vec<InstBind>, Option<Value>, Option<Value>);

struct Instance<'a> {
    def: &'a ModuleDef<'a>,
    address: Arc<str>,
    parent: Option<(usize, usize)>,
    binds: Vec<(&'static str, Value)>,
    existence: Truth,
    ancestors: Vec<PathBuf>,
    children: RefCell<HashMap<usize, Children>>,
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
    /// Definitions this root has taken from the store, by directory; the
    /// store's lookup is a lock and a hash, this one is a hash.
    defs: RefCell<HashMap<PathBuf, &'a ModuleDef<'a>>>,
    insts: RefCell<Vec<Rc<Instance<'a>>>>,
    tfvars: Vec<TfvarsBinding<'a>>,
    diags: RefCell<Vec<Diagnostic>>,
    depth: Cell<u32>,
    observer: RefCell<Option<Observer<'o>>>,
    attr_count: Cell<usize>,
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
                    let parsed = store.file(&sf);
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
            root_dir,
            defs: RefCell::new(HashMap::default()),
            insts: RefCell::new(Vec::new()),
            tfvars,
            diags: RefCell::new(diags),
            depth: Cell::new(0),
            observer: RefCell::new(observer),
            attr_count: Cell::new(0),
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
    ) -> usize {
        let inst = Instance {
            def,
            address,
            parent,
            binds: bind.binds,
            existence: bind.existence,
            ancestors,
            children: RefCell::new(HashMap::default()),
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
            return Value::error(format!("evaluation too deep at {}", what()));
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
                    let v = self.eval_const(decl.file, &d.value);
                    Some(v.push(Step::new(
                        StepKind::VariableDefault,
                        FileSpan::new(decl.file, d.span),
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
                                let v = Scope::EMPTY.with_all(&inst.binds, |sc| {
                                    self.eval(pid, call.file, &arg.value, sc)
                                });
                                v.push(Step::new(
                                    StepKind::ModuleArgument,
                                    FileSpan::new(call.file, arg.span),
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
                convert_to_type(v, decl.ty)
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
                v.push(Step::new(
                    StepKind::Local,
                    FileSpan::new(decl.file, decl.attr.span),
                    format!("local.{name}"),
                ))
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
                let v = self.eval(inst_id, decl.file, &va.value, Scope::EMPTY);
                v.push(Step::new(
                    StepKind::Output,
                    FileSpan::new(decl.file, va.span),
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

    fn expand(
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
                    Some(n) if n <= 0.0 => vec![],
                    Some(1.0) => vec![InstBind {
                        key: None,
                        binds: vec![("count", obj1("index", Value::number(0.0)))],
                        existence: Truth::True,
                    }],
                    Some(_) => vec![abstract_count(Truth::True)],
                    None => vec![abstract_count(Truth::Unknown)],
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
            return (r, Some(v), None);
        }
        if let Some(fe) = body.find_attribute("for_each") {
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
                            key: Some(key),
                            binds: vec![("each", Value::object(m))],
                            existence: Truth::True,
                        }
                    })
                    .collect(),
                Some(_) => {
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
            return (r, None, Some(v));
        }
        (vec![single()], None, None)
    }

    fn res_instances(
        &self,
        inst_id: usize,
        ri: usize,
    ) -> Rc<(Vec<InstBind>, Option<Value>, Option<Value>)> {
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
                )),
            };
        }
        inst.res_insts.borrow_mut().insert(ri, None);
        let decl = &inst.def.resources[ri];
        let r = Rc::new(self.expand(inst_id, decl.file, &decl.block.body, Scope::EMPTY));
        inst.res_insts.borrow_mut().insert(ri, Some(r.clone()));
        r
    }

    fn children_of(&self, inst_id: usize, ci: usize) -> Rc<Vec<(Option<Arc<str>>, usize)>> {
        let inst = self.inst(inst_id);
        if let Some(s) = inst.children.borrow().get(&ci) {
            return s.clone().unwrap_or_default();
        }
        inst.children.borrow_mut().insert(ci, None);
        let call = &inst.def.module_calls[ci];
        let mut out = Vec::new();
        if let ModuleSource::Local(dir) = &call.source {
            let at = Some(FileSpan::new(call.file, header_span(call.block)));
            if inst.ancestors.contains(dir) {
                self.diag(
                    DiagSeverity::Warning,
                    "module-cycle",
                    format!(
                        "module.{} calls an ancestor module ({})",
                        call.name,
                        dir.display()
                    ),
                    at,
                );
            } else if inst.ancestors.len() > self.opts.max_module_depth {
                self.diag(
                    DiagSeverity::Warning,
                    "module-depth",
                    format!(
                        "module.{}: nesting deeper than {}",
                        call.name, self.opts.max_module_depth
                    ),
                    at,
                );
            } else if module_files(self.files, dir).is_empty() {
                self.diag(
                    DiagSeverity::Warning,
                    "module-missing",
                    format!("module.{}: no .tf files in {}", call.name, dir.display()),
                    at,
                );
            } else {
                let def = self.load_def(dir);
                let (binds, _, _) = self.expand(inst_id, call.file, &call.block.body, Scope::EMPTY);
                let mut anc = inst.ancestors.clone();
                anc.push(dir.clone());
                for b in binds {
                    let addr = match &b.key {
                        Some(k) => format!(
                            "{}module.{}[{}]",
                            inst.prefix(),
                            call.name,
                            crate::address::quote(k)
                        ),
                        None => format!("{}module.{}", inst.prefix(), call.name),
                    };
                    let key = b.key.clone();
                    let b = InstBind {
                        existence: b.existence.min(inst.existence),
                        ..b
                    };
                    let id =
                        self.new_instance(def, addr.into(), Some((inst_id, ci)), b, anc.clone());
                    out.push((key, id));
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
        let mut key: Option<Arc<str>> = None;
        let mut splat = false;
        match ops.get(1) {
            Some(TraversalOperator::Index(ix)) => {
                key = ev.eval(&ix.index, sc).to_str();
                i = 2;
            }
            Some(TraversalOperator::LegacyIndex(l)) => {
                key = Some(l.index.to_string().into());
                i = 2;
            }
            Some(TraversalOperator::FullSplat(_) | TraversalOperator::AttrSplat(_)) => {
                splat = true;
                i = 2;
            }
            _ => {}
        }
        let base = Address::new(inst.address.clone(), mode, ty, name, None);
        let Some(attr) = ops.get(i).and_then(|o| o.attr_name()) else {
            let instance = base.with_key(key.map(InstanceKey::Key));
            return (Value::unknown(instance.computed("(whole object)")), i);
        };
        let v = self.resource_attr(inst_id, ri, key, attr, &base);
        (if splat { Value::list(vec![v]) } else { v }, i + 1)
    }

    fn resource_attr(
        &self,
        inst_id: usize,
        ri: usize,
        key: Option<Arc<str>>,
        attr: &str,
        base: &Address,
    ) -> Value {
        let inst = self.inst(inst_id);
        let k = (ri, key.clone(), attr.to_string());
        let instance = base.clone().with_key(key.clone().map(InstanceKey::Key));
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
                    return self.iam_policy_document(inst_id, ri, key.as_deref(), &base_str);
                }
                if let Some(a) = decl
                    .block
                    .body
                    .find_attribute(attr)
                    .filter(|_| !META_ATTRS.contains(&attr))
                {
                    let insts = self.res_instances(inst_id, ri);
                    let chosen = match &key {
                        Some(k) => insts.0.iter().find(|b| b.key.as_deref() == Some(&**k)),
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
                    let v = Scope::EMPTY
                        .with_all(&binds, |sc| self.eval(inst_id, decl.file, &a.value, sc));
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
                            FileSpan::new(decl.file, a.span),
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
        let mut i = 1;
        let mut key: Option<Value> = None;
        match ops.get(1) {
            Some(TraversalOperator::Index(ix)) => {
                key = Some(ev.eval(&ix.index, sc));
                i = 2;
            }
            Some(TraversalOperator::LegacyIndex(l)) => {
                key = Some(Value::number(l.index as f64));
                i = 2;
            }
            _ => {}
        }
        let out = ops.get(i).and_then(|o| o.attr_name());
        let call = &inst.def.module_calls[ci];
        let maddr = format!("{}module.{name}", inst.prefix());
        match &call.source {
            ModuleSource::Remote(_) => {
                let o = out.unwrap_or("(whole object)");
                (
                    Value::unknown(Origin::RemoteModule {
                        module: maddr.into(),
                        output: o.into(),
                    }),
                    if out.is_some() { i + 1 } else { i },
                )
            }
            ModuleSource::Invalid => (
                Value::other(format!("{maddr}: module source not a literal")),
                i,
            ),
            ModuleSource::Local(_) => {
                let kids = self.children_of(inst_id, ci);
                let Some(out) = out else {
                    return (Value::other(format!("{maddr} (whole module object)")), i);
                };
                let kid = match key.as_ref().and_then(|k| k.to_str()) {
                    Some(k) => kids
                        .iter()
                        .find(|(kk, _)| kk.as_deref() == Some(&*k))
                        .or(if kids.len() == 1 { kids.first() } else { None }),
                    None => {
                        if kids.len() == 1 {
                            kids.first()
                        } else {
                            None
                        }
                    }
                };
                let v = match kid {
                    Some((_, kid)) => self.output_value(*kid, out),
                    None if kids.is_empty() => {
                        Value::other(format!("{maddr}: module not instantiated"))
                    }
                    None => Value::one_of(
                        kids.iter()
                            .map(|(_, k)| self.output_value(*k, out))
                            .collect(),
                        false,
                    ),
                };
                (v, i + 1)
            }
        }
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
        key: Option<&str>,
        base: &str,
    ) -> Value {
        let inst = self.inst(inst_id);
        let decl = &inst.def.resources[ri];
        let insts = self.res_instances(inst_id, ri);
        let binds: Vec<(&str, Value)> = key
            .and_then(|k| insts.0.iter().find(|b| b.key.as_deref() == Some(k)))
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
                let id = decl_id
                    .clone()
                    .with_key(b.key.clone().map(InstanceKey::Key));
                let address: Arc<str> = id.to_string().into();
                let ctx = BodyCtx {
                    inst: inst_id,
                    file: decl.file,
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
                resources.push(model::Resource::new(
                    id,
                    FileSpan::new(decl.file, header_span(decl.block)),
                    body,
                    b.existence.min(inst.existence),
                    insts.1.clone(),
                    insts.2.clone(),
                    decl.schema.map(|s| s.provider),
                ));
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
        model::Module {
            address: inst.address.clone(),
            dir: def.dir.clone(),
            parent: inst.parent.map(|p| p.0),
            resources,
            variables,
            outputs,
            module_calls,
            symbols,
            references: def.references.clone(),
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
            span: FileSpan::new(ctx.file, body.span),
            attrs: Vec::new(),
            blocks: Vec::new(),
        };
        // (name, body, dynamic, existence, span, attribute-as-blocks)
        let mut raw: Vec<(&'a str, model::Body, bool, Truth, Span, bool)> = Vec::new();
        for a in body.attributes() {
            let name = a.key.name.as_str();
            if top && META_ATTRS.contains(&name) {
                continue;
            }
            let mut v = self.eval(ctx.inst, ctx.file, &a.value, sc).push(
                Step::new(
                    StepKind::Attribute,
                    FileSpan::new(ctx.file, a.span),
                    format!("{} {path}{name}", ctx.addr),
                )
                .with_resource(ctx.base.clone())
                .with_attribute(format!("{path}{name}")),
            );
            if ctx.strict_bool
                && let Some(at) = schema.and_then(|s| s.attribute(name))
                && at.is_bool()
                && let Some(s) = v.as_str()
                && (s == "true" || s == "false")
            {
                self.diag(
                                    DiagSeverity::Warning,
                                    "strict-bool",
                                    format!("{} {path}{name}: string \"{s}\" where the AWS provider schema requires a bool; Terraform converts it, but write {s} without quotes", ctx.addr),
                                    Some(FileSpan::new(ctx.file, a.span)),
                                );
                v = Value::bool(s == "true").with_prov(v.prov.clone());
            }
            self.observe(ctx, path, name, &a.value, &v);
            out.attrs.push(Attr {
                name: name.into(),
                value: v,
                span: FileSpan::new(ctx.file, a.span),
                from_blocks: false,
            });
        }
        for b in body.blocks() {
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
                let fv = self.eval(ctx.inst, ctx.file, &fe.value, sc).push(Step::new(
                    StepKind::Iteration,
                    FileSpan::new(ctx.file, fe.span),
                    format!("{} dynamic \"{label}\" for_each", ctx.addr),
                ));
                let sub = format!("{path}{label}.");
                match collection_items(&fv) {
                    Some(items) if items.len() <= self.opts.max_expand => {
                        for (k, v) in items {
                            let it = obj2(k, v);
                            let bd = sc.with(it_name, &it, |s| {
                                self.eval_body(ctx, &content.body, nested, s, &sub, false)
                            });
                            raw.push((label, bd, true, Truth::True, b.span, as_attr));
                        }
                    }
                    other => {
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
                        raw.push((label, bd, true, ex, b.span, as_attr));
                    }
                }
            } else {
                let (nested, as_attr) = nested_schema(schema, ty);
                let sub = format!("{path}{ty}.");
                let bd = self.eval_body(ctx, &b.body, nested, sc, &sub, false);
                raw.push((ty, bd, false, Truth::True, b.span, as_attr));
            }
        }
        // Group: attributes written as blocks become list-of-object values.
        let mut grouped: Vec<(&'a str, Vec<Value>, Span)> = Vec::new();
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
                span: FileSpan::new(ctx.file, span),
                from_blocks: true,
            });
        }
        out
    }

    fn observe(
        &self,
        ctx: &BodyCtx<'a>,
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
                file: ctx.file,
                expr,
                value: v,
            });
        }
    }
}

struct BodyCtx<'a> {
    inst: usize,
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
                        Value::number(i as f64)
                    };
                    (k, x)
                })
                .collect(),
        ),
        Kind::Known(Known::Object(m)) => Some(
            m.iter()
                .map(|(k, x)| (Value::string(k.clone()), x.child_of(v)))
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
fn convert_to_type(v: Value, ty: Option<&Expression<'_>>) -> Value {
    match ty {
        Some(t) => apply_type(v, t),
        None => v,
    }
}

fn apply_type(v: Value, ty: &Expression<'_>) -> Value {
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
                ("list" | "set", Kind::Known(Known::List(l)), Some(et)) => {
                    Value::list(l.iter().map(|e| apply_type(e.clone(), et)).collect())
                        .with_prov(prov)
                }
                ("map", Kind::Known(Known::Object(m)), Some(et)) => Value::object(
                    m.iter()
                        .map(|(k, e)| (k.clone(), apply_type(e.clone(), et)))
                        .collect(),
                )
                .with_prov(prov),
                ("tuple", Kind::Known(Known::List(l)), Some(Expression::Tuple(ts))) => Value::list(
                    l.iter()
                        .enumerate()
                        .map(|(i, e)| match ts.elements.get(i) {
                            Some(t) => apply_type(e.clone(), t),
                            None => e.clone(),
                        })
                        .collect(),
                )
                .with_prov(prov),
                ("object", Kind::Known(Known::Object(m)), Some(Expression::Object(o))) => {
                    let mut out = (**m).clone();
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
                        let cur = out.get(k).cloned();
                        let val = match cur {
                            Some(x) if !(optional && x.is_null()) => match inner {
                                Some(t) => apply_type(x, t),
                                None => x,
                            },
                            _ if optional => match default {
                                Some(d) => {
                                    let dv = Evaluator::new(&NoResolver, FileId(0)).eval_static(d);
                                    match inner {
                                        Some(t) => apply_type(dv, t),
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

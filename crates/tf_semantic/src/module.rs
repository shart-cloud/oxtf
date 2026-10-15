//! Module assembly and the symbol table.
//!
//! A module is every `.tf` file in one directory. Its symbol table holds the
//! declared `variable`, `locals` entries, `resource`, `data`, `module` and
//! `output` blocks, plus a reference edge for every traversal root found in
//! their expressions (lexical names bound by `for`, `dynamic` iterators,
//! `each`, `count`, `self` are recorded as implicit references).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tf_allocator::Allocator;
use tf_ast::{Attribute, Block, Body, Expression, ObjectKey, TemplateElement, TraversalOperator};
use tf_span::{FileId, FileSpan, Span};

use crate::source::{FileTable, SourceFile, normalize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Mode {
    Managed,
    Data,
}

pub struct VarDecl<'a> {
    pub name: &'a str,
    pub block: &'a Block<'a>,
    pub file: FileId,
    pub default: Option<&'a Attribute<'a>>,
    pub ty: Option<&'a Expression<'a>>,
    /// `nullable = false`: a null argument means "use the default".
    pub non_nullable: bool,
}

pub struct LocalDecl<'a> {
    pub name: &'a str,
    pub attr: &'a Attribute<'a>,
    pub file: FileId,
}

pub struct ResourceDecl<'a> {
    pub mode: Mode,
    pub ty: &'a str,
    pub name: &'a str,
    pub block: &'a Block<'a>,
    pub file: FileId,
    pub schema: Option<&'static tf_schema::ResourceSchema>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ModuleSource {
    /// `./x` or `../x`, resolved against the calling module's directory.
    Local(PathBuf),
    /// Registry, git, http, s3, ...: not fetched; outputs are Unknown.
    Remote(String),
    /// `source` missing or not a literal string.
    Invalid,
}

pub struct ModuleCall<'a> {
    pub name: &'a str,
    pub block: &'a Block<'a>,
    pub file: FileId,
    pub source: ModuleSource,
}

pub struct OutputDecl<'a> {
    pub name: &'a str,
    pub block: &'a Block<'a>,
    pub file: FileId,
    pub value: Option<&'a Attribute<'a>>,
}

/// A declared symbol, addressable as in Terraform (`var.x`, `local.y`,
/// `aws_s3_bucket.b`, `data.aws_caller_identity.c`, `module.m`,
/// `output.o`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SymbolRef {
    Variable(String),
    Local(String),
    Resource(String, String),
    Data(String, String),
    Module(String),
    Output(String),
    /// `count`, `each`, `self`, `path`, `terraform`, a `for` variable or a
    /// `dynamic` iterator.
    Implicit(String),
    /// A root that does not name any declaration.
    Unresolved(String),
}

impl std::fmt::Display for SymbolRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymbolRef::Variable(n) => write!(f, "var.{n}"),
            SymbolRef::Local(n) => write!(f, "local.{n}"),
            SymbolRef::Resource(t, n) => write!(f, "{t}.{n}"),
            SymbolRef::Data(t, n) => write!(f, "data.{t}.{n}"),
            SymbolRef::Module(n) => write!(f, "module.{n}"),
            SymbolRef::Output(n) => write!(f, "output.{n}"),
            SymbolRef::Implicit(n) => write!(f, "{n} (implicit)"),
            SymbolRef::Unresolved(n) => write!(f, "{n} (unresolved)"),
        }
    }
}

/// A reference edge: `from` uses `to` at `at`.
#[derive(Clone, Debug)]
pub struct Reference {
    pub from: SymbolRef,
    pub to: SymbolRef,
    pub at: FileSpan,
}

/// A parsed module directory. Borrows the arena.
pub struct ModuleDef<'a> {
    pub dir: PathBuf,
    pub files: Vec<(Arc<SourceFile>, &'a tf_ast::File<'a>)>,
    pub variables: Vec<VarDecl<'a>>,
    pub locals: Vec<LocalDecl<'a>>,
    pub resources: Vec<ResourceDecl<'a>>,
    pub module_calls: Vec<ModuleCall<'a>>,
    pub outputs: Vec<OutputDecl<'a>>,
    pub references: Vec<Reference>,
    pub parse_errors: Vec<(FileSpan, String)>,
    var_index: HashMap<&'a str, usize>,
    local_index: HashMap<&'a str, usize>,
    res_index: HashMap<(Mode, &'a str, &'a str), usize>,
    call_index: HashMap<&'a str, usize>,
    output_index: HashMap<&'a str, usize>,
}

impl<'a> ModuleDef<'a> {
    pub fn variable(&self, name: &str) -> Option<&VarDecl<'a>> {
        self.var_index.get(name).map(|&i| &self.variables[i])
    }
    pub fn local(&self, name: &str) -> Option<&LocalDecl<'a>> {
        self.local_index.get(name).map(|&i| &self.locals[i])
    }
    pub fn resource_index(&self, mode: Mode, ty: &str, name: &str) -> Option<usize> {
        self.res_index.get(&(mode, ty, name)).copied()
    }
    pub fn module_call(&self, name: &str) -> Option<usize> {
        self.call_index.get(name).copied()
    }
    pub fn output(&self, name: &str) -> Option<&OutputDecl<'a>> {
        self.output_index.get(name).map(|&i| &self.outputs[i])
    }
    pub fn file_source(&self, id: FileId) -> Option<&Arc<SourceFile>> {
        self.files.iter().map(|(f, _)| f).find(|f| f.id == id)
    }
}

/// The `.tf` files of a directory, sorted by name, as the file table sees
/// it (overlay included). (`.tf.json` and override files are not handled
/// specially: see W3 scope cuts.)
pub fn module_files(files: &FileTable, dir: &Path) -> Vec<PathBuf> {
    files
        .read_dir(dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|x| x == "tf"))
        .collect()
}

/// `terraform.tfvars` then `*.auto.tfvars` (lexical order), as Terraform
/// loads them; later files win.
pub fn auto_tfvars(files: &FileTable, dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    let t = dir.join("terraform.tfvars");
    if files.is_file(&t) {
        v.push(t);
    }
    v.extend(files.read_dir(dir).into_iter().filter(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".auto.tfvars"))
    }));
    v
}

/// Parse one file into the arena.
pub fn parse_file<'a>(
    alloc: &'a Allocator,
    sf: &Arc<SourceFile>,
    errors: &mut Vec<(FileSpan, String)>,
) -> &'a tf_ast::File<'a> {
    let text: &'a str = alloc.alloc_str(&sf.text);
    let ret = tf_parser::parse(alloc, text);
    for e in ret.errors {
        errors.push((FileSpan::new(sf.id, e.span), e.message));
    }
    alloc.alloc(ret.file)
}

/// Load and index a module directory.
pub fn load_module<'a>(alloc: &'a Allocator, files: &FileTable, dir: &Path) -> ModuleDef<'a> {
    let dir = normalize(dir);
    let mut def = ModuleDef {
        dir: dir.clone(),
        files: Vec::new(),
        variables: Vec::new(),
        locals: Vec::new(),
        resources: Vec::new(),
        module_calls: Vec::new(),
        outputs: Vec::new(),
        references: Vec::new(),
        parse_errors: Vec::new(),
        var_index: HashMap::new(),
        local_index: HashMap::new(),
        res_index: HashMap::new(),
        call_index: HashMap::new(),
        output_index: HashMap::new(),
    };
    for p in module_files(files, &dir) {
        let Ok(sf) = files.load(&p) else { continue };
        let f = parse_file(alloc, &sf, &mut def.parse_errors);
        def.files.push((sf, f));
    }
    let file_list: Vec<(FileId, &'a tf_ast::File<'a>)> =
        def.files.iter().map(|(s, f)| (s.id, *f)).collect();
    for (fid, f) in file_list {
        for b in f.body.blocks() {
            index_block(&mut def, fid, b);
        }
    }
    collect_references(&mut def);
    def
}

fn index_block<'a>(def: &mut ModuleDef<'a>, file: FileId, b: &'a Block<'a>) {
    match b.block_type() {
        "variable" => {
            if let Some(name) = b.label(0) {
                def.var_index.entry(name).or_insert(def.variables.len());
                def.variables.push(VarDecl {
                    name,
                    block: b,
                    file,
                    default: b.body.find_attribute("default"),
                    ty: b.body.find_attribute("type").map(|a| &a.value),
                    non_nullable: b
                        .body
                        .find_attribute("nullable")
                        .is_some_and(|a| matches!(&a.value, Expression::Bool(x) if !x.value)),
                });
            }
        }
        "locals" => {
            for a in b.body.attributes() {
                let name = a.key.name.as_str();
                def.local_index.entry(name).or_insert(def.locals.len());
                def.locals.push(LocalDecl {
                    name,
                    attr: a,
                    file,
                });
            }
        }
        "resource" | "data" => {
            let mode = if b.block_type() == "resource" {
                Mode::Managed
            } else {
                Mode::Data
            };
            if let (Some(ty), Some(name)) = (b.label(0), b.label(1)) {
                let schema = match mode {
                    Mode::Managed => tf_schema::lookup_resource(ty),
                    Mode::Data => tf_schema::lookup_data_source(ty),
                };
                def.res_index
                    .entry((mode, ty, name))
                    .or_insert(def.resources.len());
                def.resources.push(ResourceDecl {
                    mode,
                    ty,
                    name,
                    block: b,
                    file,
                    schema,
                });
            }
        }
        "module" => {
            if let Some(name) = b.label(0) {
                let source = match b
                    .body
                    .find_attribute("source")
                    .and_then(|a| a.value.as_string_literal())
                {
                    Some(s)
                        if s.starts_with("./") || s.starts_with("../") || s == "." || s == ".." =>
                    {
                        ModuleSource::Local(normalize(&def.dir.join(s)))
                    }
                    Some(s) => ModuleSource::Remote(s.to_string()),
                    None => ModuleSource::Invalid,
                };
                def.call_index.entry(name).or_insert(def.module_calls.len());
                def.module_calls.push(ModuleCall {
                    name,
                    block: b,
                    file,
                    source,
                });
            }
        }
        "output" => {
            if let Some(name) = b.label(0) {
                def.output_index.entry(name).or_insert(def.outputs.len());
                def.outputs.push(OutputDecl {
                    name,
                    block: b,
                    file,
                    value: b.body.find_attribute("value"),
                });
            }
        }
        _ => {}
    }
}

// ---- reference collection ---------------------------------------------------

const IMPLICIT: &[&str] = &["count", "each", "self", "path", "terraform"];

struct RefCollector<'m, 'd> {
    file: FileId,
    from: SymbolRef,
    bound: Vec<&'d str>,
    out: Vec<Reference>,
    vars: &'m HashMap<&'d str, usize>,
    locals: &'m HashMap<&'d str, usize>,
    res: &'m HashMap<(Mode, &'d str, &'d str), usize>,
    calls: &'m HashMap<&'d str, usize>,
}

impl<'d> RefCollector<'_, 'd> {
    fn root(&mut self, root: &str, ops: &[TraversalOperator<'_>], span: Span) {
        let at = FileSpan::new(self.file, span);
        let a0 = ops.first().and_then(|o| o.attr_name());
        let a1 = ops.get(1).and_then(|o| o.attr_name());
        let to = if self.bound.contains(&root) || IMPLICIT.contains(&root) {
            SymbolRef::Implicit(root.to_string())
        } else {
            match (root, a0, a1) {
                ("var", Some(n), _) => {
                    if self.vars.contains_key(n) {
                        SymbolRef::Variable(n.into())
                    } else {
                        SymbolRef::Unresolved(format!("var.{n}"))
                    }
                }
                ("local", Some(n), _) => {
                    if self.locals.contains_key(n) {
                        SymbolRef::Local(n.into())
                    } else {
                        SymbolRef::Unresolved(format!("local.{n}"))
                    }
                }
                ("module", Some(n), _) => {
                    if self.calls.contains_key(n) {
                        SymbolRef::Module(n.into())
                    } else {
                        SymbolRef::Unresolved(format!("module.{n}"))
                    }
                }
                ("data", Some(t), Some(n)) => {
                    if self.res.contains_key(&(Mode::Data, t, n)) {
                        SymbolRef::Data(t.into(), n.into())
                    } else {
                        SymbolRef::Unresolved(format!("data.{t}.{n}"))
                    }
                }
                (t, Some(n), _) if self.res.contains_key(&(Mode::Managed, t, n)) => {
                    SymbolRef::Resource(t.into(), n.into())
                }
                (r, _, _) => SymbolRef::Unresolved(r.to_string()),
            }
        };
        self.out.push(Reference {
            from: self.from.clone(),
            to,
            at,
        });
    }

    fn expr(&mut self, e: &'d Expression<'d>) {
        match e {
            Expression::Variable(v) => self.root(&v.name, &[], v.span),
            Expression::Traversal(t) => {
                if let Expression::Variable(v) = &t.object {
                    self.root(&v.name, &t.operators, t.span);
                } else {
                    self.expr(&t.object);
                }
                for op in t.operators.iter() {
                    if let TraversalOperator::Index(ix) = op {
                        self.expr(&ix.index);
                    }
                }
            }
            Expression::Template(t) => self.template(&t.template),
            Expression::Heredoc(h) => self.template(&h.template),
            Expression::FunctionCall(f) => f.arguments.iter().for_each(|a| self.expr(a)),
            Expression::Tuple(t) => t.elements.iter().for_each(|a| self.expr(a)),
            Expression::Object(o) => {
                for it in o.items.iter() {
                    if let ObjectKey::Expression(k) = &it.key {
                        // `{ (var.k) = v }`; a bare traversal key is still an expression
                        self.expr(k);
                    }
                    self.expr(&it.value);
                }
            }
            Expression::For(f) => {
                self.expr(&f.collection);
                let n = self.bound.len();
                if let Some(k) = &f.key_var {
                    self.bound.push(k.name.as_str());
                }
                self.bound.push(f.value_var.name.as_str());
                if let Some(k) = &f.key_expr {
                    self.expr(k);
                }
                self.expr(&f.value_expr);
                if let Some(c) = &f.condition {
                    self.expr(c);
                }
                self.bound.truncate(n);
            }
            Expression::Conditional(c) => {
                self.expr(&c.condition);
                self.expr(&c.true_expr);
                self.expr(&c.false_expr);
            }
            Expression::Unary(u) => self.expr(&u.operand),
            Expression::Binary(b) => {
                self.expr(&b.left);
                self.expr(&b.right);
            }
            Expression::Parenthesized(p) => self.expr(&p.expression),
            _ => {}
        }
    }

    fn template(&mut self, t: &'d tf_ast::Template<'d>) {
        for el in t.elements.iter() {
            match el {
                TemplateElement::Literal(_) => {}
                TemplateElement::Interpolation(i) => self.expr(&i.expression),
                TemplateElement::If(i) => {
                    self.expr(&i.condition);
                    self.template(&i.then_template);
                    if let Some(e) = &i.else_template {
                        self.template(e);
                    }
                }
                TemplateElement::For(f) => {
                    self.expr(&f.collection);
                    let n = self.bound.len();
                    if let Some(k) = &f.key_var {
                        self.bound.push(k.name.as_str());
                    }
                    self.bound.push(f.value_var.name.as_str());
                    self.template(&f.template);
                    self.bound.truncate(n);
                }
            }
        }
    }

    fn body(&mut self, b: &'d Body<'d>) {
        for a in b.attributes() {
            self.expr(&a.value);
        }
        for blk in b.blocks() {
            if blk.block_type() == "dynamic" {
                let it = blk
                    .body
                    .find_attribute("iterator")
                    .and_then(|a| match &a.value {
                        Expression::Variable(v) => Some(v.name.as_str()),
                        _ => None,
                    })
                    .or(blk.label(0))
                    .unwrap_or("");
                if let Some(fe) = blk.body.find_attribute("for_each") {
                    self.expr(&fe.value);
                }
                self.bound.push(it);
                if let Some(c) = blk.body.find_block("content") {
                    self.body(&c.body);
                }
                self.bound.pop();
            } else {
                self.body(&blk.body);
            }
        }
    }
}

fn collect_references<'a>(def: &mut ModuleDef<'a>) {
    let mut out = Vec::new();
    {
        let d: &ModuleDef<'a> = def;
        let mut c = RefCollector {
            file: FileId(0),
            from: SymbolRef::Unresolved(String::new()),
            bound: Vec::new(),
            out: Vec::new(),
            vars: &d.var_index,
            locals: &d.local_index,
            res: &d.res_index,
            calls: &d.call_index,
        };
        for v in &d.variables {
            c.file = v.file;
            c.from = SymbolRef::Variable(v.name.into());
            if let Some(a) = v.default {
                c.expr(&a.value);
            }
        }
        for l in &d.locals {
            c.file = l.file;
            c.from = SymbolRef::Local(l.name.into());
            c.expr(&l.attr.value);
        }
        for r in &d.resources {
            c.file = r.file;
            c.from = match r.mode {
                Mode::Managed => SymbolRef::Resource(r.ty.into(), r.name.into()),
                Mode::Data => SymbolRef::Data(r.ty.into(), r.name.into()),
            };
            c.body(&r.block.body);
        }
        for m in &d.module_calls {
            c.file = m.file;
            c.from = SymbolRef::Module(m.name.into());
            c.body(&m.block.body);
        }
        for o in &d.outputs {
            c.file = o.file;
            c.from = SymbolRef::Output(o.name.into());
            c.body(&o.block.body);
        }
        out.append(&mut c.out);
    }
    def.references = out;
}

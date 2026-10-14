//! The owned, evaluated module/resource model: what rules (and the Python
//! bindings) see. Nothing here borrows the AST arena; values are
//! `tf_eval::Value`s (Arc-shared, `Send + Sync`) with provenance chains of
//! `FileSpan`s that resolve through the scan's `FileTable`.

use std::path::PathBuf;
use std::sync::Arc;

use tf_eval::{Prov, Step, StepKind, Truth, Value};
use tf_schema::DefaultValue;
use tf_span::FileSpan;

pub use crate::module::{Mode, SymbolRef};

/// An attribute in configuration, evaluated.
#[derive(Clone, Debug)]
pub struct Attr {
    pub name: Arc<str>,
    pub value: Value,
    /// The attribute (or, for attributes written in block syntax, the first
    /// block) in source.
    pub span: FileSpan,
    /// Written as blocks (`ingress { ... }`) for an attribute whose schema
    /// type is a list/set of objects (Terraform's attributes-as-blocks). The
    /// value is then a list of objects, one per block (`dynamic` expanded).
    pub from_blocks: bool,
}

/// A nested block, evaluated.
#[derive(Clone, Debug)]
pub struct Block {
    pub ty: Arc<str>,
    pub body: Body,
    /// Produced by a `dynamic` block.
    pub dynamic: bool,
    /// `True` normally; `Tainted` / `Unknown` for the single abstract
    /// instance of a `dynamic` block whose `for_each` is not known.
    pub existence: Truth,
}

#[derive(Clone, Debug, Default)]
pub struct Body {
    pub span: FileSpan,
    pub attrs: Vec<Attr>,
    pub blocks: Vec<Block>,
}

impl Body {
    pub fn attr(&self, name: &str) -> Option<&Attr> {
        self.attrs.iter().find(|a| &*a.name == name)
    }
    pub fn value(&self, name: &str) -> Option<&Value> {
        self.attr(name).map(|a| &a.value)
    }
    pub fn blocks_of<'s>(&'s self, ty: &'s str) -> impl Iterator<Item = &'s Block> + 's {
        self.blocks.iter().filter(move |b| &*b.ty == ty)
    }
}

/// One resource or data-source instance.
#[derive(Clone, Debug)]
pub struct Resource {
    pub mode: Mode,
    pub ty: Arc<str>,
    pub name: Arc<str>,
    /// Instance key for expanded `for_each` instances (`"a"`), or `None` for
    /// a single / representative instance.
    pub key: Option<Arc<str>>,
    /// Full address: `module.m.aws_s3_bucket.b["a"]`.
    pub address: Arc<str>,
    /// Address without instance key: `module.m.aws_s3_bucket.b`.
    pub base_address: Arc<str>,
    /// Module instance address (`""` for the root module).
    pub module: Arc<str>,
    /// The block header (`resource "aws_s3_bucket" "b"`).
    pub span: FileSpan,
    pub body: Body,
    /// Does this instance exist? `True`; `Tainted` when `count` / `for_each`
    /// depends on an unconstrained variable; `Unknown` when it depends on
    /// apply-time data.
    pub existence: Truth,
    /// `count` / `for_each` as evaluated (if present).
    pub count: Option<Value>,
    pub for_each: Option<Value>,
    pub provider: Option<tf_schema::Provider>,
}

impl Resource {
    pub fn attr(&self, name: &str) -> Option<&Attr> {
        self.body.attr(name)
    }

    /// The configured value of top-level attribute `name`.
    pub fn value(&self, name: &str) -> Option<Value> {
        self.body.value(name).cloned()
    }

    /// The configured value, or the provider default from the defaults
    /// overlay (`defaults/*.toml`) when absent, with a provenance step
    /// pointing at the resource header that says so.
    pub fn value_or_default(&self, name: &str) -> Option<Value> {
        if let Some(v) = self.value(name) {
            return Some(v);
        }
        let d = tf_schema::default_for(&self.ty, name)?;
        let note = tf_schema::defaults_for(&self.ty)
            .iter()
            .find(|e| e.path == name)
            .map(|e| e.note)
            .unwrap_or("");
        let v = match d {
            DefaultValue::Bool(b) => Value::bool(b),
            DefaultValue::Number(n) => Value::number(n),
            DefaultValue::String(s) => Value::string(s),
            DefaultValue::Empty => Value::list(vec![]),
        };
        let label = format!(
            "{} {name} not set: provider default {} (defaults overlay; {note})",
            self.address, v
        );
        Some(v.with_prov(Prov::single(
            Step::new(StepKind::Default, self.span, label).with_resource(self.base_address.clone()),
        )))
    }

    /// `aws_s3_bucket.b` style local address (no module prefix, no key).
    pub fn local_address(&self) -> String {
        match self.mode {
            Mode::Managed => format!("{}.{}", self.ty, self.name),
            Mode::Data => format!("data.{}.{}", self.ty, self.name),
        }
    }
}

/// `tf_schema` typed views work over the evaluated model:
/// `tf_schema::views::AwsDbInstance(&resource.body).storage_encrypted()`.
impl<'b> tf_schema::ResourceNode for &'b Body {
    type Value = Value;
    type Block = &'b Body;
    fn attr(&self, name: &str) -> Option<Value> {
        self.value(name).cloned()
    }
    fn blocks(&self, name: &str) -> impl Iterator<Item = &'b Body> {
        let name = name.to_string();
        self.blocks
            .iter()
            .filter(move |b| *b.ty == *name)
            .map(|b| &b.body)
    }
}

#[derive(Clone, Debug)]
pub struct VariableInfo {
    pub name: Arc<str>,
    pub value: Value,
    pub span: FileSpan,
}

#[derive(Clone, Debug)]
pub struct ModuleCallInfo {
    pub name: Arc<str>,
    pub source: String,
    pub remote: bool,
    pub span: FileSpan,
}

#[derive(Clone, Debug)]
pub struct SymbolInfo {
    pub symbol: SymbolRef,
    pub span: FileSpan,
}

/// One module instance (root or child).
#[derive(Clone, Debug)]
pub struct Module {
    /// `""` for the root, `module.vpc`, `module.a.module.b["k"]`.
    pub address: Arc<str>,
    pub dir: PathBuf,
    /// Index of the parent module instance in `Analysis::modules`.
    pub parent: Option<usize>,
    pub resources: Vec<Resource>,
    pub variables: Vec<VariableInfo>,
    pub outputs: Vec<VariableInfo>,
    pub module_calls: Vec<ModuleCallInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub references: Vec<crate::module::Reference>,
}

impl Module {
    /// Resource-index lookup by (type, name) within this module instance.
    pub fn resources_of<'s>(&'s self, ty: &'s str) -> impl Iterator<Item = &'s Resource> + 's {
        self.resources
            .iter()
            .filter(move |r| r.mode == Mode::Managed && &*r.ty == ty)
    }
    pub fn resource(&self, ty: &str, name: &str) -> impl Iterator<Item = &Resource> {
        let (ty, name) = (ty.to_string(), name.to_string());
        self.resources
            .iter()
            .filter(move |r| r.mode == Mode::Managed && *r.ty == *ty && *r.name == *name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub severity: DiagSeverity,
    pub code: &'static str,
    pub message: String,
    pub at: Option<FileSpan>,
}

#[derive(Clone, Debug, Default)]
pub struct AnalysisStats {
    pub files: usize,
    pub module_instances: usize,
    pub resources: usize,
    pub attributes: usize,
}

/// Result of analysing one root module (and its local child modules).
#[derive(Clone, Debug)]
pub struct Analysis {
    pub root_dir: PathBuf,
    /// Root first, then children depth-first.
    pub modules: Vec<Module>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: AnalysisStats,
}

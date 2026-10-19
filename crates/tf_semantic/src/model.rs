//! The owned, evaluated module/resource model: what rules (and the Python
//! bindings) see. Nothing here borrows the AST arena; values are
//! `tf_eval::Value`s (Arc-shared, `Send + Sync`) with provenance chains of
//! `FileSpan`s that resolve through the scan's `FileTable`.

use std::path::PathBuf;
use std::sync::Arc;

use tf_eval::{Prov, Step, StepKind, Truth, Value};
use tf_schema::DefaultValue;
use tf_span::FileSpan;

pub use crate::address::{Address, InstanceKey};
pub use crate::module::{Mode, SymbolRef};

/// A provider default from the defaults overlay as a value.
pub fn default_value(d: DefaultValue) -> Value {
    match d {
        DefaultValue::Bool(b) => Value::bool(b),
        DefaultValue::Number(n) => Value::number(n),
        DefaultValue::String(s) => Value::string(s),
        DefaultValue::Empty => Value::list(vec![]),
    }
}

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

/// One resource or data-source instance. Build it with [`Resource::new`]
/// so the string forms of the address are spelled by [`Address`].
#[derive(Clone, Debug)]
pub struct Resource {
    /// The instance's identity.
    pub id: Address,
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
    /// Dependencies retained outside evaluated attributes (e.g. depends_on or
    /// plan configuration expressions). These describe graph edges, not identity.
    pub dependencies: Vec<tf_eval::prov::ResourceDependency>,
    /// False when a plan lacks configuration/source needed to recover edges.
    pub dependencies_complete: bool,
    /// Views of `body` that rule engines derive, computed once on first use
    /// and shared by every rule that judges this instance.
    pub derived: Derived,
    /// Unique per instance in this process (a cache key that, unlike an
    /// address in memory, is never reused).
    pub uid: u64,
}

/// Lazily computed views of a resource's body, by slot. A slot is owned
/// by one rule engine (`tf_rule_ir` uses them for the Checkov-shaped
/// configurations); `body` never changes after construction, so a view
/// never goes stale.
#[derive(Clone, Debug, Default)]
pub struct Derived {
    slots: [std::sync::OnceLock<Value>; Derived::SLOTS],
}

impl Derived {
    pub const SLOTS: usize = 3;

    /// The view in `slot`, computed by `f` the first time.
    pub fn get_or_init(&self, slot: usize, f: impl FnOnce() -> Value) -> &Value {
        self.slots[slot].get_or_init(f)
    }
}

impl Resource {
    pub fn new(
        id: Address,
        span: FileSpan,
        body: Body,
        existence: Truth,
        count: Option<Value>,
        for_each: Option<Value>,
        provider: Option<tf_schema::Provider>,
    ) -> Resource {
        Resource {
            mode: id.mode,
            ty: id.ty.clone(),
            name: id.name.clone(),
            key: id.key_str(),
            address: id.to_string().into(),
            base_address: id.base_string().into(),
            module: id.module.clone(),
            id,
            span,
            body,
            existence,
            count,
            for_each,
            provider,
            dependencies: Vec::new(),
            dependencies_complete: true,
            derived: Derived::default(),
            uid: {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            },
        }
    }

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
            // `attr = null` means "unset" in Terraform.
            if !v.is_null() {
                return Some(v);
            }
        }
        let d = tf_schema::default_for(&self.ty, name)?;
        let note = tf_schema::defaults_for(&self.ty)
            .iter()
            .find(|e| e.path == name)
            .map(|e| e.note)
            .unwrap_or("");
        let v = default_value(d);
        let label = format!(
            "{} {name} not set: provider default {} (defaults overlay; {note})",
            self.address, v
        );
        Some(
            v.with_prov(Prov::single(
                Step::new(StepKind::Default, self.span, label)
                    .with_resource(self.base_address.clone())
                    .with_attribute(name),
            )),
        )
    }
    /// `value`, set at `path` but without provenance of its own (a
    /// rendered view of the configuration), with a step naming the
    /// attribute at the resource header.
    pub fn mentioned(&self, path: &str, value: Value) -> Value {
        value.push(
            Step::new(
                StepKind::Attribute,
                self.span,
                format!("{} {path}", self.address),
            )
            .with_resource(self.base_address.clone())
            .with_attribute(path),
        )
    }

    /// A null witnessing that the attribute at `path` (dotted, no indices)
    /// is not set: one [`StepKind::Absent`] step at the resource header,
    /// so a finding it decides names the attribute and points at the
    /// block it would be added to.
    pub fn absent(&self, path: &str) -> Value {
        Value::null().with_prov(Prov::single(
            Step::new(
                StepKind::Absent,
                self.span,
                format!("{} {path} not set", self.address),
            )
            .with_resource(self.base_address.clone())
            .with_attribute(path),
        ))
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
    /// Evaluated arguments (all but `providers` and `depends_on`), when
    /// analysed with `AnalyzeOptions::whole_files`; else empty.
    pub arguments: Vec<(Arc<str>, Value)>,
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
    /// Evaluated `locals`, when analysed with
    /// `AnalyzeOptions::whole_files`; else empty.
    pub locals: Vec<VariableInfo>,
    /// Attribute values of the other top-level blocks (`provider`,
    /// `terraform`, `check`, ...), by the expression's span, when analysed
    /// with `AnalyzeOptions::whole_files`; else empty.
    pub block_values: std::collections::HashMap<FileSpan, Value>,
    pub module_calls: Vec<ModuleCallInfo>,
    pub symbols: Vec<SymbolInfo>,
    /// The definition's reference edges, shared by its instances.
    pub references: Arc<Vec<crate::module::Reference>>,
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

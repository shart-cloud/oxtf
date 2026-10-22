//! Module assembly and the symbol table.
//!
//! A module composes the `.tf` and `.tf.json` files in one directory. Its symbol table holds the
//! declared `variable`, `locals` entries, `resource`, `data`, `module` and
//! `output` blocks, plus a reference edge for every traversal root found in
//! their expressions (lexical names bound by `for`, `dynamic` iterators,
//! `each`, `count`, `self` are recorded as implicit references).

use rustc_hash::FxHashMap as HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tf_allocator::Allocator;
use tf_ast::{Attribute, Block, Expression};
use tf_span::{FileId, FileSpan, Span};

use crate::model_budget::{self as storage, Build};
use crate::source::{FileTable, SourceFile, normalize};

mod index;
mod references;

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
    /// Default converted through each stage of override composition.
    pub default_value: Option<tf_eval::Value>,
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
    /// Registry, git, http, s3, ...: resolved from installed modules only.
    /// Unavailable sources produce Unknown outputs and coverage diagnostics.
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
    /// Logical cost of preparing cached defaults, charged once per definition per root.
    pub loader_steps: u64,
    pub loader_limit: Option<tf_eval::budget::EvaluationLimit>,
    pub dir: PathBuf,
    /// Original source paired with the effective AST anchored in that file.
    /// After composition, individual nodes may belong to other source files.
    pub files: Vec<(Arc<SourceFile>, &'a tf_ast::File<'a>)>,
    /// Effective bodies can contain nodes from several original files.
    pub origins: crate::compose::Origins,
    pub variables: Vec<VarDecl<'a>>,
    pub locals: Vec<LocalDecl<'a>>,
    pub resources: Vec<ResourceDecl<'a>>,
    pub module_calls: Vec<ModuleCall<'a>>,
    pub outputs: Vec<OutputDecl<'a>>,
    /// Shared with every module instance built from this definition.
    pub references: Arc<Vec<Reference>>,
    pub parse_errors: Vec<(FileSpan, String)>,
    pub parse_limits: Vec<(FileSpan, tf_parser::Diagnostic)>,
    pub load_errors: Vec<String>,
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
}

/// Check the shared listing without copying paths into another collection.
pub fn has_module_files(files: &FileTable, dir: &Path) -> bool {
    files.read_dir(dir).iter().any(|p| is_config(p))
}

pub fn is_override(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        matches!(n, "override.tf" | "override.tf.json")
            || n.ends_with("_override.tf")
            || n.ends_with("_override.tf.json")
    })
}

pub fn is_config(path: &Path) -> bool {
    path.extension().is_some_and(|x| x == "tf")
        || path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(".tf.json"))
}

/// Default HCL then JSON variable files, then both auto-file formats in
/// lexical order, as Terraform loads them; later files win.
pub fn auto_tfvars(files: &FileTable, dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for name in ["terraform.tfvars", "terraform.tfvars.json"] {
        let t = dir.join(name);
        if files.is_file(&t) {
            v.push(t);
        }
    }
    v.extend(
        files
            .read_dir(dir)
            .iter()
            .filter(|p| {
                p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    n.ends_with(".auto.tfvars") || n.ends_with(".auto.tfvars.json")
                })
            })
            .cloned(),
    );
    v
}

/// Parse one file into the arena.
pub fn parse_file<'a>(
    alloc: &'a Allocator,
    sf: &Arc<SourceFile>,
    errors: &mut Vec<(FileSpan, String)>,
    limits: &mut Vec<(FileSpan, tf_parser::Diagnostic)>,
) -> std::io::Result<&'a tf_ast::File<'a>> {
    alloc
        .alloc(parse_config(alloc, sf, errors, limits)?)
        .map(|file| &*file)
        .map_err(std::io::Error::other)
}

fn parse_config<'a>(
    alloc: &'a Allocator,
    sf: &Arc<SourceFile>,
    errors: &mut Vec<(FileSpan, String)>,
    limits: &mut Vec<(FileSpan, tf_parser::Diagnostic)>,
) -> std::io::Result<tf_ast::File<'a>> {
    parse_config_with_providers(alloc, sf, errors, limits, &HashMap::default())
}

fn parse_config_with_providers<'a>(
    alloc: &'a Allocator,
    sf: &Arc<SourceFile>,
    errors: &mut Vec<(FileSpan, String)>,
    limits: &mut Vec<(FileSpan, tf_parser::Diagnostic)>,
    providers: &HashMap<String, String>,
) -> std::io::Result<tf_ast::File<'a>> {
    sf.reserve_text_copy()?;
    let text: &'a str = alloc.alloc_str(&sf.text).map_err(std::io::Error::other)?;
    let ret = if sf.path.to_string_lossy().ends_with(".tf.json") {
        crate::json_config::parse(alloc, text, providers)
    } else {
        tf_parser::parse(alloc, text)
    };
    for e in ret.errors {
        let at = FileSpan::new(sf.id, e.span);
        match e.kind {
            tf_parser::DiagnosticKind::Syntax => errors.push((at, e.message)),
            tf_parser::DiagnosticKind::Limit(tf_parser::ParseLimit::Storage(error)) => {
                return Err(std::io::Error::other(error));
            }
            tf_parser::DiagnosticKind::Limit(_) => limits.push((at, e)),
        }
    }
    Ok(ret.file)
}

/// Load and index a module directory.
pub fn load_module<'a>(alloc: &'a Allocator, files: &FileTable, dir: &Path) -> ModuleDef<'a> {
    load_module_with_limits(alloc, files, dir, tf_limits::Limits::default())
}

pub fn load_module_with_limits<'a>(
    alloc: &'a Allocator,
    files: &FileTable,
    dir: &Path,
    limits: tf_limits::Limits,
) -> ModuleDef<'a> {
    let budget = tf_eval::EvaluationBudget::with_storage(
        limits,
        tf_limits::Resource::LoaderSteps,
        files.shared_input_budget(),
    );
    let mut def = empty_module(normalize(dir));
    let mut parsed = load_configurations(alloc, files, &mut def);
    let composed = crate::compose::compose(alloc, &mut parsed, &mut def.parse_errors, &budget);
    let storage_limited = composed.is_err() || alloc.budget().exhaustion().is_some();
    if let Some(error) = alloc.budget().exhaustion()
        && let Some((source, _)) = parsed.first()
    {
        record_storage_error(&mut def, files, source, error);
    }
    def.origins = composed.unwrap_or_default();
    def.loader_steps = budget.used();
    def.loader_limit = budget.first_limit();
    if def.loader_limit.is_some() || storage_limited {
        // A partial override conversion is not a valid effective module. Keep diagnostics
        // and file identities, but never expose partially converted declarations to consumers.
        def.origins = crate::compose::Origins::default();
        for (_, file) in &mut parsed {
            file.body.items.clear();
        }
    }
    retain_files(alloc, files, &mut def, parsed);
    let indexed = index::build(&mut def, files.input_budget())
        .and_then(|()| references::collect(&mut def, files.input_budget()));
    if indexed.is_err() {
        index::discard(&mut def);
    }
    def
}

fn retain_files<'a>(
    alloc: &'a Allocator,
    files: &FileTable,
    def: &mut ModuleDef<'a>,
    parsed: Vec<(Arc<SourceFile>, tf_ast::File<'a>)>,
) {
    if storage::reserve(&mut def.files, parsed.len(), files.input_budget()).is_err() {
        return;
    }
    for (sf, f) in parsed {
        match alloc.alloc(f) {
            Ok(file) => def.files.push((sf, file)),
            Err(error) => {
                record_storage_error(def, files, &sf, error);
                def.files.clear();
                break;
            }
        }
    }
}

fn empty_module<'a>(dir: PathBuf) -> ModuleDef<'a> {
    ModuleDef {
        loader_steps: 0,
        loader_limit: None,
        dir,
        files: Vec::new(),
        origins: crate::compose::Origins::default(),
        variables: Vec::new(),
        locals: Vec::new(),
        resources: Vec::new(),
        module_calls: Vec::new(),
        outputs: Vec::new(),
        references: Arc::new(Vec::new()),
        parse_errors: Vec::new(),
        parse_limits: Vec::new(),
        load_errors: Vec::new(),
        var_index: HashMap::default(),
        local_index: HashMap::default(),
        res_index: HashMap::default(),
        call_index: HashMap::default(),
        output_index: HashMap::default(),
    }
}

fn load_configurations<'a>(
    alloc: &'a Allocator,
    files: &FileTable,
    def: &mut ModuleDef<'a>,
) -> Vec<(Arc<SourceFile>, tf_ast::File<'a>)> {
    let mut parsed = Vec::new();
    let listing = files.read_dir(&def.dir);
    for p in listing.iter().filter(|p| is_config(p)) {
        let sf = match files.load(p) {
            Ok(sf) => sf,
            Err(e) => {
                if tf_limits::input::exhaustion(&e).is_some() {
                    break;
                }
                def.load_errors.push(format!("{}: {e}", p.display()));
                continue;
            }
        };
        if storage::reserve(&mut parsed, 1, files.input_budget()).is_err() {
            break;
        }
        let f = match parse_config(alloc, &sf, &mut def.parse_errors, &mut def.parse_limits) {
            Ok(file) => file,
            Err(error) => {
                if let Some(error) = tf_limits::input::exhaustion(&error) {
                    record_storage_error(def, files, &sf, error);
                } else {
                    def.load_errors
                        .push(format!("{}: {error}", sf.path.display()));
                }
                break;
            }
        };
        parsed.push((sf, f));
    }
    resolve_providers(alloc, files, def, &mut parsed);

    parsed
}

fn resolve_providers<'a>(
    alloc: &'a Allocator,
    files: &FileTable,
    def: &mut ModuleDef<'a>,
    parsed: &mut [(Arc<SourceFile>, tf_ast::File<'a>)],
) {
    if parsed
        .iter()
        .any(|(sf, _)| sf.path.extension().is_some_and(|e| e == "json"))
    {
        let Ok(providers) = provider_names(parsed, files.input_budget()) else {
            return;
        };
        if !providers.is_empty() {
            // Requirements can come from another file or an override. Resolve
            // them before assigning provider-specific JSON block structure.
            for (sf, ast) in parsed {
                if sf.path.extension().is_some_and(|e| e == "json") {
                    def.parse_errors.retain(|(at, _)| at.file != sf.id);
                    def.parse_limits.retain(|(at, _)| at.file != sf.id);
                    let reparsed = parse_config_with_providers(
                        alloc,
                        sf,
                        &mut def.parse_errors,
                        &mut def.parse_limits,
                        &providers,
                    );
                    match reparsed {
                        Ok(reparsed) => *ast = reparsed,
                        Err(error) => {
                            if let Some(error) = tf_limits::input::exhaustion(&error) {
                                record_storage_error(def, files, sf, error);
                            } else {
                                def.load_errors
                                    .push(format!("{}: {error}", sf.path.display()));
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn record_storage_error(
    def: &mut ModuleDef<'_>,
    files: &FileTable,
    source: &SourceFile,
    error: tf_limits::Exhaustion,
) {
    // Shared scan admission has one terminal diagnostic. Independent low-level arenas
    // still need to report their own refusal through the returned module definition.
    if files.input_budget().exhaustion().is_none()
        && !def.parse_limits.iter().any(|(_, diagnostic)| {
            matches!(
                diagnostic.kind,
                tf_parser::DiagnosticKind::Limit(tf_parser::ParseLimit::Storage(_))
            )
        })
    {
        let diagnostic =
            tf_parser::Diagnostic::limit(Span::EMPTY, tf_parser::ParseLimit::Storage(error));
        def.parse_limits
            .push((FileSpan::new(source.id, Span::EMPTY), diagnostic));
    }
}

fn provider_names(
    files: &[(Arc<SourceFile>, tf_ast::File<'_>)],
    budget: &tf_limits::input::InputBudget,
) -> Build<HashMap<String, String>> {
    let mut names = HashMap::default();
    for overriding in [false, true] {
        for (_, ast) in files
            .iter()
            .filter(|(sf, _)| is_override(&sf.path) == overriding)
        {
            for requirements in ast
                .body
                .blocks()
                .filter(|b| b.block_type() == "terraform")
                .flat_map(|b| b.body.blocks())
                .filter(|b| b.block_type() == "required_providers")
            {
                for attr in requirements.body.attributes() {
                    let source = match &attr.value {
                        Expression::Object(o) => o
                            .items
                            .iter()
                            .find(|i| i.key.as_static_str() == Some("source"))
                            .and_then(|i| i.value.as_string_literal()),
                        _ => None,
                    };
                    let canonical = source
                        .map(|s| s.strip_prefix("registry.terraform.io/").unwrap_or(s))
                        .map(|source| {
                            tf_schema::Provider::ALL
                                .into_iter()
                                .find(|p| p.source() == source)
                                .map(|p| p.name())
                                .unwrap_or("")
                        })
                        .unwrap_or(attr.key.name.as_str());
                    if canonical == attr.key.name.as_str() {
                        names.remove(attr.key.name.as_str());
                    } else {
                        if !names.contains_key(attr.key.name.as_str()) {
                            storage::hash_slot(&mut names, budget)?;
                        }
                        names.insert(attr.key.name.to_string(), canonical.to_owned());
                    }
                }
            }
        }
    }
    Ok(names)
}

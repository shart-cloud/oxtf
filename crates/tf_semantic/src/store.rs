//! Parsed modules and files shared by every root of a scan.
//!
//! A recursive scan reaches most module directories from several roots:
//! every `examples/*` root calls the repository's module, and that module
//! directory is a root of its own. The [`ModuleStore`] caches each directory
//! per loader allowance, in an arena the entry owns, and hands every root
//! a shared `&ModuleDef`. Concurrent misses share one initialization cell.
//! Entries are appended and never removed while the
//! store lives, so a reference into one is valid for the store's lifetime,
//! which is what lets one analysis borrow definitions from many entries
//! under a single lifetime.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tf_allocator::Allocator;
use tf_span::FileSpan;

use crate::module::{ModuleDef, load_module_with_limits, parse_file};
use crate::source::{FileTable, SourceFile, normalize};

mod cache;
use cache::ParsedCache;

/// Admission can fail before a cache cell exists; parse failures borrow the cell.
#[derive(Debug)]
pub enum FileError<'a> {
    Storage(tf_limits::Exhaustion),
    Parse(&'a std::io::Error),
}

impl std::fmt::Display for FileError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => error.fmt(f),
            Self::Parse(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for FileError<'_> {}

/// A module directory parsed and indexed into its own arena.
///
/// The arena is boxed so its address is stable, and it is declared after
/// `def` so the definition drops first. `def` is stored with a `'static`
/// lifetime only because Rust cannot name "this struct's own arena"; it is
/// never exposed with that lifetime.
pub struct LoadedModule {
    def: ModuleDef<'static>,
    _alloc: Box<Allocator>,
}

// SAFETY: the arena is written only while the entry is built. `ModuleDef`
// holds shared references into it and no handle to the allocator, the
// field is private, and nothing hands out the arena, so once constructed
// the entry is read-only and can be read from any thread. (The arena type
// is `!Sync` only because it can allocate through a shared reference.)
unsafe impl Sync for LoadedModule {}
// SAFETY: the entry owns its arena outright (`bumpalo::Bump` is `Send`);
// the definition's raw pointers all point into that arena, so moving the
// pair to another thread moves everything they can reach.
unsafe impl Send for LoadedModule {}

impl LoadedModule {
    fn new(files: &FileTable, dir: &Path, limits: tf_limits::Limits) -> Self {
        let alloc = Box::new(files.allocator());
        let def = load_module_with_limits(&alloc, files, dir, limits);
        // SAFETY: `def` borrows only from `*alloc`, whose heap allocation
        // outlives `def` because the field order drops `def` first and the
        // box is never moved out. The borrow is shortened again in `def()`;
        // the AST is invariant in its lifetime (arena boxes are `&mut`),
        // which is why this cannot be expressed with plain subtyping, but
        // nothing can write through a shared `&ModuleDef`.
        let def: ModuleDef<'static> = unsafe { std::mem::transmute(def) };
        LoadedModule { def, _alloc: alloc }
    }

    /// The definition, borrowed for no longer than the entry.
    pub fn def<'s>(&'s self) -> &'s ModuleDef<'s> {
        // SAFETY: see `new`; shortening the lifetime of a read-only view.
        unsafe { std::mem::transmute::<&'s ModuleDef<'static>, &'s ModuleDef<'s>>(&self.def) }
    }
}

/// A standalone HCL or JSON variable file parsed into its own arena.
pub struct ParsedFile<'a> {
    pub file: &'a tf_ast::File<'a>,
    pub errors: Vec<(FileSpan, String)>,
    pub limits: Vec<(FileSpan, tf_parser::Diagnostic)>,
}

pub struct LoadedFile {
    parsed: ParsedFile<'static>,
    _alloc: Box<Allocator>,
}

// SAFETY: as for `LoadedModule`.
unsafe impl Sync for LoadedFile {}
unsafe impl Send for LoadedFile {}

impl LoadedFile {
    fn new(sf: &Arc<SourceFile>) -> std::io::Result<Self> {
        let alloc = Box::new(sf.allocator());
        let mut errors = Vec::new();
        let mut limits = Vec::new();
        let file = if sf.path.extension().is_some_and(|ext| ext == "json") {
            sf.reserve_text_copy()?;
            let text = alloc.alloc_str(&sf.text).map_err(std::io::Error::other)?;
            let ret = tf_parser::parse_json_vars(&alloc, text);
            for e in ret.errors {
                let at = FileSpan::new(sf.id, e.span);
                match e.kind {
                    tf_parser::DiagnosticKind::Syntax => errors.push((at, e.message)),
                    tf_parser::DiagnosticKind::Limit(tf_parser::ParseLimit::Storage(_)) => {}
                    tf_parser::DiagnosticKind::Limit(_) => limits.push((at, e)),
                }
            }
            alloc.alloc(ret.file).map_err(std::io::Error::other)?
        } else {
            parse_file(&alloc, sf, &mut errors, &mut limits)?
        };
        // SAFETY: as for `LoadedModule::new`.
        let parsed: ParsedFile<'static> = unsafe {
            std::mem::transmute(ParsedFile {
                file,
                errors,
                limits,
            })
        };
        Ok(LoadedFile {
            parsed,
            _alloc: alloc,
        })
    }

    pub fn parsed<'s>(&'s self) -> &'s ParsedFile<'s> {
        // SAFETY: as for `LoadedModule::def`.
        unsafe { std::mem::transmute::<&'s ParsedFile<'static>, &'s ParsedFile<'s>>(&self.parsed) }
    }
}

/// Every module directory and standalone file parsed so far in a scan.
/// Append-only; shared between the roots analysed in parallel.
#[derive(Default)]
pub struct ModuleStore {
    modules: ParsedCache<(u64, PathBuf, u64), LoadedModule>,
    files: ParsedCache<(u64, PathBuf), std::io::Result<LoadedFile>>,
}

impl ModuleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The parsed, indexed module in `dir`, initialized once even on concurrent access.
    pub fn module(
        &self,
        files: &FileTable,
        dir: &Path,
    ) -> Result<&ModuleDef<'_>, tf_limits::Exhaustion> {
        self.module_with_limits(files, dir, tf_limits::Limits::default())
    }

    /// Loader allowance is part of the cache identity: an exhausted entry must not
    /// poison a later request with a larger allowance. Runtime work is not cached here.
    /// Admission failure creates no entry. Once admitted, the definition retains
    /// load diagnostics and failed initialization is reused without another charge.
    pub fn module_with_limits(
        &self,
        files: &FileTable,
        dir: &Path,
        limits: tf_limits::Limits,
    ) -> Result<&ModuleDef<'_>, tf_limits::Exhaustion> {
        let dir = normalize(dir);
        let key = (
            files.input_budget().identity(),
            dir.clone(),
            limits.loader_steps(),
        );
        let cell = self.modules.entry(key, files.input_budget())?;
        // Loading one definition does not call back into ModuleStore: child modules
        // are instantiated only after this returns. No map lock is held while parsing.
        Ok(cell
            .get_or_init(|| LoadedModule::new(files, &dir, limits))
            .def())
    }

    /// `sf` parsed as a variable file, loaded on first request. JSON strings
    /// are literal here; configuration uses the module loader instead.
    pub fn variable_file(&self, sf: &Arc<SourceFile>) -> Result<&ParsedFile<'_>, FileError<'_>> {
        let cell = self
            .files
            .entry((sf.input_identity(), sf.path.clone()), sf.input_budget())
            .map_err(FileError::Storage)?;
        cell.get_or_init(|| LoadedFile::new(sf))
            .as_ref()
            .map(LoadedFile::parsed)
            .map_err(FileError::Parse)
    }

    /// Cached module entries, including separate entries for different loader allowances.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

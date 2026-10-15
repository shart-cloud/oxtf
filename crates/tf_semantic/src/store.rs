//! Parsed modules and files shared by every root of a scan.
//!
//! A recursive scan reaches most module directories from several roots:
//! every `examples/*` root calls the repository's module, and that module
//! directory is a root of its own. The [`ModuleStore`] parses and indexes
//! each directory once, into an arena the entry owns, and hands every root
//! a shared `&ModuleDef`. Entries are appended and never removed while the
//! store lives, so a reference into one is valid for the store's lifetime,
//! which is what lets one analysis borrow definitions from many entries
//! under a single lifetime.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use elsa::sync::FrozenMap;
use tf_allocator::Allocator;
use tf_span::FileSpan;

use crate::module::{ModuleDef, load_module, parse_file};
use crate::source::{FileTable, SourceFile, normalize};

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
    fn new(files: &FileTable, dir: &Path) -> Self {
        let alloc = Box::new(Allocator::new());
        let def = load_module(&alloc, files, dir);
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

/// A standalone file (a `.tfvars`) parsed into its own arena.
pub struct ParsedFile<'a> {
    pub file: &'a tf_ast::File<'a>,
    pub errors: Vec<(FileSpan, String)>,
}

pub struct LoadedFile {
    parsed: ParsedFile<'static>,
    _alloc: Box<Allocator>,
}

// SAFETY: as for `LoadedModule`.
unsafe impl Sync for LoadedFile {}
unsafe impl Send for LoadedFile {}

impl LoadedFile {
    fn new(sf: &Arc<SourceFile>) -> Self {
        let alloc = Box::new(Allocator::new());
        let mut errors = Vec::new();
        let file = parse_file(&alloc, sf, &mut errors);
        // SAFETY: as for `LoadedModule::new`.
        let parsed: ParsedFile<'static> =
            unsafe { std::mem::transmute(ParsedFile { file, errors }) };
        LoadedFile {
            parsed,
            _alloc: alloc,
        }
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
    modules: FrozenMap<PathBuf, Box<LoadedModule>>,
    files: FrozenMap<PathBuf, Box<LoadedFile>>,
}

impl ModuleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The parsed, indexed module in `dir`, loaded on first request. Two
    /// threads asking for a new directory at once may both parse it; the
    /// first to insert wins and the other copy is dropped.
    pub fn module(&self, files: &FileTable, dir: &Path) -> &ModuleDef<'_> {
        let dir = normalize(dir);
        if let Some(m) = self.modules.get(&dir) {
            return m.def();
        }
        let loaded = LoadedModule::new(files, &dir);
        self.modules.insert(dir, Box::new(loaded)).def()
    }

    /// `sf` parsed as a file on its own, loaded on first request.
    pub fn file(&self, sf: &Arc<SourceFile>) -> &ParsedFile<'_> {
        if let Some(f) = self.files.get(&sf.path) {
            return f.parsed();
        }
        self.files
            .insert(sf.path.clone(), Box::new(LoadedFile::new(sf)))
            .parsed()
    }

    /// Module directories loaded so far.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

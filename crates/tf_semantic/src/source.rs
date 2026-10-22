//! Source files and the file table shared by a scan.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};

use tf_limits::input::InputBudget;
use tf_span::{FileId, FileSpan, LineIndex, Span};

/// A loaded source file.
#[derive(Debug)]
pub struct SourceFile {
    input: Arc<InputBudget>,
    pub id: FileId,
    /// Lexically normalised path (no `.` / `..` components), as given
    /// (relative paths stay relative).
    pub path: PathBuf,
    pub text: Arc<str>,
    pub lines: LineIndex,
}

impl SourceFile {
    pub(crate) fn input_budget(&self) -> &InputBudget {
        &self.input
    }

    pub fn allocator(&self) -> tf_allocator::Allocator {
        tf_allocator::Allocator::with_budget(self.input.clone())
    }

    /// Reserve another retained copy before moving source text into a parser arena.
    pub(crate) fn reserve_text_copy(&self) -> io::Result<()> {
        self.input.admit(self.text.len() as u64)
    }

    pub(crate) fn input_identity(&self) -> u64 {
        self.input.identity()
    }
    /// 1-based line of a byte offset.
    pub fn line(&self, offset: u32) -> u32 {
        self.lines.line_col(offset).0
    }
    pub fn line_col(&self, offset: u32) -> (u32, u32) {
        self.lines.line_col(offset)
    }
}

/// Append-only, thread-safe registry of source files, so that `FileId`s are
/// stable across all modules of a scan (including modules analysed in
/// parallel and local child modules shared between roots).
///
/// The table is also the seam between the analysis and the disk. An
/// **overlay** ([`FileTable::with_overlay`]) is a set of in-memory files
/// that win over the disk: their text is what `load` returns and their
/// paths appear in `read_dir`, whether or not the file or even its
/// directory exists on disk. Everything that lists or reads source goes
/// through here, so an analysis of edited-but-unsaved text, of stdin, or of
/// a proposed patch is the same code as an analysis of a checkout.
#[derive(Default, Debug)]
pub struct FileTable {
    input: Arc<InputBudget>,
    inner: RwLock<Inner>,
    /// Normalised overlay paths, sorted.
    overlay: Vec<PathBuf>,
    /// Directory listings already taken this scan (`read_dir`), by
    /// normalised directory. A recursive scan lists each module directory
    /// once per root that reaches it; the disk does not change during a
    /// scan, so the second listing is the first one.
    listings: RwLock<HashMap<PathBuf, Arc<Vec<PathBuf>>>>,
    listing_errors: RwLock<HashMap<PathBuf, String>>,
    /// Source ranges known to contain sensitive values. Evaluators keep
    /// original text; renderers use a masked view.
    sensitive: RwLock<HashMap<FileId, Vec<Span>>>,
    protected: RwLock<HashSet<PathBuf>>,
    canonical: RwLock<HashMap<PathBuf, PathBuf>>,
    bytes: RwLock<HashMap<PathBuf, Arc<[u8]>>>,
}

#[derive(Default, Debug)]
struct Inner {
    files: Vec<Arc<SourceFile>>,
    by_path: HashMap<PathBuf, FileId>,
}

impl FileTable {
    pub fn allocator(&self) -> tf_allocator::Allocator {
        tf_allocator::Allocator::with_budget(self.input.clone())
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared_input_budget(&self) -> Arc<InputBudget> {
        self.input.clone()
    }

    pub fn input_budget(&self) -> &InputBudget {
        &self.input
    }

    pub fn with_limits(limits: tf_limits::Limits) -> Self {
        Self {
            input: Arc::new(InputBudget::new(limits)),
            ..Self::default()
        }
    }

    pub fn limit_diagnostic(&self) -> Option<crate::Diagnostic> {
        Some(crate::Diagnostic {
            severity: crate::DiagSeverity::Warning,
            code: "coverage-storage",
            message: self.input.exhaustion()?.to_string(),
            at: None,
        })
    }

    /// Terminal evidence that results were truncated, outside the results allowance.
    pub fn results_diagnostic(&self) -> Option<crate::Diagnostic> {
        Some(crate::Diagnostic {
            severity: crate::DiagSeverity::Warning,
            code: "coverage-results",
            message: self.input.results_exhaustion()?.to_string(),
            at: None,
        })
    }

    /// Installed package files may be scanned but must not be auto-edited.
    pub fn protect_dir(&self, dir: &Path) {
        let mut dirs = self.protected.write().unwrap();
        dirs.insert(normalize(
            &std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf()),
        ));
        dirs.insert(self.canonical_path(dir));
    }

    /// Resolve filesystem aliases once per path in this scan. Overlay-only
    /// paths use their absolute lexical identity.
    pub fn canonical_path(&self, path: &Path) -> PathBuf {
        let path = normalize(path);
        if let Some(p) = self.canonical.read().unwrap().get(&path) {
            return p.clone();
        }
        let resolved = path.canonicalize().unwrap_or_else(|_| {
            normalize(&std::path::absolute(&path).unwrap_or_else(|_| path.clone()))
        });
        self.canonical
            .write()
            .unwrap()
            .insert(path, resolved.clone());
        resolved
    }

    pub fn is_protected(&self, path: &Path) -> bool {
        let path = normalize(path);
        if path.components().any(|c| c.as_os_str() == ".terraform") {
            return true;
        }
        let abs = std::path::absolute(&path).ok().map(|p| normalize(&p));
        let real = self.canonical_path(&path);
        let dirs = self.protected.read().unwrap();
        [Some(&path), abs.as_ref(), Some(&real)]
            .into_iter()
            .flatten()
            .any(|p| p.ancestors().any(|a| dirs.contains(a)))
    }

    pub fn mark_sensitive(&self, at: FileSpan) {
        let mut sensitive = self.sensitive.write().unwrap();
        let spans = sensitive.entry(at.file).or_default();
        if !spans.contains(&at.span) {
            spans.push(at.span);
        }
    }

    /// Mask sensitive bytes without changing offsets or line breaks.
    pub fn display_text(&self, file: FileId) -> Arc<str> {
        let sf = self.get(file);
        let sensitive = self.sensitive.read().unwrap();
        let Some(spans) = sensitive.get(&file) else {
            return sf.text.clone();
        };
        let mut bytes = sf.text.as_bytes().to_vec();
        for span in spans {
            let end = (span.end as usize).min(bytes.len());
            if let Some(slice) = bytes.get_mut(span.start as usize..end) {
                for b in slice {
                    if !matches!(*b, b'\n' | b'\r' | b'\t') {
                        *b = b'*';
                    }
                }
            }
        }
        String::from_utf8(bytes)
            .expect("whole UTF-8 source spans are masked")
            .into()
    }

    /// A table whose `files` shadow the disk. Paths are compared lexically
    /// after normalisation, so give them in the same form (relative or
    /// absolute) as the directories that will be analysed.
    pub fn with_overlay(files: impl IntoIterator<Item = (PathBuf, Arc<str>)>) -> Self {
        Self::with_overlay_and_limits(files, tf_limits::Limits::default())
    }

    /// Refused input remains visible in `input_budget().exhaustion()`; never scan a
    /// partial overlay as complete. Scan and analysis entry points retain that evidence.
    pub fn with_overlay_and_limits(
        files: impl IntoIterator<Item = (PathBuf, Arc<str>)>,
        limits: tf_limits::Limits,
    ) -> Self {
        let table = FileTable::with_limits(limits);
        let mut overlay = std::collections::BTreeSet::new();
        for (path, text) in files {
            let path = normalize(&path);
            if table.insert(path.clone(), text).is_err() {
                break;
            }
            overlay.insert(path);
        }
        FileTable {
            overlay: overlay.into_iter().collect(),
            ..table
        }
    }

    /// Whether `path` names a file: in the overlay, else on disk. Answered
    /// from the (cached) listing of its directory, so asking about
    /// `terraform.tfvars` in every module costs no `stat`.
    pub fn is_file(&self, path: &Path) -> bool {
        let path = normalize(path);
        if self.overlay.binary_search(&path).is_ok() {
            return true;
        }
        match path.parent() {
            Some(dir) => self.read_dir(dir).binary_search(&path).is_ok(),
            None => path.is_file(),
        }
    }

    /// Whether `dir` is a directory: on disk, or implied by an overlay file
    /// somewhere beneath it.
    pub fn is_dir(&self, dir: &Path) -> bool {
        dir.is_dir() || self.has_overlay_under(dir)
    }

    /// The files directly in `dir` (not subdirectories), overlay and disk
    /// united, sorted by path.
    pub fn read_dir(&self, dir: &Path) -> Arc<Vec<PathBuf>> {
        let dir = normalize(dir);
        let mut listings = self.listings.write().unwrap();
        if let Some(v) = listings.get(&dir) {
            return v.clone();
        }
        let mut v = Vec::new();
        let record_error = |e: io::Error| {
            if tf_limits::input::exhaustion(&e).is_some() {
                return;
            }
            self.listing_errors
                .write()
                .unwrap()
                .insert(dir.clone(), e.to_string());
        };
        let read = self
            .input
            .directory_entry()
            .and_then(|()| std::fs::read_dir(&dir));
        match read {
            Ok(rd) => {
                for entry in rd {
                    if self.input.directory_entry().is_err() {
                        break;
                    }
                    match entry.and_then(|e| Ok((e.file_type()?, e.path()))) {
                        Ok((t, p)) if t.is_file() || (t.is_symlink() && p.is_file()) => {
                            v.push(normalize(&p))
                        }
                        Ok(_) => {}
                        Err(e) => record_error(e),
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && self.has_overlay_under(&dir) => {}
            Err(e) => record_error(e),
        }
        for path in self
            .overlay
            .iter()
            .filter(|p| p.parent().is_some_and(|parent| normalize(parent) == dir))
        {
            if self.input.directory_entry().is_err() {
                break;
            }
            v.push(path.clone());
        }
        v.sort();
        v.dedup();
        let v = Arc::new(v);
        if self.input.exhaustion().is_none() {
            listings.insert(dir, v.clone());
        }
        v
    }

    pub fn listing_error(&self, dir: &Path) -> Option<String> {
        self.listing_errors
            .read()
            .unwrap()
            .get(&normalize(dir))
            .cloned()
    }

    /// Overlay files (any depth) under `dir`.
    pub fn overlay_under(&self, dir: &Path) -> impl Iterator<Item = &PathBuf> {
        let dir = normalize(dir);
        self.overlay.iter().filter(move |p| {
            if dir == Path::new(".") {
                // Normalised relative paths have no leading `.` component.
                // Absolute paths and paths starting with `..` are outside it.
                matches!(p.components().next(), Some(Component::Normal(_)))
            } else {
                p.starts_with(&dir)
            }
        })
    }

    fn has_overlay_under(&self, dir: &Path) -> bool {
        self.overlay_under(dir).next().is_some()
    }

    /// Load (or return the already loaded) file at `path`.
    pub fn load(&self, path: &Path) -> io::Result<Arc<SourceFile>> {
        let path = normalize(path);
        if let Some(f) = self.get_by_path(&path) {
            return Ok(f);
        }
        let bytes = self.read_bytes(&path)?;
        let mut inner = self.inner.write().unwrap();
        if let Some(&id) = inner.by_path.get(&path) {
            return Ok(inner.files[id.0 as usize].clone());
        }
        self.input.admit(decoded_len(&bytes))?;
        let text: Arc<str> = String::from_utf8_lossy(&bytes).into();
        Ok(register(&mut inner, path, text, self.input.clone()))
    }

    /// Strict UTF-8 document loading for rule/policy formats, sharing the same snapshots.
    pub fn read_text(&self, path: &Path) -> io::Result<Arc<str>> {
        let bytes = self.read_bytes(path)?;
        std::str::from_utf8(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(self.load(path)?.text.clone())
    }

    /// Snapshot raw bytes for file functions. Text overlays win, and binary
    /// files are never round-tripped through lossy UTF-8 decoding.
    pub fn read_bytes(&self, path: &Path) -> io::Result<Arc<[u8]>> {
        let path = normalize(path);
        let overlay = self.overlay.binary_search(&path).ok().map(|_| {
            self.get_by_path(&path)
                .expect("overlay registered before use")
        });
        let mut cache = self.bytes.write().unwrap();
        if let Some(bytes) = cache.get(&path) {
            return Ok(bytes.clone());
        }
        let bytes: Arc<[u8]> = match overlay {
            Some(file) => {
                self.input.admit(file.text.len() as u64)?;
                file.text.as_bytes().into()
            }
            None => self.input.read(&path)?.into(),
        };
        cache.insert(path, bytes.clone());
        Ok(bytes)
    }

    /// Register in-memory text under `path` (tests, stdin).
    pub fn insert(&self, path: PathBuf, text: Arc<str>) -> io::Result<Arc<SourceFile>> {
        let path = normalize(&path);
        let mut g = self.inner.write().unwrap();
        if let Some(&id) = g.by_path.get(&path) {
            return Ok(g.files[id.0 as usize].clone());
        }
        self.input.admit(text.len() as u64)?;
        Ok(register(&mut g, path, text, self.input.clone()))
    }

    fn get_by_path(&self, path: &Path) -> Option<Arc<SourceFile>> {
        let g = self.inner.read().unwrap();
        g.by_path.get(path).map(|id| g.files[id.0 as usize].clone())
    }

    pub fn get(&self, id: FileId) -> Arc<SourceFile> {
        self.inner.read().unwrap().files[id.0 as usize].clone()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn all(&self) -> Vec<Arc<SourceFile>> {
        self.inner.read().unwrap().files.clone()
    }

    /// `path:line:col` for a file span.
    pub fn location(&self, at: FileSpan) -> String {
        let f = self.get(at.file);
        let (l, c) = f.line_col(at.span.start);
        format!("{}:{}:{}", f.path.display(), l, c)
    }
}

fn register(
    inner: &mut Inner,
    path: PathBuf,
    text: Arc<str>,
    input: Arc<InputBudget>,
) -> Arc<SourceFile> {
    assert!(text.len() <= u32::MAX as usize);
    let id = FileId(u32::try_from(inner.files.len()).expect("admitted file identifier"));
    let file = Arc::new(SourceFile {
        input,
        id,
        lines: LineIndex::new(&text),
        path: path.clone(),
        text,
    });
    inner.files.push(file.clone());
    assert_eq!(inner.files[id.0 as usize].id, id);
    assert!(inner.by_path.insert(path, id).is_none());
    file
}

/// Compute lossy UTF-8 expansion before allocating its retained text snapshot.
fn decoded_len(mut bytes: &[u8]) -> u64 {
    let mut length = 0;
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(_) => return length + bytes.len() as u64,
            Err(error) => {
                length += error.valid_up_to() as u64 + 3;
                bytes = match error.error_len() {
                    Some(count) => &bytes[error.valid_up_to() + count..],
                    None => &[],
                };
            }
        }
    }
    length
}

/// Lexical path normalisation: drop `.`, resolve `..` against preceding
/// normal components.
pub fn normalize(p: &Path) -> PathBuf {
    let mut out: Vec<Component> = Vec::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => match out.last() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir) => {}
                _ => out.push(c),
            },
            other => out.push(other),
        }
    }
    if out.is_empty() {
        return PathBuf::from(".");
    }
    out.iter().collect()
}

/// A lexical path relative to a module root, including sibling packages.
pub(crate) fn relative_to(path: &Path, base: &Path) -> PathBuf {
    let path = normalize(&std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()));
    let base = normalize(&std::path::absolute(base).unwrap_or_else(|_| base.to_path_buf()));
    if path.is_absolute() != base.is_absolute() {
        return path;
    }
    let a: Vec<_> = base
        .components()
        .filter(|c| *c != Component::CurDir)
        .collect();
    let b: Vec<_> = path
        .components()
        .filter(|c| *c != Component::CurDir)
        .collect();
    let shared = a.iter().zip(&b).take_while(|(a, b)| a == b).count();
    let mut result = PathBuf::new();
    for _ in &a[shared..] {
        result.push("..");
    }
    for c in &b[shared..] {
        result.push(c.as_os_str());
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn norm() {
        assert_eq!(normalize(Path::new("a/b/../c/./d")), PathBuf::from("a/c/d"));
        assert_eq!(normalize(Path::new("../x")), PathBuf::from("../x"));
        assert_eq!(
            normalize(Path::new("a/examples/complete/../../")),
            PathBuf::from("a")
        );
    }

    #[test]
    fn relative_module_paths_round_trip_across_parent_components() {
        for (target, base) in [("shared", "../root"), ("../shared", "root"), (".", ".")] {
            let path = relative_to(Path::new(target), Path::new(base));
            assert_eq!(
                normalize(&std::path::absolute(Path::new(base).join(path)).unwrap()),
                normalize(&std::path::absolute(target).unwrap()),
            );
        }
    }
}

#[cfg(test)]
mod overlay_tests {
    use super::*;

    #[test]
    fn current_directory_lists_relative_overlays_and_excludes_outside_paths() {
        let files = FileTable::with_overlay([
            (PathBuf::from("./memory.tf"), Arc::from("new file")),
            (
                PathBuf::from("./nested/memory.tf"),
                Arc::from("nested file"),
            ),
            (PathBuf::from("../outside/memory.tf"), Arc::from("outside")),
            (
                PathBuf::from("/nonexistent/absolute/memory.tf"),
                Arc::from("absolute"),
            ),
        ]);
        for dir in [".", "./", ""] {
            let listing = files.read_dir(Path::new(dir));
            assert!(
                listing.contains(&PathBuf::from("memory.tf")),
                "{dir:?}: {listing:?}"
            );
            assert!(!listing.contains(&PathBuf::from("nested/memory.tf")));
            let under: Vec<_> = files.overlay_under(Path::new(dir)).cloned().collect();
            assert_eq!(
                under,
                [
                    PathBuf::from("memory.tf"),
                    PathBuf::from("nested/memory.tf")
                ],
                "{dir:?}"
            );
        }
        assert_eq!(
            &*files.load(Path::new("memory.tf")).unwrap().text,
            "new file"
        );
        assert_eq!(
            files.read_dir(Path::new("nested")).as_slice(),
            [PathBuf::from("nested/memory.tf")]
        );
    }

    #[test]
    fn overlay_shadows_disk_for_content_and_listing() {
        let dir = std::env::temp_dir().join(format!("oxtf-overlay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.tf"), "on disk").unwrap();
        std::fs::write(dir.join("b.tf"), "on disk").unwrap();
        let files = FileTable::with_overlay([
            (dir.join("./b.tf"), Arc::from("in memory")),
            (dir.join("c.tf"), Arc::from("new file")),
            (dir.join("sub/d.tf"), Arc::from("nested")),
        ]);
        assert_eq!(&*files.load(&dir.join("a.tf")).unwrap().text, "on disk");
        assert_eq!(&*files.load(&dir.join("b.tf")).unwrap().text, "in memory");
        assert_eq!(&*files.load(&dir.join("c.tf")).unwrap().text, "new file");
        let names: Vec<String> = files
            .read_dir(&dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.tf", "b.tf", "c.tf"]);
        assert!(files.is_file(&dir.join("c.tf")) && !dir.join("c.tf").exists());
        assert!(files.is_dir(&dir.join("sub")) && !dir.join("sub").exists());
        assert!(!files.is_dir(&dir.join("other")));
        assert_eq!(files.overlay_under(&dir).count(), 3);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

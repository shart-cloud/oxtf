//! Source files and the file table shared by a scan.

use std::collections::HashMap;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};

use tf_span::{FileId, FileSpan, LineIndex};

/// A loaded source file.
#[derive(Debug)]
pub struct SourceFile {
    pub id: FileId,
    /// Lexically normalised path (no `.` / `..` components), as given
    /// (relative paths stay relative).
    pub path: PathBuf,
    pub text: Arc<str>,
    pub lines: LineIndex,
}

impl SourceFile {
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
    inner: RwLock<Inner>,
    /// Normalised overlay paths, sorted.
    overlay: Vec<PathBuf>,
}

#[derive(Default, Debug)]
struct Inner {
    files: Vec<Arc<SourceFile>>,
    by_path: HashMap<PathBuf, FileId>,
}

impl FileTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// A table whose `files` shadow the disk. Paths are compared lexically
    /// after normalisation, so give them in the same form (relative or
    /// absolute) as the directories that will be analysed.
    pub fn with_overlay(files: impl IntoIterator<Item = (PathBuf, Arc<str>)>) -> Self {
        let table = FileTable::default();
        let mut overlay = Vec::new();
        for (path, text) in files {
            let path = normalize(&path);
            table.insert(path.clone(), text);
            overlay.push(path);
        }
        overlay.sort();
        overlay.dedup();
        FileTable { overlay, ..table }
    }

    /// Whether `path` names a file: in the overlay, else on disk.
    pub fn is_file(&self, path: &Path) -> bool {
        self.overlay.binary_search(&normalize(path)).is_ok() || path.is_file()
    }

    /// Whether `dir` is a directory: on disk, or implied by an overlay file
    /// somewhere beneath it.
    pub fn is_dir(&self, dir: &Path) -> bool {
        dir.is_dir() || self.has_overlay_under(dir)
    }

    /// The files directly in `dir` (not subdirectories), overlay and disk
    /// united, sorted by path.
    pub fn read_dir(&self, dir: &Path) -> Vec<PathBuf> {
        let dir = normalize(dir);
        let mut v: Vec<PathBuf> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect(),
            Err(_) => Vec::new(),
        };
        v.extend(
            self.overlay
                .iter()
                .filter(|p| p.parent() == Some(dir.as_path()))
                .cloned(),
        );
        v.sort();
        v.dedup();
        v
    }

    /// Overlay files (any depth) under `dir`.
    pub fn overlay_under(&self, dir: &Path) -> impl Iterator<Item = &PathBuf> {
        let dir = normalize(dir);
        self.overlay.iter().filter(move |p| p.starts_with(&dir))
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
        let bytes = std::fs::read(&path)?;
        let text: Arc<str> = String::from_utf8_lossy(&bytes).into();
        Ok(self.insert(path, text))
    }

    /// Register in-memory text under `path` (tests, stdin).
    pub fn insert(&self, path: PathBuf, text: Arc<str>) -> Arc<SourceFile> {
        let mut g = self.inner.write().unwrap();
        if let Some(&id) = g.by_path.get(&path) {
            return g.files[id.0 as usize].clone();
        }
        let id = FileId(g.files.len() as u32);
        let f = Arc::new(SourceFile {
            id,
            lines: LineIndex::new(&text),
            path: path.clone(),
            text,
        });
        g.files.push(f.clone());
        g.by_path.insert(path, id);
        f
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
}

#[cfg(test)]
mod overlay_tests {
    use super::*;

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

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
#[derive(Default, Debug)]
pub struct FileTable {
    inner: RwLock<Inner>,
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

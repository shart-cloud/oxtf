//! Source spans and file identifiers.
//!
//! Spans are `u32` byte offsets, as in oxc: 8 bytes per span keeps AST nodes
//! small, and no single `.tf` file is anywhere near 4 GiB.

use std::fmt;

/// A half-open byte range `[start, end)` into a source file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub const EMPTY: Span = Span { start: 0, end: 0 };

    #[inline]
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    #[inline]
    pub const fn empty(at: u32) -> Self {
        Self { start: at, end: at }
    }

    #[inline]
    pub const fn len(self) -> u32 {
        self.end - self.start
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Smallest span covering both `self` and `other`.
    #[inline]
    pub fn merge(self, other: Span) -> Span {
        Span::new(self.start.min(other.start), self.end.max(other.end))
    }

    #[inline]
    pub fn source_text(self, source: &str) -> &str {
        &source[self.start as usize..self.end as usize]
    }

    #[inline]
    pub fn contains(self, offset: u32) -> bool {
        self.start <= offset && offset < self.end
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

impl From<Span> for std::ops::Range<usize> {
    fn from(s: Span) -> Self {
        s.start as usize..s.end as usize
    }
}

/// Implemented by every AST node.
pub trait GetSpan {
    fn span(&self) -> Span;
}

impl GetSpan for Span {
    fn span(&self) -> Span {
        *self
    }
}

/// Index of a source file within a module/project.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, PartialOrd, Ord)]
pub struct FileId(pub u32);

/// A span qualified with the file it belongs to. Used for provenance chains
/// that cross files (`.tfvars` -> `variables.tf` -> `main.tf`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct FileSpan {
    pub file: FileId,
    pub span: Span,
}

impl FileSpan {
    pub const fn new(file: FileId, span: Span) -> Self {
        Self { file, span }
    }
}

/// Maps byte offsets to 1-based line/column for diagnostics.
#[derive(Debug, Clone)]
pub struct LineIndex {
    line_starts: Vec<u32>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i as u32 + 1);
            }
        }
        Self { line_starts }
    }

    /// 1-based (line, column) of a byte offset; column counts bytes.
    pub fn line_col(&self, offset: u32) -> (u32, u32) {
        let line = match self.line_starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        (line as u32 + 1, offset - self.line_starts[line] + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_is_8_bytes() {
        assert_eq!(std::mem::size_of::<Span>(), 8);
    }

    #[test]
    fn line_col() {
        let idx = LineIndex::new("a\nbc\n\nd");
        assert_eq!(idx.line_col(0), (1, 1));
        assert_eq!(idx.line_col(3), (2, 2));
        assert_eq!(idx.line_col(5), (3, 1));
        assert_eq!(idx.line_col(6), (4, 1));
    }
}

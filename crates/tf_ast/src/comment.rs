use tf_span::{GetSpan, Span};

/// A source comment. Comments are kept on the side (in the parse result),
/// not in the tree, as in oxc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comment {
    /// Covers the whole comment including its `#`, `//` or `/* */` markers
    /// (and excluding the terminating newline of a line comment).
    pub span: Span,
    pub kind: CommentKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    /// `# ...`
    Hash,
    /// `// ...`
    DoubleSlash,
    /// `/* ... */`
    Block,
}

impl Comment {
    /// The comment text without its markers.
    pub fn text<'s>(&self, source: &'s str) -> &'s str {
        let s = self.span.source_text(source);
        match self.kind {
            CommentKind::Hash => &s[1..],
            CommentKind::DoubleSlash => &s[2..],
            CommentKind::Block => s.strip_prefix("/*").and_then(|s| s.strip_suffix("*/")).unwrap_or(s),
        }
    }
}

impl GetSpan for Comment {
    fn span(&self) -> Span {
        self.span
    }
}

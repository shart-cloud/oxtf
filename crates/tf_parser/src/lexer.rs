//! Hand-written HCL lexer.
//!
//! The lexer is a byte cursor with no hidden state beyond `pos`, so the parser
//! can reposition it freely. Two modes are driven by the parser:
//!
//! - *normal mode* ([`Lexer::next_token`]): punctuation, identifiers, numbers,
//!   comments, newlines, and the openers `"` and `<<EOT`;
//! - *template mode* ([`Lexer::scan_template_literal`]): literal text inside a
//!   quoted string or heredoc, up to the next `${`, `%{`, closing quote or
//!   heredoc terminator.

use tf_span::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Eof,
    Newline,
    Comment(tf_ast::CommentKind),
    Ident,
    Number,
    /// `"` opening a quoted template.
    OQuote,
    /// `<<EOT\n` or `<<-EOT\n` (the span covers the whole opener including the
    /// newline).
    HeredocStart {
        indented: bool,
    },
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
    Dot,
    Ellipsis,
    Eq,
    EqEq,
    Bang,
    BangEq,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Question,
    Colon,
    ColonColon,
    FatArrow,
    Tilde,
    /// Unterminated block comment or any byte that starts no token.
    Invalid,
}

#[derive(Debug, Clone, Copy)]
pub struct Token {
    pub kind: Kind,
    pub span: Span,
}

/// Why literal scanning stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LitStop {
    /// `${`; `pos` is after it.
    Interp,
    /// `%{`; `pos` is after it.
    Directive,
    /// Closing `"`; `pos` is after it.
    Quote,
    /// Heredoc terminator line; `pos` is after the delimiter.
    HeredocEnd,
    /// Newline inside a quoted string (error); `pos` is at the newline.
    Newline,
    Eof,
}

#[derive(Debug, Clone, Copy)]
pub enum TemplateCtx<'d> {
    Quoted,
    Raw,
    Heredoc { delimiter: &'d str },
}

pub struct Literal {
    /// Raw source range of the literal text.
    pub span: Span,
    /// Decoded text; `None` means it is identical to the raw source slice.
    pub decoded: Option<String>,
    pub stop: LitStop,
    /// Span of the stop token (`${`, `%{`, `"`, terminator line).
    pub stop_span: Span,
    /// First invalid escape, if any (for a diagnostic).
    pub bad_escape: Option<Span>,
}

#[derive(Clone)]
pub struct Lexer<'s> {
    pub src: &'s str,
    pub pos: usize,
}

#[inline]
pub fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || (!c.is_ascii() && c.is_alphabetic())
}

#[inline]
pub fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || (!c.is_ascii() && c.is_alphanumeric())
}

impl<'s> Lexer<'s> {
    pub fn new(src: &'s str) -> Self {
        // Skip a UTF-8 BOM.
        let pos = if src.starts_with('\u{feff}') { 3 } else { 0 };
        Self { src, pos }
    }

    #[inline]
    fn bytes(&self) -> &'s [u8] {
        self.src.as_bytes()
    }

    #[inline]
    fn peek_byte(&self, off: usize) -> u8 {
        *self.bytes().get(self.pos + off).unwrap_or(&0)
    }

    fn tok(&self, kind: Kind, start: usize) -> Token {
        Token {
            kind,
            span: Span::new(start as u32, self.pos as u32),
        }
    }

    /// Next token in normal mode. Skips spaces and tabs; emits comments and
    /// newlines as tokens.
    #[expect(clippy::too_many_lines)]
    pub fn next_token(&mut self) -> Token {
        let b = self.bytes();
        while self.pos < b.len() && matches!(b[self.pos], b' ' | b'\t' | b'\r') {
            // A lone `\r` not followed by `\n` is treated as whitespace.
            if b[self.pos] == b'\r' && self.peek_byte(1) == b'\n' {
                break;
            }
            self.pos += 1;
        }
        let start = self.pos;
        if self.pos >= b.len() {
            return self.tok(Kind::Eof, start);
        }
        let c = b[self.pos];
        macro_rules! one {
            ($k:expr) => {{
                self.pos += 1;
                return self.tok($k, start);
            }};
        }
        macro_rules! two {
            ($second:expr, $k2:expr, $k1:expr) => {{
                if self.peek_byte(1) == $second {
                    self.pos += 2;
                    return self.tok($k2, start);
                }
                self.pos += 1;
                return self.tok($k1, start);
            }};
        }
        match c {
            b'\n' => one!(Kind::Newline),
            b'\r' => {
                self.pos += 2;
                self.tok(Kind::Newline, start)
            }
            b'#' => self.line_comment(start, tf_ast::CommentKind::Hash),
            b'/' if self.peek_byte(1) == b'/' => {
                self.line_comment(start, tf_ast::CommentKind::DoubleSlash)
            }
            b'/' if self.peek_byte(1) == b'*' => match self.src[self.pos + 2..].find("*/") {
                Some(i) => {
                    self.pos += 2 + i + 2;
                    self.tok(Kind::Comment(tf_ast::CommentKind::Block), start)
                }
                None => {
                    self.pos = b.len();
                    self.tok(Kind::Invalid, start)
                }
            },
            b'{' => one!(Kind::LBrace),
            b'}' => one!(Kind::RBrace),
            b'[' => one!(Kind::LBracket),
            b']' => one!(Kind::RBracket),
            b'(' => one!(Kind::LParen),
            b')' => one!(Kind::RParen),
            b',' => one!(Kind::Comma),
            b'.' => {
                if self.peek_byte(1) == b'.' && self.peek_byte(2) == b'.' {
                    self.pos += 3;
                    return self.tok(Kind::Ellipsis, start);
                }
                one!(Kind::Dot)
            }
            b'=' => match self.peek_byte(1) {
                b'=' => {
                    self.pos += 2;
                    self.tok(Kind::EqEq, start)
                }
                b'>' => {
                    self.pos += 2;
                    self.tok(Kind::FatArrow, start)
                }
                _ => one!(Kind::Eq),
            },
            b'!' => two!(b'=', Kind::BangEq, Kind::Bang),
            b'<' => {
                if self.peek_byte(1) == b'<'
                    && let Some(t) = self.try_heredoc_start(start)
                {
                    return t;
                }
                two!(b'=', Kind::Le, Kind::Lt)
            }
            b'>' => two!(b'=', Kind::Ge, Kind::Gt),
            b'&' if self.peek_byte(1) == b'&' => {
                self.pos += 2;
                self.tok(Kind::AndAnd, start)
            }
            b'|' if self.peek_byte(1) == b'|' => {
                self.pos += 2;
                self.tok(Kind::OrOr, start)
            }
            b'+' => one!(Kind::Plus),
            b'-' => one!(Kind::Minus),
            b'*' => one!(Kind::Star),
            b'/' => one!(Kind::Slash),
            b'%' => one!(Kind::Percent),
            b'?' => one!(Kind::Question),
            b':' => two!(b':', Kind::ColonColon, Kind::Colon),
            b'~' => one!(Kind::Tilde),
            b'"' => one!(Kind::OQuote),
            b'0'..=b'9' => {
                self.number();
                self.tok(Kind::Number, start)
            }
            _ => {
                let ch = self.src[self.pos..].chars().next().unwrap();
                if is_ident_start(ch) {
                    self.pos += ch.len_utf8();
                    self.ident_rest();
                    self.tok(Kind::Ident, start)
                } else {
                    self.pos += ch.len_utf8();
                    self.tok(Kind::Invalid, start)
                }
            }
        }
    }

    fn line_comment(&mut self, start: usize, kind: tf_ast::CommentKind) -> Token {
        let rest = &self.bytes()[self.pos..];
        let len = memchr_newline(rest);
        self.pos += len;
        // Exclude a trailing `\r` of a CRLF line ending.
        let mut end = self.pos;
        if end > start && self.bytes()[end - 1] == b'\r' {
            end -= 1;
            self.pos = end;
        }
        Token {
            kind: Kind::Comment(kind),
            span: Span::new(start as u32, end as u32),
        }
    }

    fn ident_rest(&mut self) {
        let b = self.bytes();
        while self.pos < b.len() {
            let c = b[self.pos];
            if c.is_ascii() {
                if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
                    self.pos += 1;
                } else {
                    break;
                }
            } else {
                let ch = self.src[self.pos..].chars().next().unwrap();
                if is_ident_continue(ch) {
                    self.pos += ch.len_utf8();
                } else {
                    break;
                }
            }
        }
    }

    /// `[0-9]+ ('.' [0-9]+)? ([eE] [+-]? [0-9]+)?`
    fn number(&mut self) {
        let b = self.bytes();
        let digits = |p: &mut usize| {
            let s = *p;
            while *p < b.len() && b[*p].is_ascii_digit() {
                *p += 1;
            }
            *p > s
        };
        let mut p = self.pos;
        digits(&mut p);
        if p < b.len() && b[p] == b'.' {
            let mut q = p + 1;
            if digits(&mut q) {
                p = q;
            }
        }
        if p < b.len() && (b[p] == b'e' || b[p] == b'E') {
            let mut q = p + 1;
            if q < b.len() && (b[q] == b'+' || b[q] == b'-') {
                q += 1;
            }
            if digits(&mut q) {
                p = q;
            }
        }
        self.pos = p;
    }

    /// Length of the leading run of ASCII digits at `pos`.
    pub fn digit_run_len(&self, pos: usize) -> usize {
        self.bytes()[pos..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count()
    }

    /// At `<<`: `<<` `-`? ident newline.
    fn try_heredoc_start(&mut self, start: usize) -> Option<Token> {
        let b = self.bytes();
        let mut p = start + 2;
        let indented = b.get(p) == Some(&b'-');
        if indented {
            p += 1;
        }
        let ch = self.src[p..].chars().next()?;
        if !is_ident_start(ch) {
            return None;
        }
        let save = self.pos;
        self.pos = p + ch.len_utf8();
        self.ident_rest();
        let mut q = self.pos;
        if b.get(q) == Some(&b'\r') {
            q += 1;
        }
        if b.get(q) == Some(&b'\n') {
            self.pos = q + 1;
            Some(self.tok(Kind::HeredocStart { indented }, start))
        } else {
            self.pos = save;
            None
        }
    }

    /// Heredoc delimiter from a `HeredocStart` token span.
    pub fn heredoc_delimiter(&self, span: Span) -> &'s str {
        let s = &self.src[span.start as usize + 2..span.end as usize];
        let s = s.strip_prefix('-').unwrap_or(s);
        s.trim_end_matches(['\n', '\r'])
    }

    /// If a heredoc terminator line (`[ \t]* DELIM (\r?\n | EOF)`) starts at
    /// `p`, returns the offset just after the delimiter.
    fn heredoc_end_at(&self, p: usize, delimiter: &str) -> Option<usize> {
        let b = self.bytes();
        let mut q = p;
        while q < b.len() && (b[q] == b' ' || b[q] == b'\t') {
            q += 1;
        }
        if !self.src[q..].starts_with(delimiter) {
            return None;
        }
        let e = q + delimiter.len();
        match b.get(e) {
            None | Some(b'\n') => Some(e),
            Some(b'\r') if b.get(e + 1) == Some(&b'\n') => Some(e),
            _ => None,
        }
    }

    /// Scan literal template text starting at `pos`.
    ///
    /// `at_line_start` must be true when `pos` is at the beginning of a
    /// heredoc line (so a terminator there is recognised).
    #[expect(clippy::too_many_lines)]
    pub fn scan_template_literal(
        &mut self,
        ctx: TemplateCtx<'_>,
        mut at_line_start: bool,
    ) -> Literal {
        let b = self.bytes();
        let start = self.pos;
        let mut decoded: Option<String> = None;
        let mut bad_escape = None;
        let mut p = self.pos;
        // `seg` is the start of not-yet-copied raw text (only used once
        // `decoded` is Some).
        let mut seg = p;
        let finish = |this: &mut Self,
                      p: usize,
                      stop: LitStop,
                      stop_end: usize,
                      decoded: Option<String>,
                      seg: usize,
                      bad_escape| {
            let decoded = decoded.map(|mut d| {
                d.push_str(&this.src[seg..p]);
                d
            });
            this.pos = stop_end;
            Literal {
                span: Span::new(start as u32, p as u32),
                decoded,
                stop,
                stop_span: Span::new(p as u32, stop_end as u32),
                bad_escape,
            }
        };
        loop {
            if let TemplateCtx::Heredoc { delimiter } = ctx
                && at_line_start
                && let Some(e) = self.heredoc_end_at(p, delimiter)
            {
                return finish(self, p, LitStop::HeredocEnd, e, decoded, seg, bad_escape);
            }
            at_line_start = false;
            if p >= b.len() {
                return finish(self, p, LitStop::Eof, p, decoded, seg, bad_escape);
            }
            match b[p] {
                b'$' | b'%' => {
                    let next = b.get(p + 1).copied();
                    if next == Some(b'{') {
                        let stop = if b[p] == b'$' {
                            LitStop::Interp
                        } else {
                            LitStop::Directive
                        };
                        return finish(self, p, stop, p + 2, decoded, seg, bad_escape);
                    }
                    // `$${` -> `${`, `%%{` -> `%{`
                    if next == Some(b[p]) && b.get(p + 2) == Some(&b'{') {
                        let d = decoded.get_or_insert_with(String::new);
                        d.push_str(&self.src[seg..p + 1]);
                        p += 2; // skip the doubled char; `{` copied with the next segment
                        seg = p;
                        continue;
                    }
                    p += 1;
                }
                b'\n' => match ctx {
                    TemplateCtx::Quoted => {
                        return finish(self, p, LitStop::Newline, p, decoded, seg, bad_escape);
                    }
                    TemplateCtx::Heredoc { .. } | TemplateCtx::Raw => {
                        p += 1;
                        at_line_start = true;
                    }
                },
                b'"' if matches!(ctx, TemplateCtx::Quoted) => {
                    return finish(self, p, LitStop::Quote, p + 1, decoded, seg, bad_escape);
                }
                b'\\' if matches!(ctx, TemplateCtx::Quoted) => {
                    let d = decoded.get_or_insert_with(String::new);
                    d.push_str(&self.src[seg..p]);
                    let esc_start = p;
                    p += 1;
                    match b.get(p) {
                        Some(b'n') => d.push('\n'),
                        Some(b'r') => d.push('\r'),
                        Some(b't') => d.push('\t'),
                        Some(b'"') => d.push('"'),
                        Some(b'\\') => d.push('\\'),
                        Some(c @ (b'u' | b'U')) => {
                            let n = if *c == b'u' { 4 } else { 8 };
                            let hex = self
                                .src
                                .get(p + 1..p + 1 + n)
                                .filter(|h| h.bytes().all(|x| x.is_ascii_hexdigit()));
                            match hex
                                .and_then(|h| u32::from_str_radix(h, 16).ok())
                                .and_then(char::from_u32)
                            {
                                Some(ch) => {
                                    d.push(ch);
                                    p += n;
                                }
                                None => {
                                    bad_escape
                                        .get_or_insert(Span::new(esc_start as u32, (p + 1) as u32));
                                }
                            }
                        }
                        _ => {
                            bad_escape.get_or_insert(Span::new(
                                esc_start as u32,
                                (p + 1).min(b.len()) as u32,
                            ));
                            // Keep the raw text.
                            d.push('\\');
                            p -= 1;
                        }
                    }
                    p += 1;
                    seg = p;
                }
                _ => p += 1,
            }
        }
    }

    /// Error recovery: skip a quoted string whose opening `"` was just lexed
    /// (pos is after it). Stops after the closing quote or at a newline/EOF.
    /// Interpolations are skipped with brace counting.
    pub fn skip_quoted(&mut self) {
        let b = self.bytes();
        let mut depth = 0usize;
        while self.pos < b.len() {
            match b[self.pos] {
                b'\\' => self.pos += 1,
                b'"' if depth == 0 => {
                    self.pos += 1;
                    return;
                }
                b'\n' if depth == 0 => return,
                b'{' if depth > 0 => depth += 1,
                b'$' | b'%' if self.peek_byte(1) == b'{' => {
                    depth += 1;
                    self.pos += 1;
                }
                b'}' if depth > 0 => depth -= 1,
                _ => {}
            }
            self.pos += 1;
        }
    }

    /// Error recovery: skip a heredoc body (pos just after the opener).
    pub fn skip_heredoc(&mut self, delimiter: &str) {
        let b = self.bytes();
        let mut p = self.pos;
        loop {
            if let Some(e) = self.heredoc_end_at(p, delimiter) {
                self.pos = e;
                return;
            }
            match memchr_newline_opt(&b[p..]) {
                Some(i) => p += i + 1,
                None => {
                    self.pos = b.len();
                    return;
                }
            }
        }
    }
}

#[inline]
fn memchr_newline(s: &[u8]) -> usize {
    memchr_newline_opt(s).unwrap_or(s.len())
}

#[inline]
fn memchr_newline_opt(s: &[u8]) -> Option<usize> {
    s.iter().position(|&c| c == b'\n')
}

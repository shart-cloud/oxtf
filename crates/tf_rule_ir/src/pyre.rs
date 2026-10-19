//! Python `re.match` / `re.search` for patterns from Checkov policies.
//!
//! Patterns are translated once, at load time, into the `regex` crate's
//! syntax. Only constructs whose meaning is identical in both engines are
//! admitted; anything else (backreferences, lookaround, `\b`, flags other
//! than `i`, a `$` that is not final) makes the pattern unsupported, never
//! approximated. Python's Unicode classes are spelled out explicitly:
//!
//! - `\s` is `str.isspace`, which adds U+001C..U+001F to Unicode White_Space;
//! - `\w` is `str.isalnum` or `_`: letters and numbers, but not marks or
//!   connector punctuation, unlike the `regex` crate's `\w`;
//! - `\d` is the decimal digits (`Nd`) in both;
//! - `$` (end, or before a final newline) becomes `\n?\z`, which is only
//!   equivalent when nothing but closing groups follows it;
//! - case-insensitive matching is admitted for ASCII only, where Python's
//!   lowercase-based comparison differs from simple case folding in one
//!   place: `i`/`I` also match `İ` (U+0130) and `ı` (U+0131).
//!
//! Unicode classes follow the `regex` crate's Unicode version. Code points
//! assigned after the Python version Checkov runs on can therefore differ.

use regex::Regex;

const SPACE: &str = r"\s\x1C-\x1F";
const WORD: &str = r"\p{L}\p{N}_";

/// How a compiled pattern is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `re.match`: anchored at the start.
    Match,
    /// `re.search`: anywhere.
    Search,
}

/// Translate a Python pattern, or explain why it is not admitted.
pub fn translate(pattern: &str) -> Result<String, String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut t = Translator {
        p: &chars,
        i: 0,
        out: String::new(),
        depth: 0,
        ignore_case: vec![false],
        multiline: false,
        repeated: false,
    };
    t.run()?;
    Ok(t.out)
}

/// Compile a Python pattern for `mode`.
pub fn compile(pattern: &str, mode: Mode) -> Result<Regex, String> {
    let body = translate(pattern)?;
    let anchored = match mode {
        Mode::Match => format!(r"\A(?:{body})"),
        Mode::Search => body,
    };
    Regex::new(&anchored).map_err(|e| format!("pattern {pattern:?} cannot be compiled: {e}"))
}

struct Translator<'a> {
    p: &'a [char],
    i: usize,
    out: String,
    depth: usize,
    /// Case-insensitivity at each open group (and the pattern, at 0).
    ignore_case: Vec<bool>,
    /// `re.MULTILINE` (`(?m)` at the start): `^` and `$` also match at
    /// line boundaries, as the `regex` crate's `(?m:^)` / `(?m:$)` do.
    multiline: bool,
    /// The previous item was a quantifier: Python rejects another.
    repeated: bool,
}

fn unsupported(what: &str) -> Result<(), String> {
    Err(format!(
        "regular expression uses {what}, which is not supported"
    ))
}

/// A literal character, escaped for the `regex` crate outside a class.
fn literal(c: char) -> String {
    if c.is_ascii_punctuation() || c == ' ' {
        format!("\\{c}")
    } else if c.is_control() {
        format!("\\x{{{:X}}}", c as u32)
    } else {
        c.to_string()
    }
}

impl Translator<'_> {
    fn peek(&self) -> Option<char> {
        self.p.get(self.i).copied()
    }

    fn at(&self, s: &str) -> bool {
        let s: Vec<char> = s.chars().collect();
        self.p[self.i..].starts_with(&s)
    }

    fn run(&mut self) -> Result<(), String> {
        // Global inline flags: Python accepts them only at the start.
        if self.at("(?") {
            let mut j = self.i + 2;
            while self.p.get(j).is_some_and(|c| c.is_ascii_alphabetic()) {
                j += 1;
            }
            if self.p.get(j) == Some(&')') {
                let flags: String = self.p[self.i + 2..j].iter().collect();
                for f in flags.chars() {
                    match f {
                        'i' | 'u' => {}
                        'm' => self.multiline = true,
                        's' => {}
                        _ => return unsupported(&format!("the inline flag {f:?}")),
                    }
                }
                if flags.contains('i') {
                    self.out.push_str("(?i)");
                    self.ignore_case[0] = true;
                }
                // `re.DOTALL`: `.` also matches a newline, as `(?s)`.
                if flags.contains('s') {
                    self.out.push_str("(?s)");
                }
                self.i = j + 1;
            }
        }
        while let Some(c) = self.peek() {
            self.i += 1;
            let quantifier = matches!(c, '*' | '+' | '?') || (c == '{' && self.repeat_ahead());
            if quantifier && self.repeated {
                return Err("multiple repeat".into());
            }
            self.repeated = quantifier;
            match c {
                '\\' => self.escape()?,
                '[' => self.class()?,
                '(' => self.group()?,
                ')' => {
                    if self.depth == 0 {
                        return Err("unbalanced parenthesis".into());
                    }
                    self.depth -= 1;
                    self.ignore_case.pop();
                    self.out.push(')');
                }
                '^' if self.multiline => self.out.push_str("(?m:^)"),
                '$' if self.multiline => self.out.push_str("(?m:$)"),
                '|' | '.' | '^' => self.out.push(c),
                '$' => {
                    let rest = &self.p[self.i..];
                    let closing = rest.iter().take_while(|c| **c == ')').count();
                    if closing != rest.len() && !(self.depth == 0 && rest.first() == Some(&'|')) {
                        return unsupported("`$` before more pattern");
                    }
                    self.out.push_str(r"(?:\n?\z)");
                }
                '*' | '+' | '?' => {
                    self.out.push(c);
                    self.quantifier_suffix()?;
                }
                '{' => match self.repeat() {
                    Some(q) => {
                        self.out.push_str(&q);
                        self.quantifier_suffix()?;
                    }
                    None => self.out.push_str(r"\{"),
                },
                _ => self.literal(c)?,
            }
        }
        if self.depth != 0 {
            return Err("missing ), unterminated subpattern".into());
        }
        Ok(())
    }

    fn case_insensitive(&self) -> bool {
        *self.ignore_case.last().expect("pattern level")
    }

    fn open(&mut self, prefix: &str, ignore_case: bool) {
        self.depth += 1;
        self.ignore_case.push(ignore_case);
        self.out.push_str(prefix);
    }

    /// A literal outside a class, with Python's case-insensitive extras.
    fn literal(&mut self, c: char) -> Result<(), String> {
        if self.case_insensitive() {
            if !c.is_ascii() {
                return unsupported("case-insensitive matching of non-ASCII characters");
            }
            if c.eq_ignore_ascii_case(&'i') {
                self.out.push_str(r"[iI\x{130}\x{131}]");
                return Ok(());
            }
        }
        self.out.push_str(&literal(c));
        Ok(())
    }

    /// Whether a `{` here starts a repetition (without consuming it).
    fn repeat_ahead(&mut self) -> bool {
        let save = self.i;
        let out = self.repeat().is_some();
        self.i = save;
        out
    }

    /// A lazy `?` is shared; a possessive `+` (Python 3.11) is not.
    fn quantifier_suffix(&mut self) -> Result<(), String> {
        match self.peek() {
            Some('?') => {
                self.i += 1;
                self.out.push('?');
                if matches!(self.peek(), Some('*' | '+' | '?'))
                    || (self.peek() == Some('{') && self.repeat_ahead())
                {
                    return Err("multiple repeat".into());
                }
                Ok(())
            }
            Some('+') => unsupported("a possessive quantifier"),
            _ => Ok(()),
        }
    }

    /// `{m}`, `{m,}`, `{,n}`, `{m,n}` as Python's parser reads them, or
    /// `None` when the brace is a literal.
    fn repeat(&mut self) -> Option<String> {
        let start = self.i;
        let digits = |t: &mut Self| {
            let s = t.i;
            while t.peek().is_some_and(|c| c.is_ascii_digit()) {
                t.i += 1;
            }
            t.p[s..t.i].iter().collect::<String>()
        };
        let lo = digits(self);
        let (hi, comma) = if self.peek() == Some(',') {
            self.i += 1;
            (digits(self), true)
        } else {
            (String::new(), false)
        };
        if self.peek() != Some('}') || (lo.is_empty() && !comma) {
            self.i = start;
            return None;
        }
        self.i += 1;
        let lo = if lo.is_empty() { "0".to_string() } else { lo };
        Some(match (comma, hi.is_empty()) {
            (false, _) => format!("{{{lo}}}"),
            (true, true) => format!("{{{lo},}}"),
            (true, false) => format!("{{{lo},{hi}}}"),
        })
    }

    fn group(&mut self) -> Result<(), String> {
        if self.peek() != Some('?') {
            // Captures are never read; keep the grouping only.
            let ic = self.case_insensitive();
            self.open("(?:", ic);
            return Ok(());
        }
        self.i += 1;
        match self.peek() {
            Some(':') => {
                self.i += 1;
                let ic = self.case_insensitive();
                self.open("(?:", ic);
                Ok(())
            }
            Some('P') if self.p.get(self.i + 1) == Some(&'<') => {
                // A named group: the name is not needed.
                while self.peek().is_some_and(|c| c != '>') {
                    self.i += 1;
                }
                if self.peek() != Some('>') {
                    return Err("unterminated group name".into());
                }
                self.i += 1;
                let ic = self.case_insensitive();
                self.open("(?:", ic);
                Ok(())
            }
            Some('#') => {
                while self.peek().is_some_and(|c| c != ')') {
                    self.i += 1;
                }
                if self.peek() != Some(')') {
                    return Err("missing ), unterminated comment".into());
                }
                self.i += 1;
                Ok(())
            }
            Some(c) if c.is_ascii_alphabetic() || c == '-' => {
                // Scoped flags `(?i:...)`.
                let start = self.i;
                while self
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '-')
                {
                    self.i += 1;
                }
                let flags: String = self.p[start..self.i].iter().collect();
                if self.peek() != Some(':') {
                    return unsupported("inline flags that are not at the start");
                }
                if !flags.chars().all(|f| f == 'i') {
                    return unsupported(&format!("the inline flags {flags:?}"));
                }
                self.i += 1;
                self.open("(?i:", true);
                Ok(())
            }
            _ => unsupported("lookaround, backreferences or atomic groups"),
        }
    }

    /// An escape outside a class.
    fn escape(&mut self) -> Result<(), String> {
        let Some(c) = self.peek() else {
            return Err("bad escape (end of pattern)".into());
        };
        self.i += 1;
        match c {
            'd' | 'D' => self.out.push_str(&format!("\\{c}")),
            's' => self.out.push_str(&format!("[{SPACE}]")),
            'S' => self.out.push_str(&format!("[^{SPACE}]")),
            'w' => self.out.push_str(&format!("[{WORD}]")),
            'W' => self.out.push_str(&format!("[^{WORD}]")),
            'A' => self.out.push_str(r"\A"),
            'Z' => self.out.push_str(r"\z"),
            'b' | 'B' => return unsupported("word boundaries"),
            _ => {
                let ch = self.char_escape(c)?;
                self.literal(ch)?;
            }
        }
        Ok(())
    }

    /// An escape that stands for one character (shared with classes).
    fn char_escape(&mut self, c: char) -> Result<char, String> {
        let hex = |t: &mut Self, n: usize| -> Result<char, String> {
            let s: String =
                t.p.get(t.i..t.i + n)
                    .map(|s| s.iter().collect())
                    .unwrap_or_default();
            if s.len() != n || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("incomplete escape \\{c}"));
            }
            t.i += n;
            char::from_u32(u32::from_str_radix(&s, 16).unwrap())
                .ok_or_else(|| format!("bad escape \\{c}{s}"))
        };
        match c {
            'n' => Ok('\n'),
            't' => Ok('\t'),
            'r' => Ok('\r'),
            'f' => Ok('\x0C'),
            'v' => Ok('\x0B'),
            'a' => Ok('\x07'),
            'x' => hex(self, 2),
            'u' => hex(self, 4),
            'U' => hex(self, 8),
            '0'..='9' => Err(
                "regular expression uses octal escapes or backreferences, which is not supported"
                    .into(),
            ),
            c if c.is_ascii_alphanumeric() => Err(format!("bad escape \\{c}")),
            c => Ok(c),
        }
    }

    /// A character class, rebuilt with every literal escaped so that the
    /// `regex` crate's nested classes and set operators never apply.
    fn class(&mut self) -> Result<(), String> {
        let mut out = String::from("[");
        if self.peek() == Some('^') {
            self.i += 1;
            out.push('^');
        }
        let mut first = true;
        let mut items = 0;
        let ic = self.case_insensitive();
        let mut has_i = false;
        loop {
            let Some(c) = self.peek() else {
                return Err("unterminated character set".into());
            };
            self.i += 1;
            if c == ']' && !first {
                break;
            }
            first = false;
            // A class item: a single character, or a class escape.
            let lo = if c == '\\' {
                let Some(e) = self.peek() else {
                    return Err("unterminated character set".into());
                };
                self.i += 1;
                match e {
                    'd' | 'D' => {
                        out.push_str(&format!("\\{e}"));
                        items += 1;
                        continue;
                    }
                    's' => {
                        out.push_str(SPACE);
                        items += 1;
                        continue;
                    }
                    'S' => {
                        out.push_str(&format!("[^{SPACE}]"));
                        items += 1;
                        continue;
                    }
                    'w' => {
                        out.push_str(WORD);
                        items += 1;
                        continue;
                    }
                    'W' => {
                        out.push_str(&format!("[^{WORD}]"));
                        items += 1;
                        continue;
                    }
                    'b' => '\x08',
                    _ => self.char_escape(e)?,
                }
            } else {
                c
            };
            // A range `lo-hi`, unless the `-` is the last thing in the class.
            if self.peek() == Some('-') && self.p.get(self.i + 1).is_some_and(|c| *c != ']') {
                self.i += 1;
                let h = self.peek().ok_or("unterminated character set")?;
                self.i += 1;
                let hi = if h == '\\' {
                    let e = self.peek().ok_or("unterminated character set")?;
                    self.i += 1;
                    if matches!(e, 'd' | 'D' | 's' | 'S' | 'w' | 'W') {
                        return Err(format!("bad character range {lo}-\\{e}"));
                    }
                    if e == 'b' {
                        '\x08'
                    } else {
                        self.char_escape(e)?
                    }
                } else {
                    h
                };
                if hi < lo {
                    return Err(format!("bad character range {lo}-{hi}"));
                }
                if ic && !(lo.is_ascii() && hi.is_ascii()) {
                    return unsupported("case-insensitive matching of non-ASCII characters");
                }
                has_i |= (lo..=hi).contains(&'i') || (lo..=hi).contains(&'I');
                out.push_str(&format!("{}-{}", class_char(lo), class_char(hi)));
            } else {
                if ic && !lo.is_ascii() {
                    return unsupported("case-insensitive matching of non-ASCII characters");
                }
                has_i |= lo.eq_ignore_ascii_case(&'i');
                out.push_str(&class_char(lo));
            }
            items += 1;
        }
        if ic && has_i {
            out.push_str(r"\x{130}\x{131}");
        }
        out.push(']');
        if items == 0 {
            return Err("unterminated character set".into());
        }
        self.out.push_str(&out);
        Ok(())
    }
}

fn class_char(c: char) -> String {
    if c.is_ascii_punctuation() || c == ' ' {
        format!("\\{c}")
    } else if c.is_control() || c.is_whitespace() {
        format!("\\x{{{:X}}}", c as u32)
    } else {
        c.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, s: &str) -> bool {
        compile(p, Mode::Match).unwrap().is_match(s)
    }

    #[test]
    fn python_semantics() {
        assert!(m("(^postgres|.*sqlserver).*", "sqlserver-ex"));
        assert!(!m("abc", "xabc"));
        assert!(m("abc$", "abc\n"));
        assert!(!m("abc$", "abc\n\n"));
        assert!(m("(?i)^ROOT$", "root"));
        assert!(m(r"a{,2}b", "aab"));
        assert!(m(r"a{x", "a{x"));
        assert!(m(r"[]a]+", "]a]"));
        assert!(m(r"[a-c&&b]+", "a&&b"));
        assert!(m(r"\w+", "é1_"));
        assert!(!m(r"\w", "\u{301}"));
        assert!(m(r"\s", "\x1f"));
        assert!(compile(r"\bx", Mode::Search).is_err());
        assert!(compile(r"(?=x)", Mode::Search).is_err());
        assert!(compile(r"(a)\1", Mode::Search).is_err());
        assert!(compile(r"a$b", Mode::Search).is_err());
        assert!(compile(r"[z-a]", Mode::Search).is_err());
        assert!(compile(r"\q", Mode::Search).is_err());
    }

    /// `re.MULTILINE`, against CPython: `^`/`$` also at line boundaries,
    /// while `re.match` stays anchored at the start of the string.
    #[test]
    fn multiline() {
        let p = r"(?m)^-----BEGIN (RSA|EC) PRIVATE KEY-----$";
        let s = |x: &str| compile(p, Mode::Search).unwrap().is_match(x);
        assert!(s("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(s("x\n-----BEGIN EC PRIVATE KEY-----\nabc"));
        assert!(!s("-----BEGIN RSA PRIVATE KEY----- x"));
        assert!(!m(p, "x\n-----BEGIN EC PRIVATE KEY-----\nabc"));
    }
}

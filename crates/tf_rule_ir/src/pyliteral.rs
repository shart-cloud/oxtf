//! Python literal syntax, for the strings Checkov's runner evaluates.
//!
//! Checkov's variable rendering passes configured strings to a restricted
//! `eval` (`evaluate_terraform`, `safe_eval_functions.evaluate`): a string
//! that reads as a Python literal becomes that value (`"-1"` → `-1`,
//! `"[1, 2]"` → a list, a JSON object without `true`/`false`/`null` → a
//! dict), and failing that, one that is strict JSON is parsed as JSON. This
//! module reads the literal subset of that `eval` exactly; arithmetic and
//! function calls (which `eval` would also run) are not read, and such
//! strings stay strings.

use serde_json::{Map, Number, Value as Json};

/// The value of `s` as a Python literal expression, if it is one.
pub fn eval(s: &str) -> Option<Json> {
    let chars: Vec<char> = s.chars().collect();
    let mut p = Parser {
        s: &chars,
        i: 0,
        depth: 0,
    };
    // `eval` strips leading spaces and tabs and skips blank lines, but an
    // indented line after a newline is an IndentationError; trailing
    // whitespace is allowed.
    p.space(false);
    while matches!(p.peek(), Some('\n' | '\r')) {
        p.i += 1;
        if matches!(p.peek(), Some(' ' | '\t')) {
            return None;
        }
    }
    let v = p.expr()?;
    while p.peek().is_some_and(char::is_whitespace) {
        p.i += 1;
    }
    (p.i == chars.len()).then_some(v)
}

/// Checkov's `_try_evaluate` for container results: a Python literal, else
/// strict JSON when wrapping the string in double quotes would not parse
/// (which is when it contains a double quote).
pub fn container(s: &str) -> Option<Json> {
    if s.len() > 10_000 {
        return None; // CHECKOV_RENDER_MAX_LEN
    }
    let v = match eval(s) {
        Some(v) => v,
        None if s.contains('"') => serde_json::from_str(s).ok()?,
        None => return None,
    };
    matches!(v, Json::Array(_) | Json::Object(_)).then_some(v)
}

struct Parser<'a> {
    s: &'a [char],
    i: usize,
    depth: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    /// Skip spaces (and newlines inside brackets, where Python joins lines).
    fn space(&mut self, newlines: bool) {
        while let Some(c) = self.peek() {
            let ok = c == ' '
                || c == '\t'
                || c == '\x0c'
                || ((newlines || self.depth > 0) && (c == '\n' || c == '\r'));
            if !ok {
                break;
            }
            self.i += 1;
        }
    }

    fn expr(&mut self) -> Option<Json> {
        self.space(false);
        match self.peek()? {
            '-' | '+' => {
                let neg = self.peek() == Some('-');
                self.i += 1;
                let v = self.expr()?;
                match v {
                    Json::Number(n) if neg => {
                        if let Some(i) = n.as_i64().filter(|_| !n.is_f64()) {
                            Some(Json::from(-i))
                        } else {
                            Number::from_f64(-n.as_f64()?).map(Json::Number)
                        }
                    }
                    Json::Number(_) => Some(v),
                    // `-True` is -1: a bool is an int.
                    Json::Bool(b) => Some(Json::from(if neg { -(b as i64) } else { b as i64 })),
                    _ => None,
                }
            }
            '[' | '(' => {
                let close = if self.peek() == Some('[') { ']' } else { ')' };
                let paren = close == ')';
                self.i += 1;
                self.depth += 1;
                let mut items = Vec::new();
                let mut trailing_comma = false;
                loop {
                    self.space(true);
                    if self.peek() == Some(close) {
                        self.i += 1;
                        break;
                    }
                    items.push(self.expr()?);
                    self.space(true);
                    match self.peek()? {
                        ',' => {
                            self.i += 1;
                            trailing_comma = true;
                        }
                        c if c == close => {
                            self.i += 1;
                            trailing_comma = false;
                            break;
                        }
                        _ => return None,
                    }
                }
                self.depth -= 1;
                // `(x)` is x; `(x,)` and `()` are tuples (read as lists).
                if paren && items.len() == 1 && !trailing_comma {
                    return items.pop();
                }
                Some(Json::Array(items))
            }
            '{' => {
                self.i += 1;
                self.depth += 1;
                self.space(true);
                if self.peek() == Some('}') {
                    self.i += 1;
                    self.depth -= 1;
                    return Some(Json::Object(Map::new()));
                }
                let first = self.expr()?;
                self.space(true);
                if self.peek() == Some(':') {
                    let mut map = Map::new();
                    let mut key = first;
                    loop {
                        self.i += 1; // ':'
                        let value = self.expr()?;
                        // Keys become strings, as JSON's; only hashable
                        // scalars may be keys.
                        let k = match key {
                            Json::String(s) => s,
                            Json::Number(n) => n.to_string(),
                            Json::Bool(b) => if b { "True" } else { "False" }.into(),
                            Json::Null => "None".into(),
                            _ => return None,
                        };
                        map.insert(k, value);
                        self.space(true);
                        match self.peek()? {
                            ',' => {
                                self.i += 1;
                                self.space(true);
                                if self.peek() == Some('}') {
                                    self.i += 1;
                                    break;
                                }
                                key = self.expr()?;
                                self.space(true);
                                if self.peek() != Some(':') {
                                    return None;
                                }
                            }
                            '}' => {
                                self.i += 1;
                                break;
                            }
                            _ => return None,
                        }
                    }
                    self.depth -= 1;
                    Some(Json::Object(map))
                } else {
                    // A set: read as a list of its distinct members.
                    let mut items = vec![first];
                    loop {
                        self.space(true);
                        match self.peek()? {
                            ',' => {
                                self.i += 1;
                                self.space(true);
                                if self.peek() == Some('}') {
                                    self.i += 1;
                                    break;
                                }
                                let v = self.expr()?;
                                if !items.contains(&v) {
                                    items.push(v);
                                }
                            }
                            '}' => {
                                self.i += 1;
                                break;
                            }
                            _ => return None,
                        }
                    }
                    self.depth -= 1;
                    if items.iter().any(|x| x.is_array() || x.is_object()) {
                        return None; // unhashable
                    }
                    Some(Json::Array(items))
                }
            }
            '\'' | '"' => {
                // Adjacent string literals concatenate.
                let mut out = self.string()?;
                loop {
                    let save = self.i;
                    self.space(false);
                    if matches!(self.peek(), Some('\'' | '"')) {
                        out.push_str(&self.string()?);
                    } else {
                        self.i = save;
                        break;
                    }
                }
                Some(Json::String(out))
            }
            c if c.is_ascii_digit() || c == '.' => self.number(),
            c if c.is_alphabetic() || c == '_' => {
                let start = self.i;
                while self.peek().is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    self.i += 1;
                }
                let word: String = self.s[start..self.i].iter().collect();
                // String prefixes: u'' is a plain string, r'' a raw one;
                // bytes and f-strings are not read.
                if matches!(self.peek(), Some('\'' | '"')) {
                    return match word.as_str() {
                        "u" | "U" => self.expr(),
                        "r" | "R" => self.raw_string().map(Json::String),
                        _ => None,
                    };
                }
                match word.as_str() {
                    "True" => Some(Json::Bool(true)),
                    "False" => Some(Json::Bool(false)),
                    "None" => Some(Json::Null),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn string(&mut self) -> Option<String> {
        let q = self.peek()?;
        let triple = self.s.get(self.i..self.i + 3) == Some(&[q, q, q]);
        self.i += if triple { 3 } else { 1 };
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            if c == q {
                if !triple {
                    self.i += 1;
                    return Some(out);
                }
                if self.s.get(self.i..self.i + 3) == Some(&[q, q, q]) {
                    self.i += 3;
                    return Some(out);
                }
            }
            if !triple && (c == '\n' || c == '\r') {
                return None;
            }
            self.i += 1;
            if c != '\\' {
                out.push(c);
                continue;
            }
            let e = self.peek()?;
            self.i += 1;
            match e {
                '\n' => {}
                '\\' | '\'' | '"' => out.push(e),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'a' => out.push('\x07'),
                'b' => out.push('\x08'),
                'f' => out.push('\x0c'),
                'v' => out.push('\x0b'),
                '0'..='7' => {
                    let mut n = e.to_digit(8)?;
                    for _ in 0..2 {
                        match self.peek().and_then(|c| c.to_digit(8)) {
                            Some(d) => {
                                n = n * 8 + d;
                                self.i += 1;
                            }
                            None => break,
                        }
                    }
                    out.push(char::from_u32(n)?);
                }
                'x' | 'u' | 'U' => {
                    let len = match e {
                        'x' => 2,
                        'u' => 4,
                        _ => 8,
                    };
                    let hex: String = self.s.get(self.i..self.i + len)?.iter().collect();
                    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        return None;
                    }
                    self.i += len;
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                'N' => return None,
                other => {
                    out.push('\\');
                    out.push(other);
                }
            }
        }
    }

    /// A raw string literal (no escape processing, except that a quote
    /// after a backslash does not end it).
    fn raw_string(&mut self) -> Option<String> {
        let q = self.peek()?;
        if self.s.get(self.i..self.i + 3) == Some(&[q, q, q]) {
            return None; // triple-quoted raw strings are not read
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                c if c == q => return Some(out),
                '\n' | '\r' => return None,
                '\\' => {
                    out.push('\\');
                    out.push(self.peek()?);
                    self.i += 1;
                }
                c => out.push(c),
            }
        }
    }

    fn number(&mut self) -> Option<Json> {
        let lower = |c: Option<char>| c.map(|c| c.to_ascii_lowercase());
        if self.peek() == Some('0')
            && matches!(
                lower(self.s.get(self.i + 1).copied()),
                Some('x' | 'o' | 'b')
            )
        {
            let radix = match lower(self.s.get(self.i + 1).copied())? {
                'x' => 16,
                'o' => 8,
                _ => 2,
            };
            self.i += 2;
            let digits = self.digits(|c| c.is_digit(radix))?;
            return Some(Json::from(i64::from_str_radix(&digits, radix).ok()?));
        }
        let int_part = if self.peek().is_some_and(|c| c.is_ascii_digit()) {
            Some(self.digits(|c| c.is_ascii_digit())?)
        } else {
            None
        };
        let mut float = false;
        let mut text = int_part.clone().unwrap_or_default();
        if self.peek() == Some('.') {
            self.i += 1;
            float = true;
            text.push('.');
            if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                text.push_str(&self.digits(|c| c.is_ascii_digit())?);
            } else if int_part.is_none() {
                return None;
            }
        }
        if matches!(lower(self.peek()), Some('e')) {
            let save = self.i;
            self.i += 1;
            let mut exp = String::from("e");
            if let Some(sign @ ('+' | '-')) = self.peek() {
                exp.push(sign);
                self.i += 1;
            }
            if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                exp.push_str(&self.digits(|c| c.is_ascii_digit())?);
                text.push_str(&exp);
                float = true;
            } else {
                self.i = save;
            }
        }
        if matches!(lower(self.peek()), Some('j'))
            || self.peek().is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            return None;
        }
        if !float {
            // Decimal ints have no leading zeros (except 0 itself).
            if text.len() > 1 && text.starts_with('0') && text.chars().any(|c| c != '0') {
                return None;
            }
            return Some(match text.parse::<i64>() {
                Ok(i) => Json::from(i),
                Err(_) => Json::Number(Number::from_f64(text.parse().ok()?)?),
            });
        }
        Number::from_f64(text.parse().ok()?).map(Json::Number)
    }

    /// Digits with single underscores between them.
    fn digits(&mut self, ok: impl Fn(char) -> bool) -> Option<String> {
        let mut out = String::new();
        let mut last_underscore = true;
        while let Some(c) = self.peek() {
            if ok(c) {
                out.push(c);
                last_underscore = false;
            } else if c == '_' && !last_underscore {
                last_underscore = true;
            } else {
                break;
            }
            self.i += 1;
        }
        (!out.is_empty() && !last_underscore).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_python_literals() {
        for (s, v) in [
            ("-1", json!(-1)),
            (" 5", json!(5)),
            ("1_000", json!(1000)),
            ("0x10", json!(16)),
            ("1e3", json!(1000.0)),
            ("1.5", json!(1.5)),
            ("True", json!(true)),
            ("None", json!(null)),
            ("'q'", json!("q")),
            ("[1, 'a',]", json!([1, "a"])),
            ("{\"a\": 1,}", json!({"a": 1})),
            ("{'a': {'b': [2]}}", json!({"a": {"b": [2]}})),
            ("(1,)", json!([1])),
            ("(1)", json!(1)),
            ("{\n\"a\": 1\n}\n", json!({"a": 1})),
            ("\n1", json!(1)),
            ("00", json!(0)),
            ("r'a\\b'", json!("a\\b")),
            ("\"a\" \"b\"", json!("ab")),
        ] {
            assert_eq!(eval(s), Some(v), "{s:?}");
        }
        for s in [
            "01", "true", "1 + 1", "a,b", "inf", "[1, 2", "{}x", "1j", "x", "\n  {}", "1__0",
            "b'x'",
        ] {
            assert_eq!(eval(s), None, "{s:?}");
        }
    }

    #[test]
    fn containers_fall_back_to_json() {
        assert_eq!(
            container("{\"a\": true, \"b\": null}"),
            Some(json!({"a": true, "b": null}))
        );
        // Neither a Python literal (false) nor JSON (trailing comma).
        assert_eq!(container("{\"a\": [1,], \"b\": false}"), None);
        assert_eq!(container("-1"), None);
        assert_eq!(container("[1, 2]"), Some(json!([1, 2])));
    }
}

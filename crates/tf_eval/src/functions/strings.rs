use super::*;

#[expect(clippy::too_many_lines)]
pub(super) fn strings(name: &str, a: &[Value], budget: &InputBudget) -> R {
    let string = |value: &Value| text::coerce(value, budget);
    match name {
        "lower" | "upper" | "title" | "strrev" | "urlencode" => {
            let s = string(one_arg(a)?)?;
            let mut out = Text::new(budget);
            match name {
                "lower" => {
                    // str::to_lowercase preserves context-sensitive Greek final sigma.
                    // UTF-8 case mapping expands by at most three output bytes per input byte.
                    let maximum = s.len().checked_mul(3).ok_or_else(|| out.refused())?;
                    budget
                        .admit_text(maximum as u64)
                        .map_err(|e| Value::limit(e.to_string()))?;
                    let lowered = s.to_lowercase();
                    assert!(lowered.len() <= maximum);
                    return Ok(Value::string(text::copy(&lowered, budget)?));
                }
                "upper" => {
                    for c in s.chars().flat_map(char::to_uppercase) {
                        out.push(c)?;
                    }
                }
                "title" => {
                    let mut start = true;
                    for c in s.chars() {
                        if start && c.is_alphabetic() {
                            for c in c.to_uppercase() {
                                out.push(c)?;
                            }
                        } else {
                            out.push(c)?;
                        }
                        start = !c.is_alphanumeric();
                    }
                }
                "strrev" => {
                    for c in s.chars().rev() {
                        out.push(c)?;
                    }
                }
                "urlencode" => {
                    for b in s.bytes() {
                        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                            out.push(b as char)?;
                        } else {
                            out.formatted(format_args!("%{b:02X}"))?;
                        }
                    }
                }
                _ => unreachable!(),
            }
            Ok(Value::string(out.finish()?))
        }
        "basename" | "dirname" | "trimspace" | "chomp" => {
            let s = string(one_arg(a)?)?;
            let result = match name {
                "basename" => s.trim_end_matches('/').rsplit('/').next().unwrap_or(""),
                "dirname" => {
                    let t = s.trim_end_matches('/');
                    match t.rfind('/') {
                        Some(0) => "/",
                        Some(i) => &t[..i],
                        None => ".",
                    }
                }
                "trimspace" => s.trim(),
                "chomp" => s.trim_end_matches(['\n', '\r']),
                _ => unreachable!(),
            };
            Ok(Value::string(text::copy(result, budget)?))
        }
        "strcontains" | "startswith" | "endswith" => {
            arity(a, 2)?;
            let (s, p) = (string(&a[0])?, string(&a[1])?);
            Ok(Value::bool(match name {
                "strcontains" => s.contains(&*p),
                "startswith" => s.starts_with(&*p),
                "endswith" => s.ends_with(&*p),
                _ => unreachable!(),
            }))
        }
        "indent" => indent(a, budget),
        "md5" | "sha1" | "sha256" | "sha512" | "base64sha256" | "base64sha512" => {
            let input = string(one_arg(a)?)?;
            hash_budgeted(name, input.as_bytes(), budget)
        }
        "base64encode" => Ok(Value::string(b64encode_budgeted(
            string(one_arg(a)?)?.as_bytes(),
            budget,
        )?)),
        "base64decode" => {
            let s = string(one_arg(a)?)?;
            // Decoded bytes and UTF-8 output are each no larger than the encoded input.
            let decoded = b64decode(&s, budget)?
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| Value::error("base64decode: invalid input"))?;
            Ok(Value::string(text::copy(&decoded, budget)?))
        }
        "trim" | "trimprefix" | "trimsuffix" => {
            arity(a, 2)?;
            let (s, p) = (string(&a[0])?, string(&a[1])?);
            let result = match name {
                "trim" => s.trim_matches(|c| p.contains(c)),
                "trimprefix" => s.strip_prefix(&*p).unwrap_or(&s),
                "trimsuffix" => s.strip_suffix(&*p).unwrap_or(&s),
                _ => unreachable!(),
            };
            Ok(Value::string(text::copy(result, budget)?))
        }
        "replace" => replace(a, budget),
        "regex" => regex(a, budget),
        "split" => {
            arity(a, 2)?;
            let (sep, s) = (string(&a[0])?, string(&a[1])?);
            let mut out = Buffer::new(budget);
            for part in s.split(&*sep) {
                out.push(Value::string(text::copy(part, budget)?))?;
            }
            Ok(Value::list(out.finish()))
        }
        "join" => {
            if a.len() < 2 {
                return Err(Value::error("join: wrong number of arguments"));
            }
            let sep = string(&a[0])?;
            let mut out = Text::new(budget);
            let mut first = true;
            for l in &a[1..] {
                for e in list(l)? {
                    if !first {
                        out.push_str(&sep)?;
                    }
                    out.push_str(&string(e)?)?;
                    first = false;
                }
            }
            Ok(Value::string(out.finish()?))
        }
        "substr" => {
            arity(a, 3)?;
            let s = string(&a[0])?;
            let off = number(&a[1])? as i64;
            let len = number(&a[2])? as i64;
            let n = s.chars().count() as i64;
            let start = if off < 0 {
                n.saturating_add(off).max(0)
            } else {
                off.min(n)
            } as usize;
            let count = if len < 0 { usize::MAX } else { len as usize };
            let mut out = Text::new(budget);
            for c in s.chars().skip(start).take(count) {
                out.push(c)?;
            }
            Ok(Value::string(out.finish()?))
        }
        "format" => {
            if a.is_empty() {
                return Err(Value::error("format: missing format string"));
            }
            format(&string(&a[0])?, &a[1..], budget).map(Value::string)
        }
        "formatlist" => {
            if a.is_empty() {
                return Err(Value::error("formatlist: missing format string"));
            }
            let f = string(&a[0])?;
            let mut n = None;
            for x in &a[1..] {
                if let Kind::Known(Known::List(l)) = &x.kind {
                    n = Some(l.len());
                } else if !x.is_known() {
                    return Err(x.clone());
                }
            }
            let mut out = Buffer::new(budget);
            for i in 0..n.unwrap_or(1) {
                let row = collections::collect(
                    a[1..].iter().map(|x| match x.as_list() {
                        Some(l) => l.get(i).cloned().unwrap_or_else(Value::null),
                        None => x.clone(),
                    }),
                    budget,
                )?;
                out.push(Value::string(format(&f, &row, budget)?))?;
            }
            Ok(Value::list(out.finish()))
        }
        _ => conversions(name, a, budget),
    }
}

pub(super) fn indent(args: &[Value], budget: &InputBudget) -> R {
    let string = |v: &Value| text::coerce(v, budget);
    arity(args, 2)?;
    let width = number(&args[0])?;
    if !width.is_finite() || width < 0.0 || width.fract() != 0.0 {
        return Err(Value::error(
            "indent: width must be a nonnegative whole number",
        ));
    }
    let text = string(&args[1])?;
    if width > INDENT_BYTES_MAX as f64 {
        return Err(Value::limit("indent: padding too large"));
    }
    if text.len() > INDENT_BYTES_MAX {
        return Err(Value::limit("indent: input too large"));
    }
    let width = width as usize;
    let lines = text.bytes().filter(|&byte| byte == b'\n').count();
    let bytes = lines
        .checked_mul(width)
        .and_then(|padding| text.len().checked_add(padding));
    let bytes = bytes
        .filter(|&bytes| bytes <= INDENT_BYTES_MAX)
        .ok_or_else(|| Value::limit("indent: output too large"))?;
    assert!(width <= INDENT_BYTES_MAX);
    assert!(bytes <= INDENT_BYTES_MAX);
    if lines == 0 || width == 0 {
        return Ok(Value::string(text));
    }
    let mut result = Text::new(budget);
    result.reserve(bytes)?;
    for line in text.split_inclusive('\n') {
        result.push_str(line)?;
        if line.ends_with('\n') {
            for _ in 0..width {
                result.push(' ')?;
            }
        }
    }
    assert_eq!(result.as_str().len(), bytes);
    Ok(Value::string(result.finish()?))
}

/// Go-style `format` with the verbs Terraform supports most often.
pub(super) fn format(f: &str, args: &[Value], budget: &InputBudget) -> Result<Arc<str>, Value> {
    let mut out = Text::new(budget);
    let mut it = f.char_indices().peekable();
    let mut ai = 0usize;
    while let Some((start, c)) = it.next() {
        if c != '%' {
            out.push(c)?;
            continue;
        }
        while let Some(&(_, d)) = it.peek() {
            if d.is_ascii_digit() || matches!(d, '.' | '-' | '+' | '#' | ' ') {
                it.next();
            } else {
                break;
            }
        }
        let Some((end, verb)) = it.next() else { break };
        if verb == '%' {
            out.push('%')?;
            continue;
        }
        let Some(arg) = args.get(ai) else {
            return Err(Value::error("format: not enough arguments"));
        };
        ai += 1;
        format_argument(&mut out, &f[start + 1..end], verb, arg, budget)?;
    }
    out.finish()
}

pub(super) fn format_argument(
    out: &mut Text<'_>,
    spec: &str,
    verb: char,
    arg: &Value,
    budget: &InputBudget,
) -> Result<(), Value> {
    match verb {
        's' | 'v' => {
            let s = if verb == 'v'
                && matches!(arg.kind, Kind::Known(Known::List(_) | Known::Object(_)))
            {
                text::json(arg, budget)?
            } else {
                text::coerce(arg, budget)?
            };
            out.push_str(&s)
        }
        'q' => out.formatted(format_args!("{:?}", text::coerce(arg, budget)?)),
        'd' => out.formatted(format_args!("{}", number(arg)? as i64)),
        'f' | 'g' | 'e' => {
            let n = number(arg)?;
            match spec.split('.').nth(1) {
                Some(p) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
                    let p = p.parse::<usize>().map_err(|_| out.refused())?;
                    // Rust's formatter may allocate precision scratch internally. Reserve
                    // its maximum fixed-point payload before entering the formatter.
                    let maximum = p.checked_add(330).ok_or_else(|| out.refused())?;
                    budget
                        .admit_text(maximum as u64)
                        .map_err(|e| Value::limit(e.to_string()))?;
                    out.reserve(maximum)?;
                    out.formatted(format_args!("{n:.p$}"))
                }
                _ => out.push_str(&text::coerce(&Value::number(n), budget)?),
            }
        }
        't' => out.push_str(
            if arg
                .as_bool()
                .ok_or_else(|| non_known_or(arg, "format: %t needs bool"))?
            {
                "true"
            } else {
                "false"
            },
        ),
        _ => Err(Value::unknown(Origin::UnsupportedFunction(
            format!("format %{verb}").into(),
        ))),
    }
}

pub(super) fn regex_limit() -> Value {
    Value::unknown(Origin::Limit("regular expression budget exceeded".into()))
}

pub(super) fn regex_input(input: &str) -> Result<(), Value> {
    if input.len() > 1_048_576 {
        Err(regex_limit())
    } else {
        Ok(())
    }
}

/// RE2 uses ASCII Perl classes and word boundaries, with Unicode literals and
/// explicit Unicode properties. Translate those escapes before compiling.
pub(super) fn terraform_regex(pattern: &str) -> Result<regex::Regex, Value> {
    if pattern.len() > 16_384 {
        return Err(regex_limit());
    }
    let mut translated = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            translated.push(ch);
            continue;
        }
        match chars.next() {
            Some('Q') => {
                let mut quoted = String::new();
                while let Some(ch) = chars.next() {
                    if ch == '\\' && chars.peek() == Some(&'E') {
                        chars.next();
                        break;
                    }
                    quoted.push(ch);
                }
                translated.push_str(&regex::escape(&quoted));
            }
            Some('d') => translated.push_str("[0-9]"),
            Some('D') => translated.push_str("[^0-9]"),
            Some('w') => translated.push_str("[0-9A-Za-z_]"),
            Some('W') => translated.push_str("[^0-9A-Za-z_]"),
            Some('s') => translated.push_str("[\\t\\n\\f\\r ]"),
            Some('S') => translated.push_str("[^\\t\\n\\f\\r ]"),
            Some(ch @ ('b' | 'B')) => translated.push_str(&format!("(?-u:\\{ch})")),
            Some(ch) => {
                translated.push('\\');
                translated.push(ch);
            }
            None => translated.push('\\'),
        }
    }
    regex::RegexBuilder::new(&translated)
        .size_limit(1_048_576)
        .dfa_size_limit(1_048_576)
        .build()
        .map_err(|e| match e {
            regex::Error::CompiledTooBig(_) => regex_limit(),
            _ => Value::error("invalid regular expression"),
        })
}

pub(super) fn replace(a: &[Value], budget: &InputBudget) -> R {
    arity(a, 3)?;
    let (s, sub, rep) = (
        text::coerce(&a[0], budget)?,
        text::coerce(&a[1], budget)?,
        text::coerce(&a[2], budget)?,
    );
    if sub.len() > 1 && sub.starts_with('/') && sub.ends_with('/') {
        return replace_regex(&s, &sub[1..sub.len() - 1], &rep, budget);
    }
    let mut out = Text::new(budget);
    let mut end = 0;
    for (start, matched) in s.match_indices(&*sub) {
        out.push_str(&s[end..start])?;
        out.push_str(&rep)?;
        end = start + matched.len();
    }
    out.push_str(&s[end..])?;
    Ok(Value::string(out.finish()?))
}

pub(super) fn replace_regex(s: &str, pattern: &str, rep: &str, budget: &InputBudget) -> R {
    let re = terraform_regex(pattern)?;
    regex_input(s)?;
    regex_input(rep)?;
    let mut out = Text::new(budget);
    let mut end = 0;
    for (i, captures) in re.captures_iter(s).enumerate() {
        if i >= 16_384 {
            return Err(regex_limit());
        }
        let longest = captures
            .iter()
            .flatten()
            .map(|m| m.len())
            .max()
            .unwrap_or(0);
        let maximum = rep.len().saturating_mul(longest.saturating_add(1));
        if maximum > 1_048_576 {
            return Err(regex_limit());
        }
        let matched = captures.get(0).unwrap();
        out.push_str(&s[end..matched.start()])?;
        out.generated(maximum, |output| captures.expand(rep, output))?;
        regex_input(out.as_str())?;
        end = matched.end();
    }
    out.push_str(&s[end..])?;
    regex_input(out.as_str())?;
    Ok(Value::string(out.finish()?))
}

pub(super) fn regex(a: &[Value], budget: &InputBudget) -> R {
    arity(a, 2)?;
    let (pattern, input) = (text::coerce(&a[0], budget)?, text::coerce(&a[1], budget)?);
    let re = terraform_regex(&pattern)?;
    regex_input(&input)?;
    let names = collections::collect(re.capture_names().skip(1), budget)?;
    if names.iter().any(Option::is_some) && names.iter().any(Option::is_none) {
        return Err(Value::error(
            "regex: cannot mix named and unnamed capture groups",
        ));
    }
    let captures = re
        .captures(&input)
        .ok_or_else(|| Value::error("regex: pattern did not match"))?;
    let capture = |i| -> R {
        match captures.get(i) {
            Some(m) => Ok(Value::string(text::copy(m.as_str(), budget)?)),
            None => Ok(Value::null()),
        }
    };
    Ok(if names.is_empty() {
        capture(0)?
    } else if names[0].is_some() {
        let mut out = Map::new();
        for (i, name) in names.iter().enumerate() {
            collections::insert(
                &mut out,
                text::copy(name.unwrap(), budget)?,
                capture(i + 1)?,
                budget,
            )?;
        }
        Value::object(out)
    } else {
        Value::list(collections::try_collect(
            (1..captures.len()).map(capture),
            budget,
        )?)
    })
}

use super::*;

/// One `test_*` rule's outcome (`oxtf rules test`, Conftest's `verify`).
#[derive(Clone, Debug, PartialEq)]
pub struct TestOutcome {
    /// `data.<package>.<rule>`.
    pub rule: String,
    pub file: PathBuf,
    pub result: TestResult,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TestResult {
    Pass,
    Fail,
    /// `todo_test_*`.
    Skip,
    Error(String),
}

/// Run the bundle's tests as `conftest verify` does (OPA's tester): every
/// rule named `test_*` passes when it evaluates to `true`; `todo_test_*`
/// is skipped. `namespaces` narrows the packages reported.
pub fn verify(opts: &Options) -> Result<Vec<TestOutcome>, String> {
    verify_with_sources(opts, Arc::new(tf_semantic::FileTable::new()))
}

pub fn verify_with_sources(
    opts: &Options,
    sources: Arc<tf_semantic::FileTable>,
) -> Result<Vec<TestOutcome>, String> {
    let bundle = Bundle::load_with_sources(opts, sources)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for r in &bundle.rules {
        let (name, package) = r.path.split_last().expect("a rule path");
        let skip = name.starts_with("todo_test_");
        if !(name.starts_with("test_") || skip) || !seen.insert(r.path.clone()) {
            continue;
        }
        let ns = package.join(".");
        if !opts.namespaces.is_empty() && !opts.namespaces.iter().any(|n| glob(n, &ns)) {
            continue;
        }
        let rule = format!("data.{}", r.path.join("."));
        let result = if skip {
            TestResult::Skip
        } else {
            match eval(&bundle.engine, json!({}), &rule) {
                Ok(v) if v == regorus::Value::from(true) => TestResult::Pass,
                Ok(_) => TestResult::Fail,
                Err(e) => TestResult::Error(e),
            }
        };
        out.push(TestOutcome {
            rule,
            file: r.file.clone(),
            result,
        });
    }
    Ok(out)
}

/// Conftest's namespace patterns: literal, or with `*` wildcards.
pub(super) fn glob(pattern: &str, s: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == s,
        Some((head, tail)) => {
            s.starts_with(head)
                && (0..=s.len() - head.len())
                    .any(|i| s.is_char_boundary(head.len() + i) && glob(tail, &s[head.len() + i..]))
        }
    }
}

/// The rules whose evaluation may read `data.conftest`, conservatively:
/// every rule of a module that imports `data.conftest` (or all of `data`),
/// every rule whose text reads `data.conftest` or reads `data` dynamically,
/// and every rule whose text names one of those (by its last path
/// segment), to a fixed point. A false positive only costs time.
pub(super) fn conftest_readers(
    modules: &[(PathBuf, String)],
    rules: &[RuleDef],
) -> std::collections::HashSet<Vec<String>> {
    let text = |r: &RuleDef| -> &str {
        let Some((_, src)) = modules.iter().find(|(p, _)| *p == r.file) else {
            return "";
        };
        let lines: Vec<&str> = src.lines().collect();
        let (a, b) = (
            r.lines.0 as usize - 1,
            (r.lines.1 as usize).min(lines.len()),
        );
        let start: usize = lines[..a].iter().map(|l| l.len() + 1).sum();
        let end: usize = lines[..b].iter().map(|l| l.len() + 1).sum();
        &src[start.min(src.len())..end.min(src.len())]
    };
    let mut out = std::collections::HashSet::new();
    for (path, src) in modules {
        // `import data.conftest...`, or `import data` (which makes all of
        // `data` reachable through an alias).
        let imports = src.lines().map(str::trim).any(|l| {
            l.strip_prefix("import").is_some_and(|rest| {
                let target = rest.split_whitespace().next().unwrap_or("");
                target == "data" || target.starts_with("data.conftest")
            })
        });
        for r in rules.iter().filter(|r| r.file == *path) {
            if imports || reads_conftest(text(r)) {
                out.insert(r.path.clone());
            }
        }
    }
    loop {
        let names: std::collections::HashSet<&str> = out
            .iter()
            .filter_map(|p| p.last().map(String::as_str))
            .collect();
        let more: Vec<Vec<String>> = rules
            .iter()
            .filter(|r| !out.contains(&r.path))
            .filter(|r| names.iter().any(|n| mentions(text(r), n)))
            .map(|r| r.path.clone())
            .collect();
        if more.is_empty() {
            return out;
        }
        out.extend(more);
    }
}

/// Whether `text` contains `name` as a whole identifier.
pub(super) fn mentions(text: &str, name: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(name).any(|(i, _)| {
        !text[..i].chars().next_back().is_some_and(ident)
            && !text[i + name.len()..].chars().next().is_some_and(ident)
    })
}

/// Whether text can read `data.conftest`: it names it, or reads `data`
/// other than through a static `data.<name>` path (`data[x]`, `walk(data)`).
pub(super) fn reads_conftest(src: &str) -> bool {
    let b = src.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while let Some(off) = src[i..].find("data") {
        let at = i + off;
        i = at + 4;
        if at > 0 && ident(b[at - 1]) || b.get(at + 4).is_some_and(|&c| ident(c)) {
            continue;
        }
        if b.get(at + 4) != Some(&b'.') {
            return true;
        }
        let rest = &src[at + 5..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name == "conftest" {
            return true;
        }
    }
    false
}

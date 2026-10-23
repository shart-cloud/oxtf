use super::*;

/// Documents and exceptions shared by the rules of one bundle in one root.
#[derive(Default)]
pub(super) struct RootCache {
    pub(super) documents: HashMap<(usize, tf_span::FileId), Arc<CachedDocument>>,
    pub(super) exceptions: HashMap<(String, PathBuf), regorus::Value>,
}

#[derive(Default)]
pub(super) struct BackendCache {
    pub(super) roots: HashMap<u64, RootCache>,
    pub(super) engines: HashMap<u64, regorus::Engine>,
}

/// A rendered file document without borrows: instances by index into the
/// module's resources.
pub(super) struct CachedDocument {
    pub(super) doc: regorus::Value,
    pub(super) abstractions: Vec<Abstraction>,
    pub(super) instances: Vec<(usize, regorus::Value)>,
}

/// What a path may contribute; `None` in [`collect`] is both.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Load {
    Rego,
    Data,
}

/// Collect modules and data below `root` (a file or directory), in name
/// order, as OPA's loader does: hidden files included, other extensions
/// ignored.
pub(super) fn collect(
    root: &Path,
    only: Option<Load>,
    exclude: &[PathBuf],
    modules: &mut Vec<(PathBuf, String)>,
    data: &mut Json,
    sources: &tf_semantic::FileTable,
) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if exclude.iter().any(|e| e == &path) {
            continue;
        }
        let meta = std::fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.is_dir() {
            let children = sources
                .input_budget()
                .entries(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            pending.extend(children.into_iter().rev().map(|(path, _)| path));
        } else {
            collect_document(root, &path, only, modules, data, sources)?;
        }
    }
    Ok(())
}

#[expect(clippy::too_many_lines)]
pub(super) fn collect_document(
    root: &Path,
    path: &Path,
    only: Option<Load>,
    modules: &mut Vec<(PathBuf, String)>,
    data: &mut Json,
    sources: &tf_semantic::FileTable,
) -> Result<(), String> {
    let read = || {
        sources
            .read_text(path)
            .map_err(|e| format!("{}: {e}", path.display()))
    };
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let wanted = match ext {
        "rego" => Load::Rego,
        "json" | "yaml" | "yml" => Load::Data,
        _ => Load::Rego,
    };
    if only.is_some_and(|o| o != wanted) && ["rego", "json", "yaml", "yml"].contains(&ext) {
        if path == root {
            return Err(format!(
                "{}: expected {}",
                path.display(),
                if wanted == Load::Rego {
                    "data (.json, .yaml)"
                } else {
                    "a .rego file"
                }
            ));
        }
        return Ok(());
    }
    let doc = match ext {
        "rego" => {
            let text = read()?;
            sources
                .input_budget()
                .admit(text.len() as u64)
                .map_err(|e| e.to_string())?;
            modules.push((path.to_path_buf(), text.to_string()));
            return Ok(());
        }
        "json" => serde_json::from_str::<Json>(&read()?)
            .map_err(|e| format!("{}: {e}", path.display()))?,
        "yaml" | "yml" => tf_yaml::goyaml::load(&read()?)
            .map_err(|e| format!("{}:{e}", path.display()))?
            .unwrap_or(Json::Null),
        _ if path == root => {
            return Err(format!(
                "{}: not a .rego, .json or .yaml file",
                path.display()
            ));
        }
        _ => return Ok(()),
    };
    if !doc.is_object() {
        return Err(format!(
            "{}: document must be of type object",
            path.display()
        ));
    }
    let at: Vec<String> = path
        .parent()
        .and_then(|p| p.strip_prefix(root).ok())
        .map(|rel| {
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut slot = &mut *data;
    for key in &at {
        let obj = slot.as_object_mut().ok_or_else(|| merge_error(path))?;
        slot = obj.entry(key.clone()).or_insert_with(|| json!({}));
    }
    if !merge(slot, doc) {
        return Err(merge_error(path));
    }
    Ok(())
}

pub(super) fn merge_error(path: &Path) -> String {
    format!("{}: merge error", path.display())
}

/// Deep-merge objects; any other overlap is a conflict.
pub(super) fn merge(dst: &mut Json, src: Json) -> bool {
    match (dst, src) {
        (Json::Object(d), Json::Object(s)) => {
            for (k, v) in s {
                match d.get_mut(&k) {
                    Some(existing) => {
                        if !merge(existing, v) {
                            return false;
                        }
                    }
                    None => {
                        d.insert(k, v);
                    }
                }
            }
            true
        }
        _ => false,
    }
}

pub(super) fn lookup<'a>(data: &'a Json, path: &[String]) -> Option<&'a Json> {
    path.iter().try_fold(data, |v, k| v.get(k))
}

pub(super) fn parse_entry(entry: &str) -> Result<Vec<String>, String> {
    let rest = entry
        .strip_prefix("data.")
        .ok_or_else(|| format!("entry rule {entry:?} must start with `data.`"))?;
    let path: Vec<String> = rest.split('.').map(str::to_string).collect();
    let ident = |s: &str| {
        s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if path.len() < 2 || !path.iter().all(|s| ident(s)) {
        return Err(format!(
            "entry rule {entry:?} must be `data.<package>.<rule>` with dotted identifiers"
        ));
    }
    Ok(path)
}

/// Package and rule definitions, from the parsed modules.
pub(super) fn index(
    modules: &[regorus::unstable::Ref<Module>],
) -> Result<(Vec<PackageDef>, Vec<RuleDef>), String> {
    let mut packages = Vec::new();
    let mut rules = Vec::new();
    for m in modules {
        let file = PathBuf::from(m.package.span.source.get_path());
        let package = ref_path(&m.package.refr)
            .ok_or_else(|| format!("{}: unsupported package path", file.display()))?;
        // `package data.x` and `package x` name the same package.
        let package: Vec<String> = match package.split_first() {
            Some((d, rest)) if d == "data" => rest.to_vec(),
            _ => package,
        };
        packages.push(PackageDef {
            path: package.clone(),
            file: file.clone(),
            line: m.package.span.line,
        });
        for rule in &m.policy {
            let head = match rule.as_ref() {
                Rule::Spec { head, .. } => match head {
                    RuleHead::Compr { refr, .. }
                    | RuleHead::Set { refr, .. }
                    | RuleHead::Func { refr, .. } => refr,
                },
                Rule::Default { refr, .. } => refr,
            };
            let Some(head) = ref_path(head) else {
                continue;
            };
            let span = rule.span();
            let end = span.line + span.text().matches('\n').count() as u32;
            let mut path = package.clone();
            path.extend(head);
            rules.push(RuleDef {
                path,
                file: file.clone(),
                lines: (span.line, end),
            });
        }
    }
    Ok((packages, rules))
}

/// The static path of a reference: `a.b["c"]` is `[a, b, c]`; a variable
/// index ends the path at its container (`deny[msg]` is `deny`).
pub(super) fn ref_path(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::Var { span, .. } => Some(vec![span.text().to_string()]),
        Expr::RefDot { refr, field, .. } => {
            let mut p = ref_path(refr)?;
            p.push(field.0.text().to_string());
            Some(p)
        }
        Expr::RefBrack { refr, index, .. } => {
            let mut p = ref_path(refr)?;
            match index.as_ref() {
                Expr::String { value, .. } | Expr::RawString { value, .. } => {
                    p.push(value.as_string().ok()?.to_string());
                    Some(p)
                }
                _ => Some(p),
            }
        }
        _ => None,
    }
}

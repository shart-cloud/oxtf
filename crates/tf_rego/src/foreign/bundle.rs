use super::*;

pub(super) struct PackageDef {
    pub(super) path: Vec<String>,
    pub(super) file: PathBuf,
    pub(super) line: u32,
}

pub(super) struct RuleDef {
    /// Package path followed by the head's path, without `data`.
    pub(super) path: Vec<String>,
    pub(super) file: PathBuf,
    /// First and last line of the whole rule.
    pub(super) lines: (u32, u32),
}

pub(super) struct Bundle {
    /// Unique per bundle (keys the root-owned working engines).
    pub(super) id: u64,
    pub(super) engine: regorus::Engine,
    /// Rules whose evaluation may read `data.conftest` (see
    /// [`conftest_readers`]): only these see `data.conftest.file`, set per
    /// file with Rego's `with`. Others run on the reused engine.
    pub(super) file_info: std::collections::HashSet<Vec<String>>,
    pub(super) packages: Vec<PackageDef>,
    pub(super) rules: Vec<RuleDef>,
    pub(super) annotations: Vec<Annotation>,
    pub(super) shape: Shape,
}

/// The `exception` set that can suppress a Conftest rule, and the name it
/// must contain.
#[derive(Clone, Debug)]
pub(super) struct Exception {
    pub(super) rule: String,
    pub(super) name: String,
}

pub(super) enum Fallback {
    Stem(String),
    Path,
}

pub(super) struct Unit {
    pub(super) path: Vec<String>,
    pub(super) kind: Option<RuleKind>,
    pub(super) meta: Meta,
    pub(super) fallback: Fallback,
    /// Where the rule is first defined.
    pub(super) file: PathBuf,
    pub(super) line: u32,
}

impl Bundle {
    #[cfg(test)]
    pub(super) fn load(opts: &Options) -> Result<Bundle, String> {
        Self::load_with_sources(opts, Arc::new(tf_semantic::FileTable::new()))
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn load_with_sources(
        opts: &Options,
        sources: Arc<tf_semantic::FileTable>,
    ) -> Result<Bundle, String> {
        let mut modules = Vec::new();
        let mut data = Json::Object(JsonMap::new());
        // Conftest loads only `.rego` from policy paths; `opa eval -d`
        // loads data next to the policies too.
        let only = if opts.entries.is_empty() {
            Some(Load::Rego)
        } else {
            None
        };
        for root in opts.paths {
            collect(root, only, opts.exclude, &mut modules, &mut data, &sources)?;
        }
        for root in opts.data {
            collect(
                root,
                Some(Load::Data),
                &[],
                &mut modules,
                &mut data,
                &sources,
            )?;
        }
        if modules.is_empty() {
            return Err("no .rego files in the policy paths".into());
        }
        let mut engine = new_engine(opts.rego_v0);
        // As `opa eval --strict-builtin-errors`: a builtin error fails the
        // evaluation (a rule error) rather than making the expression
        // undefined. Without it, a builtin regorus gets wrong would be a
        // silent pass.
        engine.set_strict_builtin_errors(true);
        if opts.entries.is_empty() {
            conftest_builtins(&mut engine, &modules, sources.clone())?;
        }
        for (path, source) in &modules {
            sources
                .input_budget()
                .admit(source.len() as u64)
                .map_err(|e| e.to_string())?;
            engine
                .add_policy(path.display().to_string(), source.clone())
                .map_err(|e| e.to_string())?;
        }
        let (packages, rules) = index(engine.get_modules())?;
        for r in &rules {
            if let Some(v) = lookup(&data, &r.path)
                && !v.is_object()
            {
                return Err(format!(
                    "{}: rule data.{} conflicts with a data document",
                    r.file.display(),
                    r.path.join(".")
                ));
            }
        }
        engine
            .add_data(regorus::Value::from(data))
            .map_err(|e| format!("policy data: {e}"))?;
        // Prepare (schedule, hoist, gather rules) once: a clone of a
        // prepared engine stays prepared, so per-evaluation clones only pay
        // for the evaluation.
        engine
            .eval_query("true".to_string(), false)
            .map_err(|e| e.to_string())?;
        let mut annotations = Vec::new();
        for (path, source) in &modules {
            annotations.extend(parse_annotations(path, source, &packages, &rules)?);
        }
        let file_info = conftest_readers(&modules, &rules);
        static IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Ok(Bundle {
            id: IDS
                .fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |id| id.checked_add(1),
                )
                .expect("bundle identity exhausted"),
            engine,
            file_info,
            packages,
            rules,
            annotations,
            shape: opts.shape,
        })
    }

    /// The Conftest rules in the selected namespaces, in name order.
    pub(super) fn conftest_rules(
        &self,
        opts: &Options,
    ) -> Result<Vec<(Vec<String>, RuleKind)>, String> {
        let mut namespaces: Vec<Vec<String>> = if opts.all_namespaces {
            self.packages.iter().map(|p| p.path.clone()).collect()
        } else if opts.namespaces.is_empty() {
            vec![vec!["main".to_string()]]
        } else {
            opts.namespaces
                .iter()
                .map(|n| n.split('.').map(str::to_string).collect())
                .collect()
        };
        namespaces.sort();
        namespaces.dedup();
        let mut out = Vec::new();
        for ns in &namespaces {
            if !self.packages.iter().any(|p| &p.path == ns) {
                return Err(format!(
                    "no policy declares package {} (select namespaces with --namespace or --all-namespaces)",
                    ns.join(".")
                ));
            }
            let mut names: Vec<(&str, RuleKind)> = self
                .rules
                .iter()
                .filter(|r| r.path.len() == ns.len() + 1 && r.path.starts_with(ns))
                .filter_map(|r| {
                    let name = r.path.last().expect("nonempty").as_str();
                    conftest_kind(name).map(|k| (name, k))
                })
                .collect();
            names.sort();
            names.dedup();
            for (name, kind) in names {
                let mut path = ns.clone();
                path.push(name.to_string());
                out.push((path, kind));
            }
        }
        Ok(out)
    }

    pub(super) fn unit(&self, path: Vec<String>, kind: Option<RuleKind>) -> Result<Unit, String> {
        let entry = &format!("data.{}", path.join("."));
        let defs: Vec<&RuleDef> = self.rules.iter().filter(|r| r.path == path).collect();
        let Some(first) = defs.first() else {
            return Err(format!("entry rule {entry} is not defined by any policy"));
        };
        let package = self
            .packages
            .iter()
            .map(|p| &p.path)
            .filter(|p| path.starts_with(p) && p.len() < path.len())
            .max_by_key(|p| p.len())
            .expect("a rule belongs to a package")
            .clone();
        let meta = self.meta(&path, &package)?;
        // The entry must produce violations (or nothing) on an empty document.
        let empty = match meta.shape.unwrap_or(self.shape) {
            Shape::Hcl => json!({"resource": {}}),
            Shape::Plan => {
                json!({"format_version": "1.2", "resource_changes": [], "planned_values": {"root_module": {"resources": []}}})
            }
        };
        let result = eval(&self.engine, empty, entry).map_err(|e| format!("{entry}: {e}"))?;
        violations(&result).map_err(|e| format!("{entry}: {e}"))?;
        let fallback = if defs.iter().all(|d| d.file == first.file) {
            Fallback::Stem(
                first
                    .file
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("policy")
                    .to_string(),
            )
        } else {
            Fallback::Path
        };
        Ok(Unit {
            file: first.file.clone(),
            line: first.lines.0,
            path,
            kind,
            meta,
            fallback,
        })
    }

    /// Metadata for the rule at `path`: each field from the nearest
    /// annotation that sets it (rule, document, package, then enclosing
    /// `subpackages` scopes), then `__rego_metadata__`.
    pub(super) fn meta(&self, path: &[String], package: &[String]) -> Result<Meta, String> {
        let mut chain: Vec<&Annotation> = Vec::new();
        let mut rule_scoped: Vec<&Annotation> = self
            .annotations
            .iter()
            .filter(|a| a.scope == Scope::Rule && a.target == path)
            .collect();
        rule_scoped.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
        chain.extend(rule_scoped);
        chain.extend(
            self.annotations
                .iter()
                .filter(|a| a.scope == Scope::Document && a.target == path),
        );
        chain.extend(
            self.annotations
                .iter()
                .filter(|a| a.scope == Scope::Package && a.target == package),
        );
        for len in (0..=package.len()).rev() {
            chain.extend(
                self.annotations
                    .iter()
                    .filter(|a| a.scope == Scope::Subpackages && a.target == package[..len]),
            );
        }
        let mut meta = Meta::default();
        for a in &chain {
            meta.fill(&a.fields, &format!("{}:{}:1", a.file.display(), a.line))?;
        }
        let mut legacy = package.to_vec();
        legacy.push("__rego_metadata__".into());
        if self.rules.iter().any(|r| r.path == legacy) {
            let rule = format!("data.{}", legacy.join("."));
            let v = eval(&self.engine, json!({}), &rule).map_err(|e| format!("{rule}: {e}"))?;
            if !matches!(v, regorus::Value::Undefined) {
                let v = to_serde(&v)?;
                if !v.is_object() {
                    return Err(format!("{rule} must be an object"));
                }
                meta.fill_legacy(&v, &rule)?;
            }
        }
        Ok(meta)
    }
}

/// A configuration in one of the formats `parse_config` reproduces.
pub(super) fn parse_with(
    parser: &str,
    text: &str,
    sources: &tf_semantic::FileTable,
) -> anyhow::Result<Json> {
    Ok(match parser {
        "hcl2" => {
            let alloc = sources.allocator();
            let parsed = tf_parser::parse(&alloc, text);
            if !parsed.errors.is_empty() {
                anyhow::bail!("parse_config: hcl2: the configuration does not parse");
            }
            let file = alloc.alloc(parsed.file)?;
            crate::hcl2json::raw(file, text).map_err(|e| anyhow::anyhow!("parse_config: {e}"))?
        }
        "json" => {
            serde_json::from_str(text).map_err(|e| anyhow::anyhow!("parse_config: json: {e}"))?
        }
        other => anyhow::bail!("parse_config: parser {other:?} is not supported (hcl2, json)"),
    })
}

/// Conftest's own builtins, as far as they can be reproduced exactly:
///
/// - `parse_config` for the `hcl2` parser (hcl2json,
///   [`crate::hcl2json::raw`]) and `json`;
/// - `parse_config_file`, which resolves its path against the directory of
///   the calling policy file. An extension does not see its caller, so each
///   string literal passed to it in the bundle is mapped to the directories
///   of the files that pass it; a path with exactly one such directory
///   resolves, any other is an error;
/// - `parse_combined_config_files` fails: Conftest's combined document is
///   not reproduced.
#[expect(clippy::too_many_lines)]
pub(super) fn conftest_builtins(
    engine: &mut regorus::Engine,
    modules: &[(PathBuf, String)],
    sources: Arc<tf_semantic::FileTable>,
) -> Result<(), String> {
    let inline_sources = sources.clone();
    let parse_config = move |args: Vec<regorus::Value>| -> anyhow::Result<regorus::Value> {
        let (Ok(parser), Ok(text)) = (args[0].as_string(), args[1].as_string()) else {
            anyhow::bail!("parse_config: expected (parser, configuration) strings");
        };
        inline_sources.input_budget().admit(text.len() as u64)?;
        Ok(regorus::Value::from(parse_with(
            parser,
            text,
            &inline_sources,
        )?))
    };
    let mut callers: HashMap<String, std::collections::BTreeSet<PathBuf>> = HashMap::new();
    for (path, source) in modules {
        let mut rest = source.as_str();
        while let Some(i) = rest.find("parse_config_file(") {
            rest = &rest[i + "parse_config_file(".len()..];
            let arg = rest.trim_start();
            if let Some(lit) = arg
                .strip_prefix('"')
                .and_then(|a| a.split_once('"'))
                .map(|(l, _)| l)
            {
                callers
                    .entry(lit.to_string())
                    .or_default()
                    .insert(path.parent().unwrap_or(Path::new(".")).to_path_buf());
            }
        }
    }
    let parse_config_file = move |args: Vec<regorus::Value>| -> anyhow::Result<regorus::Value> {
        let Ok(arg) = args[0].as_string() else {
            anyhow::bail!("parse_config_file: expected a path string");
        };
        let dirs = callers
            .get(&**arg)
            .map(|d| d.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let [dir] = dirs.as_slice() else {
            anyhow::bail!(
                "parse_config_file({arg:?}): the calling policy file cannot be determined (pass a string literal from one directory)"
            );
        };
        let path = dir.join(&**arg);
        let parser = match path.extension().and_then(|e| e.to_str()) {
            Some("tf" | "hcl") => "hcl2",
            Some("json") => "json",
            _ => anyhow::bail!(
                "parse_config_file: {}: unsupported file type",
                path.display()
            ),
        };
        let text = sources
            .read_text(&path)
            .map_err(|e| anyhow::anyhow!("read config file {}: {e}", path.display()))?;
        Ok(regorus::Value::from(parse_with(parser, &text, &sources)?))
    };
    let unsupported = |name: &'static str| {
        move |_: Vec<regorus::Value>| -> anyhow::Result<regorus::Value> {
            anyhow::bail!("{name} is not supported: Conftest's combined document is not reproduced")
        }
    };
    engine
        .add_extension("parse_config".into(), 2, Box::new(parse_config))
        .and_then(|_| {
            engine.add_extension("parse_config_file".into(), 1, Box::new(parse_config_file))
        })
        .and_then(|_| {
            engine.add_extension(
                "parse_combined_config_files".into(),
                1,
                Box::new(unsupported("parse_combined_config_files")),
            )
        })
        .map_err(|e| e.to_string())
}

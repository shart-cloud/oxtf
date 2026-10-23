use super::*;

// ---------------------------------------------------------------------------
// Annotations
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scope {
    Package,
    Subpackages,
    Rule,
    Document,
}

pub(super) struct Annotation {
    pub(super) scope: Scope,
    /// The package path (package scopes) or rule path (rule scopes).
    pub(super) target: Vec<String>,
    pub(super) fields: JsonMap<String, Json>,
    pub(super) file: PathBuf,
    /// Line of the `# METADATA` comment.
    pub(super) line: u32,
}

/// `# METADATA` blocks in one module, attached as OPA attaches them: to
/// the next package or rule statement, across blank lines.
pub(super) fn comment(l: &str) -> Option<&str> {
    l.trim_start().strip_prefix('#')
}

#[expect(clippy::too_many_lines)]
pub(super) fn parse_annotations(
    file: &Path,
    source: &str,
    packages: &[PackageDef],
    rules: &[RuleDef],
) -> Result<Vec<Annotation>, String> {
    let package = packages
        .iter()
        .find(|p| p.file == file)
        .expect("each module has a package");
    let file_rules: Vec<&RuleDef> = rules.iter().filter(|r| r.file == file).collect();
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let header = comment(lines[i]).is_some_and(|c| c.trim() == "METADATA");
        if !header {
            i += 1;
            continue;
        }
        let start = i + 1; // 1-based line of the header
        let mut yaml = String::new();
        i += 1;
        while i < lines.len() {
            match comment(lines[i]) {
                Some(c) if c.trim() != "METADATA" => {
                    yaml.push_str(c);
                    yaml.push('\n');
                    i += 1;
                }
                _ => break,
            }
        }
        let start = start as u32;
        let at = format!("{}:{start}:1", file.display());
        // A block inside a rule body is an ordinary comment.
        if file_rules
            .iter()
            .any(|r| r.lines.0 < start && start <= r.lines.1)
        {
            continue;
        }
        let fields =
            match tf_yaml::goyaml::load(&yaml).map_err(|e| format!("{at}: METADATA: {e}"))? {
                Some(Json::Object(m)) => m,
                None => JsonMap::new(),
                Some(_) => return Err(format!("{at}: METADATA must be a mapping")),
            };
        let end = start + yaml.lines().count() as u32;
        let next_rule = file_rules
            .iter()
            .filter(|r| r.lines.0 > end)
            .min_by_key(|r| r.lines.0);
        let (default, target, line) =
            if package.line > end && next_rule.is_none_or(|r| package.line < r.lines.0) {
                (Scope::Package, package.path.clone(), package.line)
            } else if let Some(r) = next_rule {
                (Scope::Rule, r.path.clone(), r.lines.0)
            } else {
                return Err(format!(
                    "{at}: METADATA is not followed by a package or rule"
                ));
            };
        let scope = match fields.get("scope") {
            None => default,
            Some(Json::String(s)) => match (s.as_str(), default) {
                ("package", Scope::Package) => Scope::Package,
                ("subpackages", Scope::Package) => Scope::Subpackages,
                ("rule", Scope::Rule) => Scope::Rule,
                ("document", Scope::Rule) => Scope::Document,
                _ => {
                    return Err(format!(
                        "{at}: METADATA scope `{s}` cannot annotate the statement on line {line}"
                    ));
                }
            },
            Some(other) => {
                return Err(format!(
                    "{at}: METADATA scope must be a string, got {other}"
                ));
            }
        };
        out.push(Annotation {
            scope,
            target,
            fields,
            file: file.to_path_buf(),
            line: start,
        });
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Input {
    #[default]
    Resource,
    Module,
    /// Conftest's unit: a whole document (a `.tf` file in the HCL shape,
    /// the root's plan in the plan shape), with results attributed by
    /// ablation.
    Document,
}

/// The metadata oxtf reads; `None` until some annotation sets it.
#[derive(Debug, Default)]
pub(super) struct Meta {
    pub(super) id: Option<String>,
    pub(super) level: Option<Level>,
    pub(super) description: Option<String>,
    pub(super) category: Option<Category>,
    pub(super) guideline: Option<String>,
    pub(super) resource_types: Option<Vec<String>>,
    pub(super) input: Input,
    pub(super) input_set: bool,
    pub(super) shape: Option<Shape>,
}

pub(super) fn level(s: &str, at: &str) -> Result<Level, String> {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Ok(Level::Critical),
        "high" => Ok(Level::High),
        "medium" => Ok(Level::Medium),
        "low" | "info" => Ok(Level::Low),
        _ => Err(format!(
            "{at}: unknown severity {s:?} (critical, high, medium, low, info)"
        )),
    }
}

impl Meta {
    #[expect(clippy::too_many_lines)]
    pub(super) fn fill(&mut self, fields: &JsonMap<String, Json>, at: &str) -> Result<(), String> {
        let string = |v: &Json, name: &str| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{at}: METADATA {name} must be a string"))
        };
        if self.description.is_none()
            && let Some(v) = fields.get("title").or_else(|| fields.get("description"))
        {
            self.description = Some(string(v, "title")?);
        }
        if self.guideline.is_none()
            && let Some(related) = fields.get("related_resources")
        {
            // `[{"ref": url, "description": ...}]` or `[url]` (OPA allows both).
            let first = related.as_array().and_then(|a| a.first());
            self.guideline = first
                .and_then(|r| r.get("ref").or(Some(r)))
                .and_then(Json::as_str)
                .map(str::to_string);
        }
        let Some(custom) = fields.get("custom") else {
            return Ok(());
        };
        if self.category.is_none()
            && let Some(v) = custom.get("category")
        {
            self.category = Some(Category::from_foreign(&string(v, "custom.category")?));
        }
        let custom = custom
            .as_object()
            .ok_or_else(|| format!("{at}: METADATA custom must be a mapping"))?;
        if self.id.is_none()
            && let Some(v) = custom.get("id")
        {
            self.id = Some(string(v, "custom.id")?);
        }
        if self.level.is_none()
            && let Some(v) = custom.get("severity")
        {
            self.level = Some(level(&string(v, "custom.severity")?, at)?);
        }
        let Some(oxtf) = custom.get("oxtf") else {
            return Ok(());
        };
        let oxtf = oxtf
            .as_object()
            .ok_or_else(|| format!("{at}: METADATA custom.oxtf must be a mapping"))?;
        for key in oxtf.keys() {
            if !matches!(key.as_str(), "resource_types" | "input" | "shape") {
                return Err(format!("{at}: unknown METADATA field custom.oxtf.{key}"));
            }
        }
        if self.resource_types.is_none()
            && let Some(v) = oxtf.get("resource_types")
        {
            let types = v
                .as_array()
                .and_then(|a| a.iter().map(|t| t.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
                .filter(|t| !t.is_empty())
                .ok_or_else(|| {
                    format!("{at}: METADATA custom.oxtf.resource_types must be a nonempty list of strings")
                })?;
            self.resource_types = Some(types);
        }
        if self.shape.is_none()
            && let Some(v) = oxtf.get("shape")
        {
            self.shape = Some(v.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                format!("{at}: METADATA custom.oxtf.shape must be `plan` or `hcl`")
            })?);
        }
        if !self.input_set
            && let Some(v) = oxtf.get("input")
        {
            self.input = match v.as_str() {
                Some("resource") => Input::Resource,
                Some("module") => Input::Module,
                Some("document") => Input::Document,
                _ => {
                    return Err(format!(
                        "{at}: METADATA custom.oxtf.input must be `resource`, `module` or `document`"
                    ));
                }
            };
            self.input_set = true;
        }
        Ok(())
    }

    /// `__rego_metadata__` (Trivy/tfsec style): `id`, `title`,
    /// `description`, `severity`.
    pub(super) fn fill_legacy(&mut self, v: &Json, at: &str) -> Result<(), String> {
        let get = |k: &str| -> Result<Option<String>, String> {
            match v.get(k) {
                None | Some(Json::Null) => Ok(None),
                Some(Json::String(s)) => Ok(Some(s.clone())),
                Some(other) => Err(format!("{at}: {k} must be a string, got {other}")),
            }
        };
        if self.id.is_none() {
            self.id = get("id")?;
        }
        if self.description.is_none() {
            self.description = get("title")?.or(get("description")?);
        }
        if self.level.is_none()
            && let Some(s) = get("severity")?
        {
            self.level = Some(level(&s, at)?);
        }
        if self.guideline.is_none() {
            self.guideline = get("url")?;
        }
        Ok(())
    }
}

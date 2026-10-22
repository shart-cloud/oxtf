//! Offline adapter for Terraform's installed-module manifest. Resolution is
//! scoped to one root; parsed source remains shared separately in ModuleStore.

use std::cell::OnceCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use semver::Version;
use serde::Deserialize;
use tf_span::FileSpan;

use crate::module::ModuleCall;
use crate::source::{FileTable, normalize};

mod decode;
#[cfg(test)]
mod storage_tests;

#[derive(Clone, Debug)]
pub enum ResolveError {
    Storage(tf_limits::Exhaustion),
    /// No installed-module manifest: the root was never initialized or fetched.
    NotInstalled(String),
    Invalid(String),
}

impl From<String> for ResolveError {
    fn from(message: String) -> Self {
        Self::Invalid(message)
    }
}

impl From<&str> for ResolveError {
    fn from(message: &str) -> Self {
        Self::Invalid(message.into())
    }
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => error.fmt(f),
            Self::NotInstalled(message) | Self::Invalid(message) => message.fmt(f),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Provenance of installed source, inherited by its local child modules.
#[derive(Clone, Debug)]
pub struct InstalledPackage {
    pub source: String,
    pub version: Option<String>,
    /// Resolved revision recorded by explicit fetching; Terraform manifests
    /// without this extension provide no revision identity.
    pub revision: Option<String>,
    /// Explicit fetch snapshots bound contextual file reads to their package.
    pub package_root: Option<PathBuf>,
    /// The selected module directory, an anchor for stable relative filenames.
    pub dir: PathBuf,
    /// Calls from the scanned root to this module.
    pub calls: Vec<FileSpan>,
}

impl InstalledPackage {
    pub fn relative_file(&self, path: &Path) -> String {
        let base = normalize(&self.dir);
        let path = normalize(path);
        let a: Vec<_> = base.components().collect();
        let b: Vec<_> = path.components().collect();
        let shared = a.iter().zip(&b).take_while(|(a, b)| a == b).count();
        std::iter::repeat_n("..".to_string(), a.len() - shared)
            .chain(
                b[shared..]
                    .iter()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned()),
            )
            .collect::<Vec<_>>()
            .join("/")
    }

    pub fn file_identity(&self, path: &Path) -> String {
        if let Some(revision) = &self.revision {
            return serde_json::to_string(&(
                "fetched",
                &self.source,
                &self.version,
                revision,
                self.relative_file(path),
            ))
            .expect("strings serialize");
        }
        // Structured JSON avoids source/version/path separator collisions.
        serde_json::to_string(&(
            "installed",
            &self.source,
            &self.version,
            self.relative_file(path),
        ))
        .expect("strings serialize")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Record {
    key: String,
    #[serde(default)]
    source: String,
    version: Option<String>,
    #[serde(default, rename = "OxtfRevision")]
    revision: Option<String>,
    #[serde(default, rename = "OxtfPackageRoot")]
    package_root: Option<PathBuf>,
    dir: PathBuf,
}

pub struct InstalledModules<'a> {
    root: PathBuf,
    manifest: PathBuf,
    files: &'a FileTable,
    records: OnceCell<Result<HashMap<String, Record>, ResolveError>>,
}

/// Relative data directories are resolved against each scanned root.
pub fn data_dir(root: &Path, explicit: Option<&Path>) -> PathBuf {
    normalize(&root.join(explicit.unwrap_or_else(|| Path::new(".terraform"))))
}

impl<'a> InstalledModules<'a> {
    pub fn new(root: &Path, explicit: Option<&Path>, files: &'a FileTable) -> Self {
        let modules = data_dir(root, explicit).join("modules");
        files.protect_dir(&modules);
        Self {
            root: root.to_path_buf(),
            manifest: modules.join("modules.json"),
            files,
            records: OnceCell::new(),
        }
    }

    fn records(&self) -> Result<&HashMap<String, Record>, ResolveError> {
        self.records
            .get_or_init(|| {
                let sf = self.files.load(&self.manifest).map_err(|error| {
                    if let Some(error) = tf_limits::input::exhaustion(&error) {
                        ResolveError::Storage(error)
                    } else if error.kind() == std::io::ErrorKind::NotFound {
                        ResolveError::NotInstalled(format!(
                            "not installed: no module manifest at {}",
                            self.manifest.display()
                        ))
                    } else {
                        ResolveError::Invalid(format!(
                            "cannot read installed module manifest {}: {error}",
                            self.manifest.display()
                        ))
                    }
                })?;
                decode::records(&sf.text, self.files.input_budget())
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    pub fn resolve(&self, calls: &[&ModuleCall<'_>]) -> Result<InstalledPackage, ResolveError> {
        self.files
            .input_budget()
            .admit_collection(0)
            .map_err(ResolveError::Storage)?;
        let records = self.records()?;
        let (record, key) = select_record(records, calls)?;
        let dir = normalize(&self.root.join(&record.dir));
        if !self.files.is_dir(&dir) {
            return Err(format!("installed directory for module {key} is missing").into());
        }
        self.files.protect_dir(&dir);
        Ok(InstalledPackage {
            source: normalize_source(&record.source),
            version: record.version.clone(),
            revision: record.revision.clone(),
            package_root: record
                .package_root
                .as_ref()
                .map(|p| normalize(&self.root.join(p))),
            dir,
            calls: tf_eval::collections::collect(
                calls.iter().map(|c| FileSpan::new(c.file, c.block.span)),
                self.files.input_budget(),
            )
            .map_err(|_| ResolveError::Storage(self.files.input_budget().collection_refused()))?,
        })
    }
}

fn select_record<'a>(
    records: &'a HashMap<String, Record>,
    calls: &[&ModuleCall<'_>],
) -> Result<(&'a Record, String), ResolveError> {
    let mut key = String::new();
    let mut selected = None;
    // Validate local ancestors too: a changed local source invalidates the
    // old installed descendants even when the final call's source matches.
    for call in calls {
        if !key.is_empty() {
            key.push('.');
        }
        key.push_str(call.name);
        let record = records
            .get(&key)
            .ok_or_else(|| format!("module {key} is not installed"))?;
        let source = call
            .block
            .body
            .find_attribute("source")
            .and_then(|a| a.value.as_string_literal())
            .ok_or("module source must be a literal string")?;
        if normalize_source(source) != normalize_source(&record.source) {
            return Err(format!("installed source for module {key} is stale").into());
        }
        let constraint = call
            .block
            .body
            .find_attribute("version")
            .map(|a| {
                a.value
                    .as_string_literal()
                    .ok_or("module version must be a literal string")
            })
            .transpose()?;
        if constraint.is_some_and(|c| c.trim().is_empty()) {
            return Err("module version constraint must not be empty".into());
        }
        match (&record.version, constraint) {
            (Some(version), constraint) => {
                if !version_matches(version, constraint.unwrap_or(""))? {
                    return Err(format!(
                        "installed version for module {key} does not satisfy its constraint"
                    )
                    .into());
                }
            }
            (None, Some(c)) if !c.trim().is_empty() => {
                return Err(format!("installed version for module {key} is missing").into());
            }
            _ => {}
        }
        if record.dir.as_os_str().is_empty() {
            return Err(format!("installed directory for module {key} is missing").into());
        }
        selected = Some(record);
    }
    Ok((selected.ok_or("empty module path")?, key))
}

/// Normalize the registry default host and common GitHub shorthand without
/// network discovery. Other transport spellings must match the manifest.
pub fn normalize_source(source: &str) -> String {
    let (address, query) = source.split_once('?').unwrap_or((source, ""));
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    if let Some(path) = address.strip_prefix("github.com/") {
        let mut parts = path.splitn(3, '/');
        if let (Some(owner), Some(repo)) = (parts.next(), parts.next()) {
            let repo = repo.strip_suffix(".git").unwrap_or(repo);
            let sub = parts
                .next()
                .map(|s| format!("//{}", s.trim_start_matches('/')))
                .unwrap_or_default();
            return format!("git::https://github.com/{owner}/{repo}.git{sub}{query}");
        }
    }
    let base = address.split("//").next().unwrap_or(address);
    let parts = base.split('/');
    if parts.clone().count() == 3
        && parts.clone().all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
    {
        return format!("registry.terraform.io/{source}");
    }
    source.to_string()
}

fn version(raw: &str) -> Result<(Version, usize), String> {
    let raw = raw.trim().strip_prefix('v').unwrap_or(raw.trim());
    let end = raw.find(['-', '+']).unwrap_or(raw.len());
    let core = &raw[..end];
    let n = core.split('.').count();
    if n > 3
        || core
            .split('.')
            .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("unsupported module version syntax".into());
    }
    let padded = format!("{core}{}{}", ".0".repeat(3 - n), &raw[end..]);
    Version::parse(&padded)
        .map(|v| (v, n))
        .map_err(|_| "invalid module version".into())
}

/// Terraform comparison operators, including pessimistic constraints.
/// Cargo's VersionReq has different bare-version and prerelease semantics.
pub fn version_matches(installed: &str, constraint: &str) -> Result<bool, String> {
    let (v, _) = version(installed)?;
    if constraint.trim().is_empty() {
        return Ok(true);
    }
    let mut matches = true;
    for term in constraint.split(',') {
        let term = term.trim();
        let op = ["~>", ">=", "<=", "!=", ">", "<", "="]
            .into_iter()
            .find(|op| term.starts_with(op))
            .unwrap_or("");
        let (c, components) = version(term[op.len()..].trim())?;
        let cmp = v.cmp_precedence(&c);
        let pre = v.pre.is_empty()
            || (!c.pre.is_empty() && (v.major, v.minor, v.patch) == (c.major, c.minor, c.patch));
        matches &= match op {
            "" | "=" => cmp.is_eq(),
            "!=" => !cmp.is_eq(),
            ">" => pre && cmp.is_gt(),
            ">=" => pre && !cmp.is_lt(),
            "<" => pre && cmp.is_lt(),
            "<=" => pre && !cmp.is_gt(),
            "~>" => {
                pre && !cmp.is_lt()
                    && (c.pre.is_empty() || !v.pre.is_empty())
                    && (components < 2 || v.major == c.major)
                    && (components < 3 || v.minor == c.minor)
            }
            _ => unreachable!(),
        };
    }
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terraform_constraints() {
        for (v, c, expected) in [
            ("1.2.3", "~> 1.2", true),
            ("1.9.0", "~> 1.2", true),
            ("2.0.0", "~> 1.2", false),
            ("1.3.0", "~> 1.2.3", false),
            ("1.2.4", ">= 1.0, < 2, != 1.2.3", true),
            ("1.2.3", "!= 1.2.3", false),
            ("1.2.1", "1.2", false),
            ("1.2.0", "1.2", true),
            ("1.2.3+build", "= 1.2.3", true),
            ("1.3.0-beta", ">= 1.2", false),
            ("1.2.3-beta.2", ">= 1.2.3-beta.1", true),
            ("1.2.3", "~> 1.2.3-beta.1", false),
        ] {
            assert_eq!(version_matches(v, c).unwrap(), expected, "{v} {c}");
        }
        for c in ["^1.2", "*", ">= 1 || < 2", "1.2,", "wat"] {
            assert!(version_matches("1.2.3", c).is_err(), "{c}");
        }
    }
}

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

/// Provenance of installed source, inherited by its local child modules.
#[derive(Clone, Debug)]
pub struct InstalledPackage {
    pub source: String,
    pub version: Option<String>,
    /// Resolved revision recorded by explicit fetching; Terraform manifests
    /// without this extension provide no revision identity.
    pub revision: Option<String>,
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
    dir: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Snapshot {
    modules: Vec<Record>,
}

pub struct InstalledModules<'a> {
    root: PathBuf,
    manifest: PathBuf,
    files: &'a FileTable,
    records: OnceCell<Result<HashMap<String, Record>, String>>,
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

    fn records(&self) -> Result<&HashMap<String, Record>, String> {
        self.records
            .get_or_init(|| {
                let sf = self.files.load(&self.manifest).map_err(|e| {
                    format!(
                        "cannot read installed module manifest {}: {e}",
                        self.manifest.display()
                    )
                })?;
                let snapshot: Snapshot = serde_json::from_str(&sf.text).map_err(|e| {
                    format!(
                        "invalid installed module manifest at line {}, column {}",
                        e.line(),
                        e.column()
                    )
                })?;
                let mut records = HashMap::new();
                for record in snapshot.modules {
                    if records.insert(record.key.clone(), record).is_some() {
                        return Err("duplicate module key in installed module manifest".into());
                    }
                }
                Ok(records)
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    pub fn resolve(&self, calls: &[&ModuleCall<'_>]) -> Result<InstalledPackage, String> {
        let records = self.records()?;
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
                return Err(format!("installed source for module {key} is stale"));
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
                        ));
                    }
                }
                (None, Some(c)) if !c.trim().is_empty() => {
                    return Err(format!("installed version for module {key} is missing"));
                }
                _ => {}
            }
            if record.dir.as_os_str().is_empty() {
                return Err(format!("installed directory for module {key} is missing"));
            }
            selected = Some(record);
        }
        let record = selected.ok_or("empty module path")?;
        let dir = normalize(&self.root.join(&record.dir));
        if !self.files.is_dir(&dir) {
            return Err(format!("installed directory for module {key} is missing"));
        }
        self.files.protect_dir(&dir);
        Ok(InstalledPackage {
            source: normalize_source(&record.source),
            version: record.version.clone(),
            revision: record.revision.clone(),
            dir,
            calls: calls
                .iter()
                .map(|c| FileSpan::new(c.file, c.block.span))
                .collect(),
        })
    }
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
    let parts: Vec<_> = base.split('/').collect();
    if parts.len() == 3
        && parts.iter().all(|s| {
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

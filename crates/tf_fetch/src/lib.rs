//! Explicit dependency fetching. Ordinary scans only read the installed-module
//! manifest. Packages are staged, validated and content-addressed before an
//! atomic manifest replacement makes the complete dependency tree visible.
mod archive;
mod transport;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tf_semantic::{
    FileTable, ModuleStore,
    installed::{data_dir, normalize_source, version_matches},
    module::ModuleSource,
};

#[derive(Clone, Debug)]
pub struct FetchLimits {
    pub max_download_bytes: u64,
    pub max_unpacked_bytes: u64,
    pub max_files: usize,
    pub max_modules: usize,
    pub max_depth: usize,
    pub timeout: Duration,
}
impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            max_download_bytes: 64 << 20,
            max_unpacked_bytes: 128 << 20,
            max_files: 10_000,
            max_modules: 256,
            max_depth: 10,
            timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FetchRequest {
    pub root: PathBuf,
    pub data_dir: Option<PathBuf>,
    /// Resolve moving Git refs and select registry versions again. Without this,
    /// valid cached packages are reused, even when the remote is unavailable.
    pub refresh: bool,
    /// Explicit registry service origins, primarily for private mirrors and
    /// deterministic fixtures. HTTPS, or HTTP loopback for local fixtures.
    pub registry_origins: BTreeMap<String, String>,
    pub limits: FetchLimits,
}
impl FetchRequest {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().into(),
            data_dir: None,
            refresh: false,
            registry_origins: BTreeMap::new(),
            limits: FetchLimits::default(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchReport {
    pub modules: Vec<FetchedModule>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchedModule {
    pub key: String,
    pub source: String,
    pub version: Option<String>,
    /// Git commit ID, or sha256 of the archive's extracted contents.
    pub revision: Option<String>,
    pub digest: Option<String>,
    pub directory: PathBuf,
    pub reused: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Record {
    key: String,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    dir: PathBuf,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "OxtfRevision"
    )]
    revision: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "OxtfDigest"
    )]
    digest: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "OxtfPackageRoot"
    )]
    package_root: Option<PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Manifest {
    modules: Vec<Record>,
}

pub(crate) fn error(e: impl std::fmt::Display) -> String {
    format!("module cache I/O: {e}")
}

struct CacheLock(fs::File);
impl Drop for CacheLock {
    fn drop(&mut self) {
        // Unlock explicitly: concurrent fork/exec operations can briefly
        // inherit the open file description even with close-on-exec enabled.
        let _ = self.0.unlock();
    }
}

pub fn fetch(request: FetchRequest) -> Result<FetchReport, String> {
    let root = fs::canonicalize(&request.root).map_err(|_| "fetch root is unavailable")?;
    let cache = data_dir(&root, request.data_dir.as_deref()).join("modules");
    fs::create_dir_all(cache.join("oxtf-packages")).map_err(error)?;
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(cache.join(".oxtf-fetch.lock"))
        .map_err(error)?;
    lock.try_lock()
        .map_err(|_| "another fetch is running for this data directory")?;
    let _lock = CacheLock(lock);
    let manifest_path = cache.join("modules.json");
    let files = FileTable::new();
    let previous = if files.is_file(&manifest_path) {
        let source = files.load(&manifest_path).map_err(error)?;
        let manifest: Manifest =
            serde_json::from_str(&source.text).map_err(|_| "invalid installed module manifest")?;
        let mut previous = HashMap::new();
        for r in manifest.modules {
            if previous.insert(r.key.clone(), r).is_some() {
                return Err("duplicate installed module key".into());
            }
        }
        previous
    } else {
        HashMap::new()
    };
    let mut session = Session {
        request: &request,
        root: &root,
        cache: &cache,
        deadline: Instant::now() + request.limits.timeout,
        files: FileTable::new(),
        store: ModuleStore::new(),
        previous,
        records: Vec::new(),
        report: Vec::new(),
        packages: HashMap::new(),
        verified: HashMap::new(),
    };
    session.visit(&root, "", None, &mut Vec::new())?;
    session.records.insert(
        0,
        Record {
            key: String::new(),
            source: String::new(),
            version: None,
            dir: root.clone(),
            revision: None,
            digest: None,
            package_root: None,
        },
    );
    let mut staged = tempfile::NamedTempFile::new_in(&cache).map_err(error)?;
    serde_json::to_writer_pretty(
        staged.as_file_mut(),
        &Manifest {
            modules: session.records,
        },
    )
    .map_err(error)?;
    staged.as_file().sync_all().map_err(error)?;
    staged.persist(&manifest_path).map_err(error)?;
    Ok(FetchReport {
        modules: session.report,
    })
}

struct Session<'a> {
    request: &'a FetchRequest,
    root: &'a Path,
    cache: &'a Path,
    deadline: Instant,
    files: FileTable,
    store: ModuleStore,
    previous: HashMap<String, Record>,
    records: Vec<Record>,
    report: Vec<FetchedModule>,
    packages: HashMap<(String, String), Record>,
    verified: HashMap<PathBuf, String>,
}
impl Session<'_> {
    fn check_time(&self) -> Result<(), String> {
        if Instant::now() >= self.deadline {
            Err("dependency fetch time limit exceeded".into())
        } else {
            Ok(())
        }
    }
    fn visit(
        &mut self,
        dir: &Path,
        parent: &str,
        package: Option<&Path>,
        ancestors: &mut Vec<PathBuf>,
    ) -> Result<(), String> {
        self.check_time()?;
        let canonical = fs::canonicalize(dir).map_err(|_| "module directory is unavailable")?;
        if ancestors.contains(&canonical) {
            return Err("module dependency cycle".into());
        }
        if ancestors.len() > self.request.limits.max_depth {
            return Err("module dependency depth limit exceeded".into());
        }
        if let Some(package) = package
            && !canonical.starts_with(package)
        {
            return Err("local module escapes its fetched package".into());
        }
        let def = self
            .store
            .module(&self.files, &canonical)
            .map_err(|e| e.to_string())?;
        if let Some(error) = self.files.input_budget().exhaustion() {
            return Err(error.to_string());
        }
        if !def.parse_errors.is_empty()
            || !def.parse_limits.is_empty()
            || def.loader_limit.is_some()
            || !def.load_errors.is_empty()
        {
            return Err("module configuration contains parse or load errors".into());
        }
        if def.files.is_empty() {
            return Err("module has no Terraform configuration".into());
        }
        // Copy the small static call descriptions to avoid borrowing the store
        // while descending. Evaluation uses the same composed HCL/JSON loader.
        let calls: Vec<_> = def
            .module_calls
            .iter()
            .map(|call| {
                let source = call
                    .block
                    .body
                    .find_attribute("source")
                    .and_then(|a| a.value.as_string_literal())
                    .ok_or("module source must be a literal string")?;
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
                    return Err("module version constraint must not be empty");
                }
                Ok((
                    call.name.to_string(),
                    source.to_string(),
                    constraint.map(str::to_string),
                    call.source.clone(),
                ))
            })
            .collect::<Result<_, &str>>()?;
        ancestors.push(canonical);
        for (name, source, constraint, kind) in calls {
            self.check_time()?;
            if self.records.len() >= self.request.limits.max_modules {
                return Err("module dependency count limit exceeded".into());
            }
            let key = if parent.is_empty() {
                name
            } else {
                format!("{parent}.{name}")
            };
            let (record, reused) = match kind {
                ModuleSource::Local(path) => (
                    Record {
                        key: key.clone(),
                        source,
                        version: None,
                        dir: path,
                        revision: None,
                        digest: None,
                        package_root: package.map(Path::to_path_buf),
                    },
                    false,
                ),
                ModuleSource::Remote(_) => self.remote(&key, &source, constraint.as_deref())?,
                ModuleSource::Invalid => return Err("unsupported module source".into()),
            };
            let child_dir = self.root.join(&record.dir);
            let package_dir = record.package_root.as_ref().map(|p| self.root.join(p));
            self.report.push(FetchedModule {
                key: key.clone(),
                source: record.source.clone(),
                version: record.version.clone(),
                revision: record.revision.clone(),
                digest: record.digest.clone(),
                directory: child_dir.clone(),
                reused,
            });
            self.records.push(record);
            self.visit(&child_dir, &key, package_dir.as_deref(), ancestors)?;
        }
        ancestors.pop();
        Ok(())
    }
    fn remote(
        &mut self,
        key: &str,
        source: &str,
        constraint: Option<&str>,
    ) -> Result<(Record, bool), String> {
        let source = normalize_source(source);
        let parsed = transport::Source::parse(&source)?;
        if constraint.is_some() && !parsed.is_registry() {
            return Err("version constraints require a registry module".into());
        }
        let package_key = (source.clone(), constraint.unwrap_or("").to_string());
        if let Some(record) = self.packages.get(&package_key) {
            let mut r = record.clone();
            r.key = key.into();
            return Ok((r, true));
        }
        if !self.request.refresh
            && let Some(record) = self
                .previous
                .get(key)
                .cloned()
                .filter(|r| normalize_source(&r.source) == source)
        {
            let valid_version = match (&record.version, constraint) {
                (Some(v), c) => version_matches(v, c.unwrap_or(""))?,
                (None, None) => true,
                _ => false,
            };
            if valid_version
                && let (Some(digest), Some(package), Some(_)) =
                    (&record.digest, &record.package_root, &record.revision)
            {
                let package = self.root.join(package);
                let expected = self.cache.join("oxtf-packages").join(digest);
                if package != expected
                    || digest.len() != 64
                    || !digest.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err("invalid fetched package metadata".into());
                }
                let actual = if let Some(value) = self.verified.get(&package) {
                    value.clone()
                } else {
                    let value = archive::digest(&package, &self.request.limits)?;
                    self.verified.insert(package.clone(), value.clone());
                    value
                };
                if &actual != digest {
                    return Err("cached package was modified; restore or remove the damaged cache before fetching".into());
                }
                if !self.root.join(&record.dir).starts_with(&package) {
                    return Err("invalid fetched module directory".into());
                }
                self.packages.insert(package_key, record.clone());
                return Ok((record, true));
            }
        }
        let stage = tempfile::tempdir_in(self.cache).map_err(error)?;
        let downloaded = transport::download(
            parsed,
            constraint,
            self.request,
            stage.path(),
            self.deadline,
        )?;
        let content = stage.path().join("content");
        archive::unpack(&downloaded.archive, &content, &self.request.limits)?;
        self.check_time()?;
        let digest = archive::digest(&content, &self.request.limits)?;
        let destination = self.cache.join("oxtf-packages").join(&digest);
        if destination.exists() {
            if archive::digest(&destination, &self.request.limits)? != digest {
                return Err("cached content digest mismatch".into());
            }
        } else {
            fs::rename(&content, &destination).map_err(error)?;
            archive::readonly(&destination)?;
        }
        let selected = destination.join(downloaded.subdir);
        if !selected.is_dir() {
            return Err("module package subdirectory is unavailable".into());
        }
        let record = Record {
            key: key.into(),
            source,
            version: downloaded.version,
            dir: selected,
            revision: Some(
                downloaded
                    .revision
                    .unwrap_or_else(|| format!("sha256:{digest}")),
            ),
            digest: Some(digest),
            package_root: Some(destination),
        };
        self.packages.insert(package_key, record.clone());
        Ok((record, false))
    }
}

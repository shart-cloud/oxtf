use crate::{FetchRequest, archive::safe_path, error};
use reqwest::Url;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) enum Source {
    Git {
        url: String,
        reference: String,
        subdir: PathBuf,
    },
    Registry {
        host: String,
        path: String,
        subdir: PathBuf,
    },
}
impl Source {
    pub fn parse(source: &str) -> Result<Self, String> {
        if let Some(raw) = source.strip_prefix("git::") {
            let (base, query) = raw.split_once('?').unwrap_or((raw, ""));
            let scheme_end = base
                .find("://")
                .map(|i| i + 3)
                .ok_or("Git sources require an explicit https, ssh, or file URL")?;
            let (url, subdir) = if let Some(i) = base[scheme_end..].find("//") {
                (
                    &base[..scheme_end + i],
                    safe_path(Path::new(&base[scheme_end + i + 2..]))?,
                )
            } else {
                (base, PathBuf::new())
            };
            let parsed = Url::parse(url).map_err(|_| "invalid Git source URL")?;
            if !matches!(parsed.scheme(), "https" | "ssh" | "file") {
                return Err("unsupported Git transport".into());
            }
            if parsed.password().is_some()
                || (parsed.scheme() != "ssh" && !parsed.username().is_empty())
                || parsed.fragment().is_some()
            {
                return Err("credentials and fragments are not allowed in module sources; use a credential helper or SSH agent".into());
            }
            let mut reference = None;
            for (key, value) in Url::parse(&format!("https://local.invalid/?{query}"))
                .unwrap()
                .query_pairs()
            {
                match key.as_ref() {
                    "ref"
                        if reference.is_none()
                            && !value.is_empty()
                            && !value.starts_with('-')
                            && !value.contains(['\n', '\r', '\0']) =>
                    {
                        reference = Some(value.into_owned())
                    }
                    _ => return Err("unsupported or duplicate Git source query parameter".into()),
                }
            }
            return Ok(Self::Git {
                url: url.into(),
                reference: reference.unwrap_or_else(|| "HEAD".into()),
                subdir,
            });
        }
        let (address, subdir) = match source.split_once("//") {
            Some((a, s)) => (a, safe_path(Path::new(s))?),
            None => (source, PathBuf::new()),
        };
        let parts: Vec<_> = address.split('/').collect();
        if parts.len() != 4
            || !parts[0].contains('.')
            || parts.iter().any(|s| {
                s.is_empty()
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            })
        {
            return Err(
                "unsupported module source; expected a registry address or git:: URL".into(),
            );
        }
        Ok(Self::Registry {
            host: parts[0].into(),
            path: parts[1..].join("/"),
            subdir,
        })
    }
    pub fn is_registry(&self) -> bool {
        matches!(self, Self::Registry { .. })
    }
}
pub(crate) struct Download {
    pub archive: PathBuf,
    pub subdir: PathBuf,
    pub version: Option<String>,
    pub revision: Option<String>,
}

pub(crate) fn download(
    source: Source,
    constraint: Option<&str>,
    request: &FetchRequest,
    stage: &Path,
    deadline: Instant,
) -> Result<Download, String> {
    match source {
        Source::Git {
            url,
            reference,
            subdir,
        } => {
            let repo = stage.join("git");
            fs::create_dir(&repo).map_err(error)?;
            git(&repo, &["init", "-q"], request, stage, deadline)?;
            git(
                &repo,
                &[
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--depth=1",
                    "--",
                    &url,
                    &reference,
                ],
                request,
                stage,
                deadline,
            )?;
            let revision_file = stage.join("revision");
            git_output(
                &repo,
                &["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
                &revision_file,
                request,
                stage,
                deadline,
            )?;
            let revision = fs::read_to_string(revision_file)
                .map_err(error)?
                .trim()
                .to_string();
            if !matches!(revision.len(), 40 | 64)
                || !revision.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err("invalid resolved Git revision".into());
            }
            let tree = stage.join("tree");
            git_output(
                &repo,
                &["ls-tree", "-r", &revision],
                &tree,
                request,
                stage,
                deadline,
            )?;
            if fs::read_to_string(tree)
                .map_err(error)?
                .lines()
                .any(|l| l.starts_with("160000 "))
            {
                return Err("Git submodules are not supported".into());
            }
            let archive = stage.join("package.tar");
            // Package contents must be the committed files, not a release
            // export. This highest-precedence attributes file also overrides
            // nested .gitattributes and prevents export-subst rewriting HCL.
            // https://git-scm.com/docs/git-archive#ATTRIBUTES
            fs::create_dir_all(repo.join(".git/info")).map_err(error)?;
            fs::write(
                repo.join(".git/info/attributes"),
                "* -export-ignore -export-subst\n",
            )
            .map_err(error)?;
            git_output(
                &repo,
                &["archive", "--format=tar", &revision],
                &archive,
                request,
                stage,
                deadline,
            )?;
            Ok(Download {
                archive,
                subdir,
                version: None,
                revision: Some(revision),
            })
        }
        Source::Registry { host, path, subdir } => {
            let origin = request
                .registry_origins
                .get(&host)
                .cloned()
                .unwrap_or_else(|| format!("https://{host}"));
            let origin = http_url(&origin)?;
            let token_name = format!("TF_TOKEN_{}", host.replace('-', "__").replace('.', "_"));
            let token = std::env::var(token_name).ok();
            let http = Http {
                client: reqwest::blocking::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|_| "could not initialize HTTP client")?,
                auth_origin: origin.origin().ascii_serialization(),
                token,
                deadline,
            };
            let discovery_url = origin
                .join("/.well-known/terraform.json")
                .map_err(|_| "invalid registry origin")?;
            let discovery = http.json(discovery_url.clone())?;
            let service = discovery
                .get("modules.v1")
                .and_then(|v| v.as_str())
                .ok_or("registry has no modules.v1 service")?;
            let mut service = discovery_url
                .join(service)
                .map_err(|_| "invalid registry service URL")?;
            if !service.path().ends_with('/') {
                service.set_path(&format!("{}/", service.path()));
            }
            let versions = http.json(
                service
                    .join(&format!("{path}/versions"))
                    .map_err(|_| "invalid registry module path")?,
            )?;
            let versions = versions
                .get("modules")
                .and_then(|v| v.as_array())
                .ok_or("invalid registry versions response")?;
            let mut candidates = Vec::new();
            for module in versions {
                for v in module
                    .get("versions")
                    .and_then(|v| v.as_array())
                    .ok_or("invalid registry versions response")?
                {
                    let raw = v
                        .get("version")
                        .and_then(|v| v.as_str())
                        .ok_or("invalid registry version")?;
                    let version =
                        semver::Version::parse(raw).map_err(|_| "invalid registry version")?;
                    if tf_semantic::installed::version_matches(raw, constraint.unwrap_or(""))?
                        && (version.pre.is_empty() || constraint.is_some_and(|c| c.contains('-')))
                    {
                        candidates.push(version);
                    }
                }
            }
            candidates.sort_by(semver::Version::cmp_precedence);
            let version = candidates
                .pop()
                .ok_or("no registry module version satisfies the constraint")?
                .to_string();
            let response = http.get(
                service
                    .join(&format!("{path}/{version}/download"))
                    .map_err(|_| "invalid registry download path")?,
            )?;
            let target = response
                .headers()
                .get("X-Terraform-Get")
                .and_then(|v| v.to_str().ok())
                .ok_or("registry download response has no X-Terraform-Get header")?;
            if target.starts_with("git::") || target.starts_with("github.com/") {
                let source = Source::parse(&tf_semantic::installed::normalize_source(target))?;
                if !matches!(source, Source::Git { .. }) {
                    return Err("unsupported registry download source".into());
                }
                let mut result = download(source, None, request, stage, deadline)?;
                result.subdir = result.subdir.join(subdir);
                result.version = Some(version);
                return Ok(result);
            }
            let url = response
                .url()
                .join(target)
                .map_err(|_| "invalid registry download URL")?;
            let mut response = http.get(url)?;
            let archive = stage.join("package.download");
            let mut file = fs::File::create(&archive).map_err(error)?;
            let mut left = request.limits.max_download_bytes;
            let mut buffer = [0u8; 65536];
            loop {
                let n = response
                    .read(&mut buffer)
                    .map_err(|_| "module download failed")?;
                if n == 0 {
                    break;
                }
                left = left
                    .checked_sub(n as u64)
                    .ok_or("module download size limit exceeded")?;
                file.write_all(&buffer[..n]).map_err(error)?;
            }
            Ok(Download {
                archive,
                subdir,
                version: Some(version),
                revision: None,
            })
        }
    }
}
fn git(
    repo: &Path,
    args: &[&str],
    request: &FetchRequest,
    stage: &Path,
    deadline: Instant,
) -> Result<(), String> {
    run_git(repo, args, Stdio::null(), request, stage, deadline)
}
fn git_output(
    repo: &Path,
    args: &[&str],
    path: &Path,
    request: &FetchRequest,
    stage: &Path,
    deadline: Instant,
) -> Result<(), String> {
    run_git(
        repo,
        args,
        fs::File::create(path).map_err(error)?.into(),
        request,
        stage,
        deadline,
    )
}
fn run_git(
    repo: &Path,
    args: &[&str],
    stdout: Stdio,
    request: &FetchRequest,
    stage: &Path,
    deadline: Instant,
) -> Result<(), String> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.file.allow=always",
            "-c",
            "fetch.recurseSubmodules=false",
        ])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::null());
    // A caller's Git worktree overrides must not redirect commands into it.
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ] {
        command.env_remove(key);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        let bytes = request.limits.max_download_bytes;
        // SAFETY: the child only invokes async-signal-safe setrlimit before
        // exec. This is an additional hard per-file bound; the parent monitors
        // aggregate staging size and the deadline.
        unsafe {
            command.pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: bytes as libc::rlim_t,
                    rlim_max: bytes as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command.spawn().map_err(|_| "could not start Git")?;
    let outcome = loop {
        if Instant::now() >= deadline {
            break Err("dependency fetch time limit exceeded".into());
        }
        if disk_size(stage, request.limits.max_download_bytes).is_err() {
            break Err("Git download size limit exceeded".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break if status.success() {
                    Ok(())
                } else {
                    Err("Git module fetch failed (check source, ref, and credentials)".into())
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => break Err("could not wait for Git".into()),
        }
    };
    if outcome.is_err() {
        #[cfg(unix)]
        {
            // SAFETY: a negative PID targets only the process group created
            // for this child, including transport and index-pack descendants.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    outcome
}
fn disk_size(path: &Path, limit: u64) -> Result<u64, ()> {
    let mut sum = 0u64;
    let mut stack = vec![path.to_path_buf()];
    let mut count = 0;
    while let Some(path) = stack.pop() {
        // Git renames lockfiles and temporary pack files while this monitor
        // walks the staging tree. A vanished entry contributes no bytes.
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(()),
            };
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(()),
            };
            count += 1;
            if count > 100_000 {
                return Err(());
            }
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                sum = sum.saturating_add(meta.len());
            }
            if sum > limit {
                return Err(());
            }
        }
    }
    Ok(sum)
}

fn http_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "invalid HTTP URL")?;
    let loopback = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "module HTTP requests require HTTPS (or HTTP loopback) and credentials outside the URL"
                .into(),
        );
    }
    Ok(url)
}
struct Http {
    client: reqwest::blocking::Client,
    auth_origin: String,
    token: Option<String>,
    deadline: Instant,
}
impl Http {
    fn get(&self, mut url: Url) -> Result<reqwest::blocking::Response, String> {
        for _ in 0..=5 {
            url = http_url(url.as_str())?;
            let timeout = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|t| !t.is_zero())
                .ok_or("dependency fetch time limit exceeded")?;
            let mut request = self.client.get(url.clone()).timeout(timeout);
            if url.origin().ascii_serialization() == self.auth_origin
                && let Some(token) = &self.token
            {
                request = request.bearer_auth(token);
            }
            let response = request
                .send()
                .map_err(|_| "module HTTP request failed (check source and credentials)")?;
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|h| h.to_str().ok())
                    .ok_or("HTTP redirect has no location")?;
                url = url.join(location).map_err(|_| "invalid HTTP redirect")?;
                continue;
            }
            if !response.status().is_success() {
                return Err(format!(
                    "module HTTP request returned status {}",
                    response.status().as_u16()
                ));
            }
            return Ok(response);
        }
        Err("module HTTP redirect limit exceeded".into())
    }
    fn json(&self, url: Url) -> Result<serde_json::Value, String> {
        let mut body = Vec::new();
        self.get(url)?
            .take(1_048_577)
            .read_to_end(&mut body)
            .map_err(|_| "could not read registry metadata")?;
        if body.len() > 1_048_576 {
            return Err("registry metadata size limit exceeded".into());
        }
        serde_json::from_slice(&body).map_err(|_| "invalid registry metadata JSON".into())
    }
}

//! Extraction into a fresh private staging directory. Never follow links or
//! apply archive permissions; all destinations are validated before writing.
use crate::{FetchLimits, error};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

pub(crate) fn safe_path(raw: &Path) -> Result<PathBuf, String> {
    if raw.components().count() > 64 {
        return Err("package path depth limit exceeded".into());
    }
    let mut out = PathBuf::new();
    for part in raw.components() {
        match part {
            Component::CurDir => (),
            Component::Normal(s) if s != ".git" && !s.to_string_lossy().contains(['\\', ':']) => {
                out.push(s)
            }
            _ => return Err("package path escapes its directory or is reserved".into()),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("empty package path".into());
    }
    Ok(out)
}

struct Extract<'a> {
    dest: &'a Path,
    limits: &'a FetchLimits,
    paths: BTreeSet<PathBuf>,
    size: u64,
}
impl Extract<'_> {
    fn entry(
        &mut self,
        path: &Path,
        size: u64,
        dir: bool,
        reader: impl Read,
    ) -> Result<(), String> {
        let path = safe_path(path)?;
        if !self.paths.insert(path.clone()) {
            return Err("duplicate archive entry".into());
        }
        self.size = self
            .size
            .checked_add(size)
            .ok_or("package size limit exceeded")?;
        if self.paths.len() > self.limits.max_files || self.size > self.limits.max_unpacked_bytes {
            return Err("package extraction limit exceeded".into());
        }
        let target = self.dest.join(path);
        if dir {
            fs::create_dir_all(target).map_err(error)?;
        } else {
            fs::create_dir_all(target.parent().unwrap()).map_err(error)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(target)
                .map_err(error)?;
            let written =
                io::copy(&mut reader.take(size.saturating_add(1)), &mut file).map_err(error)?;
            if written != size {
                return Err("archive entry size mismatch".into());
            }
        }
        Ok(())
    }
}

pub(crate) fn unpack(path: &Path, dest: &Path, limits: &FetchLimits) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(error)?;
    let mut prefix = [0u8; 4];
    fs::File::open(path)
        .map_err(error)?
        .read_exact(&mut prefix)
        .map_err(error)?;
    let file = fs::File::open(path).map_err(error)?;
    let mut extract = Extract {
        dest,
        limits,
        paths: BTreeSet::new(),
        size: 0,
    };
    if &prefix[..2] == b"PK" {
        let mut zip = zip::ZipArchive::new(file).map_err(|_| "invalid ZIP archive")?;
        if zip.len() > limits.max_files {
            return Err("package file limit exceeded".into());
        }
        for i in 0..zip.len() {
            let entry = zip.by_index(i).map_err(|_| "invalid ZIP entry")?;
            let mode = entry.unix_mode().unwrap_or(0) & 0o170000;
            if !matches!(mode, 0 | 0o100000 | 0o040000) {
                return Err("package links and special files are not supported".into());
            }
            let path = PathBuf::from(entry.name());
            extract.entry(&path, entry.size(), entry.is_dir(), entry)?;
        }
    } else {
        let reader: Box<dyn Read> = if prefix[..2] == [0x1f, 0x8b] {
            Box::new(flate2::read::GzDecoder::new(file))
        } else {
            Box::new(file)
        };
        // This also bounds GNU/PAX metadata before tar can allocate it.
        let cap = limits
            .max_unpacked_bytes
            .saturating_add((limits.max_files as u64).saturating_mul(2048));
        let mut archive = tar::Archive::new(reader.take(cap));
        for entry in archive.entries().map_err(error)? {
            let entry = entry.map_err(error)?;
            let kind = entry.header().entry_type();
            // `git archive` includes the commit ID in a global PAX header.
            // It is metadata, never an extracted filesystem object.
            if kind.is_pax_global_extensions() && entry.size() <= 16_384 {
                continue;
            }
            if !kind.is_file() && !kind.is_dir() {
                return Err("package links and special files are not supported".into());
            }
            let path = entry.path().map_err(error)?.into_owned();
            if path == Path::new(".") && kind.is_dir() {
                continue;
            }
            extract.entry(&path, entry.size(), kind.is_dir(), entry)?;
        }
    }
    if extract.paths.is_empty() {
        return Err("empty module package".into());
    }
    Ok(())
}

pub(crate) fn digest(dir: &Path, limits: &FetchLimits) -> Result<String, String> {
    fn walk(
        dir: &Path,
        root: &Path,
        entries: &mut Vec<PathBuf>,
        limits: &FetchLimits,
    ) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(error)? {
            let entry = entry.map_err(error)?;
            let kind = entry.file_type().map_err(error)?;
            if entries.len() >= limits.max_files {
                return Err("package file limit exceeded".into());
            }
            let path = entry.path();
            safe_path(path.strip_prefix(root).map_err(error)?)?;
            if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
                return Err("package contains a link or special file".into());
            }
            entries.push(path.clone());
            if kind.is_dir() {
                walk(&path, root, entries, limits)?;
            }
        }
        Ok(())
    }
    let mut entries = Vec::new();
    walk(dir, dir, &mut entries, limits)?;
    entries.sort();
    let mut hash = Sha256::new();
    let mut total = 0u64;
    for path in entries {
        let name = path
            .strip_prefix(dir)
            .map_err(error)?
            .to_str()
            .ok_or("non-UTF8 package path")?
            .as_bytes();
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name);
        let meta = fs::symlink_metadata(&path).map_err(error)?;
        hash.update([u8::from(meta.is_dir())]);
        if meta.is_file() {
            total = total
                .checked_add(meta.len())
                .ok_or("package size limit exceeded")?;
            if total > limits.max_unpacked_bytes {
                return Err("package size limit exceeded".into());
            }
            hash.update(meta.len().to_le_bytes());
            let mut file = fs::File::open(path).map_err(error)?;
            let mut buffer = [0u8; 65536];
            loop {
                let n = file.read(&mut buffer).map_err(error)?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
            }
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(crate) fn readonly(dir: &Path) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(error)? {
        let entry = entry.map_err(error)?;
        if entry.file_type().map_err(error)?.is_dir() {
            readonly(&entry.path())?;
        }
        let mut permissions = entry.metadata().map_err(error)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(entry.path(), permissions).map_err(error)?;
    }
    let mut permissions = fs::metadata(dir).map_err(error)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(dir, permissions).map_err(error)?;
    Ok(())
}

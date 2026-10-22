//! The finding record: the resolved, versioned, machine-readable form of a
//! scan that every output (JSON, Arrow, Python, text) is a projection of.
//!
//! Everything here is plain data with locations already resolved against
//! the scan's file table, so a reader needs no further context. The shape
//! is versioned by [`SCHEMA`]; any breaking change bumps it. The worked
//! example and field semantics live in `docs/FINDING_SCHEMA.md`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tf_eval::{Kind, Known, Step, Truth, Value};
use tf_semantic::source::normalize;
use tf_semantic::{Address, Diagnostic, FileTable, InstanceKey, Mode};
use tf_span::FileSpan;

use crate::rule::{Category, Certainty, Finding, FindingSubject, FixHint, Hidden, Level};
use crate::scan::{ScanResult, ScanStats};

/// Version of the record shape. Bumped on any breaking change.
pub const SCHEMA: u32 = 3;

/// A resolved source location.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    /// 1-based.
    pub line: u32,
    /// 1-based.
    pub column: u32,
    /// Byte offsets into the file.
    pub start: u32,
    pub end: u32,
}

pub fn location(files: &FileTable, at: FileSpan) -> Location {
    let sf = files.get(at.file);
    let (line, column) = sf.line_col(at.span.start);
    Location {
        file: sf.path.display().to_string(),
        line,
        column,
        start: at.span.start,
        end: at.span.end,
    }
}

/// A resource instance's identity, structured and as strings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceRef {
    /// Full address, module path and instance key included.
    pub address: String,
    /// Address without the instance key.
    pub base_address: String,
    /// Module instance path, `""` for the root.
    pub module: String,
    /// `managed` or `data`.
    pub mode: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub name: String,
    /// `count` index (number) or `for_each` key (string).
    pub key: Option<Json>,
}

impl From<&Address> for ResourceRef {
    fn from(a: &Address) -> Self {
        ResourceRef {
            address: a.to_string(),
            base_address: a.base_string(),
            module: a.module.to_string(),
            mode: match a.mode {
                Mode::Managed => "managed",
                Mode::Data => "data",
            }
            .into(),
            ty: a.ty.to_string(),
            name: a.name.to_string(),
            key: a.key.as_ref().map(|k| match k {
                InstanceKey::Index(i) => Json::from(*i),
                InstanceKey::Key(k) => Json::from(k.as_ref()),
            }),
        }
    }
}

/// `{"kind": "resource", ...the resource reference}` or `{"kind": "file",
/// "file", "module"}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubjectRecord {
    Resource(ResourceRef),
    File { file: String, module: String },
}

/// `{"engine", "file", "line"}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub engine: crate::rule::Engine,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl From<&crate::rule::RuleSource> for SourceRef {
    fn from(s: &crate::rule::RuleSource) -> Self {
        SourceRef {
            engine: s.engine,
            file: s.file.as_ref().map(|f| f.display().to_string()),
            line: s.line,
        }
    }
}

/// An abstract value as a reader can use it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValueRecord {
    /// `known`, `unknown`, `tainted` or `one_of`.
    pub kind: String,
    /// The value as JSON when it is wholly known.
    pub value: Option<Json>,
    /// Human rendering (strings quoted; abstract values described).
    pub display: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
}

pub fn value_record(v: &Value) -> ValueRecord {
    let kind = match &v.kind {
        Kind::Known(_) => "known",
        Kind::Unknown(_) => "unknown",
        Kind::Tainted(_) => "tainted",
        Kind::OneOf(_) => "one_of",
    };
    let value = if v.is_sensitive() {
        None
    } else {
        match &v.kind {
            Kind::Known(Known::Json(inner)) => tf_eval::value::to_json(inner),
            _ => tf_eval::value::to_json(v),
        }
    };
    ValueRecord {
        kind: kind.into(),
        value,
        display: v.to_string(),
        sensitive: v.is_sensitive(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    pub kind: String,
    pub label: String,
    /// Base address of the resource whose attribute this step reads.
    pub resource: Option<String>,
    /// Attribute path within that resource.
    pub attribute: Option<String>,
    pub location: Location,
}

pub fn step_record(files: &FileTable, s: &Step) -> StepRecord {
    StepRecord {
        kind: s.kind.as_str().into(),
        label: s.label.to_string(),
        resource: s.resource.as_deref().map(str::to_string),
        attribute: s.attribute.as_deref().map(str::to_string),
        location: location(files, s.at),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenRecord {
    pub path: String,
    /// `tainted` (unconstrained variable) or `unknown` (apply-time).
    pub kind: String,
}

impl From<&Hidden> for HiddenRecord {
    fn from(h: &Hidden) -> Self {
        HiddenRecord {
            path: h.path.clone(),
            kind: match h.truth {
                Truth::Tainted => "tainted",
                _ => "unknown",
            }
            .into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FixHintRecord {
    pub resource: ResourceRef,
    pub attribute: String,
    /// `set`.
    pub action: String,
    pub value: Json,
    /// Where the attribute is written today; `None` means insert it (and
    /// any missing blocks on its path) into the resource block.
    pub site: Option<Location>,
    /// The default of the variable the attribute is written as
    /// (`x = var.x`): the other place the literal can go, which keeps a
    /// module's interface. Only fixes occurrences no caller overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_site: Option<Location>,
    /// When the value is passed in by a caller's module argument or a tfvars
    /// binding: that binding, the only place the fix writes. `site` is then
    /// where the value lands, not an edit target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_site: Option<Location>,
}

fn fix_hint_record(files: &FileTable, h: &FixHint) -> FixHintRecord {
    FixHintRecord {
        resource: ResourceRef::from(&h.resource),
        attribute: h.attribute.clone(),
        action: h.action.as_str().into(),
        value: h.value.clone(),
        site: h.site.map(|at| location(files, at)),
        default_site: h.default_site(files).map(|at| location(files, at)),
        input_site: h.input_site().map(|at| location(files, at)),
    }
}

/// A rule that produced at least one finding: an entry of the record's
/// `rules` table, keyed by its ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRecord {
    pub category: Category,
    pub level: Level,
    pub description: String,
    /// A page explaining the rule, when it names one.
    #[serde(default)]
    pub guideline: Option<String>,
    /// Why the assigned severity fits what this check can establish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    /// Steps to address the finding, including material migration constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// The front-end the rule came through, and its file and line.
    #[serde(default)]
    pub source: SourceRef,
    /// The rule's other IDs.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// `security`, `audit`, `hygiene` or `unreviewed` (a bundled rule not
    /// curated yet).
    #[serde(default)]
    pub profile: crate::rule::Profile,
}

impl RuleRecord {
    fn of(f: &Finding) -> RuleRecord {
        RuleRecord {
            category: f.category,
            level: f.level,
            description: f.description.to_string(),
            guideline: f.guideline.as_deref().map(str::to_string),
            rationale: f.rationale.as_deref().map(str::to_string),
            remediation: f.remediation.as_deref().map(str::to_string),
            source: SourceRef::from(&f.source),
            aliases: f.aliases.iter().map(|a| a.to_string()).collect(),
            profile: f.profile,
        }
    }
}

/// Installed source metadata. `version` is what the manifest records, not
/// a lock or proof of the current Git revision. `revision` is recorded by
/// explicit fetching; ordinary scans do not rehash the installed contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRecord {
    pub source: String,
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    pub file: String,
    pub calls: Vec<Location>,
}

fn package_record(files: &FileTable, f: &Finding) -> Option<PackageRecord> {
    let p = f.package.as_ref()?;
    Some(PackageRecord {
        source: p.source.clone(),
        version: p.version.clone(),
        revision: p.revision.clone(),
        file: p.relative_file(&files.get(f.primary.file).path),
        calls: p.calls.iter().map(|at| location(files, *at)).collect(),
    })
}

/// One place a finding was produced: a root module and the resource
/// instance (or file) the rule judged there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OccurrenceRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackageRecord>,
    pub root: String,
    /// The resource address in that root, or the file's path for a file
    /// subject.
    pub address: String,
    pub certainty: Certainty,
    /// Where this occurrence points, when not at the finding's `location`
    /// (a resource that sets the attribute in alternative `dynamic`
    /// blocks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

/// A finding: one rule failing on one attribute (or the whole) of one
/// resource declaration, the identity its [`fingerprint`] hashes. The same
/// declaration reached from several roots (a module scanned on its own and
/// from each example that calls it) or as several instances (`count`,
/// `for_each`) is one finding with several `occurrences`; the remaining
/// fields describe its representative occurrence, the most certain one
/// and, among those, the one closest to the code.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FindingRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackageRecord>,
    /// Stable identity across scans (see [`fingerprint`]).
    pub fingerprint: String,
    /// The rule's ID; its metadata is in the record's `rules` table.
    pub rule: String,
    /// The rule's level, repeated here so a finding can be ranked alone.
    pub level: Level,
    /// The most certain of the occurrences.
    pub certainty: Certainty,
    /// What the representative occurrence is about.
    pub subject: SubjectRecord,
    /// Root module directory of the representative occurrence.
    pub root: String,
    /// Attribute path of the deciding value within the resource.
    pub attribute: Option<String>,
    /// The deciding top-level attribute as written; absent when not set.
    pub configured: Option<ValueRecord>,
    /// The same after the defaults overlay.
    pub effective: Option<ValueRecord>,
    /// Where to point: the deciding attribute, else the resource header.
    pub location: Location,
    /// Origin-first explanation of the deciding value.
    pub provenance: Vec<StepRecord>,
    pub message: String,
    /// Inputs a foreign policy could not see; empty for native rules.
    pub hidden: Vec<HiddenRecord>,
    pub fix_hint: Option<FixHintRecord>,
    /// Every place this finding was produced, the representative among
    /// them, ordered by root and address.
    pub occurrences: Vec<OccurrenceRecord>,
}

/// FNV-1a 64-bit of the rule ID, the repository-relative path of the
/// finding's file, the subject's local identity (its address without module
/// path or instance key, `aws_s3_bucket.this`; for a file subject, the
/// message) and the attribute path, hex. Stable across builds and
/// platforms; not a security hash.
pub fn fingerprint(rule: &str, file: &str, local: &str, attribute: Option<&str>) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in [rule, "\0", file, "\0", local, "\0", attribute.unwrap_or("")] {
        for b in part.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

/// Finds the repository a file belongs to (the outermost ancestor holding
/// `.git`, so a submodule or nested clone stays inside the checkout that
/// contains it), once per directory, so a fingerprint depends neither on
/// the directory a scan was started from nor on which root reached the
/// file.
#[derive(Default)]
pub struct RepoRoots(HashMap<PathBuf, Option<PathBuf>>);

impl RepoRoots {
    pub fn new() -> RepoRoots {
        RepoRoots::default()
    }

    /// `path` relative to its repository, `/`-separated; as given when it
    /// is in none.
    pub fn relative(&mut self, path: &Path) -> String {
        let slashed = |p: &Path| {
            p.components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
        };
        let Ok(abs) = std::path::absolute(path).map(|p| normalize(&p)) else {
            return slashed(path);
        };
        let dir = abs.parent().map(Path::to_path_buf).unwrap_or_default();
        let repo = self
            .0
            .entry(dir)
            .or_insert_with_key(|dir| {
                dir.ancestors()
                    .filter(|a| a.join(".git").exists())
                    .last()
                    .map(Path::to_path_buf)
            })
            .clone();
        match repo.as_deref().and_then(|r| abs.strip_prefix(r).ok()) {
            Some(rel) => slashed(rel),
            None => slashed(path),
        }
    }
}

/// What identifies a finding's subject within its file: the resource's
/// local address, or a file finding's message (several results of one
/// whole-file policy are told apart by what they say).
fn local_identity(f: &Finding) -> String {
    match &f.subject {
        FindingSubject::Resource(a) => a.local(),
        FindingSubject::File { .. } => f.message.clone(),
    }
}

/// The fingerprint of one finding (every occurrence of a finding has the
/// same one).
pub fn finding_fingerprint(files: &FileTable, f: &Finding, repos: &mut RepoRoots) -> String {
    let file = finding_file_identity(files, f, repos);
    fingerprint(&f.rule, &file, &local_identity(f), f.attribute.as_deref())
}

fn finding_file_identity(files: &FileTable, f: &Finding, repos: &mut RepoRoots) -> String {
    let path = &files.get(f.primary.file).path;
    f.package
        .as_ref()
        .map(|p| p.file_identity(path))
        .unwrap_or_else(|| repos.relative(path))
}

/// What a fix must make go away: the rule on the declaration (its
/// module directory, repository-relative, and local identity), whatever
/// attribute now decides it. Two findings with the same key are the same
/// rule failing on the same declaration.
pub fn finding_subject_key(files: &FileTable, f: &Finding, repos: &mut RepoRoots) -> String {
    let path = &files.get(f.primary.file).path;
    let parent = path.parent().unwrap_or(path);
    let dir = f
        .package
        .as_ref()
        .map(|p| p.file_identity(parent))
        .unwrap_or_else(|| repos.relative(parent));
    fingerprint(&f.rule, &dir, &local_identity(f), None)
}

/// Findings that are one finding: the same rule, file, local identity and
/// attribute (what [`finding_fingerprint`] hashes). `members` index the
/// scan's findings, ordered by root and address, without repeats;
/// `representative` is one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub representative: usize,
    pub members: Vec<usize>,
}

/// Group a scan's findings into findings with occurrences, ordered by
/// file, position and rule.
#[expect(clippy::too_many_lines)]
pub fn group(files: &FileTable, findings: &[Finding]) -> Vec<Group> {
    #[derive(PartialEq, Eq, Hash)]
    enum FileKey {
        Source(tf_span::FileId),
        Installed(String),
    }
    type Key<'f> = (&'f str, FileKey, String, Option<&'f str>);
    let mut by_identity: HashMap<Key<'_>, usize> = HashMap::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, f) in findings.iter().enumerate() {
        let file = match &f.package {
            Some(package) => {
                FileKey::Installed(package.file_identity(&files.get(f.primary.file).path))
            }
            None => FileKey::Source(f.primary.file),
        };
        let key = (&*f.rule, file, local_identity(f), f.attribute.as_deref());
        match by_identity.entry(key) {
            std::collections::hash_map::Entry::Occupied(e) => groups[*e.get()].push(i),
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(groups.len());
                groups.push(vec![i]);
            }
        }
    }
    let address = |i: usize| &*findings[i].address;
    let same = |a: usize, b: usize| {
        findings[a].root == findings[b].root
            && address(a) == address(b)
            && findings[a].primary == findings[b].primary
    };
    let mut out: Vec<Group> = groups
        .into_iter()
        .map(|mut members| {
            // Most certain first, then the shallowest module instance (the
            // module scanned as its own root), then the shortest root.
            let representative = *members
                .iter()
                .min_by_key(|&&i| {
                    let f = &findings[i];
                    (
                        f.certainty,
                        f.module.matches("module.").count(),
                        f.root.as_os_str().len(),
                        &f.root,
                        address(i),
                    )
                })
                .expect("a group has a member");
            let site = |i: usize| (findings[i].primary.span.start, findings[i].primary.span.end);
            members.sort_by(|&a, &b| {
                (&findings[a].root, address(a), site(a)).cmp(&(
                    &findings[b].root,
                    address(b),
                    site(b),
                ))
            });
            members.dedup_by(|a, b| same(*a, *b));
            if !members.contains(&representative) {
                // A repeat of the representative was kept in its place.
                let twin = members
                    .iter_mut()
                    .find(|m| same(**m, representative))
                    .expect("the representative's twin");
                *twin = representative;
            }
            Group {
                representative,
                members,
            }
        })
        .collect();
    out.sort_by_cached_key(|g| {
        let f = &findings[g.representative];
        (
            files.get(f.primary.file).path.clone(),
            f.primary.span.start,
            f.rule.clone(),
        )
    });
    out
}

fn subject_record(f: &Finding) -> SubjectRecord {
    match &f.subject {
        FindingSubject::Resource(a) => SubjectRecord::Resource(ResourceRef::from(a)),
        FindingSubject::File { path } => SubjectRecord::File {
            file: path.display().to_string(),
            module: f.module.to_string(),
        },
    }
}

fn group_record(
    files: &FileTable,
    findings: &[Finding],
    g: &Group,
    repos: &mut RepoRoots,
) -> FindingRecord {
    let f = &findings[g.representative];
    FindingRecord {
        package: package_record(files, f),
        fingerprint: finding_fingerprint(files, f, repos),
        rule: f.rule.to_string(),
        level: f.level,
        certainty: f.certainty,
        subject: subject_record(f),
        root: f.root.display().to_string(),
        attribute: f.attribute.as_deref().map(str::to_string),
        configured: f.configured.as_ref().map(value_record),
        effective: f.effective.as_ref().map(value_record),
        location: location(files, f.primary),
        provenance: f.provenance.iter().map(|s| step_record(files, s)).collect(),
        message: f.message.clone(),
        hidden: f.hidden.iter().map(HiddenRecord::from).collect(),
        fix_hint: f.fix_hint.as_ref().map(|h| fix_hint_record(files, h)),
        occurrences: g
            .members
            .iter()
            .map(|&i| OccurrenceRecord {
                package: package_record(files, &findings[i]),
                root: findings[i].root.display().to_string(),
                address: findings[i].address.to_string(),
                certainty: findings[i].certainty,
                location: (findings[i].primary != f.primary)
                    .then(|| location(files, findings[i].primary)),
            })
            .collect(),
    }
}

/// One finding on its own, as a record with one occurrence.
pub fn finding_record(files: &FileTable, f: &Finding) -> FindingRecord {
    group_record(
        files,
        std::slice::from_ref(f),
        &Group {
            representative: 0,
            members: vec![0],
        },
        &mut RepoRoots::new(),
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticRecord {
    /// `error`, `warning` or `info`.
    pub severity: String,
    pub code: String,
    pub message: String,
    pub location: Option<Location>,
}

pub fn diagnostic_record(files: &FileTable, d: &Diagnostic) -> DiagnosticRecord {
    DiagnosticRecord {
        severity: format!("{:?}", d.severity).to_lowercase(),
        code: d.code.to_string(),
        message: d.message.clone(),
        location: d.at.map(|at| location(files, at)),
    }
}

/// A rule that failed to run. Never silent: a reader must not take the
/// absence of a finding from this rule as a pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleError {
    pub rule: String,
    /// The resource instance the rule was evaluating, when known.
    pub resource: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatsRecord {
    pub roots: usize,
    pub module_instances: usize,
    pub files: usize,
    pub resources: usize,
    /// Findings, each counted once however many occurrences it has.
    pub findings: usize,
    /// Occurrences of all findings together.
    pub occurrences: usize,
    pub definite: usize,
    pub conditional: usize,
    pub indeterminate: usize,
    pub findings_by_rule: BTreeMap<String, usize>,
    pub elapsed_ms: f64,
}

impl StatsRecord {
    fn new(s: &ScanStats, findings: &[FindingRecord]) -> Self {
        let mut stats = StatsRecord {
            roots: s.roots,
            module_instances: s.module_instances,
            files: s.files,
            resources: s.resources,
            findings: findings.len(),
            occurrences: findings.iter().map(|f| f.occurrences.len()).sum(),
            definite: 0,
            conditional: 0,
            indeterminate: 0,
            findings_by_rule: BTreeMap::new(),
            elapsed_ms: s.elapsed.as_secs_f64() * 1000.0,
        };
        for f in findings {
            *stats.findings_by_rule.entry(f.rule.clone()).or_default() += 1;
            match f.certainty {
                Certainty::Definite => stats.definite += 1,
                Certainty::Conditional => stats.conditional += 1,
                Certainty::Indeterminate => stats.indeterminate += 1,
            }
        }
        stats
    }
}

/// A whole scan, resolved.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanRecord {
    pub schema: u32,
    /// Analysis completion, independent of the finding count.
    #[serde(default)]
    pub status: crate::ScanStatus,
    /// Metadata of every rule a finding names, by ID.
    pub rules: BTreeMap<String, RuleRecord>,
    pub findings: Vec<FindingRecord>,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub rule_errors: Vec<RuleError>,
    pub stats: StatsRecord,
    /// Findings a `checkov:skip` line suppressed.
    #[serde(default)]
    pub suppressed: Vec<SuppressedRecord>,
    /// Each scanned root's own completion. `status` also reflects scan-wide
    /// limits, so a complete root can sit inside an incomplete scan.
    #[serde(default)]
    pub roots: Vec<RootRecord>,
}

/// A root module directory and its own [`crate::ScanStatus`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RootRecord {
    pub path: String,
    pub status: crate::ScanStatus,
}

/// A suppressed finding: `rule`, `resource` (address), the `comment`'s
/// reason, and the `location` of the line that suppressed it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SuppressedRecord {
    pub rule: String,
    pub resource: String,
    pub comment: String,
    pub location: Location,
}

impl ScanRecord {
    pub fn from_result(r: &ScanResult) -> ScanRecord {
        let mut repos = RepoRoots::new();
        let groups = group(&r.files, &r.findings);
        let mut rules = BTreeMap::new();
        for g in &groups {
            let f = &r.findings[g.representative];
            rules
                .entry(f.rule.to_string())
                .or_insert_with(|| RuleRecord::of(f));
        }
        let findings: Vec<FindingRecord> = groups
            .iter()
            .map(|g| group_record(&r.files, &r.findings, g, &mut repos))
            .collect();
        ScanRecord {
            schema: SCHEMA,
            status: r.status(),
            rules,
            stats: StatsRecord::new(&r.stats, &findings),
            findings,
            diagnostics: r
                .diagnostics
                .iter()
                .map(|d| diagnostic_record(&r.files, d))
                .collect(),
            rule_errors: r.rule_errors.clone(),
            suppressed: r
                .suppressed
                .iter()
                .map(|s| SuppressedRecord {
                    rule: s.rule.to_string(),
                    resource: s.address.to_string(),
                    comment: s.comment.clone(),
                    location: location(&r.files, s.at),
                })
                .collect(),
            roots: r
                .roots
                .iter()
                .map(|root| RootRecord {
                    path: root.dir.display().to_string(),
                    status: root.status,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_ignores_presentation() {
        let a = fingerprint(
            "aws-rds-unencrypted",
            "modules/db/main.tf",
            "aws_db_instance.db",
            Some("storage_encrypted"),
        );
        assert_eq!(a.len(), 16);
        assert_ne!(
            a,
            fingerprint(
                "aws-rds-unencrypted",
                "modules/db/main.tf",
                "aws_db_instance.db",
                None
            )
        );
        assert_ne!(
            a,
            fingerprint(
                "aws-rds-unencrypted",
                "modules/other/main.tf",
                "aws_db_instance.db",
                Some("storage_encrypted")
            )
        );
        // Parts are separated: moving bytes between them changes the hash.
        assert_ne!(
            fingerprint("ab", "c", "d", None),
            fingerprint("a", "bc", "d", None)
        );
        // Pinned: a change here is a change in every backlog's identities.
        assert_eq!(a, "878e37ed1f4102cc");
    }

    #[test]
    fn repository_relative_paths_do_not_depend_on_the_working_directory() {
        let mut repos = RepoRoots::new();
        let here = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/record.rs");
        assert_eq!(repos.relative(&here), "crates/tf_linter/src/record.rs");
        let dotted = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tf_linter/src/record.rs");
        assert_eq!(repos.relative(&dotted), "crates/tf_linter/src/record.rs");
    }

    #[test]
    fn value_records_carry_known_json_and_a_display() {
        let v = value_record(&Value::bool(false));
        assert_eq!(
            (v.kind.as_str(), v.value, v.display.as_str()),
            ("known", Some(Json::Bool(false)), "false")
        );
        let t = value_record(&Value::tainted("x"));
        assert_eq!((t.kind.as_str(), t.value), ("tainted", None));
        let j = value_record(&Value::json(Value::object(Default::default())));
        assert_eq!(j.value, Some(Json::Object(Default::default())));
    }
}

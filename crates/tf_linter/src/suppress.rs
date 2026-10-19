//! Checkov's inline suppressions, for rules that came from Checkov policies.
//!
//! As Checkov 3.2.328 reads them (`terraform/context_parsers/base_parser.py`
//! and `terraform/runner.py`):
//!
//! - any line of a file that contains `checkov:skip=` or `bridgecrew:skip=`
//!   is matched with `(checkov:skip=|bridgecrew:skip=) *([A-Za-z_\d]+)(:[^\n]+)?`
//!   (it need not be a comment);
//! - a match applies to the block whose lines strictly enclose it, from the
//!   block's first line to its closing brace;
//! - a match inside a `module` block applies to every resource in that
//!   module, recursively;
//! - the ID is compared as written (Checkov maps `BC_*` IDs only with its
//!   platform metadata, which is absent offline).
//!
//! A suppressed finding is not dropped silently: it is reported in
//! [`crate::ScanResult::suppressed`] with the comment that suppressed it.

use std::collections::HashMap;
use std::sync::Arc;

use tf_semantic::source::FileTable;
use tf_semantic::store::ModuleStore;
use tf_semantic::{Analysis, Resource};
use tf_span::{FileId, FileSpan, Span};

use crate::rule::{Engine, Finding, FindingSubject};

/// A finding a `checkov:skip` comment suppressed.
#[derive(Clone, Debug)]
pub struct Suppressed {
    pub rule: Arc<str>,
    /// The resource the finding was on.
    pub address: Arc<str>,
    /// The comment's reason (`No comment provided` when it has none, as
    /// Checkov reports it).
    pub comment: String,
    /// The line that suppressed it.
    pub at: FileSpan,
}

struct Skip {
    line: u32,
    id: String,
    comment: String,
    at: FileSpan,
}

/// The skip lines of one file.
fn skips(files: &FileTable, file: FileId) -> Vec<Skip> {
    let sf = files.get(file);
    let mut out = Vec::new();
    let mut offset = 0usize;
    for (i, line) in sf.text.split_inclusive('\n').enumerate() {
        let start = offset;
        offset += line.len();
        if !(line.contains("checkov:skip=") || line.contains("bridgecrew:skip=")) {
            continue;
        }
        // `re.search`: the first match on the line.
        let found = ["checkov:skip=", "bridgecrew:skip="]
            .iter()
            .filter_map(|m| line.find(m).map(|i| (i, m.len())))
            .min();
        let Some((at, len)) = found else { continue };
        let rest = line[at + len..].trim_start_matches(' ');
        let id: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if id.is_empty() {
            continue;
        }
        let after = &rest[id.len()..];
        let comment = match after.strip_prefix(':') {
            Some(c) if !c.trim_end_matches(['\n', '\r']).is_empty() => {
                c.trim_end_matches(['\n', '\r']).to_string()
            }
            _ => "No comment provided".to_string(),
        };
        let line_len = line.trim_end_matches(['\n', '\r']).len();
        out.push(Skip {
            line: i as u32 + 1,
            id,
            comment,
            at: FileSpan::new(file, Span::new(start as u32, (start + line_len) as u32)),
        });
    }
    out
}

/// Remove the findings of Checkov-sourced rules that a `checkov:skip` line
/// suppresses, and report them. `store` (the root's parsed modules) is
/// needed for skips in `module` blocks; without it (a plan scan) only skips
/// in the resource's own block apply.
pub fn checkov_skips(
    findings: Vec<Finding>,
    analysis: &Analysis,
    files: &FileTable,
    store: Option<&ModuleStore>,
) -> (Vec<Finding>, Vec<Suppressed>) {
    // A rule that aliases a Checkov rule is suppressed by its IDs too.
    let skippable = |f: &Finding| f.source.engine == Engine::Checkov || !f.aliases.is_empty();
    if !findings.iter().any(skippable) {
        return (findings, Vec::new());
    }
    let mut cache: HashMap<FileId, Vec<Skip>> = HashMap::new();
    let mut kept = Vec::new();
    let mut suppressed = Vec::new();
    for f in findings {
        let hit = match &f.subject {
            FindingSubject::Resource(id) if skippable(&f) => analysis
                .modules
                .iter()
                .flat_map(|m| &m.resources)
                .find(|r| r.id == *id)
                .and_then(|r| {
                    blocks(r, analysis, files, store)
                        .into_iter()
                        .find_map(|(file, first, last)| {
                            let skips = cache.entry(file).or_insert_with(|| skips(files, file));
                            skips
                                .iter()
                                .find(|s| {
                                    first < s.line
                                        && s.line < last
                                        && (*s.id == *f.rule
                                            || f.aliases.iter().any(|a| **a == *s.id))
                                })
                                .map(|s| (s.comment.clone(), s.at))
                        })
                }),
            _ => None,
        };
        match hit {
            Some((comment, at)) => suppressed.push(Suppressed {
                rule: f.rule.clone(),
                address: f.address.clone(),
                comment,
                at,
            }),
            None => kept.push(f),
        }
    }
    (kept, suppressed)
}

/// The blocks a skip for `r` may sit in, as (file, first line, last line):
/// the resource's own block, then each enclosing `module` call.
fn blocks(
    r: &Resource,
    analysis: &Analysis,
    files: &FileTable,
    store: Option<&ModuleStore>,
) -> Vec<(FileId, u32, u32)> {
    let line = |at: FileSpan| files.get(at.file).line_col(at.span.start).0;
    let mut out = vec![(
        r.span.file,
        line(r.span),
        line(FileSpan::new(
            r.body.span.file,
            Span::empty(r.body.span.span.end),
        )),
    )];
    let Some(store) = store else {
        return out;
    };
    let mut module = analysis.modules.iter().find(|m| m.address == r.module);
    while let Some(m) = module {
        let Some(parent) = m.parent.map(|p| &analysis.modules[p]) else {
            break;
        };
        // `module.a.module.b["k"]`: the call is `b` in the parent's directory.
        let name = m
            .address
            .rsplit("module.")
            .next()
            .map(|s| s.split(['[', '.']).next().unwrap_or(s))
            .unwrap_or_default();
        let def = store.module(files, &parent.dir);
        if let Some(call) = def.module_call(name).map(|i| &def.module_calls[i]) {
            let span = call.block.span;
            let at = |offset: u32| line(FileSpan::new(call.file, Span::empty(offset)));
            out.push((call.file, at(span.start), at(span.end.saturating_sub(1))));
        }
        module = Some(parent);
    }
    out
}

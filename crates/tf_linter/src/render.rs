//! Rendering findings: miette (text, with the provenance chain as labels
//! in the primary file and related diagnostics in other files) and JSON.

use std::fmt;
use std::sync::Arc;

use miette::{
    Diagnostic, GraphicalReportHandler, GraphicalTheme, LabeledSpan, NamedSource, SourceSpan,
};
use serde_json::Value as J;
use tf_semantic::FileTable;
use tf_span::FileSpan;

use crate::rule::{Certainty, Finding};
use crate::scan::ScanResult;

fn source(files: &FileTable, at: FileSpan) -> NamedSource<Arc<str>> {
    let f = files.get(at.file);
    // Share the file text instead of copying it per finding and per step.
    NamedSource::new(f.path.display().to_string(), files.display_text(f.id))
}

fn span(at: FileSpan) -> SourceSpan {
    (at.span.start as usize, at.span.len() as usize).into()
}

/// A finding as a miette diagnostic.
struct Report {
    code: String,
    message: String,
    severity: miette::Severity,
    src: NamedSource<Arc<str>>,
    labels: Vec<LabeledSpan>,
    help: Option<String>,
    related: Vec<Related>,
}

/// One provenance step in another file.
struct Related {
    message: String,
    src: NamedSource<Arc<str>>,
    label: LabeledSpan,
}

impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Report {}
impl Diagnostic for Report {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(&self.code))
    }
    fn severity(&self) -> Option<miette::Severity> {
        Some(self.severity)
    }
    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.help
            .as_ref()
            .map(|h| Box::new(h) as Box<dyn fmt::Display>)
    }
    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.src)
    }
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Some(Box::new(self.labels.iter().cloned()))
    }
    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        if self.related.is_empty() {
            None
        } else {
            Some(Box::new(self.related.iter().map(|r| r as &dyn Diagnostic)))
        }
    }
}

impl fmt::Debug for Related {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl fmt::Display for Related {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Related {}
impl Diagnostic for Related {
    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Advice)
    }
    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.src)
    }
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        Some(Box::new(std::iter::once(self.label.clone())))
    }
}

/// The `file:line:col` a rule-loading message starts with (1-based line
/// and character column), as every front-end writes them.
pub fn message_location(message: &str) -> Option<(std::path::PathBuf, u32, u32)> {
    let mut parts = message.splitn(4, ':');
    let (file, line, col) = (parts.next()?, parts.next()?, parts.next()?);
    let line: u32 = line.trim().parse().ok()?;
    let col: u32 = col.trim().parse().ok()?;
    (!file.is_empty() && line > 0 && col > 0).then(|| (file.into(), line, col))
}

/// The span a `file:line:col` names in `files` (loaded on demand): from
/// the column to the end of its line.
pub fn locate(files: &FileTable, file: &std::path::Path, line: u32, col: u32) -> Option<FileSpan> {
    let sf = files.load(file).ok()?;
    let text = &*sf.text;
    let start_of_line = text
        .split_inclusive('\n')
        .take(line as usize - 1)
        .map(str::len)
        .sum::<usize>();
    let line_text = text[start_of_line..].split('\n').next()?;
    let in_line = line_text
        .char_indices()
        .nth(col as usize - 1)
        .map_or(line_text.len(), |(i, _)| i);
    let start = start_of_line + in_line;
    let end = (start_of_line + line_text.len())
        .max(start + 1)
        .min(text.len());
    Some(FileSpan::new(
        sf.id,
        tf_span::Span::new(start as u32, end as u32),
    ))
}

/// A rule-loading error or warning for the terminal: each line that starts
/// with `file:line:col: ` becomes a miette report pointing into the rule
/// file; other lines (regorus's own snippets among them) pass through.
pub fn render_load_message(message: &str, severity: miette::Severity, color: bool) -> String {
    let files = FileTable::new();
    let mut out = String::new();
    for line in message.lines() {
        let located = message_location(line).and_then(|(file, l, c)| {
            let at = locate(&files, &file, l, c)?;
            let text = line.splitn(4, ':').nth(3).unwrap_or("").trim().to_string();
            Some((at, text))
        });
        match located {
            Some((at, text)) => {
                let report = Report {
                    code: "rule-load".into(),
                    message: text.clone(),
                    severity,
                    src: source(&files, at),
                    labels: vec![LabeledSpan::new_primary_with_span(Some(text), span(at))],
                    help: None,
                    related: Vec::new(),
                };
                let mut s = String::new();
                let theme = if color {
                    GraphicalTheme::unicode()
                } else {
                    GraphicalTheme::unicode_nocolor()
                };
                let _ = GraphicalReportHandler::new_themed(theme).render_report(&mut s, &report);
                out.push_str(&s);
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// `path:line` of a step, for the provenance summary.
pub fn location(files: &FileTable, at: FileSpan) -> String {
    let f = files.get(at.file);
    format!("{}:{}", f.path.display(), f.line(at.span.start))
}

fn report(files: &FileTable, f: &Finding) -> Report {
    let primary_file = f.primary.file;
    let mut labels = vec![LabeledSpan::new_primary_with_span(
        Some(f.message.clone()),
        span(f.primary),
    )];
    let mut related = Vec::new();
    let n = f.provenance.len();
    for (i, s) in f.provenance.iter().enumerate() {
        let text = format!("[{}/{n}] {}", i + 1, s.label);
        if s.at == f.primary {
            labels[0] = LabeledSpan::new_primary_with_span(
                Some(format!("{} {text}", f.message)),
                span(f.primary),
            );
        } else if s.at.file == primary_file {
            labels.push(LabeledSpan::new_with_span(Some(text), span(s.at)));
        } else {
            related.push(Related {
                message: format!("provenance step {}/{n}: {}", i + 1, s.label),
                src: source(files, s.at),
                label: LabeledSpan::new_with_span(Some(text), span(s.at)),
            });
        }
    }
    if let Some(package) = &f.package {
        for at in &package.calls {
            related.push(Related {
                message: "installed module called here (cache files are not auto-edited)".into(),
                src: source(files, *at),
                label: LabeledSpan::new_with_span(Some("module call".into()), span(*at)),
            });
        }
    }
    let mut help = Vec::new();
    if !f.provenance.is_empty() {
        help.push(format!(
            "provenance: {}",
            f.provenance
                .iter()
                .map(|s| format!("{} ({})", s.label, location(files, s.at)))
                .collect::<Vec<_>>()
                .join(" -> ")
        ));
    }
    if let Some(rationale) = &f.rationale {
        help.push(format!("severity ({}): {rationale}", f.level.as_str()));
    }
    if let Some(remediation) = &f.remediation {
        help.push(format!("remediation: {remediation}"));
    }
    if let Some(guideline) = &f.guideline {
        help.push(format!("guideline: {guideline}"));
    }
    Report {
        code: format!("{} [{}]", f.rule, f.certainty.as_str()),
        message: format!("{}: {}", f.address, f.message),
        severity: match f.certainty {
            Certainty::Definite => miette::Severity::Error,
            Certainty::Conditional => miette::Severity::Warning,
            Certainty::Indeterminate => miette::Severity::Advice,
        },
        src: source(files, f.primary),
        labels,
        help: (!help.is_empty()).then(|| help.join("\n")),
        related,
    }
}

/// Render one finding with miette's graphical handler.
pub fn render_finding(files: &FileTable, f: &Finding, color: bool) -> String {
    let theme = if color {
        GraphicalTheme::unicode()
    } else {
        GraphicalTheme::unicode_nocolor()
    };
    let handler = GraphicalReportHandler::new_themed(theme)
        .with_width(120)
        .with_context_lines(1);
    let mut out = String::new();
    let _ = handler.render_report(&mut out, &report(files, f));
    out
}

/// One finding as JSON: the finding record (`docs/FINDING_SCHEMA.md`).
pub fn finding_json(files: &FileTable, f: &Finding) -> J {
    serde_json::to_value(crate::record::finding_record(files, f)).expect("finding record is JSON")
}

/// The whole scan result as JSON.
pub fn result_json(r: &ScanResult) -> J {
    serde_json::to_value(crate::record::ScanRecord::from_result(r)).expect("scan record is JSON")
}

//! Rendering findings: miette (text, with the provenance chain as labels
//! in the primary file and related diagnostics in other files) and JSON.

use std::fmt;

use miette::{
    Diagnostic, GraphicalReportHandler, GraphicalTheme, LabeledSpan, NamedSource, SourceSpan,
};
use serde_json::{Value as J, json};
use tf_semantic::FileTable;
use tf_span::FileSpan;

use crate::rule::{Finding, Severity};
use crate::scan::ScanResult;

fn source(files: &FileTable, at: FileSpan) -> NamedSource<String> {
    let f = files.get(at.file);
    NamedSource::new(f.path.display().to_string(), f.text.to_string())
}

fn span(at: FileSpan) -> SourceSpan {
    (at.span.start as usize, at.span.len() as usize).into()
}

/// A finding as a miette diagnostic.
struct Report {
    code: String,
    message: String,
    severity: miette::Severity,
    src: NamedSource<String>,
    labels: Vec<LabeledSpan>,
    help: Option<String>,
    related: Vec<Related>,
}

/// One provenance step in another file.
struct Related {
    message: String,
    src: NamedSource<String>,
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
    let help = if f.provenance.is_empty() {
        None
    } else {
        Some(format!(
            "provenance: {}",
            f.provenance
                .iter()
                .map(|s| format!("{} ({})", s.label, location(files, s.at)))
                .collect::<Vec<_>>()
                .join(" -> ")
        ))
    };
    Report {
        code: format!("{} [{}]", f.rule, f.severity.as_str()),
        message: format!("{}: {}", f.address, f.message),
        severity: match f.severity {
            Severity::Definite => miette::Severity::Error,
            Severity::Conditional => miette::Severity::Warning,
        },
        src: source(files, f.primary),
        labels,
        help,
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

pub fn finding_json(files: &FileTable, f: &Finding) -> J {
    let loc = |at: FileSpan| {
        let sf = files.get(at.file);
        let (line, col) = sf.line_col(at.span.start);
        json!({ "file": sf.path.display().to_string(), "line": line, "column": col,
                "start": at.span.start, "end": at.span.end })
    };
    json!({
        "rule": &*f.rule,
        "level": f.level.as_str(),
        "severity": f.severity.as_str(),
        "address": &*f.address,
        "resource_type": &*f.resource_type,
        "module": &*f.module,
        "root": f.root.display().to_string(),
        "message": f.message,
        "location": loc(f.primary),
        "provenance": f.provenance.iter().map(|s| {
            let mut l = loc(s.at);
            l["kind"] = J::from(s.kind.as_str());
            l["label"] = J::from(&*s.label);
            l
        }).collect::<Vec<_>>(),
    })
}

/// The whole scan result as JSON.
pub fn result_json(r: &ScanResult) -> J {
    json!({
        "findings": r.findings.iter().map(|f| finding_json(&r.files, f)).collect::<Vec<_>>(),
        "diagnostics": r.diagnostics.iter().map(|d| json!({
            "severity": format!("{:?}", d.severity).to_lowercase(),
            "code": d.code,
            "message": d.message,
            "location": d.at.map(|a| location(&r.files, a)),
        })).collect::<Vec<_>>(),
        "stats": {
            "roots": r.stats.roots,
            "module_instances": r.stats.module_instances,
            "files": r.stats.files,
            "resources": r.stats.resources,
            "findings": r.stats.findings,
            "definite": r.stats.definite,
            "conditional": r.stats.conditional,
            "findings_by_rule": r.stats.findings_by_rule,
            "elapsed_ms": r.stats.elapsed.as_secs_f64() * 1000.0,
        }
    })
}

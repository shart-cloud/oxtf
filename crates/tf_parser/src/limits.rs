//! Temporary guards around recursive parsing and the existing AST visitors.
//! Explicit traversal stacks and configurable budgets are separate follow-up work.
use tf_allocator::Allocator;
use tf_ast::{Body, Expression, File, GetSpan, Span, Template, VisitMut, visit_mut};

use crate::{Diagnostic, DiagnosticKind, ParseLimit};

pub use tf_limits::AST_DEPTH_MAX;
pub use tf_limits::JSON_DEPTH_MAX;
/// Conservative defaults tested on a 2 MiB stack in debug and release.
pub use tf_limits::PARSE_DEPTH_MAX;
const _: () = assert!(JSON_DEPTH_MAX <= AST_DEPTH_MAX);

#[derive(Default)]
struct Depth {
    active: usize,
    exceeded: Option<Span>,
}

impl Depth {
    fn enter(&mut self, span: Span) -> bool {
        assert!(self.active <= AST_DEPTH_MAX);
        if self.exceeded.is_some() {
            return false;
        }
        if self.active == AST_DEPTH_MAX {
            self.exceeded = Some(span);
            return false;
        }
        self.active += 1;
        true
    }

    fn leave(&mut self) {
        assert!(self.active > 0);
        self.active -= 1;
    }
}

// VisitMut permits a short borrow of the arena tree. The check changes no nodes.
// These three entry points cut every recursive cycle in the AST schema.
impl<'a> VisitMut<'a> for Depth {
    fn visit_body(&mut self, body: &mut Body<'a>) {
        if self.enter(body.span) {
            visit_mut::walk_body_mut(self, body);
            self.leave();
        }
    }

    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        if self.enter(expression.span()) {
            visit_mut::walk_expression_mut(self, expression);
            self.leave();
        }
    }

    fn visit_template(&mut self, template: &mut Template<'a>) {
        if self.enter(template.span) {
            visit_mut::walk_template_mut(self, template);
            self.leave();
        }
    }
}

pub(crate) fn file_depth(file: &mut File<'_>) -> Option<Span> {
    let mut depth = Depth::default();
    depth.visit_file(file);
    assert_eq!(depth.active, 0);
    depth.exceeded
}

pub(crate) fn bounded_expression<'a>(
    _allocator: &'a Allocator,
    mut expression: Option<Expression<'a>>,
    mut errors: Vec<Diagnostic>,
) -> (Option<Expression<'a>>, Vec<Diagnostic>) {
    let mut depth = Depth::default();
    if let Some(expression) = &mut expression {
        depth.visit_expression(expression);
    }
    assert_eq!(depth.active, 0);
    if let Some(span) = depth.exceeded {
        errors.push(Diagnostic::limit(span, ParseLimit::AstDepth));
    }
    if errors
        .iter()
        .any(|e| matches!(e.kind, DiagnosticKind::Limit(_)))
    {
        expression = None;
    }
    (expression, errors)
}

/// Count container nesting before serde's recursive validation. Quoted brackets
/// and escaped quotes do not affect nesting. Grammar validation remains serde's job.
pub(crate) fn json_depth(source: &str) -> Option<Diagnostic> {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, byte) in source.bytes().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    if depth == JSON_DEPTH_MAX {
                        return Some(Diagnostic::limit(
                            Span::new(offset as u32, offset as u32 + 1),
                            ParseLimit::JsonDepth,
                        ));
                    }
                    depth += 1;
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    assert!(depth <= JSON_DEPTH_MAX);
    None
}

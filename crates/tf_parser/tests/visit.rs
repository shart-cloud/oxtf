//! Exercises the generated `Visit` / `VisitMut` / `AstKind` API the way the
//! semantic layer will.

use tf_ast::{AstKind, AstType, Expression, GetSpan, Visit, VisitMut};

const SRC: &str = r#"
variable "cidr" { default = "0.0.0.0/0" }
locals { open = var.cidr }
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = var.rules
    content {
      cidr_blocks = [local.open, "${var.extra}/32"]
      from_port   = ingress.value.port
    }
  }
}
"#;

/// Collect every reference root + attribute path, e.g. `var.cidr`.
#[derive(Default)]
struct Refs(Vec<String>);

impl<'a> Visit<'a> for Refs {
    fn visit_expression(&mut self, it: &'a Expression<'a>) {
        if let Some((root, ops)) = it.as_reference() {
            let mut s = root.to_string();
            for op in ops {
                if let Some(a) = op.attr_name() {
                    s.push('.');
                    s.push_str(a);
                }
            }
            self.0.push(s);
            return; // do not descend into the traversal's own root
        }
        tf_ast::visit::walk_expression(self, it);
    }
}

#[test]
fn visit_collects_references() {
    let alloc = tf_allocator::Allocator::new();
    let ret = tf_parser::parse(&alloc, SRC);
    assert!(ret.errors.is_empty());
    let file = alloc.alloc(ret.file);
    let mut refs = Refs::default();
    refs.visit_file(file);
    assert_eq!(
        refs.0,
        [
            "var.cidr",
            "var.rules",
            "local.open",
            "var.extra",
            "ingress.value.port"
        ]
    );
}

#[test]
fn ast_kind_enter_leave_balanced_and_spans_nested() {
    struct Check<'a> {
        stack: Vec<AstKind<'a>>,
        count: usize,
    }
    impl<'a> Visit<'a> for Check<'a> {
        fn enter_node(&mut self, kind: AstKind<'a>) {
            if let Some(parent) = self.stack.last() {
                let (p, c) = (parent.span(), kind.span());
                assert!(
                    p.start <= c.start && c.end <= p.end,
                    "{:?} {p:?} does not contain {:?} {c:?}",
                    parent.ty(),
                    kind.ty()
                );
            }
            self.stack.push(kind);
            self.count += 1;
        }
        fn leave_node(&mut self, kind: AstKind<'a>) {
            assert_eq!(self.stack.pop().unwrap().ty(), kind.ty());
        }
    }
    let alloc = tf_allocator::Allocator::new();
    let ret = tf_parser::parse(&alloc, SRC);
    let file = alloc.alloc(ret.file);
    let mut c = Check {
        stack: vec![],
        count: 0,
    };
    c.visit_file(file);
    assert!(c.stack.is_empty());
    assert!(c.count > 40, "{}", c.count);
}

#[test]
fn visit_mut_renames_and_body_helpers() {
    struct Rename;
    impl<'a> VisitMut<'a> for Rename {
        fn enter_node(&mut self, ty: AstType) {
            let _ = ty;
        }
        fn visit_variable_expr(&mut self, it: &mut tf_ast::VariableExpr<'a>) {
            if it.name == "var" {
                it.name = "input".into();
            }
        }
    }
    let alloc = tf_allocator::Allocator::new();
    let mut ret = tf_parser::parse(&alloc, SRC);
    Rename.visit_file(&mut ret.file);
    let locals = ret.file.body.find_block("locals").unwrap();
    let open = locals.body.find_attribute("open").unwrap();
    assert_eq!(open.value.as_reference().unwrap().0, "input");
    let sg = ret.file.body.blocks_of_type("resource").next().unwrap();
    assert_eq!(
        (sg.label(0), sg.label(1)),
        (Some("aws_security_group"), Some("sg"))
    );
    let dynamic = sg.body.find_block("dynamic").unwrap();
    assert_eq!(dynamic.label(0), Some("ingress"));
}

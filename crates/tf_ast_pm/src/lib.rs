//! PROTOTYPE (open question 2): the same `ast.rs` as `tf_ast`, with
//! visitors produced by the `tf_ast_macros` proc macro at compile time
//! instead of committed generated files.
#[path = "../../tf_ast/src/ast.rs"]
pub mod ast;

pub mod generated {
    tf_ast_macros::generate_visitors!("../tf_ast/src/ast.rs");
}

pub use generated::ast_kind::{AstKind, AstType};
pub use generated::visit::Visit;
pub use generated::visit_mut::VisitMut;

#[cfg(test)]
mod tests {
    #[test]
    fn expression_is_16_bytes() {
        assert_eq!(std::mem::size_of::<crate::ast::Expression<'_>>(), 16);
    }
}

//! PROTOTYPE (open question 2). `generate_visitors!("path/to/ast.rs")` reads
//! the AST source at compile time (path relative to the calling crate's
//! manifest dir) and expands to the same modules `tf_ast_codegen` writes to
//! disk. Same generator code, different delivery mechanism.
use proc_macro::TokenStream;
use quote::{format_ident, quote};

#[proc_macro]
pub fn generate_visitors(input: TokenStream) -> TokenStream {
    let lit = syn::parse_macro_input!(input as syn::LitStr);
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let path = std::path::Path::new(&dir).join(lit.value());
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let path_str = path.to_string_lossy().to_string();
    let mods = tf_ast_codegen::generate_tokens(&src).into_iter().map(|(name, tokens)| {
        let m = format_ident!("{}", name);
        quote!(pub mod #m { #tokens })
    });
    quote! {
        // Makes cargo rebuild when ast.rs changes.
        const _: &[u8] = include_bytes!(#path_str);
        #(#mods)*
    }
    .into()
}

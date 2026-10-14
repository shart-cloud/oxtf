//! Code generator for `tf_ast`'s visitors, modelled on oxc's `oxc_ast_tools`.
//!
//! Reads `crates/tf_ast/src/ast.rs` with `syn`, classifies every type
//! (node struct / dispatch enum / leaf, see the conventions in that file) and
//! emits four modules:
//!
//! - `ast_kind`: `AstKind<'a>` (one variant per node struct, holding `&'a T`)
//!   and the fieldless `AstType`;
//! - `visit`: the `Visit<'a>` trait plus `walk_*` functions;
//! - `visit_mut`: the `VisitMut<'a>` trait plus `walk_*_mut` functions;
//! - `get_span`: `GetSpan` impls for all nodes and dispatch enums.
//!
//! The same token streams are used by the `tf_ast_macros` proc-macro
//! prototype, which exists only to measure open question 2.

use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
enum FieldTy {
    /// A visitable node type or dispatch enum, stored inline or boxed.
    Node(String),
    Vec(std::boxed::Box<FieldTy>),
    Option(std::boxed::Box<FieldTy>),
    Leaf,
}

impl FieldTy {
    fn is_leaf(&self) -> bool {
        match self {
            FieldTy::Leaf => true,
            FieldTy::Node(_) => false,
            FieldTy::Vec(t) | FieldTy::Option(t) => t.is_leaf(),
        }
    }
}

#[derive(Debug)]
struct StructDef {
    name: String,
    has_lifetime: bool,
    fields: Vec<(String, FieldTy)>,
}

#[derive(Debug)]
struct EnumDef {
    name: String,
    has_lifetime: bool,
    variants: Vec<(String, FieldTy)>,
}

#[derive(Debug, Default)]
struct Schema {
    structs: Vec<StructDef>,
    enums: Vec<EnumDef>,
}

fn has_lifetime(g: &syn::Generics) -> bool {
    g.lifetimes().next().is_some()
}

fn classify(ty: &syn::Type, visitable: &BTreeSet<String>) -> FieldTy {
    let syn::Type::Path(p) = ty else { return FieldTy::Leaf };
    let Some(seg) = p.path.segments.last() else { return FieldTy::Leaf };
    let name = seg.ident.to_string();
    let first_type_arg = || -> Option<&syn::Type> {
        if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
            args.args.iter().find_map(|a| match a {
                syn::GenericArgument::Type(t) => Some(t),
                _ => None,
            })
        } else {
            None
        }
    };
    match name.as_str() {
        "Box" => first_type_arg().map_or(FieldTy::Leaf, |t| classify(t, visitable)),
        "Vec" => FieldTy::Vec(std::boxed::Box::new(
            first_type_arg().map_or(FieldTy::Leaf, |t| classify(t, visitable)),
        )),
        "Option" => FieldTy::Option(std::boxed::Box::new(
            first_type_arg().map_or(FieldTy::Leaf, |t| classify(t, visitable)),
        )),
        _ if visitable.contains(&name) => FieldTy::Node(name),
        _ => FieldTy::Leaf,
    }
}

fn parse_schema(src: &str) -> Schema {
    let file = syn::parse_file(src).expect("ast.rs must parse");
    // Pass 1: which type names are visitable.
    let mut visitable = BTreeSet::new();
    for item in &file.items {
        match item {
            syn::Item::Struct(s) => {
                let has_span = s.fields.iter().any(|f| f.ident.as_ref().is_some_and(|i| i == "span"));
                if has_span {
                    visitable.insert(s.ident.to_string());
                }
            }
            syn::Item::Enum(e) => {
                if e.variants.iter().any(|v| !v.fields.is_empty()) {
                    visitable.insert(e.ident.to_string());
                }
            }
            _ => {}
        }
    }
    // Pass 2: fields.
    let mut schema = Schema::default();
    for item in &file.items {
        match item {
            syn::Item::Struct(s) if visitable.contains(&s.ident.to_string()) => {
                let fields = s
                    .fields
                    .iter()
                    .map(|f| {
                        let name = f.ident.as_ref().unwrap().to_string();
                        (name, classify(&f.ty, &visitable))
                    })
                    .collect();
                schema.structs.push(StructDef {
                    name: s.ident.to_string(),
                    has_lifetime: has_lifetime(&s.generics),
                    fields,
                });
            }
            syn::Item::Enum(e) if visitable.contains(&e.ident.to_string()) => {
                let variants = e
                    .variants
                    .iter()
                    .map(|v| {
                        let f = v.fields.iter().next().expect("dispatch enum variants hold one field");
                        assert_eq!(v.fields.len(), 1, "dispatch enum variants hold exactly one field");
                        (v.ident.to_string(), classify(&f.ty, &visitable))
                    })
                    .collect();
                schema.enums.push(EnumDef {
                    name: e.ident.to_string(),
                    has_lifetime: has_lifetime(&e.generics),
                    variants,
                });
            }
            _ => {}
        }
    }
    schema
}

fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn ident(s: &str) -> Ident {
    Ident::new(s, Span::call_site())
}

impl Schema {
    fn lt_of(&self, name: &str) -> bool {
        self.structs.iter().find(|s| s.name == name).map(|s| s.has_lifetime).or_else(|| {
            self.enums.iter().find(|e| e.name == name).map(|e| e.has_lifetime)
        })
        .unwrap_or(false)
    }

    fn ty_tokens(&self, name: &str) -> TokenStream {
        let id = ident(name);
        if self.lt_of(name) { quote!(#id<'a>) } else { quote!(#id) }
    }
}

/// Code that visits the value referenced by `expr` (an expression of
/// reference type) of type `ty`.
fn visit_code(expr: TokenStream, ty: &FieldTy, mutable: bool) -> TokenStream {
    match ty {
        FieldTy::Leaf => quote!(),
        FieldTy::Node(name) => {
            let m = format_ident!("visit_{}", snake(name));
            quote!(visitor.#m(#expr);)
        }
        FieldTy::Vec(inner) => {
            let body = visit_code(quote!(el), inner, mutable);
            if mutable {
                quote!(for el in (#expr).iter_mut() { #body })
            } else {
                quote!(for el in (#expr).iter() { #body })
            }
        }
        FieldTy::Option(inner) => {
            let body = visit_code(quote!(el), inner, mutable);
            quote!(if let Some(el) = #expr { #body })
        }
    }
}

fn gen_ast_kind(s: &Schema) -> TokenStream {
    let mut variants = Vec::new();
    let mut ty_variants = Vec::new();
    let mut ty_arms = Vec::new();
    let mut span_arms = Vec::new();
    let mut as_fns = Vec::new();
    for st in &s.structs {
        let v = ident(&st.name);
        let ty = s.ty_tokens(&st.name);
        variants.push(quote!(#v(&'a #ty)));
        ty_variants.push(quote!(#v));
        ty_arms.push(quote!(Self::#v(_) => AstType::#v));
        span_arms.push(quote!(Self::#v(it) => it.span));
        let f = format_ident!("as_{}", snake(&st.name));
        as_fns.push(quote! {
            #[inline]
            pub fn #f(self) -> Option<&'a #ty> {
                if let Self::#v(it) = self { Some(it) } else { None }
            }
        });
    }
    quote! {
        use crate::ast::*;
        use tf_span::{GetSpan, Span};

        /// A reference to any AST node, as handed to `Visit::enter_node`.
        #[derive(Debug, Clone, Copy)]
        pub enum AstKind<'a> { #(#variants,)* }

        /// The node type of an [`AstKind`], without the reference.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum AstType { #(#ty_variants,)* }

        impl<'a> AstKind<'a> {
            #[inline]
            pub fn ty(self) -> AstType { match self { #(#ty_arms,)* } }
            #(#as_fns)*
        }

        impl GetSpan for AstKind<'_> {
            #[inline]
            fn span(&self) -> Span { match self { #(#span_arms,)* } }
        }
    }
}

fn gen_visit(s: &Schema, mutable: bool) -> TokenStream {
    let mut methods = Vec::new();
    let mut walks = Vec::new();
    let (trait_name, suffix) = if mutable { (ident("VisitMut"), "_mut") } else { (ident("Visit"), "") };
    let refty = |ty: &TokenStream| if mutable { quote!(&mut #ty) } else { quote!(&'a #ty) };

    for st in &s.structs {
        let sn = snake(&st.name);
        let m = format_ident!("visit_{}", sn);
        let w = format_ident!("walk_{}{}", sn, suffix);
        let ty = s.ty_tokens(&st.name);
        let r = refty(&ty);
        let v = ident(&st.name);
        methods.push(quote! {
            #[inline]
            fn #m(&mut self, it: #r) { #w(self, it); }
        });
        let fields: Vec<_> = st
            .fields
            .iter()
            .filter(|(_, t)| !t.is_leaf())
            .map(|(f, t)| {
                let fi = ident(f);
                let e = if mutable { quote!(&mut it.#fi) } else { quote!(&it.#fi) };
                visit_code(e, t, mutable)
            })
            .collect();
        let (enter, leave) = if mutable {
            (quote!(visitor.enter_node(AstType::#v);), quote!(visitor.leave_node(AstType::#v);))
        } else {
            (
                quote!(let kind = AstKind::#v(it); visitor.enter_node(kind);),
                quote!(visitor.leave_node(kind);),
            )
        };
        let unused = if fields.is_empty() && mutable { quote!(let _ = it;) } else { quote!() };
        walks.push(quote! {
            #[inline]
            pub fn #w<'a, V: #trait_name<'a>>(visitor: &mut V, it: #r) {
                #enter
                #unused
                #(#fields)*
                #leave
            }
        });
    }
    for en in &s.enums {
        let sn = snake(&en.name);
        let m = format_ident!("visit_{}", sn);
        let w = format_ident!("walk_{}{}", sn, suffix);
        let ty = s.ty_tokens(&en.name);
        let r = refty(&ty);
        let e = ident(&en.name);
        methods.push(quote! {
            #[inline]
            fn #m(&mut self, it: #r) { #w(self, it); }
        });
        let arms = en.variants.iter().map(|(vn, t)| {
            let v = ident(vn);
            let code = visit_code(quote!(inner), t, mutable);
            quote!(#e::#v(inner) => { #code })
        });
        walks.push(quote! {
            #[inline]
            pub fn #w<'a, V: #trait_name<'a>>(visitor: &mut V, it: #r) {
                match it { #(#arms)* }
            }
        });
    }

    let (hooks, kind_import) = if mutable {
        (
            quote! {
                #[inline]
                fn enter_node(&mut self, ty: AstType) { let _ = ty; }
                #[inline]
                fn leave_node(&mut self, ty: AstType) { let _ = ty; }
            },
            quote!(use crate::generated::ast_kind::AstType;),
        )
    } else {
        (
            quote! {
                #[inline]
                fn enter_node(&mut self, kind: AstKind<'a>) { let _ = kind; }
                #[inline]
                fn leave_node(&mut self, kind: AstKind<'a>) { let _ = kind; }
            },
            quote!(use crate::generated::ast_kind::AstKind;),
        )
    };
    let walk_mod = if mutable { ident("walk_mut") } else { ident("walk") };
    quote! {
        #![allow(unused_variables, clippy::needless_lifetimes)]
        use crate::ast::*;
        #kind_import
        pub use #walk_mod::*;

        pub trait #trait_name<'a>: Sized {
            #hooks
            #(#methods)*
        }

        pub mod #walk_mod {
            use super::*;
            #(#walks)*
        }
    }
}

fn gen_get_span(s: &Schema) -> TokenStream {
    let mut impls = Vec::new();
    for st in &s.structs {
        let ty = s.ty_tokens(&st.name);
        let generics = if st.has_lifetime { quote!(<'a>) } else { quote!() };
        impls.push(quote! {
            impl #generics GetSpan for #ty {
                #[inline]
                fn span(&self) -> Span { self.span }
            }
        });
    }
    for en in &s.enums {
        let ty = s.ty_tokens(&en.name);
        let e = ident(&en.name);
        let generics = if en.has_lifetime { quote!(<'a>) } else { quote!() };
        let arms = en.variants.iter().map(|(vn, _)| {
            let v = ident(vn);
            quote!(#e::#v(it) => it.span())
        });
        impls.push(quote! {
            impl #generics GetSpan for #ty {
                #[inline]
                fn span(&self) -> Span { match self { #(#arms,)* } }
            }
        });
    }
    quote! {
        use crate::ast::*;
        use tf_span::{GetSpan, Span};
        #(#impls)*
    }
}

/// `(module name, tokens)` for each generated module.
pub fn generate_tokens(ast_src: &str) -> Vec<(&'static str, TokenStream)> {
    let schema = parse_schema(ast_src);
    vec![
        ("ast_kind", gen_ast_kind(&schema)),
        ("visit", gen_visit(&schema, false)),
        ("visit_mut", gen_visit(&schema, true)),
        ("get_span", gen_get_span(&schema)),
    ]
}

pub const HEADER: &str = "// Auto-generated by `cargo run -p tf_ast_codegen`. Do not edit.\n// Source: crates/tf_ast/src/ast.rs\n\n";

/// `(file name, formatted source)` for each generated module.
pub fn generate_files(ast_src: &str) -> Vec<(String, String)> {
    generate_tokens(ast_src)
        .into_iter()
        .map(|(name, tokens)| {
            let file: syn::File = syn::parse2(tokens).expect("generated code must parse");
            (format!("{name}.rs"), format!("{HEADER}{}", prettyplease::unparse(&file)))
        })
        .collect()
}

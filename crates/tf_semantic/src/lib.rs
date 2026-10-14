//! Terraform semantic layer: module assembly, symbol table and reference
//! graph, and schema-aware abstract evaluation into an owned resource model.
//!
//! ```no_run
//! use tf_semantic::{analyze_module, AnalyzeOptions, FileTable};
//! let files = FileTable::new();
//! let a = analyze_module("fixtures/x".as_ref(), &AnalyzeOptions::default(), &files);
//! for m in &a.modules {
//!     for r in &m.resources {
//!         println!("{} {:?}", r.address, r.value("cidr_blocks"));
//!     }
//! }
//! ```

pub mod analyze;
pub mod model;
pub mod module;
pub mod references;
pub mod source;

pub use analyze::{AnalyzeOptions, ObservedAttr, analyze_module, analyze_module_observed};
pub use model::{
    Analysis, Attr, Block, Body, DiagSeverity, Diagnostic, Mode, Module, Resource, SymbolRef,
};
pub use source::{FileTable, SourceFile};

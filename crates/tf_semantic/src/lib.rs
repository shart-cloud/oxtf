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

pub mod address;
pub mod analyze;
pub mod compose;
mod default_budget;
mod file_functions;
pub mod graph;
mod input_conversion;
pub mod installed;
mod json_config;
pub mod model;
mod model_budget;
pub mod module;
pub mod references;
pub mod source;
pub mod store;
mod variable_defaults;

pub use address::{Address, AddressError, InstanceKey};
pub use analyze::{
    AnalyzeOptions, ObservedAttr, analyze_module, analyze_module_observed, analyze_module_shared,
};
pub use model::{
    Analysis, Attr, Block, Body, DiagSeverity, Diagnostic, Mode, Module, Resource, SymbolRef,
};
pub use source::{FileTable, SourceFile};
pub use store::ModuleStore;

#[cfg(test)]
mod test_allocations;

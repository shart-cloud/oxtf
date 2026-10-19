//! YAML documents as the policy tools that wrote them read them. YAML 1.1
//! has more than one reading, and a policy's meaning can turn on which:
//! `on` is a boolean to PyYAML and go-yaml alike, but `y` only to go-yaml,
//! and `1e3` is a string to one and a number to the other.
//!
//! - [`pyyaml`]: PyYAML `safe_load` then a JSON round trip, as Checkov
//!   loads its policies.
//! - [`goyaml`]: go-yaml v2 into `interface{}` then sigs.k8s.io/yaml, as
//!   OPA and Conftest load data documents and metadata.

pub mod goyaml;
pub mod pyyaml;

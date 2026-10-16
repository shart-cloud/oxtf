//! Rego policies on regorus, in two tiers over one principle: **Rego never
//! sees an abstract value**, so it can never mishandle one. Certainty is
//! always decided on the Rust side.
//!
//! - **Foreign policies** (`policy` files people already have, written for
//!   Conftest, OPA or KICS): each resource instance is projected into the
//!   input shape the policy expects, Known values only
//!   ([`projection`]), and the policy runs unchanged. A violation is
//!   Definite when nothing was hidden from the policy, Conditional when a
//!   hidden value traces to an unconstrained variable, Indeterminate when
//!   hidden values are provider-computed.
//! - **Native-tier policies** (the bundled seed rules): the policy declares
//!   one `subject` read; the adapter evaluates it with the lattice and calls
//!   the policy's `violates` rule once per Known leaf, so the verdict and
//!   witness are exactly the native rule's.
//!
//! Policy errors never become passes: a policy that fails to compile
//! refuses the scan up front ([`catalog`] returns `Err`), and a runtime
//! failure on a resource is returned from the rule hook, so the engine
//! records it as a rule error on the scan.

pub mod foreign;
pub mod projection;

use std::cell::RefCell;
use std::fmt;
use std::path::PathBuf;

use serde_json::{Value as Json, json};
use tf_eval::value::to_json;
use tf_eval::{Truth, Value, Verdict, truth};
use tf_linter::rule::{DynRule, Judgement, Rule, RuleFailure, RuleInfo};
use tf_linter::rules::{AwsRdsUnencrypted, GcpStorageUniformAccess};
use tf_semantic::{Module, Resource};

pub use projection::Shape;

/// Which policies a scan runs.
#[derive(Clone, Debug, Default)]
pub struct Policies {
    /// Run the bundled native-tier policies for `aws-rds-unencrypted` and
    /// `gcp-storage-uniform-access`. The rules [`catalog`] returns carry
    /// those names, so a catalog that shadows by name replaces the seed
    /// rules with them.
    pub native: bool,
    /// Foreign policy files and directories, loaded as one bundle and run
    /// unchanged ([`foreign`]).
    pub foreign: Vec<PathBuf>,
    pub shape: Option<Shape>,
    /// Entry rules the foreign policies' violations are read from, one
    /// oxtf rule each ([`foreign::DEFAULT_ENTRY`] when empty).
    pub entries: Vec<String>,
    /// Parse foreign policies as Rego v0 (`opa eval --v0-compatible`).
    pub rego_v0: bool,
}

impl Policies {
    pub fn is_empty(&self) -> bool {
        !self.native && self.foreign.is_empty()
    }
}

/// A policy that could not be loaded or compiled, or whose declared
/// interface is wrong. Refuses the scan before it starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PolicyError {}

impl From<String> for PolicyError {
    fn from(s: String) -> Self {
        PolicyError(s)
    }
}

/// The rules the policies contribute: native-tier rules named after the
/// seed rules they stand in for, then one rule per foreign entry rule.
/// Every policy is compiled and its interface checked here.
pub fn catalog(policies: &Policies) -> Result<Vec<Box<dyn DynRule>>, PolicyError> {
    let mut rules: Vec<Box<dyn DynRule>> = Vec::new();
    if policies.native {
        for seed in [Seed::Rds, Seed::GcpStorage] {
            rules.push(Box::new(NativePolicy::prepare(seed)?));
        }
    }
    if !policies.foreign.is_empty() {
        rules.extend(foreign::rules(&foreign::Options {
            paths: &policies.foreign,
            entries: &policies.entries,
            shape: policies.shape.unwrap_or(Shape::Plan),
            rego_v0: policies.rego_v0,
        })?);
    }
    Ok(rules)
}

fn engine_with(name: &str, source: &str) -> Result<regorus::Engine, String> {
    let mut engine = regorus::Engine::new();
    engine.set_strict_builtin_errors(true);
    engine
        .add_policy(format!("{name}.rego"), source.to_string())
        .map_err(|e| format!("policy {name}: {e}"))?;
    // Prepare (schedule, hoist, gather rules) once here. A clone of a
    // prepared engine stays prepared, so the per-resource clones in `eval`
    // only pay for the evaluation; an unprepared engine would redo this
    // work for every resource.
    engine
        .eval_query("true".to_string(), false)
        .map_err(|e| format!("policy {name}: {e}"))?;
    Ok(engine)
}

use foreign::eval;

fn eval_bool(engine: &regorus::Engine, input: Json, rule: &str) -> Result<bool, String> {
    match eval(engine, input, rule)? {
        regorus::Value::Undefined => Ok(false),
        v => v
            .as_bool()
            .copied()
            .map_err(|_| format!("{rule} must be a boolean, got {v}")),
    }
}

// ---------------------------------------------------------------------------
// Native tier
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Seed {
    Rds,
    GcpStorage,
}

impl Seed {
    fn info(self) -> RuleInfo {
        match self {
            Seed::Rds => AwsRdsUnencrypted.info(),
            Seed::GcpStorage => GcpStorageUniformAccess.info(),
        }
    }
    fn message(self, r: &Resource, v: &Verdict) -> String {
        match self {
            Seed::Rds => AwsRdsUnencrypted.message(r, v),
            Seed::GcpStorage => GcpStorageUniformAccess.message(r, v),
        }
    }
    fn fix_hint(self, r: &Resource, v: &Verdict) -> Option<tf_linter::FixHint> {
        match self {
            Seed::Rds => AwsRdsUnencrypted.fix_hint(r, v),
            Seed::GcpStorage => GcpStorageUniformAccess.fix_hint(r, v),
        }
    }
    fn source(self) -> (&'static str, &'static str) {
        match self {
            Seed::Rds => ("oxtf.rds", include_str!("rds.rego")),
            Seed::GcpStorage => ("oxtf.gcp_storage", include_str!("gcp_storage.rego")),
        }
    }
}

/// The one lattice read a native-tier policy declares.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Subject {
    attribute: String,
    effective: bool,
}

struct NativePolicy {
    seed: Seed,
    info: RuleInfo,
    engine: regorus::Engine,
    package: &'static str,
    subject: Subject,
}

impl NativePolicy {
    fn prepare(seed: Seed) -> Result<Self, String> {
        let (package, source) = seed.source();
        Self::compile(seed, package, source)
    }

    fn compile(seed: Seed, package: &'static str, source: &str) -> Result<Self, String> {
        let engine = engine_with(package, source)?;
        let probe = json!({"configured": {}, "subject": {"value": null, "boolean": null, "number": null, "text": null}});
        let declared = eval(&engine, probe.clone(), &format!("data.{package}.subject"))?;
        let declared: Json =
            serde_json::from_str(&declared.to_json_str().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let attribute = declared["attribute"]
            .as_str()
            .ok_or_else(|| format!("policy {package}: subject.attribute must be a string"))?
            .to_string();
        let effective = match declared["mode"].as_str() {
            Some("effective") => true,
            Some("configured") => false,
            _ => {
                return Err(format!(
                    "policy {package}: subject.mode must be \"effective\" or \"configured\""
                ));
            }
        };
        // Both decision rules must exist and be boolean before any scan runs.
        eval_bool(&engine, probe.clone(), &format!("data.{package}.skip"))?;
        eval_bool(&engine, probe, &format!("data.{package}.violates"))?;
        Ok(NativePolicy {
            seed,
            info: seed.info(),
            engine,
            package,
            subject: Subject {
                attribute,
                effective,
            },
        })
    }

    /// `input.configured`: presence and Known value of each configured attribute.
    fn configured(r: &Resource) -> Json {
        let mut m = serde_json::Map::new();
        for a in &r.body.attrs {
            let mut entry = json!({"set": !a.value.is_null()});
            if let Some(j) = to_json(&a.value) {
                entry["value"] = j;
            }
            m.insert(a.name.to_string(), entry);
        }
        Json::Object(m)
    }

    /// The native verdict: the subject read lifted through the lattice, with
    /// the policy consulted on Known leaves only.
    fn verdict(&self, r: &Resource) -> Result<Option<Verdict>, String> {
        let configured = Self::configured(r);
        let input = json!({"configured": configured});
        if eval_bool(&self.engine, input, &format!("data.{}.skip", self.package))? {
            return Ok(None);
        }
        let value = if self.subject.effective {
            r.value_or_default(&self.subject.attribute)
        } else {
            r.value(&self.subject.attribute)
        };
        let Some(value) = value else {
            return Ok(None);
        };
        self.lift(&value, &configured).map(Some)
    }

    fn lift(&self, value: &Value, configured: &Json) -> Result<Verdict, String> {
        let error = RefCell::new(None);
        let rule = format!("data.{}.violates", self.package);
        let verdict = truth::test_with(value, &|known| {
            if error.borrow().is_some() {
                return Truth::Unknown;
            }
            // `value` is the Known part of the leaf; a policy decides from the
            // typed views, exactly as the native rule decides on the shape.
            let input = json!({
                "configured": configured,
                "subject": {
                    "value": projection::known_part(known),
                    "boolean": known.as_bool(),
                    "number": known.as_number(),
                    "text": known.to_str(),
                },
            });
            match eval_bool(&self.engine, input, &rule) {
                Ok(b) => Truth::from_bool(b),
                Err(e) => {
                    *error.borrow_mut() = Some(e);
                    Truth::Unknown
                }
            }
        });
        match error.into_inner() {
            Some(e) => Err(e),
            None => Ok(verdict),
        }
    }
}

impl DynRule for NativePolicy {
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn judge_resource(&self, r: &Resource) -> Result<Vec<Judgement>, RuleFailure> {
        Ok(self
            .verdict(r)?
            .and_then(|v| {
                let fix_hint = self.seed.fix_hint(r, &v);
                Judgement::from_verdict(v, |v| self.seed.message(r, v))
                    .map(|j| Judgement { fix_hint, ..j })
            })
            .into_iter()
            .collect())
    }
    fn judge_module<'m>(
        &self,
        _m: &'m Module,
    ) -> Result<Vec<(&'m Resource, Judgement)>, RuleFailure> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rds() -> NativePolicy {
        NativePolicy::prepare(Seed::Rds).unwrap()
    }

    #[test]
    fn native_tier_verdict_and_witness_equal_the_lattice() {
        let scalars = vec![
            Value::null(),
            Value::bool(true),
            Value::bool(false),
            Value::string("true"),
            Value::string("false"),
            Value::number(1.0),
            Value::list(vec![Value::tainted("child")]),
            Value::other("computed"),
            Value::tainted("input"),
        ];
        let mut values = scalars.clone();
        values.push(Value::one_of(vec![], false));
        for a in &scalars {
            for b in &scalars {
                for tainted in [false, true] {
                    values.push(Value::one_of(vec![a.clone(), b.clone()], tainted));
                }
            }
        }
        let policy = rds();
        for value in &values {
            let actual = policy.lift(value, &json!({})).unwrap();
            let expected = truth::test(value, &|v| v.as_bool() != Some(true));
            assert_eq!(actual.truth, expected.truth, "{value:?}");
            assert_eq!(
                format!("{:?}", actual.witness),
                format!("{:?}", expected.witness),
                "{value:?}"
            );
        }
    }

    #[test]
    fn native_tier_policies_are_validated_up_front() {
        let compile = |src: &str| NativePolicy::compile(Seed::Rds, "oxtf.rds", src);
        assert!(compile("this isn't rego").is_err());
        assert!(
            compile("package oxtf.rds\nviolates := true").is_err(),
            "no subject"
        );
        assert!(
            compile("package oxtf.rds\nsubject := {\"attribute\": \"x\", \"mode\": \"sometimes\"}\ndefault skip := false\nviolates := true").is_err(),
            "bad mode"
        );
        assert!(
            compile("package oxtf.rds\nsubject := {\"attribute\": \"x\", \"mode\": \"effective\"}\ndefault skip := false\nviolates := 3").is_err(),
            "non-boolean violates"
        );
        assert!(
            compile("package oxtf.rds\nsubject := {\"attribute\": \"x\", \"mode\": \"effective\"}\ndefault skip := false\nviolates := true").is_ok()
        );
    }

    #[test]
    fn runtime_failure_is_a_rule_error_on_the_resource() {
        let source = r#"package oxtf.rds
import rego.v1
subject := {"attribute": "storage_encrypted", "mode": "effective"}
default skip := false
violates if { input.subject.boolean == false; 1 / 0 == 0 }
"#;
        let roots = [std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/rules/aws-rds-unencrypted/fail_explicit_false")];
        let scan = |rules| {
            tf_linter::scan_with(
                &tf_linter::Linter::new(rules),
                &roots,
                &tf_linter::ScanOptions::default(),
            )
            .0
        };
        let bad = NativePolicy::compile(Seed::Rds, "oxtf.rds", source).unwrap();
        let result = scan(vec![Box::new(bad) as Box<dyn DynRule>]);
        assert!(result.findings.is_empty());
        assert_eq!(result.rule_errors.len(), 1);
        let e = &result.rule_errors[0];
        assert_eq!(e.rule, "aws-rds-unencrypted");
        assert!(
            e.resource
                .as_deref()
                .unwrap()
                .starts_with("aws_db_instance."),
            "{e:?}"
        );
        assert!(e.message.contains("divide"), "{e:?}");
        let good = catalog(&Policies {
            native: true,
            ..Default::default()
        })
        .unwrap();
        let result = scan(good);
        assert_eq!(result.findings.len(), 1);
        assert!(result.rule_errors.is_empty());
    }
}

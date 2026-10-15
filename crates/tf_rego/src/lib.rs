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
//! refuses the scan up front, and a runtime failure on any resource fails
//! the whole scan.

pub mod projection;

use std::cell::RefCell;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{Value as Json, json};
use tf_eval::value::to_json;
use tf_eval::{Truth, Value, Verdict, truth};
use tf_linter::rule::{DynRule, Hidden, Judgement, Rule, RuleInfo};
use tf_linter::rules::{AwsRdsUnencrypted, GcpStorageUniformAccess};
use tf_linter::{Category, Level, Severity};
use tf_semantic::{Module, Resource};

pub use projection::Shape;

/// A policy file as loaded: its display name (file stem) and Rego source.
#[derive(Clone, Debug)]
pub struct PolicyFile {
    pub name: String,
    pub source: String,
}

pub fn load_policy(path: &Path) -> Result<PolicyFile, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy {}: {e}", path.display()))?;
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("policy")
        .to_string();
    Ok(PolicyFile { name, source })
}

/// What to run for one scan.
#[derive(Clone, Debug, Default)]
pub struct Policies {
    /// Replace the bundled seed rules that have a native-tier policy
    /// (`aws-rds-unencrypted`, `gcp-storage-uniform-access`) with it.
    pub native: bool,
    pub foreign: Vec<PolicyFile>,
    pub shape: Option<Shape>,
    /// Rule path the foreign policies' violations are read from
    /// (`data.main.deny` by default).
    pub entry: Option<String>,
}

type Errors = Arc<Mutex<Vec<String>>>;

/// Run `scan` with `rules` extended (and, for native-tier policies,
/// replaced) by the policies. Compile errors are returned before the scan;
/// runtime errors invalidate its result. Complete the scan inside the
/// callback and publish its result only after this returns.
pub fn with_policies<T>(
    policies: &Policies,
    mut rules: Vec<Box<dyn DynRule>>,
    scan: impl FnOnce(Vec<Box<dyn DynRule>>) -> Result<T, String>,
) -> Result<T, String> {
    if !policies.native && policies.foreign.is_empty() {
        return scan(rules);
    }
    let errors: Errors = Arc::default();
    if policies.native {
        for seed in [Seed::Rds, Seed::GcpStorage] {
            let rule = NativePolicy::prepare(seed, errors.clone())?;
            let name = rule.info.name.clone();
            rules.retain(|r| r.info().name != name);
            rules.push(Box::new(rule));
        }
    }
    let shape = policies.shape.unwrap_or(Shape::Plan);
    let entry = policies.entry.as_deref().unwrap_or("data.main.deny");
    for file in &policies.foreign {
        rules.push(Box::new(ForeignPolicy::prepare(
            file,
            shape,
            entry,
            errors.clone(),
        )?));
    }
    let result = scan(rules);
    let mut errors = errors.lock().expect("Rego error lock poisoned");
    errors.sort();
    if errors.is_empty() {
        result
    } else {
        Err(errors.join("\n"))
    }
}

fn engine_with(name: &str, source: &str) -> Result<regorus::Engine, String> {
    let mut engine = regorus::Engine::new();
    engine.set_strict_builtin_errors(true);
    engine
        .add_policy(format!("{name}.rego"), source.to_string())
        .map_err(|e| format!("policy {name}: {e}"))?;
    Ok(engine)
}

fn eval(engine: &regorus::Engine, input: &Json, rule: &str) -> Result<regorus::Value, String> {
    let mut engine = engine.clone();
    engine.set_input(
        regorus::Value::from_json_str(&input.to_string()).map_err(|e| e.to_string())?,
    );
    engine.eval_rule(rule.to_string()).map_err(|e| e.to_string())
}

fn eval_bool(engine: &regorus::Engine, input: &Json, rule: &str) -> Result<bool, String> {
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
    errors: Errors,
}

impl NativePolicy {
    fn prepare(seed: Seed, errors: Errors) -> Result<Self, String> {
        let (package, source) = seed.source();
        Self::compile(seed, package, source, errors)
    }

    fn compile(seed: Seed, package: &'static str, source: &str, errors: Errors) -> Result<Self, String> {
        let engine = engine_with(package, source)?;
        let probe = json!({"configured": {}, "subject": {"value": null, "boolean": null, "number": null, "text": null}});
        let declared = eval(&engine, &probe, &format!("data.{package}.subject"))?;
        let declared: Json = serde_json::from_str(
            &declared.to_json_str().map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let attribute = declared["attribute"]
            .as_str()
            .ok_or_else(|| format!("policy {package}: subject.attribute must be a string"))?
            .to_string();
        let effective = match declared["mode"].as_str() {
            Some("effective") => true,
            Some("configured") => false,
            _ => return Err(format!("policy {package}: subject.mode must be \"effective\" or \"configured\"")),
        };
        // Both decision rules must exist and be boolean before any scan runs.
        eval_bool(&engine, &probe, &format!("data.{package}.skip"))?;
        eval_bool(&engine, &probe, &format!("data.{package}.violates"))?;
        Ok(NativePolicy {
            seed,
            info: seed.info(),
            engine,
            package,
            subject: Subject { attribute, effective },
            errors,
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
        if eval_bool(&self.engine, &input, &format!("data.{}.skip", self.package))? {
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
            match eval_bool(&self.engine, &input, &rule) {
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
    fn judge_resource(&self, r: &Resource) -> Vec<Judgement> {
        match self.verdict(r) {
            Ok(v) => v
                .and_then(|v| Judgement::from_verdict(v, |v| self.seed.message(r, v)))
                .into_iter()
                .collect(),
            Err(e) => {
                self.fail(r, e);
                Vec::new()
            }
        }
    }
    fn judge_module<'m>(&self, _m: &'m Module) -> Vec<(&'m Resource, Judgement)> {
        Vec::new()
    }
}

impl NativePolicy {
    fn fail(&self, r: &Resource, error: String) {
        self.errors
            .lock()
            .expect("Rego error lock poisoned")
            .push(format!("Rego {} on {}: {error}", self.info.name, r.address));
    }
}

// ---------------------------------------------------------------------------
// Foreign tier
// ---------------------------------------------------------------------------

struct ForeignPolicy {
    info: RuleInfo,
    engine: regorus::Engine,
    entry: String,
    shape: Shape,
    errors: Errors,
}

impl ForeignPolicy {
    fn prepare(file: &PolicyFile, shape: Shape, entry: &str, errors: Errors) -> Result<Self, String> {
        let engine = engine_with(&file.name, &file.source)?;
        // The entry rule must resolve on an empty document before any scan runs.
        let empty = match shape {
            Shape::Hcl => json!({"resource": {}}),
            Shape::Plan => json!({"format_version": "1.2", "resource_changes": [], "planned_values": {"root_module": {"resources": []}}}),
        };
        violations(&eval(&engine, &empty, entry).map_err(|e| format!("policy {}: {e}", file.name))?)
            .map_err(|e| format!("policy {}: {e}", file.name))?;
        Ok(ForeignPolicy {
            info: RuleInfo {
                name: format!("rego:{}", file.name).into(),
                category: Category::Other,
                // Foreign policies declare no impact level.
                level: Level::Medium,
                description: format!("Rego policy {}", file.name).into(),
                resource_types: Vec::new(),
                runs_on_module: true,
            },
            engine,
            entry: entry.to_string(),
            shape,
            errors,
        })
    }

    fn judge(&self, r: &Resource) -> Result<Vec<Judgement>, String> {
        let projection = projection::project(r, self.shape);
        let input = projection::input(r, &projection, self.shape);
        let messages = violations(&eval(&self.engine, &input, &self.entry)?)?;
        if messages.is_empty() {
            return Ok(Vec::new());
        }
        let severity = projection.certainty();
        let deciding = projection.deciding();
        let witness = deciding.map(|a| a.value.clone());
        let suffix = match severity {
            Severity::Indeterminate => {
                let paths: Vec<_> = projection.abstractions.iter().map(|a| a.path.as_str()).collect();
                format!(" (cannot be confirmed: {} computed at apply time)", paths.join(", "))
            }
            _ => String::new(),
        };
        let hidden: Vec<Hidden> = projection
            .abstractions
            .iter()
            .map(|a| Hidden {
                path: a.path.clone(),
                truth: a.truth,
            })
            .collect();
        Ok(messages
            .into_iter()
            .map(|m| Judgement {
                severity,
                witness: witness.clone(),
                message: format!("{m}{suffix}"),
                hidden: hidden.clone(),
                fix_hint: None,
            })
            .collect())
    }
}

/// The violations a foreign entry rule produced: a set or array of strings,
/// or of objects with a `msg` string.
fn violations(result: &regorus::Value) -> Result<Vec<String>, String> {
    if matches!(result, regorus::Value::Undefined) {
        return Ok(Vec::new());
    }
    let json: Json = serde_json::from_str(&result.to_json_str().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let items = match json {
        Json::Array(items) => items,
        Json::Bool(false) | Json::Null => Vec::new(),
        other => return Err(format!("entry rule must produce a set of violations, got {other}")),
    };
    items
        .into_iter()
        .map(|item| match item {
            Json::String(s) => Ok(s),
            Json::Object(ref o) => match o.get("msg") {
                Some(Json::String(s)) => Ok(s.clone()),
                _ => Ok(item.to_string()),
            },
            other => Ok(other.to_string()),
        })
        .collect()
}

impl DynRule for ForeignPolicy {
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn judge_resource(&self, _r: &Resource) -> Vec<Judgement> {
        Vec::new()
    }
    fn judge_module<'m>(&self, module: &'m Module) -> Vec<(&'m Resource, Judgement)> {
        let mut out = Vec::new();
        for r in &module.resources {
            if r.mode != tf_semantic::Mode::Managed || r.existence == Truth::False {
                continue;
            }
            match self.judge(r) {
                Ok(js) => out.extend(js.into_iter().map(|j| (r, j))),
                Err(e) => self
                    .errors
                    .lock()
                    .expect("Rego error lock poisoned")
                    .push(format!("Rego {} on {}: {e}", self.info.name, r.address)),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rds() -> NativePolicy {
        NativePolicy::prepare(Seed::Rds, Errors::default()).unwrap()
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
        let compile = |src: &str| NativePolicy::compile(Seed::Rds, "oxtf.rds", src, Errors::default());
        assert!(compile("this isn't rego").is_err());
        assert!(compile("package oxtf.rds\nviolates := true").is_err(), "no subject");
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
    fn runtime_failure_invalidates_the_scan_without_leaking() {
        let source = r#"package oxtf.rds
import rego.v1
subject := {"attribute": "storage_encrypted", "mode": "effective"}
default skip := false
violates if { input.subject.boolean == false; 1 / 0 == 0 }
"#;
        let roots = [std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/rules/aws-rds-unencrypted/fail_explicit_false")];
        let scan = |rules| {
            Ok(tf_linter::scan_with(
                &tf_linter::Linter::new(rules),
                &roots,
                &tf_linter::ScanOptions::default(),
            )
            .0)
        };
        let errors = Errors::default();
        let bad = NativePolicy::compile(Seed::Rds, "oxtf.rds", source, errors.clone()).unwrap();
        let rules: Vec<Box<dyn DynRule>> = vec![Box::new(bad)];
        let result = scan(rules).unwrap();
        assert!(result.findings.is_empty());
        let e = errors.lock().unwrap().join("\n");
        assert!(e.contains("aws_db_instance."), "{e}");
        let good = Policies {
            native: true,
            ..Default::default()
        };
        assert_eq!(with_policies(&good, vec![], scan).unwrap().findings.len(), 1);
    }

    #[test]
    fn foreign_violations_accept_strings_and_msg_objects() {
        let v = regorus::Value::from_json_str(r#"["a", {"msg": "b", "x": 1}, 3]"#).unwrap();
        assert_eq!(violations(&v).unwrap(), vec!["a", "b", "3"]);
        assert!(violations(&regorus::Value::Undefined).unwrap().is_empty());
        assert!(violations(&regorus::Value::from_json_str("\"x\"").unwrap()).is_err());
    }

    #[test]
    fn foreign_policies_must_resolve_their_entry_rule() {
        let file = PolicyFile {
            name: "p".into(),
            source: "package other\nimport rego.v1\ndeny contains \"x\" if true".into(),
        };
        assert!(ForeignPolicy::prepare(&file, Shape::Hcl, "data.main.deny", Errors::default()).is_err());
        assert!(ForeignPolicy::prepare(&file, Shape::Hcl, "data.other.deny", Errors::default()).is_ok());
    }
}

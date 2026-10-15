//! Bundled native Rego rules. The contract remains private.
//! Evidence handles exist only for one resource evaluation; no foreign policy API.
mod iam;
mod s3;
mod ssh;

use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{Value as Json, json};
use tf_eval::{Kind, Truth, Value, Verdict};
use tf_linter::rule::{DynRule, Judgement, Rule, RuleInfo};
use tf_linter::rules::{
    AwsIamWildcardPolicy, AwsRdsUnencrypted, AwsS3PublicAccessBlock, AwsSgOpenSsh,
    GcpStorageUniformAccess,
};
use tf_semantic::{Module, Resource};

const POLICY: &str = include_str!("rds.rego");
const BOOLEAN: &str = include_str!("boolean.rego");
const GCP_POLICY: &str = include_str!("gcp_storage.rego");

#[derive(Clone, Copy)]
enum NativeRule {
    Rds,
    GcpStorage,
    Ssh,
    Iam,
    S3,
}
impl NativeRule {
    fn info(self) -> RuleInfo {
        match self {
            Self::Iam => AwsIamWildcardPolicy.info(),
            Self::S3 => AwsS3PublicAccessBlock.info(),
            Self::Ssh => AwsSgOpenSsh.info(),
            Self::Rds => AwsRdsUnencrypted.info(),
            Self::GcpStorage => GcpStorageUniformAccess.info(),
        }
    }
    fn attribute(self) -> &'static str {
        match self {
            Self::Ssh | Self::Iam | Self::S3 => unreachable!("SSH uses its nested projection"),
            Self::Rds => "storage_encrypted",
            Self::GcpStorage => "uniform_bucket_level_access",
        }
    }
    fn prepare(self) -> Result<CompiledPolicy, String> {
        match self {
            Self::Iam => prepare(include_str!("iam.rego"), "data.oxtf.iam.result"),
            Self::S3 => prepare(include_str!("s3.rego"), "data.oxtf.s3.result"),
            Self::Ssh => prepare(include_str!("ssh.rego"), "data.oxtf.ssh.result"),
            Self::Rds => prepare(POLICY, "data.oxtf.rds.result"),
            Self::GcpStorage => prepare(GCP_POLICY, "data.oxtf.gcp_storage.result"),
        }
    }
    /// Native wording for a verdict, shared with the native rule.
    fn message(self, r: &Resource, verdict: &Verdict) -> String {
        match self {
            Self::Iam => AwsIamWildcardPolicy.message(r, verdict),
            Self::S3 => AwsS3PublicAccessBlock.message(r, verdict),
            Self::Ssh => AwsSgOpenSsh.message(r, verdict),
            Self::Rds => AwsRdsUnencrypted.message(r, verdict),
            Self::GcpStorage => GcpStorageUniformAccess.message(r, verdict),
        }
    }
}

struct CompiledPolicy {
    engine: regorus::Engine,
    entry: &'static str,
}

/// Replace the native RDS rule for one scan. Errors invalidate the entire result.
/// Complete the scan inside the callback; publish its result only after this returns.
pub fn with_rds_policy<T>(
    rules: Vec<Box<dyn DynRule>>,
    scan: impl FnOnce(Vec<Box<dyn DynRule>>) -> Result<T, String>,
) -> Result<T, String> {
    with_engines(
        vec![(NativeRule::Rds, NativeRule::Rds.prepare()?)],
        rules,
        scan,
    )
}

/// Replace all five seed rules with bundled native Rego.
/// Additional rules stay unchanged. Complete the scan before returning from the callback.
pub fn with_native_policies<T>(
    rules: Vec<Box<dyn DynRule>>,
    scan: impl FnOnce(Vec<Box<dyn DynRule>>) -> Result<T, String>,
) -> Result<T, String> {
    let policies = [
        NativeRule::Rds,
        NativeRule::GcpStorage,
        NativeRule::Ssh,
        NativeRule::Iam,
        NativeRule::S3,
    ]
    .into_iter()
    .map(|kind| Ok((kind, kind.prepare()?)))
    .collect::<Result<Vec<_>, String>>()?;
    with_engines(policies, rules, scan)
}

fn with_engines<T>(
    policies: Vec<(NativeRule, CompiledPolicy)>,
    mut rules: Vec<Box<dyn DynRule>>,
    scan: impl FnOnce(Vec<Box<dyn DynRule>>) -> Result<T, String>,
) -> Result<T, String> {
    let errors = Arc::new(Mutex::new(Vec::new()));
    for (kind, policy) in policies {
        let name = kind.info().name;
        rules.retain(|r| r.info().name != name);
        rules.push(Box::new(PolicyRule {
            kind,
            policy,
            errors: errors.clone(),
        }));
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

fn prepare(source: &str, entry: &'static str) -> Result<CompiledPolicy, String> {
    let mut engine = regorus::Engine::new();
    engine.set_strict_builtin_errors(true);
    engine
        .add_policy("lattice.rego".into(), include_str!("lattice.rego").into())
        .map_err(|e| e.to_string())?;
    engine
        .add_policy("boolean.rego".into(), BOOLEAN.into())
        .map_err(|e| e.to_string())?;
    engine
        .add_policy("rule.rego".into(), source.into())
        .map_err(|e| e.to_string())?;
    // Evaluate once to prepare this engine before cloning it for parallel scans.
    engine.set_input(
        regorus::Value::from_json_str(
            r#"{"policy":{"kind":"known","document":null},"candidates":[],"replica":{"kind":"missing"},"effective":{"kind":"missing"},"target":{"resource_type":"aws_security_group"},"ingress":{"kind":"known","type":"null"}}"#,
        )
        .map_err(|e| e.to_string())?,
    );
    let result = engine.eval_rule(entry.into()).map_err(|e| e.to_string())?;
    decode(result, &[], entry)?;
    Ok(CompiledPolicy { engine, entry })
}

#[derive(Default)]
struct Evidence(Vec<Value>);
impl Evidence {
    fn tag(&mut self, value: Option<Value>) -> Json {
        let Some(value) = value else {
            return json!({"kind":"missing"});
        };
        let handle = self.0.len();
        self.0.push(value.clone());
        match &value.kind {
            // Only the boolean view is needed by this rule. Containers remain
            // known even when their children are abstract; never flatten to null.
            Kind::Known(_) => {
                json!({"kind":"known", "type":value.type_name(), "boolean":value.as_bool(), "handle":handle})
            }
            Kind::Unknown(_) => json!({"kind":"unknown", "handle":handle}),
            Kind::Tainted(_) => json!({"kind":"tainted", "handle":handle}),
            Kind::OneOf(o) => {
                let alternatives: Vec<_> = o
                    .alternatives
                    .iter()
                    .map(|a| self.tag(Some(a.child_of(&value))))
                    .collect();
                json!({"kind":"one_of", "tainted":o.tainted, "alternatives":alternatives, "handle":handle})
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    rank: u8,
    evidence: Option<usize>,
    reason: Option<String>,
}

fn evaluate(policy: &CompiledPolicy, input: &Json, evidence: &[Value]) -> Result<Verdict, String> {
    let mut engine = policy.engine.clone();
    engine.set_input(regorus::Value::from_json_str(&input.to_string()).map_err(|e| e.to_string())?);
    let result = engine
        .eval_rule(policy.entry.into())
        .map_err(|e| e.to_string())?;
    decode(result, evidence, policy.entry)
}

fn decode(result: regorus::Value, evidence: &[Value], entry: &str) -> Result<Verdict, String> {
    let decision: Decision =
        serde_json::from_str(&result.to_json_str().map_err(|e| e.to_string())?)
            .map_err(|e| format!("invalid Rego decision: {e}"))?;
    let truth = Truth::from_rank(decision.rank)
        .ok_or_else(|| format!("invalid Rego truth rank: {}", decision.rank))?;
    let witness = decision
        .evidence
        .map(|id| {
            evidence
                .get(id)
                .cloned()
                .ok_or_else(|| format!("invalid Rego evidence handle: {id}"))
        })
        .transpose()?;
    let structural = match decision.reason.as_deref() {
        None => false,
        Some("missing_protection")
            if entry == "data.oxtf.s3.result" && truth == Truth::True && witness.is_none() =>
        {
            true
        }
        Some("pab_existence")
            if entry == "data.oxtf.s3.result" && truth == Truth::Tainted && witness.is_none() =>
        {
            true
        }
        Some(_) => return Err("invalid Rego structural evidence reason".into()),
    };
    if truth != Truth::False && witness.is_none() && !structural {
        return Err("Rego decision requires evidence".into());
    }
    Ok(Verdict::new(truth, witness))
}

struct PolicyRule {
    kind: NativeRule,
    policy: CompiledPolicy,
    errors: Arc<Mutex<Vec<String>>>,
}
impl DynRule for PolicyRule {
    fn info(&self) -> RuleInfo {
        self.kind.info()
    }
    fn judge_module<'m>(&self, module: &'m Module) -> Vec<(&'m Resource, Judgement)> {
        if !matches!(self.kind, NativeRule::S3) {
            return Vec::new();
        }
        module
            .resources_of("aws_s3_bucket")
            .filter_map(|bucket| {
                let mut evidence = Evidence::default();
                let input = evidence.s3_input(bucket, module);
                self.judge(bucket, input, evidence).map(|j| (bucket, j))
            })
            .collect()
    }
    fn judge_resource(&self, r: &Resource) -> Vec<Judgement> {
        let mut evidence = Evidence::default();
        let replica = match r.value("replicate_source_db") {
            None => "missing",
            Some(v) if v.is_null() => "null",
            Some(_) => "set",
        };
        let input = if matches!(self.kind, NativeRule::Ssh) {
            evidence.ssh_input(r)
        } else if matches!(self.kind, NativeRule::Iam) {
            evidence.iam_input(r)
        } else {
            let attribute = self.kind.attribute();
            json!({
                "target": {"address": r.address, "resource_type": r.ty},
                "replica": {"kind":replica},
                "configured": evidence.tag(r.value(attribute)),
                "effective": evidence.tag(r.value_or_default(attribute)),
            })
        };
        self.judge(r, input, evidence).into_iter().collect()
    }
}
impl PolicyRule {
    /// Evaluate the policy; a failure is recorded and yields no judgement.
    fn judge(&self, r: &Resource, input: Json, evidence: Evidence) -> Option<Judgement> {
        match evaluate(&self.policy, &input, &evidence.0) {
            Ok(verdict) => {
                let message = if verdict.holds() {
                    self.kind.message(r, &verdict)
                } else {
                    String::new()
                };
                Some(Judgement { verdict, message })
            }
            Err(error) => {
                self.errors
                    .lock()
                    .expect("Rego error lock poisoned")
                    .push(format!("Rego {} on {}: {error}", self.info().name, r.address));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_eval::truth;

    fn compile(source: &str) -> Result<CompiledPolicy, String> {
        prepare(source, "data.oxtf.rds.result")
    }

    #[test]
    fn verdict_and_witness_match_native_lattice() {
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
        for kind in [NativeRule::Rds, NativeRule::GcpStorage] {
            let engine = kind.prepare().unwrap();
            for value in &values {
                let mut evidence = Evidence::default();
                let input = json!({"replica":{"kind":"missing"},"effective":evidence.tag(Some(value.clone()))});
                let actual = evaluate(&engine, &input, &evidence.0).unwrap();
                let expected = truth::test(value, &|v| v.as_bool() != Some(true));
                assert_eq!(actual.truth, expected.truth, "{value:?}");
                assert_eq!(
                    format!("{:?}", actual.witness),
                    format!("{:?}", expected.witness),
                    "{value:?}"
                );
            }
        }
    }

    #[test]
    fn runtime_failure_invalidates_scan_without_leaking_to_next_scan() {
        let source = r#"package oxtf.rds
import rego.v1
result := {"rank":0,"evidence":null} if input.effective.kind == "missing"
result := {"rank":3,"evidence":99999} if input.effective.kind != "missing"
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
        let error = with_engines(
            vec![(NativeRule::Rds, compile(source).unwrap())],
            vec![],
            scan,
        )
        .err()
        .unwrap();
        assert!(error.contains("invalid Rego evidence handle"), "{error}");
        assert!(error.contains("aws_db_instance."), "{error}");
        assert_eq!(with_rds_policy(vec![], scan).unwrap().findings.len(), 1);
    }

    #[test]
    fn bad_policy_and_decisions_are_errors() {
        assert!(compile("this isn't rego").is_err());
        for result in [
            r#"{"rank":9,"evidence":null}"#,
            r#"{"rank":3,"evidence":999}"#,
            r#"{"rank":3,"evidence":null}"#,
            r#"{"rank":0,"evidence":null,"extra":true}"#,
            "null",
        ] {
            assert!(
                compile(&format!("package oxtf.rds\nresult := {result}")).is_err(),
                "{result}"
            );
        }
        assert!(compile("package oxtf.rds\nother := false").is_err());
    }
}

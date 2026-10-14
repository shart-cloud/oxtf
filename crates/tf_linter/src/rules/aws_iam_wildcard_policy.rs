use tf_eval::truth::{self, exists, test};
use tf_eval::value::from_json;
use tf_eval::{Kind, Known, Value, Verdict};
use tf_semantic::Resource;

use super::{field, str_in};
use crate::rule::{Category, Level, Rule, RuleContext, RuleMeta};

/// An IAM policy statement with `Effect = "Allow"`, `Action = "*"` and
/// `Resource = "*"` (each as a string or inside a list).
///
/// The `policy` document may be built with `jsonencode` (inline, via
/// locals, via `for` over a variable: the evaluator keeps the structure) or
/// be a raw JSON string / heredoc (parsed here). Deny statements do not
/// fire; `NotAction` / `NotResource` are not considered.
pub struct AwsIamWildcardPolicy;

impl RuleMeta for AwsIamWildcardPolicy {
    const NAME: &'static str = "aws-iam-wildcard-policy";
    const CATEGORY: Category = Category::Iam;
    const LEVEL: Level = Level::Critical;
    const DESCRIPTION: &'static str = "IAM policy allows Action \"*\" on Resource \"*\"";
    const RESOURCE_TYPES: &'static [&'static str] = &[
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    ];
}

/// The policy document as a structured value: the argument of
/// `jsonencode`, or a JSON string parsed.
fn document(v: &Value) -> Option<Value> {
    match &v.kind {
        Kind::Known(Known::Json(inner)) => Some(inner.child_of(v)),
        Kind::Known(Known::String(s)) => serde_json::from_str::<serde_json::Value>(s)
            .ok()
            .map(|j| from_json(&j, &v.prov)),
        _ => None,
    }
}

fn wildcard(v: &Value) -> Verdict {
    exists(v, &|e| test(e, &|x| str_in(x, &["*"])))
}

fn statement(s: &Value) -> Verdict {
    truth::map(s, &|s| {
        let action = wildcard(&field(s, "Action"));
        let resource = wildcard(&field(s, "Resource"));
        let effect = test(&field(s, "Effect"), &|e| e.as_str() == Some("Allow"));
        action.and(resource).and(effect)
    })
}

fn policy(v: &Value) -> Verdict {
    truth::map(v, &|p| match document(p) {
        Some(doc) => truth::map(&doc, &|d| exists(&field(d, "Statement"), &statement)),
        None => Verdict::FALSE,
    })
}

impl Rule for AwsIamWildcardPolicy {
    fn run_on_resource(&self, r: &Resource, ctx: &mut RuleContext<'_>) {
        let Some(p) = r.value("policy") else { return };
        let v = policy(&p);
        Self::report(r, ctx, &v);
    }
}

impl AwsIamWildcardPolicy {
    /// Shared native/Rego finding presentation.
    pub fn report(r: &Resource, ctx: &mut RuleContext<'_>, v: &Verdict) {
        ctx.report(r, v, |_| {
            "policy statement allows Action \"*\" on Resource \"*\"".to_string()
        });
    }
}

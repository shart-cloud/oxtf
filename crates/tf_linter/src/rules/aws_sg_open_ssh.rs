use tf_eval::truth::{self, exists, test};
use tf_eval::{Value, Verdict};
use tf_semantic::Resource;

use super::{field, str_in};
use crate::rule::{Category, Level, Rule, RuleContext, RuleMeta};

/// SSH (TCP 22) reachable from the whole internet (`0.0.0.0/0` or `::/0`).
///
/// - `aws_security_group`: every inline `ingress` rule (block syntax,
///   `dynamic "ingress"`, or the attribute form).
/// - `aws_vpc_security_group_ingress_rule`: `cidr_ipv4` / `cidr_ipv6`.
/// - `aws_security_group_rule` with `type = "ingress"`.
///
/// Port 22 is reachable when `protocol` is `-1` / `all` (any port), or
/// when it is `tcp` / `6` and `from_port <= 22 <= to_port`.
pub struct AwsSgOpenSsh;

impl RuleMeta for AwsSgOpenSsh {
    const NAME: &'static str = "aws-sg-open-ssh";
    const CATEGORY: Category = Category::Network;
    const LEVEL: Level = Level::High;
    const DESCRIPTION: &'static str =
        "Security group ingress allows SSH (port 22) from 0.0.0.0/0 or ::/0";
    const RESOURCE_TYPES: &'static [&'static str] = &[
        "aws_security_group",
        "aws_vpc_security_group_ingress_rule",
        "aws_security_group_rule",
    ];
}

const OPEN: &[&str] = &["0.0.0.0/0", "::/0"];
const ANY_PROTO: &[&str] = &["-1", "all"];
const TCP: &[&str] = &["tcp", "6", "TCP"];

fn open_cidr(v: &Value) -> Verdict {
    test(v, &|x| str_in(x, OPEN))
}

fn open_list(v: &Value) -> Verdict {
    exists(v, &open_cidr)
}

/// Port 22 reachable given protocol / from_port / to_port values.
fn reaches_22(protocol: &Value, from: &Value, to: &Value) -> Verdict {
    let any = test(protocol, &|p| str_in(p, ANY_PROTO));
    let tcp = test(protocol, &|p| str_in(p, TCP));
    let lo = test(from, &|f| f.as_number().is_some_and(|n| n <= 22.0));
    let hi = test(to, &|t| t.as_number().is_some_and(|n| n >= 22.0));
    any.or(tcp.and(lo).and(hi))
}

fn inline_rule(rule: &Value) -> Verdict {
    truth::map(rule, &|r| {
        let open = open_list(&field(r, "cidr_blocks")).or(open_list(&field(r, "ipv6_cidr_blocks")));
        open.and(reaches_22(
            &field(r, "protocol"),
            &field(r, "from_port"),
            &field(r, "to_port"),
        ))
    })
}

fn message(w: Option<&Value>) -> String {
    let src = w
        .and_then(|v| v.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "the internet".into());
    format!("ingress allows SSH (port 22) from {src}")
}

impl AwsSgOpenSsh {
    /// Shared native/Rego presentation of the deciding witness.
    pub fn report(r: &Resource, ctx: &mut RuleContext<'_>, verdict: &Verdict) {
        ctx.report(r, verdict, message);
    }
}

impl Rule for AwsSgOpenSsh {
    fn run_on_resource(&self, r: &Resource, ctx: &mut RuleContext<'_>) {
        let v = match &*r.ty {
            "aws_security_group" => match r.value("ingress") {
                Some(ingress) => exists(&ingress, &inline_rule),
                None => return,
            },
            "aws_vpc_security_group_ingress_rule" => {
                let get = |n: &str| r.value(n).unwrap_or_else(Value::null);
                let open = open_cidr(&get("cidr_ipv4")).or(open_cidr(&get("cidr_ipv6")));
                open.and(reaches_22(
                    &get("ip_protocol"),
                    &get("from_port"),
                    &get("to_port"),
                ))
            }
            "aws_security_group_rule" => {
                let get = |n: &str| r.value(n).unwrap_or_else(Value::null);
                let ingress = test(&get("type"), &|t| t.as_str() == Some("ingress"));
                let open = open_list(&get("cidr_blocks")).or(open_list(&get("ipv6_cidr_blocks")));
                open.and(reaches_22(
                    &get("protocol"),
                    &get("from_port"),
                    &get("to_port"),
                ))
                .and(ingress)
            }
            _ => return,
        };
        Self::report(r, ctx, &v);
    }
}

//! policy_sentry's IAM database, as the cloudsplaining checks read it.

use std::sync::OnceLock;

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{Map, Value as Json, json};

/// The compact form bundled in `data/checkov/iam.ndjson` (written by
/// the importer from the pinned policy_sentry): a header line, then one
/// line per service, each parsed only when first read.
pub const COMPACT: &str = include_str!("../../data/checkov/iam.ndjson");

/// The compact database: the header, and each service's line with its
/// compact and full (policy_sentry-shaped) forms, built on first use.
struct Compact {
    header: Json,
    prefixes: Vec<&'static str>,
    services: std::collections::HashMap<&'static str, Service>,
}

struct Service {
    line: &'static str,
    compact: OnceLock<Json>,
    full: OnceLock<Json>,
}

fn compact() -> Result<&'static Compact, String> {
    static COMPACT_DB: OnceLock<Result<Compact, String>> = OnceLock::new();
    COMPACT_DB
        .get_or_init(|| {
            let mut lines = COMPACT.lines();
            let header: Json = serde_json::from_str(lines.next().ok_or("iam.ndjson: empty")?)
                .map_err(|e| format!("iam.ndjson: {e}"))?;
            let mut prefixes = Vec::new();
            let mut services = std::collections::HashMap::default();
            for line in lines {
                // {"prefix":"<p>","service":...}: the prefix without a parse.
                let rest = line
                    .strip_prefix("{\"prefix\":\"")
                    .ok_or("iam.ndjson: a line without its prefix first")?;
                let prefix = &rest[..rest.find('"').ok_or("iam.ndjson: prefix")?];
                prefixes.push(prefix);
                services.insert(
                    prefix,
                    Service {
                        line,
                        compact: OnceLock::new(),
                        full: OnceLock::new(),
                    },
                );
            }
            Ok(Compact {
                header: header["header"].clone(),
                prefixes,
                services,
            })
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// A service's compact entry (`prefix`, `actions`, `resources`).
fn compact_service(prefix: &str) -> Option<&'static Json> {
    let s = compact().ok()?.services.get(prefix)?;
    Some(s.compact.get_or_init(|| {
        serde_json::from_str::<Json>(s.line)
            .map(|mut v| v["service"].take())
            .unwrap_or(Json::Null)
    }))
}

/// The prefix `get_service_prefix_data` reads for `prefix`: itself, or
/// `servicecatalog` for `catalog` (the service name in Service Catalog
/// resource ARNs).
fn aliased(prefix: &str) -> &str {
    if prefix == "catalog" && !compact().is_ok_and(|c| c.services.contains_key(prefix)) {
        "servicecatalog"
    } else {
        prefix
    }
}

/// `policy_sentry.shared.iam_data.iam_definition`, built (once) for
/// Python that reads it directly; the native queries do not need it.
pub fn definition() -> Result<&'static Json, String> {
    static DEFINITION: OnceLock<Result<Json, String>> = OnceLock::new();
    DEFINITION
        .get_or_init(|| {
            let c = compact()?;
            let mut out = Map::new();
            let key = c.header["schema_key"]
                .as_str()
                .ok_or("iam.ndjson: schema_key")?;
            out.insert(key.to_string(), c.header["schema"].clone());
            for prefix in prefixes() {
                out.insert(
                    prefix.to_string(),
                    raw_service(prefix).cloned().unwrap_or(Json::Null),
                );
            }
            Ok(Json::Object(out))
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Every service prefix.
pub fn prefixes() -> impl Iterator<Item = &'static str> {
    compact()
        .ok()
        .into_iter()
        .flat_map(|c| c.prefixes.iter().copied())
}

/// A service in policy_sentry's shape, built on first use.
fn raw_service(prefix: &str) -> Option<&'static Json> {
    let s = compact().ok()?.services.get(prefix)?;
    let service = compact_service(prefix)?;
    Some(s.full.get_or_init(|| build_service(service)))
}

/// `get_service_prefix_data`: the service, or `servicecatalog` for the
/// `catalog` ARNs of its resource types; `None` where it returns `{}`.
pub fn service(prefix: &str) -> Option<&'static Json> {
    raw_service(aliased(prefix))
}

/// A service's action names, as written and lowercased.
type Names = &'static [(String, String)];

/// A service's action names, as written and lowercased, built once.
pub fn action_names(prefix: &str) -> &'static [(String, String)] {
    static NAMES: OnceLock<Mutex<HashMap<String, Names>>> = OnceLock::new();
    let names = NAMES.get_or_init(Default::default);
    let mut names = names.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(found) = names.get(prefix) {
        return found;
    }
    let list: Vec<(String, String)> = compact_service(aliased(prefix))
        .and_then(|s| s["actions"].as_object())
        .into_iter()
        .flatten()
        .map(|(a, _)| (a.clone(), a.to_lowercase()))
        .collect();
    let leaked: &'static [(String, String)] = Box::leak(list.into_boxed_slice());
    names.insert(prefix.to_string(), leaked);
    leaked
}

/// `get_all_actions(lowercase)`.
pub fn all_actions(lowercase: bool) -> Vec<String> {
    prefixes()
        .flat_map(|p| actions_for_service(p, lowercase))
        .collect()
}

/// `get_actions_for_service(prefix, lowercase)`, from the compact data.
pub fn actions_for_service(prefix: &str, lowercase: bool) -> Vec<String> {
    let Some(service) = compact_service(aliased(prefix)) else {
        return Vec::new();
    };
    service["actions"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(a, _)| {
            if lowercase {
                format!("{prefix}:{}", a.to_lowercase())
            } else {
                format!("{prefix}:{a}")
            }
        })
        .collect()
}

/// The action's name as the database spells it (case-insensitive).
pub fn action_name(service: &'static Json, action: &str) -> Option<&'static str> {
    service["privileges_lower_name"]
        .get(action.to_lowercase())?
        .as_str()
}

/// The ARN format of each of an action's entries, in order.
pub fn entries(service: &'static Json, name: &str) -> Vec<String> {
    service["privileges"][name]["resource_types"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(rt, _)| arn_format(service, rt).to_string())
        .collect()
}

/// `create_action_data_entries`' `resource_arn_format` for resource
/// type `rt`: its ARN, or `*` for the empty type or one without an ARN.
pub fn arn_format<'a>(service: &'a Json, rt: &str) -> &'a str {
    if rt.is_empty() {
        return "*";
    }
    service["resources"]
        .get(rt)
        .and_then(|r| r.get("arn"))
        .and_then(Json::as_str)
        .unwrap_or("*")
}

fn build_service(service: &Json) -> Json {
    let mut privileges = Map::new();
    let mut privileges_lower = Map::new();
    for (action, entry) in service["actions"].as_object().into_iter().flatten() {
        let mut resource_types = Map::new();
        let mut resource_types_lower = Map::new();
        for (rt, deps) in entry[1].as_object().into_iter().flatten() {
            resource_types.insert(
                rt.clone(),
                json!({"resource_type": rt, "required": false,
                       "condition_keys": [], "dependent_actions": deps}),
            );
            resource_types_lower.insert(rt.to_lowercase(), Json::String(rt.clone()));
        }
        privileges.insert(
            action.clone(),
            json!({
                "privilege": action, "access_level": entry[0], "description": "",
                "resource_types": resource_types,
                "resource_types_lower_name": resource_types_lower,
                "api_documentation_link": "",
            }),
        );
        privileges_lower.insert(action.to_lowercase(), Json::String(action.clone()));
    }
    let mut resources = Map::new();
    let mut resources_lower = Map::new();
    for (name, arn) in service["resources"].as_object().into_iter().flatten() {
        resources.insert(
            name.clone(),
            json!({"resource": name, "arn": arn, "condition_keys": []}),
        );
        resources_lower.insert(name.to_lowercase(), Json::String(name.clone()));
    }
    json!({
        "prefix": service["prefix"], "service_name": "", "privileges": privileges,
        "privileges_lower_name": privileges_lower, "resources": resources,
        "resources_lower_name": resources_lower, "conditions": {},
    })
}

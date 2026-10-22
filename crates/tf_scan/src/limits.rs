//! Strict wire format for the allowances exposed by every scan adapter.
use serde::Deserialize;
pub use tf_limits::Limits;

/// Omitted fields inherit finite defaults. Explicit null is invalid, like any non-integer.
pub fn from_json(text: &str) -> Result<Limits, String> {
    if !text.trim_start().starts_with('{') {
        return Err("invalid limits: expected a JSON object".into());
    }
    // A concrete field with a default rejects null; Option would silently accept it.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        #[serde(default = "default_evaluation_steps")]
        evaluation_steps: u64,
        #[serde(default = "default_loader_steps")]
        loader_steps: u64,
        #[serde(default = "default_rule_steps")]
        rule_steps: u64,
        #[serde(default = "default_rego_time_ms")]
        rego_time_ms: u64,
        #[serde(default = "default_input_bytes")]
        input_bytes: u64,
        #[serde(default = "default_source_bytes")]
        source_bytes: u64,
        #[serde(default = "default_file_entries")]
        file_entries: u64,
        #[serde(default = "default_directory_entries")]
        directory_entries: u64,
        #[serde(default = "default_roots")]
        roots: u64,
        #[serde(default = "default_arena_bytes")]
        arena_bytes: u64,
        #[serde(default = "default_ast_nodes")]
        ast_nodes: u64,
        #[serde(default = "default_text_bytes")]
        text_bytes: u64,
        #[serde(default = "default_collection_bytes")]
        collection_bytes: u64,
    }
    let wire: Wire = serde_json::from_str(text).map_err(|e| format!("invalid limits: {e}"))?;
    Limits::new(wire.evaluation_steps)
        .and_then(|limits| limits.with_loader_steps(wire.loader_steps))
        .and_then(|limits| limits.with_rule_steps(wire.rule_steps))
        .and_then(|limits| limits.with_rego_time_ms(wire.rego_time_ms))
        .and_then(|limits| limits.with_input_bytes(wire.input_bytes))
        .and_then(|limits| limits.with_source_bytes(wire.source_bytes))
        .and_then(|limits| limits.with_file_entries(wire.file_entries))
        .and_then(|limits| limits.with_directory_entries(wire.directory_entries))
        .and_then(|limits| limits.with_roots(wire.roots))
        .and_then(|limits| limits.with_arena_bytes(wire.arena_bytes))
        .and_then(|limits| limits.with_ast_nodes(wire.ast_nodes))
        .and_then(|limits| limits.with_text_bytes(wire.text_bytes))
        .and_then(|limits| limits.with_collection_bytes(wire.collection_bytes))
        .map_err(|e| format!("invalid limits: {e}"))
}

fn default_loader_steps() -> u64 {
    Limits::default().loader_steps()
}

fn default_rule_steps() -> u64 {
    Limits::default().rule_steps()
}

fn default_rego_time_ms() -> u64 {
    Limits::default().rego_time_ms()
}

fn default_evaluation_steps() -> u64 {
    Limits::default().evaluation_steps()
}

fn default_input_bytes() -> u64 {
    Limits::default().input_bytes()
}

fn default_source_bytes() -> u64 {
    Limits::default().source_bytes()
}

fn default_file_entries() -> u64 {
    Limits::default().file_entries()
}

fn default_directory_entries() -> u64 {
    Limits::default().directory_entries()
}

fn default_roots() -> u64 {
    Limits::default().roots()
}

fn default_arena_bytes() -> u64 {
    Limits::default().arena_bytes()
}
fn default_text_bytes() -> u64 {
    Limits::default().text_bytes()
}

fn default_ast_nodes() -> u64 {
    Limits::default().ast_nodes()
}

fn default_collection_bytes() -> u64 {
    Limits::default().collection_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_is_strict() {
        assert_eq!(from_json("{}").unwrap(), Limits::default());
        assert_eq!(
            from_json(r#"{"evaluation_steps":3}"#).unwrap(),
            Limits::new(3).unwrap()
        );
        assert_eq!(
            from_json(r#"{"loader_steps":3}"#).unwrap().loader_steps(),
            3
        );
        assert_eq!(from_json(r#"{"rule_steps":3}"#).unwrap().rule_steps(), 3);
        for text in [
            r#"{"evaluation_step":1}"#,
            r#"{"evaluation_steps":0}"#,
            r#"{"evaluation_steps":null}"#,
            r#"{"evaluation_steps":true}"#,
            r#"{"evaluation_steps":1.0}"#,
            r#"{"evaluation_steps":-1}"#,
            r#"{"evaluation_steps":18446744073709551616}"#,
            r#"{"evaluation_steps":1,"evaluation_steps":2}"#,
            "[]",
            "null",
            r#"{"loader_steps":0}"#,
            r#"{"loader_steps":true}"#,
            r#"{"loader_steps":null}"#,
            r#"{"loader_steps":-1}"#,
            r#"{"loader_steps":1.0}"#,
            r#"{"loader_steps":18446744073709551616}"#,
            r#"{"loader_steps":1,"loader_steps":2}"#,
            r#"{"rule_steps":0}"#,
            r#"{"rule_steps":true}"#,
            r#"{"rule_steps":null}"#,
            r#"{"rule_steps":-1}"#,
            r#"{"rule_steps":1.0}"#,
            r#"{"rule_steps":18446744073709551616}"#,
            r#"{"rule_steps":1,"rule_steps":2}"#,
        ] {
            assert!(from_json(text).is_err(), "{text}");
        }
    }
}

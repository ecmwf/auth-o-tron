use serde_json::Value;

/// Convert arbitrary JSON values into sanitized strings for attribute storage.
pub fn value_to_string(value: Value) -> String {
    let raw = match value {
        Value::String(s) => s,
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    };
    sanitize_attribute_value(raw)
}

fn sanitize_attribute_value(s: String) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

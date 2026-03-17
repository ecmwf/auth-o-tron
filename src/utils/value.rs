// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

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

//! GraphQL operation extraction helpers.

use std::collections::BTreeSet;

/// Extract a compact GraphQL operation label from a JSON request payload.
///
/// Supports single-object and batched-array GraphQL payloads.
pub fn extract_graphql_operation(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    match value {
        serde_json::Value::Object(map) => extract_operation_from_map(&map),
        serde_json::Value::Array(items) => {
            let mut names = Vec::new();
            let mut seen = BTreeSet::new();
            for item in items {
                if let serde_json::Value::Object(map) = item {
                    if let Some(name) = extract_operation_from_map(&map) {
                        if seen.insert(name.clone()) {
                            names.push(name);
                        }
                    }
                }
            }
            if names.is_empty() {
                None
            } else if names.len() == 1 {
                Some(names.remove(0))
            } else {
                let shown = names.iter().take(3).cloned().collect::<Vec<_>>();
                let mut label = format!("batch[{}]", shown.join(","));
                if names.len() > 3 {
                    label.push_str(&format!("+{}", names.len() - 3));
                }
                Some(label)
            }
        }
        _ => None,
    }
}

fn extract_operation_from_map(map: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    if let Some(name) = map
        .get("operationName")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Some(name.to_string());
    }

    map.get("query")
        .and_then(|v| v.as_str())
        .and_then(extract_operation_name_from_query)
}

fn extract_operation_name_from_query(query: &str) -> Option<String> {
    let query = query.trim_start();
    for keyword in ["query", "mutation", "subscription"] {
        if let Some(rest) = query.strip_prefix(keyword) {
            let rest = rest.trim_start();
            if rest.starts_with('{') {
                return Some("anonymous".to_string());
            }
            let mut name = String::new();
            for ch in rest.chars() {
                if ch == '_' || ch.is_ascii_alphanumeric() {
                    name.push(ch);
                } else {
                    break;
                }
            }
            if !name.is_empty() {
                return Some(name);
            }
            return Some("anonymous".to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::extract_graphql_operation;

    #[test]
    fn extracts_single_operation_name() {
        let body =
            r#"{"operationName":"GetBudget","query":"query GetBudget { budget { total } }"}"#;
        assert_eq!(
            extract_graphql_operation(body).as_deref(),
            Some("GetBudget")
        );
    }

    #[test]
    fn extracts_batched_operation_names() {
        let body = r#"[{"operationName":"One"},{"operationName":"Two"}]"#;
        assert_eq!(
            extract_graphql_operation(body).as_deref(),
            Some("batch[One,Two]")
        );
    }

    #[test]
    fn extracts_query_name_when_operation_name_missing() {
        let body = r#"{"query":"mutation UpdateCost { updateCost { ok } }"}"#;
        assert_eq!(
            extract_graphql_operation(body).as_deref(),
            Some("UpdateCost")
        );
    }
}

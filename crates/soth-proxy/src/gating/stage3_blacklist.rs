use soth_core::{BlacklistMatchType, DecisionReason, Stage3Config};

pub fn evaluate(
    cfg: &Stage3Config,
    full_url: &str,
    path: &str,
    body: &[u8],
) -> Option<DecisionReason> {
    if matches!(cfg.match_type, BlacklistMatchType::CaseInsensitiveSubstring) {
        let url = full_url.to_ascii_lowercase();
        if cfg
            .blacklisted_keywords
            .iter()
            .any(|needle| !needle.is_empty() && url.contains(&needle.to_ascii_lowercase()))
        {
            return Some(DecisionReason::BlacklistedKeyword);
        }
        if cfg.blacklisted_path_substrings.iter().any(|needle| {
            !needle.is_empty()
                && path
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
        }) {
            return Some(DecisionReason::BlacklistedKeyword);
        }
    }

    if !cfg.graphql_operation_blacklist_enabled {
        return None;
    }
    if !path.to_ascii_lowercase().contains("graphql") {
        return None;
    }
    let operation_name = extract_graphql_operation_name(body)?;
    let operation_name = operation_name.to_ascii_lowercase();
    if cfg.graphql_operation_blacklist.iter().any(|needle| {
        let needle = needle.to_ascii_lowercase();
        !needle.is_empty() && operation_name.contains(needle.as_str())
    }) {
        return Some(DecisionReason::BlacklistedGraphQLOperation);
    }
    None
}

fn extract_graphql_operation_name(body: &[u8]) -> Option<String> {
    let json = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    json.get("operationName")
        .and_then(serde_json::Value::as_str)
        .map(std::string::ToString::to_string)
}

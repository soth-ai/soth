use soth_core::{BlacklistMatchType, Stage3Config};

use crate::gating::types::DecisionReason;

pub fn evaluate(cfg: &Stage3Config, host: &str, path: &str, body: &[u8]) -> Option<DecisionReason> {
    if matches!(cfg.match_type, BlacklistMatchType::CaseInsensitiveSubstring) {
        let host_lc = host.to_ascii_lowercase();
        if cfg
            .blacklisted_host_substrings
            .iter()
            .any(|needle| !needle.is_empty() && host_lc.contains(&needle.to_ascii_lowercase()))
        {
            return Some(DecisionReason::BlacklistedKeyword);
        }
        let path_lc = path.to_ascii_lowercase();
        if cfg
            .blacklisted_keywords
            .iter()
            .any(|needle| !needle.is_empty() && path_lc.contains(&needle.to_ascii_lowercase()))
        {
            return Some(DecisionReason::BlacklistedKeyword);
        }
        if cfg
            .blacklisted_path_substrings
            .iter()
            .any(|needle| !needle.is_empty() && path_lc.contains(&needle.to_ascii_lowercase()))
        {
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

#[cfg(test)]
mod tests {
    use soth_core::{BlacklistMatchType, Stage3Config};

    use super::evaluate;
    use crate::gating::types::DecisionReason;

    fn stage3() -> Stage3Config {
        Stage3Config {
            blacklisted_keywords: vec!["telemetry".to_string()],
            blacklisted_path_substrings: vec!["/monitoring".to_string()],
            blacklisted_host_substrings: vec!["cloudflare".to_string()],
            graphql_operation_blacklist: Vec::new(),
            graphql_operation_blacklist_enabled: false,
            match_type: BlacklistMatchType::CaseInsensitiveSubstring,
        }
    }

    #[test]
    fn keywords_are_path_only_not_host() {
        let cfg = stage3();
        let got = evaluate(&cfg, "telemetry.example.com", "/v1/chat/completions", b"{}");
        assert!(got.is_none(), "keyword should not match host");
    }

    #[test]
    fn host_substrings_match_host_only() {
        let cfg = stage3();
        let got = evaluate(
            &cfg,
            "gateway.ai.cloudflare.com",
            "/v1/chat/completions",
            b"{}",
        );
        assert_eq!(got, Some(DecisionReason::BlacklistedKeyword));
    }
}

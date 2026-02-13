use serde_json::Value;
use std::collections::BTreeMap;

fn normalize_plan(plan: &str) -> String {
    plan.trim().to_ascii_lowercase()
}

fn map_plan_kind(plan: &str) -> &'static str {
    match plan {
        "free" => "free",
        "plus" | "pro" | "max" => "individual",
        "team" => "team",
        "enterprise" | "business" => "enterprise",
        _ => "unknown",
    }
}

fn looks_like_chatgpt_usage_path(path: &str) -> bool {
    path.contains("/backend-api/wham/usage") || path.contains("/backend-api/accounts/check/")
}

fn looks_like_claude_subscription_path(path: &str) -> bool {
    (path.contains("/api/organizations/") && path.contains("/subscription_details"))
        || path == "/api/organizations"
        || path.starts_with("/api/organizations/")
}

fn parse_json(body: &str) -> Option<Value> {
    let trimmed = body.trim();
    if trimmed.is_empty() || trimmed.starts_with('[') {
        return None;
    }
    serde_json::from_str::<Value>(trimmed).ok()
}

fn first_chatgpt_account_plan(root: &Value) -> Option<String> {
    root.get("accounts")
        .and_then(Value::as_object)
        .and_then(|accounts| {
            accounts
                .values()
                .find_map(|entry| {
                    entry
                        .get("account")
                        .and_then(Value::as_object)
                        .and_then(|account| account.get("plan_type"))
                        .and_then(Value::as_str)
                })
                .map(str::to_owned)
        })
}

fn extract_chatgpt_tags(path: &str, root: &Value, tags: &mut BTreeMap<String, String>) {
    let mut plan = root
        .get("plan_type")
        .and_then(Value::as_str)
        .map(str::to_owned);

    if plan.is_none() && path.contains("/backend-api/accounts/check/") {
        plan = first_chatgpt_account_plan(root);
    }

    if let Some(plan) = plan {
        let normalized = normalize_plan(&plan);
        tags.insert("billing.plan".to_string(), normalized.clone());
        tags.insert(
            "billing.plan_kind".to_string(),
            map_plan_kind(normalized.as_str()).to_string(),
        );
    }

    if let Some(used_percent) = root
        .pointer("/rate_limit/primary_window/used_percent")
        .and_then(Value::as_u64)
    {
        tags.insert(
            "billing.limit_primary_used_pct".to_string(),
            used_percent.to_string(),
        );
    }
}

fn extract_claude_tags(root: &Value, tags: &mut BTreeMap<String, String>) {
    if let Some(status) = root.get("status").and_then(Value::as_str) {
        tags.insert(
            "billing.subscription_status".to_string(),
            status.to_string(),
        );
    }
    if let Some(interval) = root.get("billing_interval").and_then(Value::as_str) {
        tags.insert("billing.billing_interval".to_string(), interval.to_string());
    }
    if let Some(billing_type) = root.get("billing_type").and_then(Value::as_str) {
        tags.insert("billing.billing_type".to_string(), billing_type.to_string());
    }
    if let Some(rate_limit_tier) = root.get("rate_limit_tier").and_then(Value::as_str) {
        tags.insert(
            "billing.rate_limit_tier".to_string(),
            rate_limit_tier.to_string(),
        );
        let normalized = normalize_plan(rate_limit_tier);
        if normalized.contains("max") {
            tags.insert("billing.plan".to_string(), "max".to_string());
            tags.insert(
                "billing.plan_kind".to_string(),
                map_plan_kind("max").to_string(),
            );
        } else if normalized.contains("pro") {
            tags.insert("billing.plan".to_string(), "pro".to_string());
            tags.insert(
                "billing.plan_kind".to_string(),
                map_plan_kind("pro").to_string(),
            );
        }
    }
    if let Some(free_credits) = root.get("free_credits_status").and_then(Value::as_str) {
        tags.insert(
            "billing.free_credits_status".to_string(),
            free_credits.to_string(),
        );
        if !tags.contains_key("billing.plan") && free_credits.eq_ignore_ascii_case("available") {
            tags.insert("billing.plan".to_string(), "free".to_string());
            tags.insert(
                "billing.plan_kind".to_string(),
                map_plan_kind("free").to_string(),
            );
        }
    }
}

pub fn extract_subscription_tags(
    provider: &str,
    host: &str,
    path: &str,
    response_body: &str,
) -> BTreeMap<String, String> {
    let host_lc = host.to_ascii_lowercase();
    let provider_lc = provider.to_ascii_lowercase();

    let is_chatgpt_app = provider_lc == "chatgpt"
        || host_lc.contains("chatgpt.com")
        || host_lc.contains("chat.openai.com");
    let is_claude_app = provider_lc == "claude-web" || host_lc == "claude.ai";

    if !(is_chatgpt_app || is_claude_app) {
        return BTreeMap::new();
    }

    let should_parse = if is_chatgpt_app {
        looks_like_chatgpt_usage_path(path)
    } else {
        looks_like_claude_subscription_path(path)
    };
    if !should_parse {
        return BTreeMap::new();
    }

    let Some(root) = parse_json(response_body) else {
        return BTreeMap::new();
    };

    let mut tags = BTreeMap::new();
    if is_chatgpt_app {
        extract_chatgpt_tags(path, &root, &mut tags);
        if !tags.is_empty() {
            tags.insert(
                "billing.detect_source".to_string(),
                "agent_usage_endpoint".to_string(),
            );
        }
    } else if is_claude_app {
        extract_claude_tags(&root, &mut tags);
        if !tags.is_empty() {
            tags.insert(
                "billing.detect_source".to_string(),
                "agent_subscription_endpoint".to_string(),
            );
        }
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::extract_subscription_tags;

    #[test]
    fn extracts_chatgpt_wham_usage_plan() {
        let body = r#"{"plan_type":"pro","rate_limit":{"primary_window":{"used_percent":42}}}"#;
        let tags =
            extract_subscription_tags("chatgpt", "chatgpt.com", "/backend-api/wham/usage", body);
        assert_eq!(tags.get("billing.plan").map(String::as_str), Some("pro"));
        assert_eq!(
            tags.get("billing.plan_kind").map(String::as_str),
            Some("individual")
        );
        assert_eq!(
            tags.get("billing.limit_primary_used_pct")
                .map(String::as_str),
            Some("42")
        );
    }

    #[test]
    fn extracts_chatgpt_accounts_check_plan() {
        let body = r#"{"accounts":{"acct_1":{"account":{"plan_type":"plus"}}}}"#;
        let tags = extract_subscription_tags(
            "chatgpt",
            "chatgpt.com",
            "/backend-api/accounts/check/v4-2023-04-27",
            body,
        );
        assert_eq!(tags.get("billing.plan").map(String::as_str), Some("plus"));
        assert_eq!(
            tags.get("billing.plan_kind").map(String::as_str),
            Some("individual")
        );
    }

    #[test]
    fn extracts_claude_subscription_fields() {
        let body = r#"{"status":"active","billing_interval":"monthly","billing_type":"stripe_subscription","rate_limit_tier":"default_claude_max_20x"}"#;
        let tags = extract_subscription_tags(
            "claude-web",
            "claude.ai",
            "/api/organizations/org/subscription_details",
            body,
        );
        assert_eq!(
            tags.get("billing.subscription_status").map(String::as_str),
            Some("active")
        );
        assert_eq!(
            tags.get("billing.billing_interval").map(String::as_str),
            Some("monthly")
        );
        assert_eq!(tags.get("billing.plan").map(String::as_str), Some("max"));
    }
}

use soth_core::RequestHeaders;

use crate::gating::stage0_tls::host_pattern_matches;

pub fn origin_allowed(
    headers: &RequestHeaders,
    allowed_host_origins: &std::collections::HashSet<String>,
) -> bool {
    ["origin", "referer"]
        .iter()
        .filter_map(|name| header_value(headers, name))
        .filter_map(extract_host_from_url)
        .any(|host| {
            allowed_host_origins
                .iter()
                .any(|pattern| host_pattern_matches(pattern, host.as_str()))
        })
}

pub fn extract_host_from_url(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_scheme = if let Some((_, rest)) = trimmed.split_once("://") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("//") {
        rest
    } else {
        trimmed
    };

    let authority = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim();
    if authority.is_empty() {
        return None;
    }

    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }

    let host = if authority.starts_with('[') {
        let end = authority.find(']')?;
        &authority[1..end]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };

    let normalized = host.trim().trim_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn header_value<'a>(headers: &'a RequestHeaders, key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(k, v)| k.eq_ignore_ascii_case(key).then_some(v.as_str()))
}

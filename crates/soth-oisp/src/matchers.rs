use crate::types::bundle::DomainIndexEntry;

pub(crate) fn select_best_domain_match<'a>(
    entries: &'a [DomainIndexEntry],
    host: &str,
) -> Option<&'a DomainIndexEntry> {
    let host = normalize_host_for_matching(host);

    if let Some(exact) = entries
        .iter()
        .find(|entry| !entry.host.contains('*') && entry.host.eq_ignore_ascii_case(host.as_str()))
    {
        return Some(exact);
    }

    entries
        .iter()
        .filter(|entry| entry.host.contains('*'))
        .filter(|entry| host_matches_pattern(host.as_str(), entry.host.as_str()))
        .max_by_key(|entry| wildcard_specificity(entry.host.as_str()))
}

fn wildcard_specificity(pattern: &str) -> usize {
    pattern.chars().filter(|ch| *ch != '*').count()
}

pub(crate) fn contains_noise_keyword_for_host(host: &str, path: &str, keywords: &[String]) -> bool {
    if keywords.is_empty() {
        return false;
    }

    let lower_host = normalize_host_for_matching(host);
    let lower_path = path.to_ascii_lowercase();
    keywords.iter().any(|keyword| {
        let candidate = keyword.trim().to_ascii_lowercase();
        if candidate.is_empty() {
            return false;
        }

        // Host-scoped noise rule: "<host-pattern>/<path-fragment>".
        // Example: "api.anthropic.com/api/hello" or "*.chatgpt.com/backend-api/wham/usage".
        if let Some(slash_idx) = candidate.find('/') {
            if slash_idx > 0 {
                let host_pattern = &candidate[..slash_idx];
                let path_fragment = &candidate[slash_idx..];
                return host_matches_pattern(lower_host.as_str(), host_pattern)
                    && lower_path.contains(path_fragment);
            }
        }

        lower_path.contains(&candidate)
    })
}

pub(crate) fn contains_noise_keyword_text(text: &str, keywords: &[String]) -> bool {
    if keywords.is_empty() {
        return false;
    }

    let lower = text.to_ascii_lowercase();
    keywords.iter().any(|keyword| {
        let candidate = keyword.trim().to_ascii_lowercase();
        if candidate.is_empty() {
            return false;
        }

        // Host-scoped entries are only evaluated in host+path context.
        if candidate.find('/').is_some_and(|idx| idx > 0) {
            return false;
        }
        lower.contains(&candidate)
    })
}

pub(crate) fn host_matches_any(host: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| host_matches_pattern(host, pattern))
}

pub(crate) fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = normalize_host_for_matching(host);
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();

    if !pattern.contains('*') {
        return host == pattern;
    }

    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        let suffix = &pattern[star_pos + 1..];
        if host.starts_with(prefix) && host.ends_with(suffix) {
            let middle_len = host.len().saturating_sub(prefix.len() + suffix.len());
            return middle_len > 0;
        }
    }

    false
}

pub(crate) fn normalize_host_for_matching(host: &str) -> String {
    let mut value = host.trim();

    if let Some(rest) = value.strip_prefix("http://") {
        value = rest;
    } else if let Some(rest) = value.strip_prefix("https://") {
        value = rest;
    }

    if let Some((authority, _)) = value.split_once('/') {
        value = authority;
    }

    if let Some(stripped) = value.strip_suffix('.') {
        value = stripped;
    }

    // Bracketed IPv6 literal: [::1]:443 or [::1]
    if let Some(inner) = value.strip_prefix('[').and_then(|rest| {
        let end = rest.find(']')?;
        Some(&rest[..end])
    }) {
        return inner.to_ascii_lowercase();
    }

    if let Some((host_part, port_part)) = value.rsplit_once(':') {
        if !host_part.contains(':')
            && !host_part.is_empty()
            && !port_part.is_empty()
            && port_part.chars().all(|ch| ch.is_ascii_digit())
        {
            value = host_part;
        }
    }

    value.to_ascii_lowercase()
}

pub(crate) fn path_matches_any(path: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| path_matches_pattern(path, pattern.as_str()))
}

pub(crate) fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let mut pattern = pattern.trim().to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    while pattern.contains("**") {
        pattern = pattern.replace("**", "*");
    }
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return path == pattern || (pattern.ends_with('/') && path.starts_with(pattern.as_str()));
    }
    wildcard_match(path.as_str(), pattern.as_str())
}

pub(crate) fn wildcard_match(text: &str, pattern: &str) -> bool {
    let text = text.as_bytes();
    let pattern = pattern.as_bytes();
    let mut text_idx = 0usize;
    let mut pattern_idx = 0usize;
    let mut last_star: Option<usize> = None;
    let mut last_match = 0usize;

    while text_idx < text.len() {
        if pattern_idx < pattern.len() && pattern[pattern_idx] == text[text_idx] {
            text_idx += 1;
            pattern_idx += 1;
            continue;
        }

        if pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
            last_star = Some(pattern_idx);
            pattern_idx += 1;
            last_match = text_idx;
            continue;
        }

        if let Some(star_idx) = last_star {
            pattern_idx = star_idx + 1;
            last_match += 1;
            text_idx = last_match;
            continue;
        }

        return false;
    }

    while pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
        pattern_idx += 1;
    }

    pattern_idx == pattern.len()
}

use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct HostMatcher {
    exact_only: HashSet<String>,
    suffix: Vec<String>,
    globs: Vec<String>,
}

impl HostMatcher {
    pub fn from_patterns(patterns: &HashSet<String>) -> Self {
        let mut exact_only = HashSet::new();
        let mut suffix = Vec::new();
        let mut globs = Vec::new();

        for pattern in patterns {
            let pattern = pattern.trim().to_ascii_lowercase();
            if pattern.is_empty() {
                continue;
            }

            if let Some(exact) = pattern.strip_prefix('=') {
                if !exact.is_empty() {
                    exact_only.insert(exact.to_string());
                }
                continue;
            }

            if pattern.contains('*') {
                globs.push(pattern);
            } else {
                suffix.push(pattern);
            }
        }

        Self {
            exact_only,
            suffix,
            globs,
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }

        if self.exact_only.contains(host.as_str()) {
            return true;
        }

        if self
            .suffix
            .iter()
            .any(|pattern| host == *pattern || host.ends_with(format!(".{pattern}").as_str()))
        {
            return true;
        }

        self.globs
            .iter()
            .any(|pattern| wildcard_match(pattern.as_str(), host.as_str()))
    }
}

pub fn normalize_sni(value: &str) -> String {
    value
        .split(':')
        .next()
        .unwrap_or(value)
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase()
}

pub fn matches_patterns(patterns: &HashSet<String>, host: &str) -> bool {
    HostMatcher::from_patterns(patterns).matches(host)
}

pub fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if let Some(exact) = pattern.strip_prefix('=') {
        return host == exact;
    }
    if pattern == host {
        return true;
    }
    if pattern.contains('*') {
        return wildcard_match(pattern.as_str(), host.as_str());
    }
    host == pattern || host.ends_with(format!(".{pattern}").as_str())
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern.eq_ignore_ascii_case(text);
    }

    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }

    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        let is_first = idx == 0;
        let is_last = idx + 1 == parts.len();

        if is_first && !starts_with_wildcard {
            if !text[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
            continue;
        }

        if is_last && !ends_with_wildcard {
            return text.ends_with(part);
        }

        if let Some(offset) = text[cursor..].find(part) {
            cursor += offset + part.len();
        } else {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_pattern_supports_exact_suffix_and_glob() {
        assert!(host_pattern_matches("=ab.chatgpt.com", "ab.chatgpt.com"));
        assert!(!host_pattern_matches(
            "=ab.chatgpt.com",
            "foo.ab.chatgpt.com"
        ));
        assert!(host_pattern_matches("api.openai.com", "api.openai.com"));
        assert!(host_pattern_matches("openai.com", "api.openai.com"));
        assert!(host_pattern_matches("*.openai.com", "api.openai.com"));
        assert!(!host_pattern_matches("api.openai.com", "openai.com"));
    }

    #[test]
    fn compiled_host_matcher_matches_exact_suffix_and_glob() {
        let patterns = HashSet::from([
            "=ab.chatgpt.com".to_string(),
            "openai.com".to_string(),
            "*.anthropic.com".to_string(),
        ]);
        let matcher = HostMatcher::from_patterns(&patterns);

        assert!(matcher.matches("ab.chatgpt.com"));
        assert!(!matcher.matches("x.ab.chatgpt.com"));
        assert!(matcher.matches("api.openai.com"));
        assert!(matcher.matches("console.anthropic.com"));
        assert!(!matcher.matches("example.invalid"));
    }
}

use crate::CollectorSource;
use globset::Glob;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tracing::warn;
use walkdir::WalkDir;

pub(crate) fn resolve_collector_sources_for_scan(
    sources: &[CollectorSource],
) -> Vec<CollectorSource> {
    let mut resolved = Vec::new();
    let mut seen = BTreeSet::new();

    for source in sources {
        for path in expand_source_paths_for_scan(&source.path) {
            if source_path_matches_skip_patterns(&path, &source.skip_patterns) {
                continue;
            }
            let key = format!(
                "{}|{}|{}",
                source.name,
                source.agent.clone().unwrap_or_default(),
                path.to_string_lossy()
            );
            if !seen.insert(key) {
                continue;
            }
            let mut resolved_source = source.clone();
            resolved_source.path = path;
            resolved.push(resolved_source);
        }
    }

    resolved
}

pub(crate) fn expand_source_paths_for_scan(path: &Path) -> Vec<PathBuf> {
    if !source_path_contains_glob(path) {
        return vec![path.to_path_buf()];
    }

    let pattern = normalize_glob_path(path);
    let Some(matcher) = build_glob_matcher(&pattern) else {
        return Vec::new();
    };

    let root = glob_search_root(&pattern);
    if !root.exists() {
        return Vec::new();
    }

    let mut matches = if root.is_file() {
        if matcher.is_match(normalize_glob_path(&root)) {
            vec![root]
        } else {
            Vec::new()
        }
    } else {
        WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.into_path())
            .filter(|candidate| matcher.is_match(normalize_glob_path(candidate)))
            .collect::<Vec<_>>()
    };

    matches.sort_by(|left, right| left.to_string_lossy().cmp(&right.to_string_lossy()));
    matches.dedup();
    matches
}

pub(crate) fn source_path_matches_skip_patterns(path: &Path, skip_patterns: &[String]) -> bool {
    if skip_patterns.is_empty() {
        return false;
    }

    let normalized_path = normalize_glob_path(path);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();

    skip_patterns.iter().any(|pattern| {
        let normalized_pattern = normalize_skip_pattern(pattern);
        let Some(matcher) = build_glob_matcher(&normalized_pattern) else {
            return false;
        };
        matcher.is_match(&normalized_path) || matcher.is_match(file_name)
    })
}

pub(crate) fn normalize_glob_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
pub(crate) fn glob_pattern_matches(pattern: &str, candidate: &str) -> bool {
    build_glob_matcher(pattern)
        .map(|matcher| matcher.is_match(candidate))
        .unwrap_or(false)
}

fn source_path_contains_glob(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    raw.contains('*') || raw.contains('?')
}

fn normalize_skip_pattern(pattern: &str) -> String {
    if pattern.starts_with("~/") {
        expand_home_pattern(pattern)
            .map(|expanded| normalize_glob_path(&expanded))
            .unwrap_or_else(|| pattern.replace('\\', "/"))
    } else {
        pattern.replace('\\', "/")
    }
}

fn expand_home_pattern(pattern: &str) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let suffix = pattern.strip_prefix("~/")?;
    Some(home.join(suffix))
}

fn glob_search_root(pattern: &str) -> PathBuf {
    let first_meta = pattern.find(|ch| matches!(ch, '*' | '?'));
    let Some(meta_index) = first_meta else {
        return PathBuf::from(pattern);
    };
    let prefix = &pattern[..meta_index];
    let last_sep = prefix.rfind(|ch| matches!(ch, '/' | '\\'));
    match last_sep {
        Some(0) if pattern.starts_with('/') => PathBuf::from("/"),
        Some(index) if index > 0 => PathBuf::from(&pattern[..index]),
        _ if pattern.starts_with('/') => PathBuf::from("/"),
        _ => PathBuf::from("."),
    }
}

fn build_glob_matcher(pattern: &str) -> Option<globset::GlobMatcher> {
    let normalized_pattern = enforce_recursive_depth(pattern);
    match Glob::new(&normalized_pattern) {
        Ok(glob) => Some(glob.compile_matcher()),
        Err(error) => {
            warn!(pattern = normalized_pattern, error = %error, "collector glob pattern is invalid");
            None
        }
    }
}

fn enforce_recursive_depth(pattern: &str) -> String {
    pattern.replace("**/", "*/**/")
}

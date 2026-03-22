use soth_core::{IdentityEntry, IdentityIndex, ProcessInfo, ProcessMatchKind};

use crate::gating::stage0_tls::host_pattern_matches;

#[derive(Debug, Clone)]
pub struct IdentityMatch {
    pub entry: IdentityEntry,
    pub match_kind: ProcessMatchKind,
}

pub fn resolve_identity(index: &IdentityIndex, info: &ProcessInfo) -> Option<IdentityMatch> {
    let candidates = [info.bundle_id.as_deref(), info.process_name.as_deref()];
    for key in candidates.into_iter().flatten() {
        let normalized = key.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }

        if let Some(entry) = index.hosts.get(normalized.as_str()) {
            return Some(IdentityMatch {
                entry: entry.clone(),
                match_kind: ProcessMatchKind::Exact,
            });
        }
        if let Some(entry) = index.non_hosts.get(normalized.as_str()) {
            return Some(IdentityMatch {
                entry: entry.clone(),
                match_kind: ProcessMatchKind::Exact,
            });
        }

        if let Some(entry) = glob_lookup(&index.hosts, normalized.as_str()) {
            return Some(IdentityMatch {
                entry,
                match_kind: ProcessMatchKind::Pattern,
            });
        }
        if let Some(entry) = glob_lookup(&index.non_hosts, normalized.as_str()) {
            return Some(IdentityMatch {
                entry,
                match_kind: ProcessMatchKind::Pattern,
            });
        }
    }
    None
}

fn glob_lookup(
    map: &std::collections::HashMap<String, IdentityEntry>,
    value: &str,
) -> Option<IdentityEntry> {
    map.iter()
        .find(|(pattern, _)| pattern.contains('*') && host_pattern_matches(pattern, value))
        .map(|(_, entry)| entry.clone())
}

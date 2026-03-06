use crate::types::{AppIdentity, AppKind, ApplicationEntry, DetectBundleSlice, ProcessInfo};
use crate::util::host_without_port;
use serde_json::Value as JsonValue;

pub fn resolve_app_identity(
    process_info: &ProcessInfo,
    bundle: &DetectBundleSlice<'_>,
) -> AppIdentity {
    resolve_app_identity_for_host(process_info, None, bundle)
}

pub fn resolve_app_identity_for_host(
    process_info: &ProcessInfo,
    host: Option<&str>,
    bundle: &DetectBundleSlice<'_>,
) -> AppIdentity {
    let host_lc = host.map(|value| host_without_port(value).to_ascii_lowercase());

    if let Some(bundle_id) = process_info.bundle_id.as_deref() {
        if let Some((app_id, app)) = find_by_bundle_id(bundle_id, bundle) {
            let mut confidence: f32 = 0.9;
            if host_matches_detection(app, host_lc.as_deref()) {
                confidence = (confidence + 0.05f32).min(1.0f32);
            }
            return AppIdentity {
                app_id: app_id.to_string(),
                display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                app_kind: app_kind_for_application(app),
                is_known: true,
                confidence,
            };
        }
    }

    if let Some(process_name) = process_info.process_name.as_deref() {
        if let Some((app_id, app)) = find_by_process_name(process_name, bundle) {
            let mut confidence: f32 = 0.8;
            if host_matches_detection(app, host_lc.as_deref()) {
                confidence = (confidence + 0.1f32).min(1.0f32);
            }
            return AppIdentity {
                app_id: app_id.to_string(),
                display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                app_kind: app_kind_for_application(app),
                is_known: true,
                confidence,
            };
        }
    }

    if let Some(parent) = process_info.parent_process_name.as_deref() {
        if is_script_runtime(process_info.process_name.as_deref()) {
            if let Some((app_id, app)) = find_by_process_name(parent, bundle) {
                let mut confidence: f32 = 0.6;
                if host_matches_detection(app, host_lc.as_deref()) {
                    confidence = (confidence + 0.1f32).min(1.0f32);
                }
                return AppIdentity {
                    app_id: app_id.to_string(),
                    display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                    app_kind: app_kind_for_application(app),
                    is_known: true,
                    confidence,
                };
            }
        }
    }

    if let Some(host_value) = host_lc.as_deref() {
        if let Some((app_id, app)) = find_by_detection_host(host_value, bundle) {
            return AppIdentity {
                app_id: app_id.to_string(),
                display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                app_kind: app_kind_for_application(app),
                is_known: true,
                confidence: 0.55,
            };
        }
    }

    AppIdentity::default()
}

fn find_by_process_name<'a>(
    process_name: &str,
    bundle: &'a DetectBundleSlice<'_>,
) -> Option<(&'a String, &'a ApplicationEntry)> {
    let process_lc = process_name.to_ascii_lowercase();

    bundle.applications.iter().find(|(_, app)| {
        app.process_names
            .iter()
            .any(|name| process_lc.contains(&name.to_ascii_lowercase()))
            || app
                .name
                .as_ref()
                .map(|name| process_lc.contains(&name.to_ascii_lowercase()))
                .unwrap_or(false)
    })
}

fn find_by_bundle_id<'a>(
    bundle_id: &str,
    bundle: &'a DetectBundleSlice<'_>,
) -> Option<(&'a String, &'a ApplicationEntry)> {
    bundle.applications.iter().find(|(_, app)| {
        app.bundle_ids
            .iter()
            .any(|item| item.eq_ignore_ascii_case(bundle_id))
    })
}

fn find_by_detection_host<'a>(
    host_lc: &str,
    bundle: &'a DetectBundleSlice<'_>,
) -> Option<(&'a String, &'a ApplicationEntry)> {
    bundle
        .applications
        .iter()
        .find(|(_, app)| host_matches_detection(app, Some(host_lc)))
}

fn is_script_runtime(process_name: Option<&str>) -> bool {
    let Some(name) = process_name else {
        return false;
    };

    let lower = name.to_ascii_lowercase();
    [
        "python", "python3", "node", "bun", "deno", "ruby", "bash", "zsh",
    ]
    .iter()
    .any(|item| lower.contains(item))
}

fn app_kind_for_application(app: &ApplicationEntry) -> AppKind {
    match app
        .app_type
        .as_deref()
        .map(|value| value.to_ascii_lowercase())
    {
        Some(kind) if kind == "browser" || kind == "host" => AppKind::Browser,
        Some(kind) if kind == "ide" => AppKind::Ide,
        Some(kind) if kind == "cli" => AppKind::Cli,
        Some(kind) if kind == "agent_app" || kind == "agent-app" || kind == "non_host" => {
            AppKind::AgentApp
        }
        _ => AppKind::AgentApp,
    }
}

fn host_matches_detection(app: &ApplicationEntry, host_lc: Option<&str>) -> bool {
    let Some(host_lc) = host_lc else {
        return false;
    };
    let Some(detection) = app.detection.as_ref() else {
        return false;
    };
    let Some(hosts) = detection.get("hosts").and_then(JsonValue::as_array) else {
        return false;
    };
    hosts
        .iter()
        .filter_map(|entry| entry.get("pattern").and_then(JsonValue::as_str))
        .map(|pattern| pattern.to_ascii_lowercase())
        .any(|pattern| glob_match(pattern.as_str(), host_lc))
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let starts_anchored = !pattern.starts_with('*');
    let ends_anchored = !pattern.ends_with('*');

    let mut index = 0usize;
    let mut first_non_empty = true;
    for part in parts.iter().copied().filter(|part| !part.is_empty()) {
        if first_non_empty && starts_anchored {
            if !text[index..].starts_with(part) {
                return false;
            }
            index += part.len();
            first_non_empty = false;
            continue;
        }

        match text[index..].find(part) {
            Some(pos) => index += pos + part.len(),
            None => return false,
        }
        first_non_empty = false;
    }

    if ends_anchored {
        let last_non_empty = pattern
            .split('*')
            .filter(|part| !part.is_empty())
            .next_back()
            .unwrap_or("");
        text.ends_with(last_non_empty)
    } else {
        true
    }
}

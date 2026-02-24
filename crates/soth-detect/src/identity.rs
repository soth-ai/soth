use crate::types::{AppIdentity, AppKind, ApplicationEntry, DetectBundleSlice, ProcessInfo};

pub fn resolve_app_identity(
    process_info: &ProcessInfo,
    bundle: &DetectBundleSlice<'_>,
) -> AppIdentity {
    if let Some(bundle_id) = process_info.bundle_id.as_deref() {
        if let Some(policy) = bundle.app_policies.get(bundle_id) {
            let mut app_kind = policy.app_kind.clone();
            if app_kind == AppKind::Browser
                && bundle
                    .browser_policies
                    .allowed_apps
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(bundle_id))
            {
                app_kind = AppKind::AgentApp;
            }

            return AppIdentity {
                app_id: policy.app_id.clone(),
                display_name: policy
                    .display_name
                    .clone()
                    .unwrap_or_else(|| policy.app_id.clone()),
                app_kind,
                is_known: true,
                confidence: 1.0,
            };
        }
    }

    if let Some(process_name) = process_info.process_name.as_deref() {
        if let Some((app_id, app)) = find_by_process_name(process_name, bundle) {
            return AppIdentity {
                app_id: app_id.to_string(),
                display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                app_kind: AppKind::AgentApp,
                is_known: true,
                confidence: 0.8,
            };
        }
    }

    if let Some(parent) = process_info.parent_process_name.as_deref() {
        if is_script_runtime(process_info.process_name.as_deref()) {
            if let Some((app_id, app)) = find_by_process_name(parent, bundle) {
                return AppIdentity {
                    app_id: app_id.to_string(),
                    display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                    app_kind: AppKind::AgentApp,
                    is_known: true,
                    confidence: 0.6,
                };
            }
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

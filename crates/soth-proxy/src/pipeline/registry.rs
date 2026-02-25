use std::collections::{HashMap, HashSet};

use soth_core::{AppType, CaptureMode};

#[derive(Debug, Clone)]
pub struct ApplicationRule {
    pub app_id: String,
    pub display_name: String,
    pub bundle_ids: Vec<String>,
    pub process_names: Vec<String>,
    pub app_type: AppType,
}

#[derive(Debug, Clone)]
pub struct Registry {
    ai_catalog_hosts: HashSet<String>,
    provider_by_host: HashMap<String, String>,
    applications: Vec<ApplicationRule>,
    blacklist_keywords: Vec<String>,
    capture_rules: soth_detect::CaptureRules,
}

impl Registry {
    pub fn from_detect_bundle(bundle: &soth_detect::OwnedDetectBundle) -> Self {
        let mut ai_catalog_hosts = HashSet::new();
        let mut provider_by_host = HashMap::new();

        for (host, provider_key) in &bundle.domain_index {
            let host_norm = normalize_host(host);
            ai_catalog_hosts.insert(host_norm.clone());

            let provider_name = bundle
                .llm_providers
                .get(provider_key)
                .and_then(|entry| entry.name.clone().or_else(|| entry.provider_id.clone()))
                .unwrap_or_else(|| provider_key.to_string());
            provider_by_host.insert(host_norm, provider_name);
        }

        let mut applications = Vec::new();
        for (key, app) in &bundle.applications {
            let app_id = app.app_id.clone().unwrap_or_else(|| key.to_string());
            let display_name = app.name.clone().unwrap_or_else(|| app_id.clone());
            let app_type = infer_app_type(
                app_id.as_str(),
                display_name.as_str(),
                app.process_names.as_slice(),
            );
            applications.push(ApplicationRule {
                app_id,
                display_name,
                bundle_ids: app
                    .bundle_ids
                    .iter()
                    .map(|value| value.to_ascii_lowercase())
                    .collect(),
                process_names: app
                    .process_names
                    .iter()
                    .map(|value| value.to_ascii_lowercase())
                    .collect(),
                app_type,
            });
        }

        let blacklist_keywords = bundle
            .filters
            .path_keywords
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();

        Self {
            ai_catalog_hosts,
            provider_by_host,
            applications,
            blacklist_keywords,
            capture_rules: bundle.capture_rules.clone(),
        }
    }

    pub fn in_ai_catalog(&self, host: &str) -> bool {
        let host = normalize_host(host);
        self.ai_catalog_hosts.contains(host.as_str())
            || self
                .ai_catalog_hosts
                .iter()
                .any(|candidate| host.ends_with(format!(".{candidate}").as_str()))
    }

    pub fn match_provider(&self, host: &str) -> Option<String> {
        let host = normalize_host(host);

        if let Some(found) = self.provider_by_host.get(host.as_str()) {
            return Some(found.clone());
        }

        self.provider_by_host
            .iter()
            .filter(|(candidate, _)| host.ends_with(format!(".{candidate}").as_str()))
            .max_by_key(|(candidate, _)| candidate.len())
            .map(|(_, provider)| provider.clone())
    }

    pub fn match_application(
        &self,
        process_name: Option<&str>,
        bundle_id: Option<&str>,
    ) -> Option<&ApplicationRule> {
        let process_name = process_name.map(|value| value.to_ascii_lowercase());
        let bundle_id = bundle_id.map(|value| value.to_ascii_lowercase());

        self.applications.iter().find(|rule| {
            let bundle_match = bundle_id.as_ref().is_some_and(|value| {
                rule.bundle_ids
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(value))
            });
            let process_match = process_name.as_ref().is_some_and(|value| {
                rule.process_names.iter().any(|candidate| {
                    value.eq_ignore_ascii_case(candidate)
                        || value.contains(candidate)
                        || candidate.contains(value)
                })
            });
            bundle_match || process_match
        })
    }

    pub fn find_blacklisted_keyword(&self, url_like: &str) -> Option<String> {
        let lowered = url_like.to_ascii_lowercase();
        self.blacklist_keywords
            .iter()
            .find(|keyword| !keyword.is_empty() && lowered.contains(keyword.as_str()))
            .cloned()
    }

    pub fn capture_default_mode(&self) -> CaptureMode {
        self.capture_rules.default_mode.clone()
    }

    pub fn capture_mode_for_provider(&self, provider: Option<&str>) -> CaptureMode {
        match provider {
            Some(name) => {
                let provider = soth_detect::Provider::new(name);
                self.capture_rules.mode_for(&provider)
            }
            None => self.capture_rules.default_mode.clone(),
        }
    }
}

fn normalize_host(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase()
}

fn infer_app_type(app_id: &str, display_name: &str, process_names: &[String]) -> AppType {
    let mut haystacks = Vec::with_capacity(2 + process_names.len());
    haystacks.push(app_id.to_ascii_lowercase());
    haystacks.push(display_name.to_ascii_lowercase());
    haystacks.extend(process_names.iter().map(|value| value.to_ascii_lowercase()));

    let host_markers = [
        "chrome", "firefox", "safari", "edge", "arc", "browser", "brave",
    ];

    if haystacks
        .iter()
        .any(|value| host_markers.iter().any(|marker| value.contains(marker)))
    {
        AppType::Host
    } else {
        AppType::NonHost
    }
}

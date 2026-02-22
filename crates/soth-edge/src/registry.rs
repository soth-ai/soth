//! Registry integration primitives for the SOTH edge runtime.

use crate::normalize::{BundleStreamFormat, BundleStreamParser};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("failed to read bundle from {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse bundle JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("invalid pattern `{pattern}`: {source}")]
    InvalidPattern {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    LlmProvider,
    Application,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptionAction {
    Intercept,
    Tunnel,
    Skip,
    HostOnly,
    Block,
}

impl InterceptionAction {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "intercept" => Self::Intercept,
            "tunnel" => Self::Tunnel,
            "skip" => Self::Skip,
            "host_only" => Self::HostOnly,
            "block" => Self::Block,
            _ => Self::Intercept,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    Full,
    #[default]
    MetadataOnly,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Bundle {
    pub schema_version: u32,
    #[serde(default)]
    pub metadata: BundleMetadata,
    #[serde(default)]
    pub detection_index: HashMap<String, String>,
    #[serde(default)]
    pub llm_providers: HashMap<String, DetectionTarget>,
    #[serde(default)]
    pub applications: HashMap<String, DetectionTarget>,
    #[serde(default)]
    pub catalogs: Catalogs,
    #[serde(default)]
    pub filters: Filters,
    #[serde(default)]
    pub formats: HashMap<String, Value>,
    #[serde(default)]
    pub interception: Interception,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct BundleMetadata {
    #[serde(default)]
    pub bundle_version: String,
    #[serde(default)]
    pub compiled_at: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct Catalogs {
    #[serde(default)]
    pub ai_catalog: Vec<String>,
    #[serde(default)]
    pub analytics_blocklist: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct Filters {
    #[serde(default)]
    pub domain_patterns: Vec<String>,
    #[serde(default)]
    pub path_patterns: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct Interception {
    #[serde(default)]
    pub app_policies: HashMap<String, AppPolicy>,
    #[serde(default)]
    pub browser_policies: BrowserPolicies,
    #[serde(default)]
    pub defaults: InterceptionDefaults,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AppPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_intercept")]
    pub action: String,
    #[serde(default = "default_non_host")]
    pub app_type: String,
    #[serde(default)]
    pub capture_mode: Option<CaptureMode>,
    #[serde(default = "default_allowlist")]
    pub host_filter: String,
    #[serde(default = "default_ai_catalog")]
    pub host_list_ref: String,
}

impl Default for AppPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            action: default_intercept(),
            app_type: default_non_host(),
            capture_mode: Some(CaptureMode::MetadataOnly),
            host_filter: default_allowlist(),
            host_list_ref: default_ai_catalog(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct BrowserPolicies {
    #[serde(default)]
    pub allowed_browsers: Vec<String>,
    #[serde(default)]
    pub allowed_apps: Vec<String>,
    #[serde(default = "default_intercept")]
    pub default_action: String,
}

impl Default for BrowserPolicies {
    fn default() -> Self {
        Self {
            allowed_browsers: Vec::new(),
            allowed_apps: Vec::new(),
            default_action: default_intercept(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct InterceptionDefaults {
    #[serde(default = "default_tunnel")]
    pub non_whitelisted_host_action: String,
    #[serde(default = "default_host_only")]
    pub unknown_app_action: String,
    #[serde(default = "default_intercept")]
    pub whitelisted_unknown_app_action: String,
}

impl Default for InterceptionDefaults {
    fn default() -> Self {
        Self {
            non_whitelisted_host_action: default_tunnel(),
            unknown_app_action: default_host_only(),
            whitelisted_unknown_app_action: default_intercept(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct DetectionTarget {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub target_type: String,
    #[serde(default)]
    pub api_format: Option<String>,
    #[serde(default, alias = "parser_key")]
    pub parser: Option<String>,
    #[serde(default)]
    pub detection: Detection,
    #[serde(default)]
    pub capture: Capture,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct Detection {
    #[serde(default)]
    pub hosts: Vec<HostRule>,
    #[serde(default)]
    pub path_patterns: Vec<String>,
    #[serde(default)]
    pub header_hints: Vec<serde_json::Value>,
    #[serde(default)]
    pub model_rules: Vec<serde_json::Value>,
    #[serde(default)]
    pub env_rules: Vec<serde_json::Value>,
    #[serde(default)]
    pub process_rules: Vec<serde_json::Value>,
    #[serde(default)]
    pub ua_rules: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct HostRule {
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub paths: HostPaths,
    #[serde(default)]
    pub priority: i64,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct HostPaths {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny_exact: Vec<String>,
    #[serde(default)]
    pub deny_glob: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Capture {
    #[serde(default)]
    pub mode: CaptureMode,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for Capture {
    fn default() -> Self {
        Self {
            mode: CaptureMode::MetadataOnly,
            methods: Vec::new(),
            enabled: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetMatch {
    pub key: String,
    pub id: String,
    pub name: String,
    pub kind: TargetKind,
    pub api_format: Option<String>,
    pub parser_key: Option<String>,
    pub capture_mode: CaptureMode,
    pub capture_enabled: bool,
    pub method_allowed: bool,
}

#[derive(Clone, Debug)]
pub struct EdgeRegistry {
    bundle: Bundle,
    detection_index_by_target: HashMap<String, String>,
    ai_catalog_exact: HashSet<String>,
    ai_catalog_suffixes: Vec<String>,
    ai_catalog_patterns: Vec<HostPattern>,
    blacklist_keywords: Vec<String>,
    providers: Vec<CompiledTarget>,
    applications: Vec<CompiledTarget>,
    app_policies: HashMap<String, AppPolicy>,
    browser_ids: HashSet<String>,
    allowed_app_ids: HashSet<String>,
}

impl EdgeRegistry {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| RegistryError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_json_str(&raw)
    }

    pub fn from_json_str(raw: &str) -> Result<Self, RegistryError> {
        let value: Value = serde_json::from_str(raw)?;
        let bundle_value = extract_bundle_payload(value);
        let bundle: Bundle = serde_json::from_value(bundle_value)?;
        Self::from_bundle(bundle)
    }

    pub fn from_bundle(bundle: Bundle) -> Result<Self, RegistryError> {
        let mut ai_catalog_exact = HashSet::new();
        let mut ai_catalog_suffixes = Vec::new();
        let mut ai_catalog_patterns = Vec::new();

        for entry in &bundle.catalogs.ai_catalog {
            let trimmed = entry.trim().to_ascii_lowercase();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed.contains('*') {
                ai_catalog_patterns.push(HostPattern::compile(&trimmed)?);
            } else {
                ai_catalog_suffixes.push(trimmed.clone());
                ai_catalog_exact.insert(trimmed);
            }
        }

        let blacklist_keywords = bundle
            .filters
            .keywords
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect::<Vec<_>>();

        let providers = compile_targets(&bundle.llm_providers, TargetKind::LlmProvider)?;
        let applications = compile_targets(&bundle.applications, TargetKind::Application)?;

        let mut app_policies = HashMap::new();
        for (key, policy) in &bundle.interception.app_policies {
            app_policies.insert(key.to_ascii_lowercase(), policy.clone());
        }

        let browser_ids = bundle
            .interception
            .browser_policies
            .allowed_browsers
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect::<HashSet<_>>();

        let allowed_app_ids = bundle
            .interception
            .browser_policies
            .allowed_apps
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect::<HashSet<_>>();

        let mut detection_index_by_target = HashMap::new();
        for (detection_id, target_id) in &bundle.detection_index {
            let detection_id = detection_id.trim();
            let target_id = target_id.trim().to_ascii_lowercase();
            if detection_id.is_empty() || target_id.is_empty() {
                continue;
            }
            detection_index_by_target.insert(target_id, detection_id.to_string());
        }

        Ok(Self {
            bundle,
            detection_index_by_target,
            ai_catalog_exact,
            ai_catalog_suffixes,
            ai_catalog_patterns,
            blacklist_keywords,
            providers,
            applications,
            app_policies,
            browser_ids,
            allowed_app_ids,
        })
    }

    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    pub fn app_policy_for(&self, process_id: &str) -> Option<&AppPolicy> {
        self.app_policies.get(&process_id.to_ascii_lowercase())
    }

    pub fn is_browser_process(&self, process_id: &str) -> bool {
        self.browser_ids.contains(&process_id.to_ascii_lowercase())
    }

    pub fn is_explicit_allowed_app(&self, process_id: &str) -> bool {
        self.allowed_app_ids
            .contains(&process_id.to_ascii_lowercase())
    }

    pub fn browser_default_action(&self) -> InterceptionAction {
        InterceptionAction::parse(&self.bundle.interception.browser_policies.default_action)
    }

    pub fn non_whitelisted_host_action(&self) -> InterceptionAction {
        InterceptionAction::parse(
            &self
                .bundle
                .interception
                .defaults
                .non_whitelisted_host_action,
        )
    }

    pub fn unknown_app_action(&self) -> InterceptionAction {
        InterceptionAction::parse(&self.bundle.interception.defaults.unknown_app_action)
    }

    pub fn whitelisted_unknown_app_action(&self) -> InterceptionAction {
        InterceptionAction::parse(
            &self
                .bundle
                .interception
                .defaults
                .whitelisted_unknown_app_action,
        )
    }

    pub fn in_ai_catalog(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();

        if self.ai_catalog_exact.contains(&host) {
            return true;
        }

        for suffix in &self.ai_catalog_suffixes {
            if host.ends_with(&format!(".{suffix}")) {
                return true;
            }
        }

        self.ai_catalog_patterns
            .iter()
            .any(|pattern| pattern.is_match(&host))
    }

    pub fn find_blacklisted_keyword<'a>(&'a self, text: &str) -> Option<&'a str> {
        let lower = text.to_ascii_lowercase();
        self.blacklist_keywords
            .iter()
            .find(|keyword| lower.contains(keyword.as_str()))
            .map(String::as_str)
    }

    pub fn detection_id_for_target(&self, target_id: &str) -> Option<String> {
        let key = target_id.trim().to_ascii_lowercase();
        if key.is_empty() {
            return None;
        }
        self.detection_index_by_target.get(&key).cloned()
    }

    pub fn match_provider(&self, host: &str, path: &str, method: &str) -> Option<TargetMatch> {
        self.best_match(&self.providers, host, path, method)
    }

    pub fn match_application(&self, host: &str, path: &str, method: &str) -> Option<TargetMatch> {
        self.best_match(&self.applications, host, path, method)
    }

    pub fn stream_parser_for_match(&self, matched: &TargetMatch) -> Option<BundleStreamParser> {
        let mut keys = Vec::new();
        if let Some(parser_key) = matched.parser_key.as_deref() {
            keys.push(parser_key);
        }
        if let Some(api_format) = matched.api_format.as_deref() {
            if !keys
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(api_format))
            {
                keys.push(api_format);
            }
        }
        if !keys
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(matched.key.as_str()))
        {
            keys.push(matched.key.as_str());
        }

        keys.into_iter()
            .find_map(|key| self.stream_parser_from_format_key(key))
    }

    fn best_match(
        &self,
        targets: &[CompiledTarget],
        host: &str,
        path: &str,
        method: &str,
    ) -> Option<TargetMatch> {
        let host = host.to_ascii_lowercase();
        let path = normalize_path(path);
        let method = method.to_ascii_uppercase();

        let mut best: Option<(MatchScore, &CompiledTarget)> = None;

        for target in targets {
            let Some(score) = target.match_score(&host, &path) else {
                continue;
            };

            if let Some((best_score, _)) = best {
                if score <= best_score {
                    continue;
                }
            }

            best = Some((score, target));
        }

        best.map(|(_, target)| TargetMatch {
            key: target.key.clone(),
            id: target.id.clone(),
            name: target.name.clone(),
            kind: target.kind,
            api_format: target.api_format.clone(),
            parser_key: target.parser_key.clone(),
            capture_mode: target.capture_mode.clone(),
            capture_enabled: target.capture_enabled,
            method_allowed: target.capture_methods.is_empty()
                || target.capture_methods.contains(&method),
        })
    }

    fn stream_parser_from_format_key(&self, key: &str) -> Option<BundleStreamParser> {
        let format_value = self.bundle.formats.get(key).or_else(|| {
            self.bundle
                .formats
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
                .map(|(_, value)| value)
        })?;

        let stream = format_value.get("response").and_then(|response| {
            response
                .as_object()
                .and_then(|value| value.get("stream"))
                .filter(|value| !value.is_null())
        })?;

        let format = stream
            .get("format")
            .and_then(Value::as_str)
            .map(BundleStreamFormat::parse)
            .unwrap_or(BundleStreamFormat::Sse);

        let prefixes = stream
            .get("format_options")
            .and_then(|value| value.get("prefixes"))
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["data: ".to_string()]);

        let skip_values = stream
            .get("format_options")
            .and_then(|value| value.get("skip_values"))
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["[DONE]".to_string()]);

        Some(BundleStreamParser {
            format,
            prefixes,
            skip_values,
        })
    }
}

fn extract_bundle_payload(root: Value) -> Value {
    let Some(object) = root.as_object() else {
        return root;
    };

    if let Some(inner) = object.get("bundle").cloned() {
        return inner;
    }
    if let Some(inner) = object.get("compiled_bundle").cloned() {
        return inner;
    }
    if let Some(inner) = object
        .get("data")
        .and_then(Value::as_object)
        .and_then(|value| value.get("bundle"))
        .cloned()
    {
        return inner;
    }
    if let Some(inner) = object
        .get("data")
        .and_then(Value::as_object)
        .and_then(|value| value.get("compiled_bundle"))
        .cloned()
    {
        return inner;
    }

    root
}

#[derive(Clone, Debug)]
struct CompiledTarget {
    key: String,
    id: String,
    name: String,
    kind: TargetKind,
    api_format: Option<String>,
    parser_key: Option<String>,
    host_rules: Vec<CompiledHostRule>,
    path_patterns: Vec<UrlPatternMatcher>,
    capture_mode: CaptureMode,
    capture_enabled: bool,
    capture_methods: HashSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MatchScore {
    priority: i64,
    specificity: usize,
    path_hint_matched: bool,
}

impl CompiledTarget {
    fn match_score(&self, host: &str, path: &str) -> Option<MatchScore> {
        let host_score = self
            .host_rules
            .iter()
            .find_map(|rule| rule.matches(host, path).then_some(rule.score))?;

        let path_hint_matched = if self.path_patterns.is_empty() {
            false
        } else {
            let full = format!("{host}{path}");
            self.path_patterns
                .iter()
                .any(|pattern| pattern.is_match(path) || pattern.is_match(&full))
        };

        Some(MatchScore {
            priority: host_score.priority,
            specificity: host_score.specificity,
            path_hint_matched,
        })
    }
}

#[derive(Clone, Debug)]
struct CompiledHostRule {
    pattern: HostPattern,
    allow_paths: Vec<UrlPatternMatcher>,
    deny_exact: HashSet<String>,
    deny_glob: Vec<UrlPatternMatcher>,
    score: MatchScore,
}

impl CompiledHostRule {
    fn matches(&self, host: &str, path: &str) -> bool {
        if !self.pattern.is_match(host) {
            return false;
        }

        if self.deny_exact.contains(path) {
            return false;
        }

        if self.deny_glob.iter().any(|pattern| pattern.is_match(path)) {
            return false;
        }

        if self.allow_paths.is_empty() {
            return true;
        }

        self.allow_paths
            .iter()
            .any(|pattern| pattern.is_match(path))
    }
}

#[derive(Clone, Debug)]
enum HostPattern {
    Exact(String),
    WildcardSuffix(String),
    Regex(Regex),
}

impl HostPattern {
    fn compile(pattern: &str) -> Result<Self, RegistryError> {
        let pattern = pattern.trim().to_ascii_lowercase();

        if let Some(suffix) = pattern.strip_prefix("*.") {
            return Ok(Self::WildcardSuffix(suffix.to_string()));
        }

        if pattern.contains('*') {
            let regex =
                glob_host_to_regex(&pattern).map_err(|source| RegistryError::InvalidPattern {
                    pattern: pattern.clone(),
                    source,
                })?;
            return Ok(Self::Regex(regex));
        }

        Ok(Self::Exact(pattern))
    }

    fn is_match(&self, host: &str) -> bool {
        match self {
            Self::Exact(exact) => host == exact,
            Self::WildcardSuffix(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            Self::Regex(regex) => regex.is_match(host),
        }
    }
}

#[derive(Clone, Debug)]
struct UrlPatternMatcher {
    regex: Regex,
}

impl UrlPatternMatcher {
    fn compile(pattern: &str) -> Result<Self, RegistryError> {
        let regex_str = build_url_regex(pattern);
        let regex = Regex::new(&regex_str).map_err(|source| RegistryError::InvalidPattern {
            pattern: pattern.to_string(),
            source,
        })?;
        Ok(Self { regex })
    }

    fn is_match(&self, input: &str) -> bool {
        self.regex.is_match(&input.to_ascii_lowercase())
    }
}

fn compile_targets(
    targets: &HashMap<String, DetectionTarget>,
    kind: TargetKind,
) -> Result<Vec<CompiledTarget>, RegistryError> {
    let mut compiled = Vec::with_capacity(targets.len());

    for (key, target) in targets {
        let mut host_rules = Vec::new();

        for host_rule in &target.detection.hosts {
            let pattern = HostPattern::compile(&host_rule.pattern)?;

            let mut allow_paths = Vec::new();
            for path in &host_rule.paths.allow {
                allow_paths.push(UrlPatternMatcher::compile(path)?);
            }

            let deny_exact = host_rule
                .paths
                .deny_exact
                .iter()
                .map(|path| normalize_path(path))
                .collect::<HashSet<_>>();

            let mut deny_glob = Vec::new();
            for path in &host_rule.paths.deny_glob {
                deny_glob.push(UrlPatternMatcher::compile(path)?);
            }

            host_rules.push(CompiledHostRule {
                pattern,
                allow_paths,
                deny_exact,
                deny_glob,
                score: MatchScore {
                    priority: host_rule.priority,
                    specificity: host_rule.pattern.len(),
                    path_hint_matched: false,
                },
            });
        }

        host_rules.sort_by(|left, right| right.score.cmp(&left.score));

        let mut path_patterns = Vec::new();
        for pattern in &target.detection.path_patterns {
            path_patterns.push(UrlPatternMatcher::compile(pattern)?);
        }

        let capture_methods = target
            .capture
            .methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect::<HashSet<_>>();

        compiled.push(CompiledTarget {
            key: key.clone(),
            id: if target.id.is_empty() {
                key.clone()
            } else {
                target.id.clone()
            },
            name: if target.name.is_empty() {
                key.clone()
            } else {
                target.name.clone()
            },
            kind,
            api_format: target
                .api_format
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
            parser_key: target
                .parser
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .or_else(|| {
                    target
                        .api_format
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToString::to_string)
                }),
            host_rules,
            path_patterns,
            capture_mode: target.capture.mode.clone(),
            capture_enabled: target.capture.enabled,
            capture_methods,
        });
    }

    compiled.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(compiled)
}

fn glob_host_to_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let escaped = regex::escape(&pattern.to_ascii_lowercase()).replace(r"\*", ".*");
    Regex::new(&format!("^{escaped}$"))
}

fn build_url_regex(pattern: &str) -> String {
    let pattern = pattern.to_ascii_lowercase();
    let bytes = pattern.as_bytes();
    let mut regex = String::from("^");
    let mut idx = 0;

    while idx < bytes.len() {
        if idx + 4 <= bytes.len() && &bytes[idx..idx + 4] == b"/**/" {
            regex.push_str("(?:/|/.*/)");
            idx += 4;
            continue;
        }

        if idx + 2 <= bytes.len() && &bytes[idx..idx + 2] == b"**" {
            regex.push_str(".*");
            idx += 2;
            continue;
        }

        if bytes[idx] == b'*' {
            regex.push_str("[^/]*");
            idx += 1;
            continue;
        }

        let ch = bytes[idx] as char;
        if matches!(
            ch,
            '.' | '?' | '+' | '^' | '$' | '{' | '}' | '[' | ']' | '|' | '(' | ')' | '\\'
        ) {
            regex.push('\\');
        }

        regex.push(ch);
        idx += 1;
    }

    regex
}

pub fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }

    if path.starts_with('/') {
        return path.to_ascii_lowercase();
    }

    format!("/{}", path.to_ascii_lowercase())
}

fn default_true() -> bool {
    true
}

fn default_intercept() -> String {
    "intercept".to_string()
}

fn default_tunnel() -> String {
    "tunnel".to_string()
}

fn default_host_only() -> String {
    "host_only".to_string()
}

fn default_non_host() -> String {
    "non_host".to_string()
}

fn default_allowlist() -> String {
    "allowlist".to_string()
}

fn default_ai_catalog() -> String {
    "ai_catalog".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn home_bundle_json() -> String {
        let path = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .expect("HOME env should be set for edge registry tests")
            .join(".soth")
            .join("registry_bundle_cache.json");
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "expected ~/.soth registry bundle cache at {}: {}",
                path.display(),
                error
            )
        })
    }

    fn load_test_registry() -> EdgeRegistry {
        let bundle_json = home_bundle_json();
        EdgeRegistry::from_json_str(&bundle_json).expect("~/.soth registry bundle should parse")
    }

    #[test]
    fn registry_loader_accepts_cached_bundle_envelope_shape() {
        let bundle_json = home_bundle_json();
        let bundle_value: Value =
            serde_json::from_str(&bundle_json).expect("bundle JSON from ~/.soth should parse");
        let envelope = json!({
            "schema_version": 1,
            "fetched_at": "2026-02-22T00:00:00Z",
            "etag": "etag-1",
            "metadata": {
                "version": "2026.02.22",
                "compiled_at": "2026-02-22T00:00:00Z",
                "provider_count": 0,
                "format_count": 0,
                "domain_count": 0,
                "size_bytes": 0,
                "bundle_type": "edge",
                "bundle_hash": null,
                "manifest": null,
            },
            "bundle": bundle_value,
        });

        let registry = EdgeRegistry::from_json_str(
            serde_json::to_string_pretty(&envelope)
                .expect("cached bundle envelope should serialize")
                .as_str(),
        )
        .expect("cached bundle envelope should parse");
        assert!(registry.bundle().schema_version > 0);
    }

    #[test]
    fn catalog_matches_exact_subdomain_and_wildcard_entries() {
        let registry = load_test_registry();
        let entry = registry
            .bundle()
            .catalogs
            .ai_catalog
            .first()
            .expect("~/.soth registry bundle should contain ai_catalog entries");
        let probe = entry
            .strip_prefix("*.")
            .map(|suffix| format!("probe.{suffix}"))
            .unwrap_or_else(|| entry.to_string());
        assert!(registry.in_ai_catalog(&probe));
    }

    #[test]
    fn blacklist_keyword_match_is_case_insensitive() {
        let registry = load_test_registry();
        let Some(keyword) = registry.bundle().filters.keywords.first() else {
            eprintln!("Skipping blacklist keyword assertion: ~/.soth bundle has no keywords");
            return;
        };
        let mixed_case = keyword
            .chars()
            .enumerate()
            .map(|(idx, ch)| {
                if idx % 2 == 0 {
                    ch.to_ascii_uppercase()
                } else {
                    ch.to_ascii_lowercase()
                }
            })
            .collect::<String>();
        let hit = registry
            .find_blacklisted_keyword(format!("https://example.test/{mixed_case}").as_str())
            .expect("expected blacklist match");

        assert_eq!(hit, keyword.to_ascii_lowercase());
    }

    #[test]
    fn provider_matching_respects_methods() {
        let registry = load_test_registry();
        let (provider, host) = registry
            .providers
            .iter()
            .filter(|candidate| !candidate.host_rules.is_empty())
            .find_map(|candidate| {
                let host = candidate
                    .host_rules
                    .iter()
                    .find_map(|rule| match &rule.pattern {
                        HostPattern::Exact(value) => Some(value.clone()),
                        HostPattern::WildcardSuffix(suffix) => Some(format!("probe.{suffix}")),
                        HostPattern::Regex(_) => None,
                    })?;
                Some((candidate, host))
            })
            .expect("~/.soth bundle should contain a provider host rule");

        let path = ["/", "/v1/messages", "/v1/responses", "/v1/chat/completions"]
            .into_iter()
            .find(|candidate_path| provider.match_score(&host, candidate_path).is_some())
            .expect("bundle provider host rule should match one probe path");

        let allowed_method = provider
            .capture_methods
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "GET".to_string());
        let matched = registry
            .match_provider(&host, path, &allowed_method)
            .expect("provider should match probe host/path");
        assert_eq!(matched.key, provider.key);
        assert!(matched.method_allowed);

        if !provider.capture_methods.is_empty() {
            let disallowed_method = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
                .into_iter()
                .find(|candidate| !provider.capture_methods.contains(*candidate))
                .expect("should find a method outside capture allowlist");
            let disallowed = registry
                .match_provider(&host, path, disallowed_method)
                .expect("provider should still match host/path for disallowed method check");
            assert!(!disallowed.method_allowed);
        }
    }

    #[test]
    fn stream_parser_is_resolved_from_target_parser_key() {
        let registry = EdgeRegistry::from_json_str(
            json!({
                "schema_version": 1,
                "metadata": {},
                "llm_providers": {
                    "openai": {
                        "id": "openai",
                        "name": "OpenAI",
                        "type": "ai-inference",
                        "api_format": "openai",
                        "parser_key": "chatgpt_stream",
                        "detection": {
                            "hosts": [{
                                "pattern": "api.openai.com",
                                "paths": { "allow": ["/v1/**"], "deny_exact": [], "deny_glob": [] },
                                "priority": 9000
                            }],
                            "path_patterns": ["**/v1/chat/completions**"],
                            "header_hints": [],
                            "model_rules": [],
                            "env_rules": [],
                            "process_rules": [],
                            "ua_rules": []
                        },
                        "capture": { "mode": "full", "methods": ["POST"], "enabled": true }
                    }
                },
                "applications": {},
                "catalogs": { "ai_catalog": [], "analytics_blocklist": [] },
                "filters": { "domain_patterns": [], "path_patterns": [], "keywords": [] },
                "formats": {
                    "chatgpt_stream": {
                        "response": {
                            "stream": {
                                "format": "sse",
                                "format_options": {
                                    "prefixes": ["data: "],
                                    "skip_values": ["[DONE]", "v1", "v2"]
                                }
                            }
                        }
                    }
                },
                "interception": {
                    "app_policies": {},
                    "browser_policies": { "allowed_browsers": [], "allowed_apps": [], "default_action": "intercept" },
                    "defaults": {
                        "non_whitelisted_host_action": "tunnel",
                        "unknown_app_action": "host_only",
                        "whitelisted_unknown_app_action": "intercept"
                    }
                }
            })
            .to_string()
            .as_str(),
        )
        .expect("registry should parse");

        let matched = registry
            .match_provider("api.openai.com", "/v1/chat/completions", "POST")
            .expect("provider should match");
        let parser = registry
            .stream_parser_for_match(&matched)
            .expect("stream parser should resolve");

        assert_eq!(parser.format, BundleStreamFormat::Sse);
        assert_eq!(parser.prefixes, vec!["data: ".to_string()]);
        assert_eq!(
            parser.skip_values,
            vec!["[DONE]".to_string(), "v1".to_string(), "v2".to_string()]
        );
    }

    #[test]
    fn path_glob_engine_matches_python_style_patterns() {
        let matcher = UrlPatternMatcher::compile("/api/organizations/**/completion")
            .expect("pattern should compile");

        assert!(matcher.is_match("/api/organizations/org-1/completion"));
        assert!(!matcher.is_match("/api/organizations/org-1/projects"));

        let matcher =
            UrlPatternMatcher::compile("**/v1/chat/completions**").expect("pattern should compile");

        assert!(matcher.is_match("/v1/chat/completions"));
        assert!(matcher.is_match("/foo/v1/chat/completions/stream"));
    }

    #[test]
    fn path_patterns_do_not_gate_host_allow_matches() {
        let registry = EdgeRegistry::from_json_str(
            json!({
                "schema_version": 1,
                "metadata": {},
                "llm_providers": {},
                "applications": {
                    "chatgpt_like": {
                        "id": "chatgpt_like",
                        "name": "ChatGPT Like",
                        "type": "agent-app",
                        "detection": {
                            "hosts": [{
                                "pattern": "chatgpt.com",
                                "paths": {
                                    "allow": ["/backend-api/**/conversation"],
                                    "deny_exact": [],
                                    "deny_glob": []
                                },
                                "priority": 9500
                            }],
                            "path_patterns": ["**/backend-api/conversation"],
                            "header_hints": [],
                            "model_rules": [],
                            "env_rules": [],
                            "process_rules": [],
                            "ua_rules": []
                        },
                        "capture": {
                            "mode": "full",
                            "methods": ["POST"],
                            "enabled": true
                        }
                    }
                },
                "catalogs": { "ai_catalog": [], "analytics_blocklist": [] },
                "filters": { "domain_patterns": [], "path_patterns": [], "keywords": [] },
                "interception": {
                    "app_policies": {},
                    "browser_policies": { "allowed_browsers": [], "allowed_apps": [], "default_action": "intercept" },
                    "defaults": {
                        "non_whitelisted_host_action": "tunnel",
                        "unknown_app_action": "host_only",
                        "whitelisted_unknown_app_action": "intercept"
                    }
                }
            })
            .to_string()
            .as_str(),
        )
        .expect("registry should parse");

        let matched = registry
            .match_application("chatgpt.com", "/backend-api/f/conversation", "POST")
            .expect("allow-path host match should pass even when path_patterns miss");
        assert_eq!(matched.key, "chatgpt_like");
        assert!(matched.method_allowed);
    }

    #[test]
    fn path_pattern_match_breaks_tie_between_equal_host_matches() {
        let registry = EdgeRegistry::from_json_str(
            json!({
                "schema_version": 1,
                "metadata": {},
                "llm_providers": {},
                "applications": {
                    "fallback_target": {
                        "id": "fallback_target",
                        "name": "Fallback",
                        "type": "agent-app",
                        "detection": {
                            "hosts": [{
                                "pattern": "chatgpt.com",
                                "paths": {
                                    "allow": ["/backend-api/**/conversation"],
                                    "deny_exact": [],
                                    "deny_glob": []
                                },
                                "priority": 9500
                            }],
                            "path_patterns": ["**/v1/not-this-path"],
                            "header_hints": [],
                            "model_rules": [],
                            "env_rules": [],
                            "process_rules": [],
                            "ua_rules": []
                        },
                        "capture": {
                            "mode": "full",
                            "methods": ["POST"],
                            "enabled": true
                        }
                    },
                    "preferred_target": {
                        "id": "preferred_target",
                        "name": "Preferred",
                        "type": "agent-app",
                        "detection": {
                            "hosts": [{
                                "pattern": "chatgpt.com",
                                "paths": {
                                    "allow": ["/backend-api/**/conversation"],
                                    "deny_exact": [],
                                    "deny_glob": []
                                },
                                "priority": 9500
                            }],
                            "path_patterns": ["**/backend-api/f/conversation"],
                            "header_hints": [],
                            "model_rules": [],
                            "env_rules": [],
                            "process_rules": [],
                            "ua_rules": []
                        },
                        "capture": {
                            "mode": "full",
                            "methods": ["POST"],
                            "enabled": true
                        }
                    }
                },
                "catalogs": { "ai_catalog": [], "analytics_blocklist": [] },
                "filters": { "domain_patterns": [], "path_patterns": [], "keywords": [] },
                "interception": {
                    "app_policies": {},
                    "browser_policies": { "allowed_browsers": [], "allowed_apps": [], "default_action": "intercept" },
                    "defaults": {
                        "non_whitelisted_host_action": "tunnel",
                        "unknown_app_action": "host_only",
                        "whitelisted_unknown_app_action": "intercept"
                    }
                }
            })
            .to_string()
            .as_str(),
        )
        .expect("registry should parse");

        let matched = registry
            .match_application("chatgpt.com", "/backend-api/f/conversation", "POST")
            .expect("one target should match");
        assert_eq!(matched.key, "preferred_target");
    }
}

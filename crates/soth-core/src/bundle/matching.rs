use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A signal-based matching rule attached to a provider or application entity.
///
/// Wire-compatible with `NativeBundleRule` from soth-cloud's NativeBundle v3.
/// Each rule contains one or more signal matchers; `requires_all` controls
/// whether ALL signals must match (AND) or ANY signal suffices (OR).
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct MatchingRule {
    #[serde(alias = "rule_key")]
    pub rule_id: String,
    pub priority: u32,
    #[serde(default)]
    pub requires_all: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub signals: Vec<SignalMatcher>,
}

/// A single signal within a matching rule.
///
/// Wire-compatible with `NativeBundleSignal` from soth-cloud.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct SignalMatcher {
    #[serde(alias = "signal_kind")]
    pub kind: SignalKind,
    #[serde(alias = "signal_pattern")]
    pub pattern: String,
    #[serde(alias = "signal_name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub is_negated: bool,
    #[serde(default)]
    pub metadata: Value,
}

/// Enumeration of signal kinds used in matching rules.
///
/// String representations match the cloud's NativeBundle format exactly
/// (e.g. `"HttpHost"`, `"ProcessBundleId"`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SignalKind {
    TlsSni,
    ProcessBundleId,
    ProcessName,
    ParentProcessName,
    HttpHost,
    HttpPath,
    HttpMethod,
    HttpHeader,
    ContentType,
    BodyStructure,
}

impl Default for SignalKind {
    fn default() -> Self {
        SignalKind::HttpHost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_native_bundle_rule_format() {
        let json = r#"{
            "rule_id": "openai-host",
            "priority": 900,
            "requires_all": true,
            "notes": null,
            "metadata": {},
            "signals": [
                {
                    "kind": "HttpHost",
                    "pattern": "api.openai.com",
                    "name": null,
                    "is_negated": false,
                    "metadata": {}
                }
            ]
        }"#;
        let rule: MatchingRule = serde_json::from_str(json).expect("deserialize");
        assert_eq!(rule.rule_id, "openai-host");
        assert_eq!(rule.priority, 900);
        assert!(rule.requires_all);
        assert_eq!(rule.signals.len(), 1);
        assert_eq!(rule.signals[0].kind, SignalKind::HttpHost);
        assert_eq!(rule.signals[0].pattern, "api.openai.com");
        assert!(!rule.signals[0].is_negated);
    }

    #[test]
    fn deserialize_with_aliases() {
        let json = r#"{
            "rule_key": "test-rule",
            "priority": 850,
            "requires_all": false,
            "signals": [
                {
                    "signal_kind": "HttpPath",
                    "signal_pattern": "/v1/chat/completions",
                    "signal_name": "openai-chat"
                }
            ]
        }"#;
        let rule: MatchingRule = serde_json::from_str(json).expect("deserialize");
        assert_eq!(rule.rule_id, "test-rule");
        assert_eq!(rule.signals[0].kind, SignalKind::HttpPath);
        assert_eq!(rule.signals[0].name.as_deref(), Some("openai-chat"));
    }

    #[test]
    fn default_fields_for_minimal_json() {
        let json = r#"{
            "rule_id": "min",
            "priority": 100,
            "signals": []
        }"#;
        let rule: MatchingRule = serde_json::from_str(json).expect("deserialize");
        assert!(!rule.requires_all);
        assert!(rule.notes.is_none());
        assert_eq!(rule.metadata, serde_json::json!(null));
        assert!(rule.signals.is_empty());
    }

    #[test]
    fn roundtrip_serialization() {
        let rule = MatchingRule {
            rule_id: "test".to_string(),
            priority: 500,
            requires_all: true,
            notes: Some("test note".to_string()),
            metadata: serde_json::json!({"key": "value"}),
            signals: vec![
                SignalMatcher {
                    kind: SignalKind::ProcessBundleId,
                    pattern: "com.cursor.Cursor".to_string(),
                    name: Some("cursor-bundle-id".to_string()),
                    is_negated: false,
                    metadata: serde_json::json!({}),
                },
                SignalMatcher {
                    kind: SignalKind::HttpHost,
                    pattern: "api.openai.com".to_string(),
                    name: None,
                    is_negated: true,
                    metadata: serde_json::json!({}),
                },
            ],
        };

        let json = serde_json::to_string(&rule).expect("serialize");
        let deserialized: MatchingRule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rule, deserialized);
    }
}

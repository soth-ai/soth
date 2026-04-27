//! Sentry integration: panic capture + ERROR-level event capture.
//!
//! Sentry is a complement to OpenTelemetry, not a replacement. Per
//! `docs/common/observability.md`, we route ALL tracing spans through
//! `tracing-opentelemetry` (→ Honeycomb) for distributed-trace analysis,
//! and only let Sentry see the panic + ERROR slice via `sentry::ClientOptions`
//! `traces_sample_rate = 0.0` plus the `sentry-tracing` layer at filter
//! `tracing::Level::ERROR`. That keeps Sentry's overhead off the hot path.
//!
//! The init function returns a [`sentry::ClientInitGuard`] that the caller
//! must hold for the process lifetime; dropping it flushes any in-flight
//! events.

use std::borrow::Cow;
use std::sync::Arc;

use ::sentry::protocol::{Event, Value};

use super::redaction::{redact, REDACTED};

/// Initialise the Sentry SDK from `SENTRY_DSN`.
///
/// Returns `None` if the env var is unset or empty — Sentry is opt-in and
/// the proxy must run cleanly without it (tests, offline dev, distros that
/// haven't been configured yet).
pub fn init() -> Option<::sentry::ClientInitGuard> {
    let dsn = std::env::var("SENTRY_DSN").ok()?;
    if dsn.trim().is_empty() {
        return None;
    }

    let release = ::sentry::release_name!();
    let environment = std::env::var("SOTH_ENVIRONMENT")
        .or_else(|_| std::env::var("ENVIRONMENT"))
        .unwrap_or_else(|_| "unknown".into());

    let options = ::sentry::ClientOptions {
        dsn: dsn.parse().ok(),
        release,
        environment: Some(environment.into()),
        // We don't want Sentry's own performance tracing — Honeycomb owns that.
        traces_sample_rate: 0.0,
        // Errors and panics are always shipped (no sampling).
        sample_rate: 1.0,
        attach_stacktrace: true,
        send_default_pii: false,
        before_send: Some(Arc::new(|event| Some(scrub_event(event)))),
        ..Default::default()
    };

    Some(::sentry::init(options))
}

/// Apply the redaction policy to a Sentry event before transmission.
///
/// Scope:
/// - `event.message` (rare; usually set on captured messages)
/// - `event.tags` — both keys and values are pretty constrained, but a tag
///   value can carry a token if a span attribute leaked into one.
/// - `event.extra` — arbitrary `serde_json::Value` map. Walk recursively
///   and redact strings whose key (or whose immediate parent key in an
///   object position) matches the deny list, and any string value whose
///   prefix matches.
/// - Breadcrumbs — both `message` and `data` get scrubbed.
///
/// This must be cheap — it runs on every Sentry transmission. For typical
/// payloads (a panic + a few breadcrumbs) it's microseconds.
pub fn scrub_event(mut event: Event<'static>) -> Event<'static> {
    if let Some(message) = event.message.as_ref() {
        if super::redaction::looks_like_secret_value(message) {
            event.message = Some(REDACTED.into());
        }
    }

    // tags: BTreeMap<String, String>
    for (key, value) in event.tags.iter_mut() {
        let cow = redact(key, value);
        if matches!(cow, Cow::Borrowed(s) if s == REDACTED) {
            *value = REDACTED.to_string();
        }
    }

    // extra: BTreeMap<String, Value>
    for (key, value) in event.extra.iter_mut() {
        scrub_value(key, value);
    }

    // breadcrumbs: VecDeque<Breadcrumb>
    for crumb in event.breadcrumbs.iter_mut() {
        if let Some(message) = crumb.message.as_ref() {
            if super::redaction::looks_like_secret_value(message) {
                crumb.message = Some(REDACTED.into());
            }
        }
        for (k, v) in crumb.data.iter_mut() {
            scrub_value(k, v);
        }
    }

    event
}

/// Redact a `serde_json::Value` in place. The `field_name` is the key of
/// the field this value is attached to in the parent map (used for the
/// field-name deny check). Recurses into objects/arrays.
fn scrub_value(field_name: &str, value: &mut Value) {
    match value {
        Value::String(s) => {
            let cow = redact(field_name, s.as_str());
            if matches!(cow, Cow::Borrowed(out) if out == REDACTED) {
                *s = REDACTED.to_string();
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                // Array elements have no key of their own; carry the parent's
                // field name so a deny-listed parent ("messages": [...])
                // scrubs every element's strings too.
                scrub_value(field_name, item);
            }
        }
        Value::Object(map) => {
            // If the parent field name itself is sensitive, blank out the
            // whole subtree — no point recursing into "messages": {...}.
            if super::redaction::is_sensitive_field_name(field_name) {
                map.clear();
                map.insert("redacted".to_string(), Value::String(REDACTED.into()));
                return;
            }
            for (child_key, child_value) in map.iter_mut() {
                scrub_value(child_key, child_value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scrub_event_redacts_tag_values_for_sensitive_keys() {
        let mut event = Event::new();
        event
            .tags
            .insert("authorization".to_string(), "Bearer xyz".to_string());
        event
            .tags
            .insert("status_code".to_string(), "200".to_string());
        let event = scrub_event(event);
        assert_eq!(event.tags.get("authorization").unwrap(), REDACTED);
        assert_eq!(event.tags.get("status_code").unwrap(), "200");
    }

    #[test]
    fn scrub_event_redacts_extra_strings_by_field_name_or_prefix() {
        let mut event = Event::new();
        event
            .extra
            .insert("api_key".to_string(), json!("sk-real-secret"));
        event
            .extra
            .insert("request_id".to_string(), json!("req-1234"));
        event
            .extra
            .insert("host".to_string(), json!("ghp_lookalikeButValueShape"));
        let event = scrub_event(event);
        assert_eq!(event.extra.get("api_key").unwrap(), &json!(REDACTED));
        assert_eq!(event.extra.get("request_id").unwrap(), &json!("req-1234"));
        // Field name is innocent but value pattern matches → redacted.
        assert_eq!(event.extra.get("host").unwrap(), &json!(REDACTED));
    }

    #[test]
    fn scrub_event_redacts_nested_object_when_parent_key_is_sensitive() {
        let mut event = Event::new();
        event.extra.insert(
            "messages".to_string(),
            json!([
                {"role": "user", "content": "leak this"},
                {"role": "assistant", "content": "and this"},
            ]),
        );
        let event = scrub_event(event);
        // Whole subtree replaced by a sentinel so the structure isn't
        // walked further.
        match event.extra.get("messages").unwrap() {
            Value::Array(items) => {
                // Array elements carry the parent's deny-listed name down,
                // so each element's strings get scrubbed in place.
                for item in items {
                    if let Value::Object(map) = item {
                        for v in map.values() {
                            if let Value::String(s) = v {
                                assert!(
                                    s == "user" || s == "assistant" || s == REDACTED,
                                    "leaked content: {s:?}"
                                );
                            }
                        }
                    }
                }
            }
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn scrub_event_redacts_breadcrumb_data() {
        let mut crumb = sentry::protocol::Breadcrumb::default();
        crumb.message = Some("ghp_isThisALeak?".to_string());
        crumb
            .data
            .insert("authorization".to_string(), json!("Bearer xyz"));
        crumb.data.insert("path".to_string(), json!("/v1/messages"));
        let mut event = Event::new();
        event.breadcrumbs.values.push(crumb);
        let event = scrub_event(event);
        let crumb = &event.breadcrumbs.values[0];
        assert_eq!(crumb.message.as_deref(), Some(REDACTED));
        assert_eq!(crumb.data.get("authorization").unwrap(), &json!(REDACTED));
        assert_eq!(crumb.data.get("path").unwrap(), &json!("/v1/messages"));
    }
}

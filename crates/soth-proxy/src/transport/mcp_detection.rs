//! MCP JSON-RPC detection helpers for HTTP/WS payloads.

use rmcp::model::{
    CustomNotification as RmcpCustomNotification, CustomRequest as RmcpCustomRequest,
    JsonRpcMessage as RmcpJsonRpcMessage,
};

use crate::protocol::mcp::methods as mcp_methods;

type RmcpWireJsonRpcMessage =
    RmcpJsonRpcMessage<RmcpCustomRequest, serde_json::Value, RmcpCustomNotification>;

fn is_jsonrpc_v2(value: &serde_json::Value) -> bool {
    matches!(
        value.get("jsonrpc"),
        Some(serde_json::Value::String(version)) if version == "2.0"
    )
}

fn is_likely_mcp_method(method: &str) -> bool {
    matches!(
        method,
            mcp_methods::INITIALIZE
            | mcp_methods::INITIALIZED
            | mcp_methods::CANCELLED
            | mcp_methods::PROGRESS
            | mcp_methods::TOOLS_LIST
            | mcp_methods::TOOLS_CALL
            | mcp_methods::RESOURCES_LIST
            | mcp_methods::RESOURCES_READ
            | mcp_methods::RESOURCES_SUBSCRIBE
            | mcp_methods::RESOURCES_UNSUBSCRIBE
            | mcp_methods::RESOURCES_UPDATED
            | mcp_methods::RESOURCES_LIST_CHANGED
            | mcp_methods::PROMPTS_LIST
            | mcp_methods::PROMPTS_GET
            | mcp_methods::PROMPTS_LIST_CHANGED
            | mcp_methods::LOGGING_SET_LEVEL
            | mcp_methods::LOGGING_MESSAGE
            | mcp_methods::SAMPLING_CREATE_MESSAGE
    ) || method.starts_with("tools/")
        || method.starts_with("resources/")
        || method.starts_with("prompts/")
        || method.starts_with("sampling/")
        || method.starts_with("roots/")
        || method.starts_with("tasks/")
        || method.starts_with("completion/")
        || method.starts_with("elicitation/")
        || method.starts_with("logging/")
}

fn params_is_empty_or_null(params: Option<&serde_json::Value>) -> bool {
    match params {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Object(obj)) => obj.is_empty(),
        _ => false,
    }
}

fn initialize_params_look_like_mcp(params: Option<&serde_json::Value>) -> bool {
    let Some(serde_json::Value::Object(obj)) = params else {
        return false;
    };
    obj.contains_key("protocolVersion")
        && obj.contains_key("capabilities")
        && obj.contains_key("clientInfo")
}

fn should_accept_mcp_method(method: &str, params: Option<&serde_json::Value>) -> bool {
    if method == mcp_methods::INITIALIZE {
        // Content-only gate: require RMCP initialize shape.
        return initialize_params_look_like_mcp(params);
    }

    if method == mcp_methods::INITIALIZED {
        // notifications/initialized should not carry meaningful params.
        return params_is_empty_or_null(params);
    }

    // Don't classify bare "ping" as MCP; too many non-MCP JSON-RPC systems use it.
    if method == mcp_methods::PING {
        return false;
    }

    is_likely_mcp_method(method)
}

fn extract_mcp_request_method_from_json(
    value: serde_json::Value,
) -> Option<String> {
    if !is_jsonrpc_v2(&value) {
        return None;
    }
    match serde_json::from_value::<RmcpWireJsonRpcMessage>(value).ok()? {
        RmcpWireJsonRpcMessage::Request(req) => {
            should_accept_mcp_method(&req.request.method, req.request.params.as_ref())
                .then_some(req.request.method)
        }
        RmcpWireJsonRpcMessage::Notification(notification) => {
            should_accept_mcp_method(
                &notification.notification.method,
                notification.notification.params.as_ref(),
            )
                .then_some(notification.notification.method)
        }
        RmcpWireJsonRpcMessage::Response(_) | RmcpWireJsonRpcMessage::Error(_) => None,
    }
}

pub(crate) fn extract_mcp_request_method(payload: &str, _path: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    match value {
        serde_json::Value::Object(_) => extract_mcp_request_method_from_json(value),
        serde_json::Value::Array(items) => {
            let mut methods = Vec::new();
            for item in items {
                if let Some(method) = extract_mcp_request_method_from_json(item) {
                    methods.push(method);
                }
            }
            if methods.is_empty() {
                None
            } else if methods.len() == 1 {
                methods.into_iter().next()
            } else {
                Some(format!("batch:{} (+{})", methods[0], methods.len() - 1))
            }
        }
        _ => None,
    }
}

fn result_looks_like_mcp(result: &serde_json::Value) -> bool {
    let serde_json::Value::Object(obj) = result else {
        return false;
    };
    obj.contains_key("protocolVersion")
        || obj.contains_key("serverInfo")
        || obj.contains_key("tools")
        || obj.contains_key("resources")
        || obj.contains_key("prompts")
        || obj.contains_key("content")
        || obj.contains_key("isError")
        || obj.contains_key("completion")
}

pub(crate) fn is_jsonrpc_response_for_mcp(payload: &str) -> bool {
    let value: serde_json::Value = match serde_json::from_str(payload) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let items: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(values) => values,
        other => vec![other],
    };
    items.into_iter().any(|item| {
        if !is_jsonrpc_v2(&item) {
            return false;
        }
        match serde_json::from_value::<RmcpWireJsonRpcMessage>(item) {
            Ok(RmcpWireJsonRpcMessage::Response(resp)) => result_looks_like_mcp(&resp.result),
            Ok(RmcpWireJsonRpcMessage::Error(err)) => {
                let code = err.error.code.0;
                // MCP-specific extension errors live in the -328xx range.
                (-32899..=-32800).contains(&code)
            }
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{extract_mcp_request_method, is_jsonrpc_response_for_mcp};

    #[test]
    fn test_non_jsonrpc_payload_not_detected_as_mcp() {
        let payload = r#"{"method":"conversation","id":"123","message":"hello"}"#;
        assert_eq!(extract_mcp_request_method(payload, "/mcp"), None);
    }

    #[test]
    fn test_jsonrpc_unknown_method_not_detected_as_mcp() {
        let payload = r#"{"jsonrpc":"2.0","id":1,"method":"rpc.unknown","params":{"x":1}}"#;
        assert_eq!(extract_mcp_request_method(payload, "/jsonrpc"), None);
    }

    #[test]
    fn test_jsonrpc_mcp_method_is_detected() {
        let payload = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        assert_eq!(
            extract_mcp_request_method(payload, "/jsonrpc"),
            Some("tools/list".to_string())
        );
    }

    #[test]
    fn test_initialize_requires_mcp_params_shape_without_path_hints() {
        let init_payload =
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1.0.0"}}}"#;
        assert_eq!(
            extract_mcp_request_method(init_payload, "/pubsub"),
            Some("initialize".to_string())
        );

        let weak_init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        assert_eq!(extract_mcp_request_method(weak_init, "/jsonrpc"), None);
    }

    #[test]
    fn test_ping_is_not_used_for_mcp_classification() {
        let ping_payload = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#;
        assert_eq!(extract_mcp_request_method(ping_payload, "/mcp"), None);
    }

    #[test]
    fn test_initialized_notification_requires_empty_params() {
        let initialized_ok = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert_eq!(
            extract_mcp_request_method(initialized_ok, "/ws"),
            Some("notifications/initialized".to_string())
        );

        let initialized_bad =
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{"unexpected":true}}"#;
        assert_eq!(extract_mcp_request_method(initialized_bad, "/ws"), None);
    }

    #[test]
    fn test_non_jsonrpc_response_not_detected_as_mcp_response() {
        let payload = r#"{"id":1,"result":{"ok":true}}"#;
        assert!(!is_jsonrpc_response_for_mcp(payload));
    }

    #[test]
    fn test_mcp_response_requires_mcp_like_result_shape() {
        let tools_response = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let generic_response = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
        assert!(is_jsonrpc_response_for_mcp(tools_response));
        assert!(!is_jsonrpc_response_for_mcp(generic_response));
    }
}

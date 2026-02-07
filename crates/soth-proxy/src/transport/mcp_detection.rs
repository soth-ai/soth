//! MCP JSON-RPC detection helpers for HTTP/WS payloads.

use rmcp::model::{
    CustomNotification as RmcpCustomNotification, CustomRequest as RmcpCustomRequest,
    JsonRpcMessage as RmcpJsonRpcMessage,
};

use crate::protocol::mcp::methods as mcp_methods;

type RmcpWireJsonRpcMessage =
    RmcpJsonRpcMessage<RmcpCustomRequest, serde_json::Value, RmcpCustomNotification>;

fn mcp_path_hint(path: &str) -> bool {
    let path_lower = path.to_ascii_lowercase();
    path_lower.contains("/mcp") || path_lower.contains("/jsonrpc")
}

fn is_likely_mcp_method(method: &str) -> bool {
    matches!(
        method,
        mcp_methods::INITIALIZE
            | mcp_methods::INITIALIZED
            | mcp_methods::PING
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
        || method.starts_with("notifications/")
        || method.starts_with("sampling/")
        || method.starts_with("roots/")
        || method.starts_with("tasks/")
        || method.starts_with("completion/")
        || method.starts_with("elicitation/")
        || method.starts_with("logging/")
}

fn extract_mcp_request_method_from_json(
    value: serde_json::Value,
    path_hint_is_mcp: bool,
) -> Option<String> {
    match serde_json::from_value::<RmcpWireJsonRpcMessage>(value).ok()? {
        RmcpWireJsonRpcMessage::Request(req) => {
            if is_likely_mcp_method(&req.request.method) || path_hint_is_mcp {
                Some(req.request.method)
            } else {
                None
            }
        }
        RmcpWireJsonRpcMessage::Notification(notification) => {
            if is_likely_mcp_method(&notification.notification.method) || path_hint_is_mcp {
                Some(notification.notification.method)
            } else {
                None
            }
        }
        RmcpWireJsonRpcMessage::Response(_) | RmcpWireJsonRpcMessage::Error(_) => None,
    }
}

pub(crate) fn extract_mcp_request_method(payload: &str, path: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    let path_hint_is_mcp = mcp_path_hint(path);
    match value {
        serde_json::Value::Object(_) => {
            extract_mcp_request_method_from_json(value, path_hint_is_mcp)
        }
        serde_json::Value::Array(items) => {
            let mut methods = Vec::new();
            for item in items {
                if let Some(method) = extract_mcp_request_method_from_json(item, path_hint_is_mcp) {
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

pub(crate) fn is_jsonrpc_response_for_mcp(payload: &str, path: &str) -> bool {
    if !mcp_path_hint(path) {
        return false;
    }
    let value: serde_json::Value = match serde_json::from_str(payload) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let items: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(values) => values,
        other => vec![other],
    };
    items.into_iter().any(|item| {
        matches!(
            serde_json::from_value::<RmcpWireJsonRpcMessage>(item),
            Ok(RmcpWireJsonRpcMessage::Response(_)) | Ok(RmcpWireJsonRpcMessage::Error(_))
        )
    })
}

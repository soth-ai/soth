//! MCP method routing

use crate::error::ProxyError;
use crate::protocol::{methods, JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestId};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Method handler type
pub type MethodHandler = Arc<
    dyn Fn(
            JsonRpcRequest,
        ) -> Pin<Box<dyn Future<Output = Result<JsonRpcResponse, ProxyError>> + Send>>
        + Send
        + Sync,
>;

/// MCP method router
pub struct Router {
    /// Registered handlers
    handlers: HashMap<String, MethodHandler>,
    /// Default handler for unregistered methods
    default_handler: Option<MethodHandler>,
}

impl Router {
    /// Create a new router
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            default_handler: None,
        }
    }

    /// Register a handler for a method
    pub fn register<F, Fut>(&mut self, method: &str, handler: F)
    where
        F: Fn(JsonRpcRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<JsonRpcResponse, ProxyError>> + Send + 'static,
    {
        self.handlers.insert(
            method.to_string(),
            Arc::new(move |req| Box::pin(handler(req))),
        );
    }

    /// Set the default handler
    pub fn set_default<F, Fut>(&mut self, handler: F)
    where
        F: Fn(JsonRpcRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<JsonRpcResponse, ProxyError>> + Send + 'static,
    {
        self.default_handler = Some(Arc::new(move |req| Box::pin(handler(req))));
    }

    /// Route a request to the appropriate handler
    pub async fn route(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, ProxyError> {
        let id = request.id.clone().unwrap_or(RequestId::Null);

        // Find handler
        if let Some(handler) = self.handlers.get(&request.method) {
            handler(request).await
        } else if let Some(ref default) = self.default_handler {
            default(request).await
        } else {
            Ok(JsonRpcResponse::error(id, JsonRpcError::method_not_found()))
        }
    }

    /// Check if a method is registered
    pub fn has_handler(&self, method: &str) -> bool {
        self.handlers.contains_key(method) || self.default_handler.is_some()
    }

    /// List registered methods
    pub fn methods(&self) -> Vec<&str> {
        self.handlers.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a router with standard MCP method handlers
pub fn create_standard_router() -> Router {
    let mut router = Router::new();

    // Ping handler
    router.register(methods::PING, |req| async move {
        let id = req.id.unwrap_or(RequestId::Null);
        Ok(JsonRpcResponse::success(id, serde_json::json!({})))
    });

    router
}

/// Type alias for pre-hook function
type PreHook = Arc<dyn Fn(&JsonRpcRequest) -> bool + Send + Sync>;
/// Type alias for post-hook function
type PostHook = Arc<dyn Fn(&JsonRpcRequest, &JsonRpcResponse) + Send + Sync>;

/// Method interceptor for pre/post processing
pub struct MethodInterceptor {
    /// Pre-processing hooks
    pre_hooks: Vec<PreHook>,
    /// Post-processing hooks
    post_hooks: Vec<PostHook>,
}

impl MethodInterceptor {
    /// Create a new interceptor
    pub fn new() -> Self {
        Self {
            pre_hooks: Vec::new(),
            post_hooks: Vec::new(),
        }
    }

    /// Add a pre-processing hook (returns false to block)
    pub fn add_pre_hook<F>(&mut self, hook: F)
    where
        F: Fn(&JsonRpcRequest) -> bool + Send + Sync + 'static,
    {
        self.pre_hooks.push(Arc::new(hook));
    }

    /// Add a post-processing hook
    pub fn add_post_hook<F>(&mut self, hook: F)
    where
        F: Fn(&JsonRpcRequest, &JsonRpcResponse) + Send + Sync + 'static,
    {
        self.post_hooks.push(Arc::new(hook));
    }

    /// Run pre-processing hooks
    pub fn pre_process(&self, request: &JsonRpcRequest) -> bool {
        for hook in &self.pre_hooks {
            if !hook(request) {
                return false;
            }
        }
        true
    }

    /// Run post-processing hooks
    pub fn post_process(&self, request: &JsonRpcRequest, response: &JsonRpcResponse) {
        for hook in &self.post_hooks {
            hook(request, response);
        }
    }
}

impl Default for MethodInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_router_register_and_route() {
        let mut router = Router::new();

        router.register("test/method", |req| async move {
            let id = req.id.unwrap_or(RequestId::Null);
            Ok(JsonRpcResponse::success(
                id,
                serde_json::json!({"status": "ok"}),
            ))
        });

        let req = JsonRpcRequest::new("test/method", None, RequestId::Number(1));
        let resp = router.route(req).await.unwrap();

        assert!(!resp.is_error());
        assert_eq!(resp.result.unwrap()["status"], "ok");
    }

    #[tokio::test]
    async fn test_router_method_not_found() {
        let router = Router::new();

        let req = JsonRpcRequest::new("unknown/method", None, RequestId::Number(1));
        let resp = router.route(req).await.unwrap();

        assert!(resp.is_error());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn test_router_default_handler() {
        let mut router = Router::new();

        router.set_default(|req| async move {
            let id = req.id.unwrap_or(RequestId::Null);
            Ok(JsonRpcResponse::success(
                id,
                serde_json::json!({"handled": "default"}),
            ))
        });

        let req = JsonRpcRequest::new("any/method", None, RequestId::Number(1));
        let resp = router.route(req).await.unwrap();

        assert!(!resp.is_error());
        assert_eq!(resp.result.unwrap()["handled"], "default");
    }

    #[test]
    fn test_method_interceptor() {
        let mut interceptor = MethodInterceptor::new();

        let blocked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let blocked_clone = blocked.clone();

        interceptor.add_pre_hook(move |req| {
            if req.method == "blocked/method" {
                blocked_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                false
            } else {
                true
            }
        });

        let req = JsonRpcRequest::new("blocked/method", None, RequestId::Number(1));
        let allowed = interceptor.pre_process(&req);

        assert!(!allowed);
        assert!(blocked.load(std::sync::atomic::Ordering::SeqCst));
    }
}

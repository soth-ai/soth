use std::env;
use std::net::IpAddr;
use std::time::Duration;

use crate::api_types::{version::API_VERSION_HEADER, API_VERSION};

fn should_bypass_proxy(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    let normalized_host = host.trim_matches('[').trim_matches(']');
    match normalized_host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => false,
    }
}

fn has_loopback_proxy_env() -> bool {
    [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .any(|key| {
        env::var(key)
            .ok()
            .as_deref()
            .map(proxy_target_is_loopback)
            .unwrap_or(false)
    })
}

fn proxy_target_is_loopback(raw: &str) -> bool {
    let candidate = raw.trim();
    if candidate.is_empty() {
        return false;
    }

    let parse_url = |value: &str| {
        reqwest::Url::parse(value).ok().or_else(|| {
            if value.contains("://") {
                None
            } else {
                reqwest::Url::parse(format!("http://{value}").as_str()).ok()
            }
        })
    };

    let Some(url) = parse_url(candidate) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    let normalized = host.trim_matches('[').trim_matches(']');
    match normalized.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => false,
    }
}

pub fn build_cloud_client(endpoint: &str) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(20))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(30));
    if should_bypass_proxy(endpoint) || has_loopback_proxy_env() {
        builder = builder.no_proxy();
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

#[derive(Clone)]
pub struct SothHttpClient {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
}

impl SothHttpClient {
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        Self {
            client: build_cloud_client(endpoint.as_str()),
            endpoint,
            api_key: api_key.into(),
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn url(&self, path_or_url: &str) -> String {
        compose_url(self.endpoint.as_str(), path_or_url)
    }

    pub fn get(&self, path_or_url: &str) -> reqwest::RequestBuilder {
        self.client
            .get(self.url(path_or_url))
            .header(API_VERSION_HEADER, API_VERSION)
            .bearer_auth(&self.api_key)
    }

    pub fn post(&self, path_or_url: &str) -> reqwest::RequestBuilder {
        self.client
            .post(self.url(path_or_url))
            .header(API_VERSION_HEADER, API_VERSION)
            .bearer_auth(&self.api_key)
    }
}

fn compose_url(endpoint: &str, path_or_url: &str) -> String {
    if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
        return path_or_url.to_string();
    }
    if path_or_url.starts_with('/') {
        return format!("{endpoint}{path_or_url}");
    }
    format!("{endpoint}/{path_or_url}")
}

#[cfg(test)]
mod tests {
    use super::{compose_url, proxy_target_is_loopback, should_bypass_proxy, SothHttpClient};

    #[test]
    fn bypasses_proxy_for_loopback_endpoints() {
        assert!(should_bypass_proxy("http://localhost:8081"));
        assert!(should_bypass_proxy("http://127.0.0.1:8081"));
        assert!(should_bypass_proxy("http://[::1]:8081"));
    }

    #[test]
    fn keeps_proxy_for_non_loopback_endpoints() {
        assert!(!should_bypass_proxy("https://api.soth.example"));
    }

    #[test]
    fn detects_loopback_proxy_targets() {
        assert!(proxy_target_is_loopback("http://127.0.0.1:8080"));
        assert!(proxy_target_is_loopback("http://localhost:8080"));
        assert!(proxy_target_is_loopback("127.0.0.1:8080"));
        assert!(!proxy_target_is_loopback("http://proxy.corp:8080"));
    }

    #[test]
    fn compose_url_preserves_absolute_url() {
        assert_eq!(
            compose_url("https://api.soth.example", "https://other.example/path"),
            "https://other.example/path"
        );
    }

    #[test]
    fn compose_url_handles_relative_path() {
        assert_eq!(
            compose_url("https://api.soth.example", "/v1/edge/heartbeat"),
            "https://api.soth.example/v1/edge/heartbeat"
        );
        assert_eq!(
            compose_url("https://api.soth.example", "v1/edge/heartbeat"),
            "https://api.soth.example/v1/edge/heartbeat"
        );
    }

    #[test]
    fn soth_http_client_normalizes_endpoint() {
        let client = SothHttpClient::new("https://api.soth.example/", "test-key");
        assert_eq!(client.endpoint(), "https://api.soth.example");
        assert_eq!(
            client.url("/v1/edge/heartbeat"),
            "https://api.soth.example/v1/edge/heartbeat"
        );
    }
}

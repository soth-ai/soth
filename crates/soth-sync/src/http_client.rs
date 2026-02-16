use std::net::IpAddr;
use std::time::Duration;

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

pub fn build_cloud_client(endpoint: &str) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(20))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(30));
    if should_bypass_proxy(endpoint) {
        builder = builder.no_proxy();
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::should_bypass_proxy;

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
}

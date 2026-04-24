use crate::cli_config;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clap::Args;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use soth_core::derive_proxy_signing_seed;
use soth_sync::api_types::{API_VERSION, API_VERSION_HEADER};
use std::collections::BTreeMap;
use std::env;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Args)]
pub struct EnrollArgs {
    /// Enrollment token (invite token). If omitted, prompt or read from stdin.
    pub token: Option<String>,

    /// Enrollment endpoint override (defaults to cloud.endpoint from config)
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Config file path to update (defaults to ~/.soth/soth.yaml)
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Read enrollment token from stdin
    #[arg(long)]
    pub from_stdin: bool,

    /// Do not prompt interactively if token is missing
    #[arg(long)]
    pub non_interactive: bool,

    /// Optional machine name override sent during enrollment
    #[arg(long)]
    pub machine_name: Option<String>,
}

pub async fn run(args: EnrollArgs, global_config: Option<PathBuf>) -> Result<()> {
    let config_path = resolve_config_path(args.config.as_ref(), global_config.as_ref());
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating config directory {}", parent.display()))?;
    }

    let mut config = if config_path.exists() {
        cli_config::load_config(config_path.clone())?
    } else {
        cli_config::SothConfig::default()
    };

    let enroll_token = resolve_enroll_token(&args)?;
    let endpoint_override = args.endpoint.clone();
    // Management endpoint (for display + persistence in cloud.endpoint).
    let management_endpoint = endpoint_override
        .clone()
        .unwrap_or_else(|| config.cloud.endpoint.clone());
    // Enrollment itself is an edge-plane call (/v1/edge/enroll/exchange) and
    // must go to soth-ingestion. Derive from the effective management URL
    // so `--endpoint https://api.<domain>` auto-rewrites to `ingest.<domain>`
    // without the user needing to know the split.
    let ingest_endpoint = cli_config::derive_ingest_endpoint(management_endpoint.as_str());
    let machine_name = args
        .machine_name
        .clone()
        .unwrap_or_else(default_machine_name);
    let enrollment_device_id = cli_config::sync_client_device_id(&mut config, None)?;
    let enrollment_proxy_public_key = proxy_public_key_base64(enrollment_device_id.as_str());

    let response_json = exchange_enroll_token(
        &ingest_endpoint,
        &enroll_token,
        &machine_name,
        enrollment_device_id.as_str(),
        enrollment_proxy_public_key.as_str(),
    )
    .await?;
    let exchanged = parse_enrollment_exchange(&response_json)
        .context("enrollment response did not contain usable machine credentials")?;

    config.cloud.enabled = true;
    config.cloud.api_key = Some(exchanged.api_key);
    // If user passed --endpoint, keep it authoritative for this enrollment.
    // Otherwise accept server-provided management endpoint when available.
    config.cloud.endpoint = if let Some(explicit) = endpoint_override {
        explicit
    } else {
        exchanged.endpoint.unwrap_or(management_endpoint)
    };
    // Cloud sync uses the unified Exchange pipeline (schema_version=1).
    config.exchange.enabled = true;

    if let Some(workspace_id) = exchanged.workspace_id {
        config
            .cloud
            .tags
            .insert("workspace_id".to_string(), workspace_id);
    }
    if let Some(org_id) = exchanged.org_id {
        config.cloud.tags.insert("org_id".to_string(), org_id);
    }
    if let Some(tags) = exchanged.tags {
        for (key, value) in tags {
            config.cloud.tags.insert(key, value);
        }
    }
    if !config.cloud.tags.contains_key("team_id") {
        if let Some(workspace_id) = config.cloud.tags.get("workspace_id").cloned() {
            config
                .cloud
                .tags
                .insert("team_id".to_string(), workspace_id);
        }
    }
    let device_id = cli_config::sync_client_device_id(&mut config, exchanged.device_id.as_deref())?;

    cli_config::write_config(&config_path, &config)?;

    println!("Enrollment completed.");
    println!("Saved cloud credentials to {}", config_path.display());
    println!("Cloud sync enabled: {}", config.cloud.enabled);
    println!("Cloud endpoint (management): {}", config.cloud.endpoint);
    println!(
        "Cloud endpoint (edge/ingest): {}",
        config.cloud.resolved_ingest_endpoint()
    );
    println!("Exchange enabled: {}", config.exchange.enabled);
    println!("Client device ID: {device_id}");
    if let Some(workspace_id) = config.cloud.tags.get("workspace_id") {
        println!("Workspace: {workspace_id}");
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct EnrollmentExchange {
    api_key: String,
    endpoint: Option<String>,
    workspace_id: Option<String>,
    org_id: Option<String>,
    tags: Option<BTreeMap<String, String>>,
    device_id: Option<String>,
}

fn parse_enrollment_exchange(value: &Value) -> Result<EnrollmentExchange> {
    if value.pointer("/success").and_then(Value::as_bool) == Some(false) {
        let reason = first_string(
            value,
            &[
                "/error",
                "/message",
                "/data/error",
                "/data/message",
                "/detail",
            ],
        )
        .unwrap_or_else(|| "enrollment rejected by server".to_string());
        anyhow::bail!(reason);
    }

    let api_key = first_string(
        value,
        &[
            "/api_key",
            "/data/api_key",
            "/credential/api_key",
            "/data/credential/api_key",
            "/ingest_api_key",
            "/data/ingest_api_key",
            "/machine/api_key",
            "/data/machine/api_key",
        ],
    )
    .context("missing api_key in enrollment response")?;

    let endpoint = first_string(value, &["/endpoint", "/data/endpoint", "/cloud/endpoint"]);
    let workspace_id = first_string(
        value,
        &[
            "/workspace_id",
            "/data/workspace_id",
            "/workspace/id",
            "/data/workspace/id",
        ],
    );
    let org_id = first_string(
        value,
        &["/org_id", "/data/org_id", "/org/id", "/data/org/id"],
    );

    let tags = first_object_map(value, &["/tags", "/data/tags"]);
    let device_id = first_string(value, &["/device_id", "/data/device_id"]);

    Ok(EnrollmentExchange {
        api_key,
        endpoint,
        workspace_id,
        org_id,
        tags,
        device_id,
    })
}

fn first_string(value: &Value, pointers: &[&str]) -> Option<String> {
    pointers.iter().find_map(|path| {
        value
            .pointer(path)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

fn first_object_map(value: &Value, pointers: &[&str]) -> Option<BTreeMap<String, String>> {
    pointers.iter().find_map(|path| {
        let obj = value.pointer(path)?.as_object()?;
        let mut map = BTreeMap::new();
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                map.insert(k.clone(), s.to_string());
            }
        }
        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    })
}

async fn exchange_enroll_token(
    endpoint: &str,
    token: &str,
    machine_name: &str,
    device_id_hash: &str,
    proxy_public_key: &str,
) -> Result<Value> {
    let base = endpoint.trim_end_matches('/');
    let url = format!("{base}/v1/edge/enroll/exchange");
    let client = build_cloud_client(base)?;
    let body = serde_json::json!({
        "enroll_token": token,
        "machine_name": machine_name,
        "device_id_hash": device_id_hash,
        "proxy_public_key": proxy_public_key,
        "client": {
            "hostname": machine_name,
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "soth_version": env!("CARGO_PKG_VERSION"),
            "device_id": device_id_hash,
        }
    });

    let response = client
        .post(&url)
        .header(API_VERSION_HEADER, API_VERSION)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("failed calling enrollment endpoint {url}"))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .context("failed reading enrollment response body")?;

    if !status.is_success() {
        anyhow::bail!("enrollment exchange failed: HTTP {status} - {text}");
    }

    serde_json::from_str::<Value>(&text)
        .with_context(|| format!("failed parsing enrollment response JSON: {text}"))
}

fn build_cloud_client(endpoint: &str) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(20))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(30));
    if should_bypass_proxy(endpoint) || has_loopback_proxy_env() {
        builder = builder.no_proxy();
    }
    builder
        .build()
        .context("failed constructing cloud HTTP client")
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

    let normalized = host.trim_matches('[').trim_matches(']');
    match normalized.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => false,
    }
}

fn default_machine_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "soth-proxy".to_string())
}

fn proxy_public_key_base64(device_id_hash: &str) -> String {
    // The enroll command derives the public key without access to the proxy's
    // user_hmac_secret, so local_secret is empty. This is only used to display
    // the public key identity for enrollment — the actual proxy uses
    // user_hmac_secret mixed in at runtime.
    let seed = derive_proxy_signing_seed(device_id_hash, &[]);
    let signing_key = SigningKey::from_bytes(&seed);
    BASE64_STANDARD.encode(signing_key.verifying_key().as_bytes())
}

fn resolve_config_path(explicit: Option<&PathBuf>, global: Option<&PathBuf>) -> PathBuf {
    if let Some(path) = cli_config::resolve_config_path(explicit, global) {
        return path;
    }
    cli_config::expand_tilde(Path::new("~/.soth/soth.yaml"))
}

fn resolve_enroll_token(args: &EnrollArgs) -> Result<String> {
    if let Some(token) = args.token.as_ref() {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    if args.from_stdin {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed reading enroll token from stdin")?;
        let trimmed = buf.trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("stdin enroll token was empty");
        }
        return Ok(trimmed);
    }

    if args.non_interactive {
        anyhow::bail!("enroll token is required in non-interactive mode");
    }

    print!("Enter enrollment token: ");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .context("failed reading enrollment token")?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        anyhow::bail!("enroll token is required");
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::{parse_enrollment_exchange, should_bypass_proxy};
    use serde_json::json;

    #[test]
    fn parse_enrollment_from_data_payload() {
        let payload = json!({
            "success": true,
            "data": {
                "api_key": "soth_live_x",
                "endpoint": "https://api.example.com",
                "workspace_id": "ws_123",
                "tags": { "env": "prod" },
                "device_id": "device_123"
            }
        });
        let parsed = parse_enrollment_exchange(&payload).expect("parse enrollment payload");
        assert_eq!(parsed.api_key, "soth_live_x");
        assert_eq!(parsed.endpoint.as_deref(), Some("https://api.example.com"));
        assert_eq!(parsed.workspace_id.as_deref(), Some("ws_123"));
        assert_eq!(parsed.device_id.as_deref(), Some("device_123"));
        assert_eq!(
            parsed
                .tags
                .as_ref()
                .and_then(|m| m.get("env"))
                .map(String::as_str),
            Some("prod")
        );
    }

    #[test]
    fn parse_enrollment_from_credential_payload() {
        let payload = json!({
            "credential": {
                "api_key": "soth_live_cred"
            }
        });
        let parsed = parse_enrollment_exchange(&payload).expect("parse credential payload");
        assert_eq!(parsed.api_key, "soth_live_cred");
    }

    #[test]
    fn bypass_proxy_for_localhost_endpoint() {
        assert!(should_bypass_proxy("http://localhost:8081"));
        assert!(should_bypass_proxy("http://127.0.0.1:8081"));
        assert!(!should_bypass_proxy("https://api.soth.ai"));
    }
}

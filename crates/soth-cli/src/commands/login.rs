//! `soth login` — persist a long-lived cloud API key to the local config.
//!
//! Unlike `soth enroll`, which exchanges a single-use invite token for an API
//! key, `login` accepts an already-provisioned API key directly (e.g. one
//! generated in the dashboard or distributed by an admin). It writes the key
//! and endpoint into `~/.soth/soth.yaml` so subsequent `soth start` picks it
//! up from `cloud.api_key`.

use anyhow::{Context, Result};
use clap::Args;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::cli_config;

#[derive(Debug, Clone, Args)]
pub struct LoginArgs {
    /// Cloud API key. Mutually exclusive with --from-stdin.
    #[arg(long)]
    pub api_key: Option<String>,

    /// Read the API key from stdin (recommended: avoids exposing the key in
    /// shell history / process listings).
    #[arg(long)]
    pub from_stdin: bool,

    /// Cloud management endpoint (e.g. https://api.soth.ai). Serves
    /// dashboard/management routes (/v1/keys, /v1/dashboard/*, /v1/org/*).
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Cloud edge/ingest endpoint (e.g. https://ingest.soth.ai). Serves the
    /// edge plane (/v1/edge/enroll/exchange, /v1/edge/heartbeat, etc.).
    /// Optional: when omitted, derived from --endpoint by rewriting
    /// api.<domain> to ingest.<domain>. Set this explicitly only for
    /// single-host dev or custom deployments.
    #[arg(long)]
    pub ingest_endpoint: Option<String>,

    /// Config file path to update (defaults to ~/.soth/soth.yaml).
    #[arg(long)]
    pub config: Option<PathBuf>,
}

pub async fn run(args: LoginArgs, global_config: Option<PathBuf>) -> Result<()> {
    let config_path = cli_config::resolve_config_path(args.config.as_ref(), global_config.as_ref())
        .unwrap_or_else(|| cli_config::expand_tilde(Path::new("~/.soth/soth.yaml")));
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating config directory {}", parent.display()))?;
    }

    let mut config = if config_path.exists() {
        cli_config::load_config(config_path.clone())?
    } else {
        cli_config::SothConfig::default()
    };

    let api_key = resolve_api_key(&args)?;
    if api_key.is_empty() {
        anyhow::bail!("api key is empty");
    }

    config.cloud.enabled = true;
    config.cloud.api_key = Some(api_key);
    if let Some(endpoint) = args.endpoint.clone() {
        config.cloud.endpoint = endpoint;
    }
    if let Some(ingest) = args.ingest_endpoint.clone() {
        let trimmed = ingest.trim();
        config.cloud.ingest_endpoint = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }
    config.exchange.enabled = true;

    cli_config::write_config(&config_path, &config)?;

    println!("Login saved.");
    println!("Config: {}", config_path.display());
    println!("Cloud endpoint (management): {}", config.cloud.endpoint);
    println!(
        "Cloud endpoint (edge/ingest): {}",
        config.cloud.resolved_ingest_endpoint()
    );

    Ok(())
}

fn resolve_api_key(args: &LoginArgs) -> Result<String> {
    if args.from_stdin {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed reading api key from stdin")?;
        return Ok(buf.trim().to_string());
    }
    if let Some(key) = args.api_key.as_ref() {
        return Ok(key.trim().to_string());
    }
    anyhow::bail!("api key required: pass --api-key or --from-stdin")
}

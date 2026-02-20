use crate::cli_config;
use anyhow::Context;
use clap::Args;
use soth_core::config::SothConfig;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Args)]
pub struct LoginArgs {
    /// Cloud API key (if omitted, prompt or read from stdin)
    #[arg(long)]
    pub api_key: Option<String>,

    /// Cloud API endpoint override
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Config file path to update (defaults to ~/.soth/soth.yaml)
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Read API key from stdin
    #[arg(long)]
    pub from_stdin: bool,
}

pub async fn run(args: LoginArgs, global_config: Option<PathBuf>) -> anyhow::Result<()> {
    let config_path = resolve_login_config_path(args.config.as_ref(), global_config.as_ref());
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating config directory {}", parent.display()))?;
    }

    let mut config = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed reading {}", config_path.display()))?;
        serde_yaml::from_str::<SothConfig>(&content)
            .with_context(|| format!("failed parsing {}", config_path.display()))?
    } else {
        SothConfig::default()
    };

    let api_key = resolve_api_key(&args)?;
    config.cloud.api_key = Some(api_key);
    config.cloud.enabled = true;
    // Cloud sync uses unified exchange.v2 pipeline.
    config.exchange_v2.enabled = true;
    if let Some(endpoint) = args.endpoint {
        config.cloud.endpoint = endpoint;
    }
    let device_id = cli_config::sync_client_device_id(&mut config, None)?;

    let serialized = serde_yaml::to_string(&config).context("failed serializing config")?;
    std::fs::write(&config_path, serialized)
        .with_context(|| format!("failed writing {}", config_path.display()))?;

    println!("Saved cloud credentials to {}", config_path.display());
    println!("Cloud sync enabled: {}", config.cloud.enabled);
    println!("Cloud endpoint: {}", config.cloud.endpoint);
    println!("Exchange v2 enabled: {}", config.exchange_v2.enabled);
    println!("Client device ID: {device_id}");
    println!("For enterprise invites, use: soth enroll <token>");
    Ok(())
}

fn resolve_login_config_path(explicit: Option<&PathBuf>, global: Option<&PathBuf>) -> PathBuf {
    if let Some(path) = explicit {
        return cli_config::expand_tilde(path);
    }
    if let Some(path) = global {
        return cli_config::expand_tilde(path);
    }
    cli_config::expand_tilde(Path::new("~/.soth/soth.yaml"))
}

fn resolve_api_key(args: &LoginArgs) -> anyhow::Result<String> {
    if let Some(key) = args.api_key.as_ref() {
        let trimmed = key.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    if args.from_stdin {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed reading api key from stdin")?;
        let trimmed = buf.trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("stdin api key was empty");
        }
        return Ok(trimmed);
    }

    print!("Enter SOTH cloud API key: ");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .context("failed reading api key")?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        anyhow::bail!("api key is required");
    }
    Ok(trimmed)
}

//! Initialize local CLI/runtime config.

use crate::cli_config::{self, SothConfig};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub async fn run(output: PathBuf) -> Result<()> {
    let root = cli_config::expand_tilde(output.as_path());
    ensure_layout(root.as_path())?;

    let config_path = root.join("soth.yaml");
    let is_new = !config_path.exists();
    let mut config = if config_path.exists() {
        cli_config::load_config(config_path.clone())?
    } else {
        SothConfig::default()
    };

    apply_runtime_defaults(&mut config, root.as_path(), is_new);
    let _ = cli_config::sync_client_device_id(&mut config, None)?;
    cli_config::write_config(config_path.as_path(), &config)?;

    println!("Initialized SOTH at {}", root.display());
    println!("Config: {}", config_path.display());
    println!();
    println!("Next steps:");
    println!("  1. soth setup-ca");
    println!("  2. soth start");
    println!("  3. soth on");
    println!("  4. soth status");
    Ok(())
}

fn ensure_layout(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root).with_context(|| format!("failed creating {}", root.display()))?;
    for rel in ["certs", "logs", "run", "runtime", "bundle"] {
        let path = root.join(rel);
        std::fs::create_dir_all(path.as_path())
            .with_context(|| format!("failed creating {}", path.display()))?;
    }
    Ok(())
}

fn apply_runtime_defaults(config: &mut SothConfig, root: &Path, force: bool) {
    let cert = root.join("certs").join("soth-mitm-ca.pem");
    let key = root.join("certs").join("soth-mitm-ca-key.pem");
    let db = root.join("logs").join("events.db");
    let bundle = root.join("bundle");

    if force || config.forward_proxy.ca.cert_path.trim().is_empty() {
        config.forward_proxy.ca.cert_path = cert.display().to_string();
    }
    if force || config.forward_proxy.ca.key_path.trim().is_empty() {
        config.forward_proxy.ca.key_path = key.display().to_string();
    }
    if force || config.proxy.db_path.trim().is_empty() {
        config.proxy.db_path = db.display().to_string();
    }
    if force || config.bundle.bundle_dir.trim().is_empty() {
        config.bundle.bundle_dir = bundle.display().to_string();
    }
}

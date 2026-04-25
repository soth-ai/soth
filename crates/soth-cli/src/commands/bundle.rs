//! Bundle status and verification commands.

use crate::cli_config;
use crate::style;
use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use clap::{Args, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Subcommand, Clone)]
pub enum BundleCommands {
    /// Show active bundle metadata and trust state
    Status(BundleStatusArgs),
    /// Re-verify bundle contents/signature against local policy
    Verify(BundleVerifyArgs),
}

#[derive(Args, Clone)]
pub struct BundleStatusArgs {
    /// Config file path
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Clone)]
pub struct BundleVerifyArgs {
    /// Config file path
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Emit machine-readable JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct BundleStatusJson {
    loaded: bool,
    bundle_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust_level: Option<String>,
    verify_vendor_signature: bool,
    require_verified_bundle: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    load_error: Option<String>,
}

pub async fn run(action: BundleCommands, global_config: Option<PathBuf>) -> Result<()> {
    match action {
        BundleCommands::Status(args) => run_status(args, global_config).await,
        BundleCommands::Verify(args) => run_verify(args, global_config).await,
    }
}

async fn run_status(args: BundleStatusArgs, global_config: Option<PathBuf>) -> Result<()> {
    let inputs = resolve_inputs(args.config.as_ref(), global_config.as_ref())?;
    let mut status = BundleStatusJson {
        loaded: false,
        bundle_dir: inputs.bundle_dir.display().to_string(),
        bundle_id: None,
        version: None,
        model_version: None,
        policy_version: None,
        org_id: None,
        issued_at: None,
        expires_at: None,
        trust_level: None,
        verify_vendor_signature: inputs.verification.verify_vendor_signature,
        require_verified_bundle: inputs.verification.require_verified_bundle,
        source: Some(inputs.source),
        load_error: None,
    };

    match soth_bundle::load_from_dir_with_options(
        inputs.bundle_dir.as_path(),
        &inputs.vendor_pubkey,
        &inputs.org_config,
        inputs.verification,
    ) {
        Ok(bundle) => {
            status.loaded = true;
            status.bundle_id = Some(bundle.meta.bundle_id.clone());
            status.version = Some(bundle.version.clone());
            status.model_version = Some(bundle.meta.model_version.clone());
            status.policy_version = Some(bundle.meta.policy_version.clone());
            status.org_id = Some(bundle.meta.org_id.clone());
            status.issued_at = Some(bundle.meta.issued_at);
            status.expires_at = bundle.meta.expires_at;
            status.trust_level = Some(bundle_trust_level_text(bundle.trust_level).to_string());
        }
        Err(error) => {
            status.load_error = Some(error.to_string());
        }
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).context("serialize bundle status JSON")?
        );
        return Ok(());
    }

    println!("BUNDLE");
    println!("----------------------------------------");
    println!("Path:                 {}", status.bundle_dir);
    println!(
        "Loaded:               {}",
        if status.loaded { "yes" } else { "no" }
    );
    println!(
        "Version:              {}",
        status.version.as_deref().unwrap_or("not loaded")
    );
    println!(
        "Bundle ID:            {}",
        status.bundle_id.as_deref().unwrap_or("not loaded")
    );
    println!(
        "Model version:        {}",
        status.model_version.as_deref().unwrap_or("not loaded")
    );
    println!(
        "Policy version:       {}",
        status.policy_version.as_deref().unwrap_or("not loaded")
    );
    // Bundles only carry the org's UUID — the human-readable org name lives
    // in the cloud and would require an authenticated round-trip to resolve.
    // Label this as an ID so users don't read it as a missing name.
    println!(
        "Org ID:               {}",
        status.org_id.as_deref().unwrap_or("not loaded")
    );
    let now_secs = Utc::now().timestamp();
    println!(
        "Issued at:            {}",
        status
            .issued_at
            .map(format_epoch_secs)
            .unwrap_or_else(|| "not loaded".to_string())
    );
    println!(
        "Expires at:           {}",
        format_expiry(status.expires_at, now_secs)
    );
    println!(
        "Trust level:          {}",
        status.trust_level.as_deref().unwrap_or("not loaded")
    );
    println!(
        "Verify vendor sig:    {}",
        if status.verify_vendor_signature {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "Require verified:     {}",
        if status.require_verified_bundle {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "Config source:        {}",
        status.source.as_deref().unwrap_or("cli")
    );

    if let Some(error) = status.load_error.as_deref() {
        println!("Error:                {error}");
        style::warning("bundle load failed");
    } else if let Some(message) = expiry_warning(status.expires_at, now_secs) {
        style::warning(&message);
    } else {
        style::success("bundle load ok");
    }

    Ok(())
}

fn format_epoch_secs(epoch_secs: u64) -> String {
    Utc.timestamp_opt(epoch_secs as i64, 0)
        .single()
        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("{epoch_secs} (unparseable)"))
}

fn format_expiry(expires_at: Option<u64>, now_secs: i64) -> String {
    let Some(expires) = expires_at else {
        return "none (bundle has no expiry set)".to_string();
    };
    let formatted = format_epoch_secs(expires);
    let delta_secs = expires as i64 - now_secs;
    if delta_secs < 0 {
        format!(
            "{formatted} (EXPIRED {} ago)",
            format_relative_secs(-delta_secs)
        )
    } else {
        format!("{formatted} (in {})", format_relative_secs(delta_secs))
    }
}

fn format_relative_secs(seconds: i64) -> String {
    if seconds < 60 {
        return format!("{seconds}s");
    }
    if seconds < 3600 {
        return format!("{}m", seconds / 60);
    }
    if seconds < 86400 {
        return format!("{}h", seconds / 3600);
    }
    format!("{}d", seconds / 86400)
}

/// Returns a user-facing warning if the bundle is expired or expiring within 7 days.
fn expiry_warning(expires_at: Option<u64>, now_secs: i64) -> Option<String> {
    let expires = expires_at? as i64;
    let delta = expires - now_secs;
    const WARN_WINDOW_SECS: i64 = 7 * 24 * 3600;
    if delta < 0 {
        Some(format!(
            "bundle EXPIRED {} ago — refresh via `soth bundle pull` (or restart proxy)",
            format_relative_secs(-delta)
        ))
    } else if delta < WARN_WINDOW_SECS {
        Some(format!(
            "bundle expires in {} — refresh soon",
            format_relative_secs(delta)
        ))
    } else {
        None
    }
}

async fn run_verify(args: BundleVerifyArgs, global_config: Option<PathBuf>) -> Result<()> {
    let inputs = resolve_inputs(args.config.as_ref(), global_config.as_ref())?;

    let bundle = soth_bundle::load_from_dir_with_options(
        inputs.bundle_dir.as_path(),
        &inputs.vendor_pubkey,
        &inputs.org_config,
        inputs.verification,
    )
    .with_context(|| {
        format!(
            "bundle verification failed at {}",
            inputs.bundle_dir.display()
        )
    })?;

    let trust_level = bundle_trust_level_text(bundle.trust_level).to_string();

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&BundleStatusJson {
                loaded: true,
                bundle_dir: inputs.bundle_dir.display().to_string(),
                bundle_id: Some(bundle.meta.bundle_id),
                version: Some(bundle.version),
                model_version: Some(bundle.meta.model_version),
                policy_version: Some(bundle.meta.policy_version),
                org_id: Some(bundle.meta.org_id),
                issued_at: Some(bundle.meta.issued_at),
                expires_at: bundle.meta.expires_at,
                trust_level: Some(trust_level),
                verify_vendor_signature: inputs.verification.verify_vendor_signature,
                require_verified_bundle: inputs.verification.require_verified_bundle,
                source: Some(inputs.source),
                load_error: None,
            })
            .context("serialize bundle verify JSON")?
        );
        return Ok(());
    }

    println!(
        "Bundle verification succeeded: version={} trust_level={}",
        bundle.version,
        bundle_trust_level_text(bundle.trust_level)
    );

    Ok(())
}

#[derive(Clone)]
struct BundleInputs {
    bundle_dir: PathBuf,
    vendor_pubkey: [u8; 32],
    org_config: soth_bundle::OrgSignedConfig,
    verification: soth_bundle::VerificationOptions,
    source: String,
}

fn resolve_inputs(
    config: Option<&PathBuf>,
    global_config: Option<&PathBuf>,
) -> Result<BundleInputs> {
    let cli = cli_config::load_effective_config(config, global_config)?;
    let cli_bundle_dir = cli_config::expand_tilde(Path::new(cli.bundle.bundle_dir.as_str()));

    let generated = proxy_generated_config_path();
    if generated.exists() {
        if let Ok(proxy_cfg) = soth_proxy::config::ProxyConfig::from_toml_file(generated.as_path())
        {
            let source = if cli_bundle_dir != proxy_cfg.bundle.bundle_dir {
                format!(
                    "generated_proxy_config_override (cli={} proxy={})",
                    cli_bundle_dir.display(),
                    proxy_cfg.bundle.bundle_dir.display()
                )
            } else {
                "generated_proxy_config".to_string()
            };

            return Ok(BundleInputs {
                bundle_dir: proxy_cfg.bundle.bundle_dir.clone(),
                vendor_pubkey: proxy_cfg
                    .bundle_vendor_pubkey()
                    .context("parse vendor pubkey from generated proxy config")?,
                org_config: proxy_cfg.org_signed_config(),
                verification: proxy_cfg
                    .bundle_verification_options()
                    .context("parse verification options from generated proxy config")?,
                source,
            });
        }
    }

    let bundle_dir = cli_bundle_dir;
    let vendor_pubkey = parse_fixed_hex_32(
        cli.bundle.vendor_pubkey_hex.as_str(),
        "bundle.vendor_pubkey_hex",
    )?;
    let org_config = soth_bundle::OrgSignedConfig {
        allows_https_intercept: true,
        allows_http_intercept: true,
        process_filter: None,
        allowed_capture_modes: vec![
            "metadata_only".to_string(),
            "sensitive_artifacts".to_string(),
            "full".to_string(),
        ],
    };
    let verification = soth_bundle::VerificationOptions {
        verify_vendor_signature: cli.bundle.verify_vendor_signature,
        require_verified_bundle: cli.bundle.require_verified_bundle,
        org_approval_pubkey: cli
            .bundle
            .org_approval_pubkey_hex
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| parse_fixed_hex_32(value, "bundle.org_approval_pubkey_hex"))
            .transpose()?,
    };

    Ok(BundleInputs {
        bundle_dir,
        vendor_pubkey,
        org_config,
        verification,
        source: "cli_config".to_string(),
    })
}

fn proxy_generated_config_path() -> PathBuf {
    soth_home_dir().join("run").join("proxy.generated.toml")
}

fn soth_home_dir() -> PathBuf {
    if let Ok(value) = std::env::var("SOTH_HOME_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    dirs::home_dir()
        .map(|home| home.join(".soth"))
        .unwrap_or_else(|| PathBuf::from(".soth"))
}

fn parse_fixed_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value.trim()).with_context(|| format!("{field} must be hex"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "{field} must decode to exactly 32 bytes, got {} bytes",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    Ok(out)
}

fn bundle_trust_level_text(level: soth_bundle::BundleTrustLevel) -> &'static str {
    match level {
        soth_bundle::BundleTrustLevel::Verified => "verified",
        soth_bundle::BundleTrustLevel::Unverified => "unverified",
        soth_bundle::BundleTrustLevel::SignatureDisabled => "signature_disabled",
    }
}

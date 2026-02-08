//! CA certificate info command

use crate::cli_config;
use crate::style;
use owo_colors::OwoColorize;
use std::path::PathBuf;
use x509_parser::prelude::*;

/// Run the ca-info command
pub async fn run(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let cert_path = cli_config::expand_tilde(&config.forward_proxy.ca.cert_path);

    if !cert_path.exists() {
        style::warning(&format!(
            "CA certificate not found at {}",
            cert_path.display()
        ));
        style::info("Run: soth proxy setup-ca");
        return Ok(());
    }

    // Read and parse certificate
    let pem_data = std::fs::read_to_string(&cert_path)?;

    // Parse PEM
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_data.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {:?}", e))?;

    // Parse X.509
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse X.509: {:?}", e))?;

    style::header("SOTH CA Certificate");

    // Subject
    style::subtitle("Subject");
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if let Ok(s) = attr.as_str() {
                let oid_name = match attr.attr_type().to_string().as_str() {
                    "2.5.4.3" => "CN",
                    "2.5.4.10" => "O",
                    "2.5.4.6" => "C",
                    "2.5.4.7" => "L",
                    "2.5.4.8" => "ST",
                    _ => &attr.attr_type().to_string(),
                };
                style::kv(oid_name, s);
            }
        }
    }

    // Issuer (same as subject for self-signed)
    style::subtitle("Issuer");
    for rdn in cert.issuer().iter() {
        for attr in rdn.iter() {
            if let Ok(s) = attr.as_str() {
                let oid_name = match attr.attr_type().to_string().as_str() {
                    "2.5.4.3" => "CN",
                    "2.5.4.10" => "O",
                    _ => &attr.attr_type().to_string(),
                };
                style::kv(oid_name, s);
            }
        }
    }

    // Validity
    style::subtitle("Validity");
    style::kv("Not Before", &cert.validity().not_before.to_string());
    style::kv("Not After", &cert.validity().not_after.to_string());

    // Check if expired
    let now = chrono::Utc::now();
    let not_after = cert.validity().not_after.to_datetime();
    // Convert to Unix timestamp for comparison
    let not_after_ts = not_after.unix_timestamp();
    let now_ts = now.timestamp();
    if not_after_ts < now_ts {
        style::kv(
            "Status",
            &format!("{} {}", style::CROSS.red(), "EXPIRED".red().bold()),
        );
    } else {
        let days_left = (not_after_ts - now_ts) / 86400;
        style::kv(
            "Status",
            &format!(
                "{} {} ({} days remaining)",
                style::CHECK.green(),
                "valid".green(),
                days_left
            ),
        );
    }

    style::subtitle("Certificate");
    style::kv("Serial", &cert.serial.to_string());
    style::kv(
        "Public Key Algorithm",
        &cert.public_key().algorithm.algorithm.to_string(),
    );
    style::kv("Path", &cert_path.display().to_string());
    if let Ok(metadata) = std::fs::metadata(&cert_path) {
        style::kv("Size", &format!("{} bytes", metadata.len()));
    }

    style::subtitle("Usage");
    println!(
        "  {}",
        format!("curl --cacert {} https://...", cert_path.display()).dimmed()
    );
    println!(
        "  {}",
        format!("export SSL_CERT_FILE={}", cert_path.display()).dimmed()
    );
    style::footer();

    Ok(())
}

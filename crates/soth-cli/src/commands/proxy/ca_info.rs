//! CA certificate info command

use std::path::PathBuf;
use x509_parser::prelude::*;

/// Expand tilde in path
fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

/// Run the ca-info command
pub async fn run() -> anyhow::Result<()> {
    let ca_path = expand_path("~/.soth/ca");
    let cert_path = ca_path.join("ca.crt");

    if !cert_path.exists() {
        println!("CA certificate not found at {}", cert_path.display());
        println!("Run: soth proxy setup-ca");
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

    println!("SOTH CA Certificate Information");
    println!("================================");
    println!();

    // Subject
    println!("Subject:");
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
                println!("  {}: {}", oid_name, s);
            }
        }
    }
    println!();

    // Issuer (same as subject for self-signed)
    println!("Issuer:");
    for rdn in cert.issuer().iter() {
        for attr in rdn.iter() {
            if let Ok(s) = attr.as_str() {
                let oid_name = match attr.attr_type().to_string().as_str() {
                    "2.5.4.3" => "CN",
                    "2.5.4.10" => "O",
                    _ => &attr.attr_type().to_string(),
                };
                println!("  {}: {}", oid_name, s);
            }
        }
    }
    println!();

    // Validity
    println!("Validity:");
    println!("  Not Before: {}", cert.validity().not_before);
    println!("  Not After:  {}", cert.validity().not_after);

    // Check if expired
    let now = chrono::Utc::now();
    let not_after = cert.validity().not_after.to_datetime();
    // Convert to Unix timestamp for comparison
    let not_after_ts = not_after.unix_timestamp();
    let now_ts = now.timestamp();
    if not_after_ts < now_ts {
        println!("  Status: EXPIRED!");
    } else {
        let days_left = (not_after_ts - now_ts) / 86400;
        println!("  Status: Valid ({} days remaining)", days_left);
    }
    println!();

    // Serial number
    println!("Serial Number: {}", cert.serial);
    println!();

    // Key info
    println!("Public Key:");
    println!("  Algorithm: {}", cert.public_key().algorithm.algorithm);
    println!();

    // File info
    println!("File:");
    println!("  Path: {}", cert_path.display());
    if let Ok(metadata) = std::fs::metadata(&cert_path) {
        println!("  Size: {} bytes", metadata.len());
    }
    println!();

    // Usage instructions
    println!("Usage:");
    println!("  curl --cacert {} https://...", cert_path.display());
    println!("  export SSL_CERT_FILE={}", cert_path.display());

    Ok(())
}

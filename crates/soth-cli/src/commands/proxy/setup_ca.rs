//! CA setup command

use crate::cli_config;
use crate::style;
use owo_colors::OwoColorize;
use soth_tls::CertificateAuthority;
use std::path::PathBuf;

/// Expand tilde in path
fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

/// Run the setup-ca command
pub async fn run(
    output: Option<String>,
    no_trust: bool,
    config_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let proxy_addr = format!("http://{}", config.forward_proxy.socket_addr());
    let configured_cert_path = cli_config::expand_tilde(&config.forward_proxy.ca.cert_path);
    let configured_key_path = cli_config::expand_tilde(&config.forward_proxy.ca.key_path);
    let use_config_paths = output.is_none();
    let output_path = output.as_ref().map_or_else(
        || {
            configured_cert_path
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf()
        },
        |value| expand_path(value),
    );

    // Check if CA already exists
    let cert_path = if use_config_paths {
        configured_cert_path.clone()
    } else {
        output_path.join("ca.crt")
    };
    let key_path = if use_config_paths {
        configured_key_path.clone()
    } else {
        output_path.join("ca.key")
    };

    if cert_path.exists() && key_path.exists() {
        if let Ok(mut existing_ca) = CertificateAuthority::load_from_path(output_path.clone()) {
            let _ = existing_ca.apply_crypto_tls_config(&config.crypto_identity.tls, None);
        }
        style::header("CA Certificate Status");
        style::success("CA certificate already exists");
        println!();
        style::kv("Certificate", &cert_path.display().to_string());
        style::kv("Private key", &key_path.display().to_string());
        println!();
        style::warning("To regenerate, delete these files first.");
        style::footer();
        return Ok(());
    }

    style::header("CA Certificate Setup");

    // Step 1: Create directory
    style::step(1, 3, "Creating output directory...");
    std::fs::create_dir_all(&output_path)?;
    style::step_done(1, 3, "Output directory ready");

    // Step 2: Generate CA
    style::step(2, 3, "Generating CA certificate...");
    let mut ca = CertificateAuthority::generate_new(output_path.clone())
        .map_err(|e| anyhow::anyhow!("Failed to generate CA: {}", e))?;
    ca.apply_crypto_tls_config(&config.crypto_identity.tls, None)
        .map_err(|e| anyhow::anyhow!("Failed to apply TLS crypto identity settings: {}", e))?;

    if use_config_paths {
        let generated_cert_path = output_path.join("ca.crt");
        let generated_key_path = output_path.join("ca.key");
        if generated_cert_path != cert_path {
            std::fs::rename(&generated_cert_path, &cert_path)?;
        }
        if generated_key_path != key_path {
            std::fs::rename(&generated_key_path, &key_path)?;
        }
    }
    style::step_done(2, 3, "CA certificate generated");

    // Step 3: Verify
    style::step(3, 3, "Verifying certificate...");
    style::step_done(3, 3, "Certificate verified");

    println!();
    style::success("CA certificate generated successfully!");
    println!();
    style::kv("Certificate", &cert_path.display().to_string());
    style::kv("Private key", &key_path.display().to_string());
    style::kv("CA key id", &ca.identity_metadata().ca_key_id);

    // Install to trust store if requested
    if !no_trust {
        println!();
        style::subtitle("Trust Installation");
        style::info("To trust the CA certificate system-wide:");

        #[cfg(target_os = "macos")]
        {
            println!();
            println!("  {} (requires admin):", "macOS".bold());
            println!(
                "    {}",
                format!(
                    "sudo security add-trusted-cert -d -r trustRoot \\
      -k /Library/Keychains/System.keychain \\
      {}",
                    cert_path.display()
                )
                .dimmed()
            );
        }

        #[cfg(target_os = "linux")]
        {
            println!();
            println!("  {} (Ubuntu/Debian):", "Linux".bold());
            println!(
                "    {}",
                format!(
                    "sudo cp {} /usr/local/share/ca-certificates/soth-ca.crt",
                    cert_path.display()
                )
                .dimmed()
            );
            println!("    {}", "sudo update-ca-certificates".dimmed());
            println!();
            println!("  {} (Fedora/RHEL):", "Linux".bold());
            println!(
                "    {}",
                format!(
                    "sudo cp {} /etc/pki/ca-trust/source/anchors/",
                    cert_path.display()
                )
                .dimmed()
            );
            println!("    {}", "sudo update-ca-trust".dimmed());
        }

        #[cfg(target_os = "windows")]
        {
            println!();
            println!("  {} (requires admin PowerShell):", "Windows".bold());
            println!(
                "    {}",
                format!(
                    "Import-Certificate -FilePath \"{}\" -CertStoreLocation Cert:\\LocalMachine\\Root",
                    cert_path.display()
                )
                .dimmed()
            );
        }

        println!();
        style::info("Or use the CA certificate directly with curl:");
        println!(
            "    {}",
            format!(
                "curl --cacert {} --proxy {} https://api.openai.com/v1/models",
                cert_path.display(),
                proxy_addr
            )
            .dimmed()
        );
    }

    println!();
    style::info("To configure your shell, run:");
    println!("    {}", "eval $(soth proxy env)".bold());

    style::footer();
    Ok(())
}

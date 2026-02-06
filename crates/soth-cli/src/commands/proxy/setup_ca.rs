//! CA setup command

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
pub async fn run(output: String, no_trust: bool) -> anyhow::Result<()> {
    let output_path = expand_path(&output);

    // Check if CA already exists
    let cert_path = output_path.join("ca.crt");
    let key_path = output_path.join("ca.key");

    if cert_path.exists() && key_path.exists() {
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
    let _ca = CertificateAuthority::generate_new(output_path.clone())
        .map_err(|e| anyhow::anyhow!("Failed to generate CA: {}", e))?;
    style::step_done(2, 3, "CA certificate generated");

    // Step 3: Verify
    style::step(3, 3, "Verifying certificate...");
    style::step_done(3, 3, "Certificate verified");

    println!();
    style::success("CA certificate generated successfully!");
    println!();
    style::kv("Certificate", &cert_path.display().to_string());
    style::kv("Private key", &key_path.display().to_string());

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
                "curl --cacert {} --proxy http://127.0.0.1:8080 https://api.openai.com/v1/models",
                cert_path.display()
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

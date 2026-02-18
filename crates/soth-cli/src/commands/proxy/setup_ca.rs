//! CA setup command

use crate::cli_config;
use crate::style;
use owo_colors::OwoColorize;
use soth_crypto::tls::CertificateAuthority;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use which::which;

/// Expand tilde in path
fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacOsTrustResult {
    Installed,
    AlreadyPresent,
}

#[cfg(target_os = "macos")]
fn macos_login_keychain_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library")
        .join("Keychains")
        .join("login.keychain-db")
}

#[cfg(target_os = "macos")]
fn ensure_macos_login_keychain_trust(cert_path: &Path) -> anyhow::Result<MacOsTrustResult> {
    let keychain_path = macos_login_keychain_path();
    let output = Command::new("security")
        .args(["add-trusted-cert", "-d", "-r", "trustRoot", "-k"])
        .arg(&keychain_path)
        .arg(cert_path)
        .output()
        .map_err(|error| anyhow::anyhow!("failed to execute security add-trusted-cert: {}", error))?;

    if output.status.success() {
        return Ok(MacOsTrustResult::Installed);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{} {}", stdout.trim(), stderr.trim()).to_ascii_lowercase();
    if combined.contains("already exists") || combined.contains("the specified item already exists")
    {
        return Ok(MacOsTrustResult::AlreadyPresent);
    }

    anyhow::bail!(
        "security add-trusted-cert failed for {}: {}",
        keychain_path.display(),
        combined.trim()
    )
}

#[cfg(target_os = "linux")]
fn run_linux_trust_command(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = if unsafe { libc::geteuid() } == 0 {
        Command::new(program)
            .args(args)
            .output()
            .map_err(|error| anyhow::anyhow!("failed to execute {}: {}", program, error))?
    } else {
        if which("sudo").is_err() {
            anyhow::bail!("sudo is not available; run trust commands manually");
        }
        let mut sudo_args = vec!["-n", program];
        sudo_args.extend(args);
        Command::new("sudo")
            .args(&sudo_args)
            .output()
            .map_err(|error| anyhow::anyhow!("failed to execute sudo {}: {}", program, error))?
    };

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!(
        "{} {:?} failed: {} {}",
        program,
        args,
        stdout.trim(),
        stderr.trim()
    )
}

#[cfg(target_os = "linux")]
fn ensure_linux_trust(cert_path: &Path) -> anyhow::Result<()> {
    let cert = cert_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid certificate path"))?;

    if which("update-ca-certificates").is_ok() {
        run_linux_trust_command("cp", &[cert, "/usr/local/share/ca-certificates/soth-ca.crt"])?;
        run_linux_trust_command("update-ca-certificates", &[])?;
        return Ok(());
    }

    if which("update-ca-trust").is_ok() {
        run_linux_trust_command("cp", &[cert, "/etc/pki/ca-trust/source/anchors/soth-ca.crt"])?;
        run_linux_trust_command("update-ca-trust", &[])?;
        return Ok(());
    }

    anyhow::bail!("no supported Linux trust command found (update-ca-certificates/update-ca-trust)")
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

    let mut generated_new_ca = false;
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
    } else {
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

        generated_new_ca = true;
        println!();
        style::success("CA certificate generated successfully!");
        println!();
        style::kv("Certificate", &cert_path.display().to_string());
        style::kv("Private key", &key_path.display().to_string());
        style::kv("CA key id", &ca.identity_metadata().ca_key_id);
    }

    // Install to trust store if requested
    if !no_trust {
        println!();
        style::subtitle("Trust Installation");
        style::info("Attempting trust installation.");

        #[cfg(target_os = "macos")]
        {
            match ensure_macos_login_keychain_trust(&cert_path) {
                Ok(MacOsTrustResult::Installed) => {
                    style::success(
                        "Installed SOTH CA into macOS login keychain trust store (auto).",
                    );
                }
                Ok(MacOsTrustResult::AlreadyPresent) => {
                    style::info("SOTH CA already present in macOS login keychain trust store.");
                }
                Err(error) => {
                    style::warning(&format!(
                        "Auto trust install failed (continuing fail-open): {}",
                        error
                    ));
                }
            }

            println!();
            println!("  {} (optional system-wide trust, requires admin):", "macOS".bold());
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
            match ensure_linux_trust(&cert_path) {
                Ok(()) => {
                    style::success("Installed SOTH CA into Linux trust store (auto).");
                }
                Err(error) => {
                    style::warning(&format!(
                        "Auto trust install failed (continuing fail-open): {}",
                        error
                    ));
                }
            }

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
    } else if generated_new_ca {
        println!();
        style::info("CA generated without trust installation (`--no-trust`).");
    }

    println!();
    style::info("To configure your shell, run:");
    println!("    {}", "eval $(soth runtime env)".bold());

    style::footer();
    Ok(())
}

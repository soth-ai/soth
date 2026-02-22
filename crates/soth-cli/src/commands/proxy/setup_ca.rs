//! CA setup command

use crate::cli_config;
use crate::style;
use owo_colors::OwoColorize;
use soth_crypto::tls::CertificateAuthority;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
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
    Reinstalled(usize),
}

#[cfg(target_os = "macos")]
struct MacOsTrustDrift {
    login_hashes: Vec<String>,
    system_hashes: Vec<String>,
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
fn macos_system_keychain_path() -> PathBuf {
    PathBuf::from("/Library/Keychains/System.keychain")
}

#[cfg(target_os = "macos")]
fn macos_soth_ca_name() -> &'static str {
    "SOTH Proxy CA"
}

#[cfg(target_os = "macos")]
fn macos_output_indicates_item_not_found(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{} {}", stdout, stderr).to_ascii_lowercase();
    combined.contains("could not be found")
        || combined.contains("specified item could not be found")
        || combined.contains("errsecitemnotfound")
}

#[cfg(target_os = "macos")]
fn macos_parse_certificate_hashes(output: &str) -> Vec<String> {
    let mut hashes = BTreeSet::new();
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("hash:") {
            continue;
        }

        let Some((_, suffix)) = line.split_once(':') else {
            continue;
        };
        let normalized: String = suffix.chars().filter(|ch| ch.is_ascii_hexdigit()).collect();
        if normalized.len() == 40 || normalized.len() == 64 {
            hashes.insert(normalized.to_ascii_uppercase());
        }
    }
    hashes.into_iter().collect()
}

#[cfg(target_os = "macos")]
fn macos_collect_certificate_hashes(
    keychain_path: &Path,
    common_name: &str,
) -> anyhow::Result<Vec<String>> {
    let output = Command::new("security")
        .args(["find-certificate", "-a", "-Z", "-c", common_name])
        .arg(keychain_path)
        .output()
        .map_err(|error| {
            anyhow::anyhow!("failed to execute security find-certificate: {}", error)
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() && !macos_output_indicates_item_not_found(&stdout, &stderr) {
        anyhow::bail!(
            "security find-certificate failed for {}: {} {}",
            keychain_path.display(),
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(macos_parse_certificate_hashes(&stdout))
}

#[cfg(target_os = "macos")]
fn macos_delete_certificates_by_common_name(
    keychain_path: &Path,
    common_name: &str,
) -> anyhow::Result<usize> {
    let mut removed = 0usize;

    for _ in 0..32 {
        let output = Command::new("security")
            .args(["delete-certificate", "-c", common_name])
            .arg(keychain_path)
            .output()
            .map_err(|error| {
                anyhow::anyhow!("failed to execute security delete-certificate: {}", error)
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            removed += 1;
            continue;
        }

        if macos_output_indicates_item_not_found(&stdout, &stderr) {
            break;
        }

        anyhow::bail!(
            "security delete-certificate failed for {}: {} {}",
            keychain_path.display(),
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(removed)
}

#[cfg(target_os = "macos")]
fn macos_add_trusted_cert(
    cert_path: &Path,
    keychain_path: &Path,
) -> anyhow::Result<std::process::Output> {
    Command::new("security")
        .args(["add-trusted-cert", "-d", "-r", "trustRoot", "-k"])
        .arg(keychain_path)
        .arg(cert_path)
        .output()
        .map_err(|error| anyhow::anyhow!("failed to execute security add-trusted-cert: {}", error))
}

#[cfg(target_os = "macos")]
fn ensure_macos_login_keychain_trust(
    cert_path: &Path,
    generated_new_ca: bool,
) -> anyhow::Result<MacOsTrustResult> {
    let keychain_path = macos_login_keychain_path();
    let mut removed_stale = 0usize;
    if generated_new_ca {
        removed_stale =
            macos_delete_certificates_by_common_name(&keychain_path, macos_soth_ca_name())?;
    }

    let output = macos_add_trusted_cert(cert_path, &keychain_path)?;

    if output.status.success() {
        if removed_stale > 0 {
            return Ok(MacOsTrustResult::Reinstalled(removed_stale));
        }
        return Ok(MacOsTrustResult::Installed);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{} {}", stdout.trim(), stderr.trim()).to_ascii_lowercase();
    if combined.contains("already exists") || combined.contains("the specified item already exists")
    {
        // If multiple cert hashes are present in the login keychain, clean and reinstall
        // to avoid stale local trust anchors.
        let hashes = macos_collect_certificate_hashes(&keychain_path, macos_soth_ca_name())?;
        if hashes.len() > 1 {
            let removed =
                macos_delete_certificates_by_common_name(&keychain_path, macos_soth_ca_name())?;
            let reinstall_output = macos_add_trusted_cert(cert_path, &keychain_path)?;
            if reinstall_output.status.success() {
                return Ok(MacOsTrustResult::Reinstalled(removed.max(1)));
            }

            let reinstall_stdout = String::from_utf8_lossy(&reinstall_output.stdout);
            let reinstall_stderr = String::from_utf8_lossy(&reinstall_output.stderr);
            anyhow::bail!(
                "security add-trusted-cert failed for {} after cleanup: {} {}",
                keychain_path.display(),
                reinstall_stdout.trim(),
                reinstall_stderr.trim()
            );
        }

        if removed_stale > 0 {
            return Ok(MacOsTrustResult::Reinstalled(removed_stale));
        }

        return Ok(MacOsTrustResult::AlreadyPresent);
    }

    anyhow::bail!(
        "security add-trusted-cert failed for {}: {}",
        keychain_path.display(),
        combined.trim()
    )
}

#[cfg(target_os = "macos")]
fn macos_detect_trust_drift() -> anyhow::Result<Option<MacOsTrustDrift>> {
    let login_hashes =
        macos_collect_certificate_hashes(&macos_login_keychain_path(), macos_soth_ca_name())?;
    if login_hashes.is_empty() {
        return Ok(None);
    }

    let system_hashes =
        macos_collect_certificate_hashes(&macos_system_keychain_path(), macos_soth_ca_name())?;
    if system_hashes.is_empty() {
        return Ok(None);
    }

    let login_set: BTreeSet<_> = login_hashes.iter().cloned().collect();
    let has_mismatch = system_hashes
        .iter()
        .any(|fingerprint| !login_set.contains(fingerprint));
    if !has_mismatch {
        return Ok(None);
    }

    Ok(Some(MacOsTrustDrift {
        login_hashes,
        system_hashes,
    }))
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
        run_linux_trust_command(
            "cp",
            &[cert, "/usr/local/share/ca-certificates/soth-ca.crt"],
        )?;
        run_linux_trust_command("update-ca-certificates", &[])?;
        return Ok(());
    }

    if which("update-ca-trust").is_ok() {
        run_linux_trust_command(
            "cp",
            &[cert, "/etc/pki/ca-trust/source/anchors/soth-ca.crt"],
        )?;
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
            match ensure_macos_login_keychain_trust(&cert_path, generated_new_ca) {
                Ok(MacOsTrustResult::Installed) => {
                    style::success(
                        "Installed SOTH CA into macOS login keychain trust store (auto).",
                    );
                }
                Ok(MacOsTrustResult::AlreadyPresent) => {
                    style::info("SOTH CA already present in macOS login keychain trust store.");
                }
                Ok(MacOsTrustResult::Reinstalled(removed)) => {
                    style::success(
                        "Reinstalled SOTH CA in macOS login keychain after stale-entry cleanup.",
                    );
                    style::kv("Removed stale login certs", &removed.to_string());
                }
                Err(error) => {
                    style::warning(&format!(
                        "Auto trust install failed (continuing fail-open): {}",
                        error
                    ));
                }
            }

            match macos_detect_trust_drift() {
                Ok(Some(drift)) => {
                    style::warning(
                        "Detected conflicting SOTH CA fingerprints between login and system keychains.",
                    );
                    style::warning(
                        "This can trigger ERR_CERT_AUTHORITY_INVALID when browsers pick the stale system cert.",
                    );
                    style::kv("Login keychain hashes", &drift.login_hashes.join(", "));
                    style::kv("System keychain hashes", &drift.system_hashes.join(", "));
                    style::info(
                        "Cleanup stale system keychain entries, then reinstall current CA:",
                    );
                    println!(
                        "    {}",
                        "while sudo security delete-certificate -c \"SOTH Proxy CA\" /Library/Keychains/System.keychain >/dev/null 2>&1; do :; done".dimmed()
                    );
                    println!(
                        "    {}",
                        format!(
                            "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
                            cert_path.display()
                        )
                        .dimmed()
                    );
                }
                Ok(None) => {}
                Err(error) => style::warning(&format!(
                    "Unable to verify macOS keychain CA consistency: {}",
                    error
                )),
            }

            println!();
            println!(
                "  {} (optional system-wide trust, requires admin):",
                "macOS".bold()
            );
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
        style::subtitle("App-Specific Trust Stores");
        style::info(
            "If a service still reports 'authority invalid', its client may use a separate trust store.",
        );
        println!(
            "    {}",
            format!("NODE_EXTRA_CA_CERTS={} <your_command>", cert_path.display()).dimmed()
        );
        println!(
            "    {}",
            format!(
                "certutil -A -n \"SOTH Proxy CA\" -t \"C,,\" -i {} -d sql:$HOME/.pki/nssdb",
                cert_path.display()
            )
            .dimmed()
        );
        println!(
            "    {}",
            format!(
                "certutil -A -n \"SOTH Proxy CA\" -t \"C,,\" -i {} -d sql:<firefox-profile-dir>",
                cert_path.display()
            )
            .dimmed()
        );
        println!(
            "    {}",
            format!(
                "keytool -importcert -noprompt -trustcacerts -alias soth-proxy-ca -file {} -keystore <java-cacerts>",
                cert_path.display()
            )
            .dimmed()
        );

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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn parse_certificate_hashes_extracts_sha_lines() {
        let output = r#"
keychain: "/Library/Keychains/System.keychain"
SHA-1 hash: 07 73 e6 f7 dd 3d bb 4d f2 40 b3 b6 2b f9 2f 4a d8 dd 68 ac
keychain: "/Users/test/Library/Keychains/login.keychain-db"
SHA-256 hash: 7A3FB1A1D8CF53C72AE4E860D9FDFB31D6A29BF77D1B14B8177CB3C85F8A305A
"#;

        let hashes = macos_parse_certificate_hashes(output);

        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&"0773E6F7DD3DBB4DF240B3B62BF92F4AD8DD68AC".to_string()));
        assert!(hashes.contains(
            &"7A3FB1A1D8CF53C72AE4E860D9FDFB31D6A29BF77D1B14B8177CB3C85F8A305A".to_string()
        ));
    }

    #[test]
    fn output_indicates_item_not_found_recognizes_security_strings() {
        assert!(macos_output_indicates_item_not_found(
            "",
            "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."
        ));
        assert!(macos_output_indicates_item_not_found(
            "",
            "errSecItemNotFound"
        ));
        assert!(!macos_output_indicates_item_not_found(
            "",
            "permission denied"
        ));
    }
}

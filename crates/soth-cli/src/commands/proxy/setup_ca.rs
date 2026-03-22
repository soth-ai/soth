//! CA setup command.

use crate::cli_config;
use crate::style;
use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use std::path::{Path, PathBuf};
use std::process::Command;

pub async fn run(
    output: Option<String>,
    no_trust: bool,
    global_config: Option<PathBuf>,
) -> Result<()> {
    let config = cli_config::load_effective_config(global_config.as_ref(), None)?;
    let resolved = super::ca_health::resolve_ca_paths(&config);
    let cert_path = output
        .as_ref()
        .map(|out| cli_config::expand_tilde(Path::new(out)).join("soth-mitm-ca.pem"))
        .unwrap_or_else(|| resolved.runtime_cert_path.clone());
    let key_path = output
        .as_ref()
        .map(|out| cli_config::expand_tilde(Path::new(out)).join("soth-mitm-ca-key.pem"))
        .unwrap_or_else(|| resolved.runtime_key_path.clone());
    let trust_cert_path = if output.is_some() {
        cert_path.clone()
    } else {
        resolved.trust_cert_path.clone()
    };
    let trust_source = if output.is_some() {
        "runtime_cert"
    } else {
        resolved.trust_source
    };
    let external_trust_path = trust_cert_path != cert_path;

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }

    let cert_exists = cert_path.exists();
    let key_exists = key_path.exists();
    match (cert_exists, key_exists) {
        (true, true) => {
            style::info(&format!(
                "Reusing existing CA cert/key at {} and {}",
                cert_path.display(),
                key_path.display()
            ));
        }
        (false, false) => {
            generate_ca_files(&cert_path, &key_path)?;
            style::success(&format!("CA generated: {}", cert_path.display()));
        }
        _ => {
            anyhow::bail!(
                "CA files are inconsistent: cert exists={}, key exists={}. Refusing implicit rotation. Remove stale file(s) and re-run `soth setup-ca`.",
                cert_exists,
                key_exists
            );
        }
    }

    let runtime_fingerprint = super::ca_health::cert_fingerprint_sha256(&cert_path)
        .context("failed computing runtime CA fingerprint")?;

    if external_trust_path {
        if !trust_cert_path.exists() {
            anyhow::bail!(
                "Configured external trust cert path ({}) is missing. Install the CA via MDM or update forward_proxy.ca.trust_cert_path.",
                trust_cert_path.display()
            );
        }
        let trust_fingerprint = super::ca_health::cert_fingerprint_sha256(&trust_cert_path)
            .context("failed computing external trust cert fingerprint")?;
        if trust_fingerprint != runtime_fingerprint {
            anyhow::bail!(
                "Runtime CA fingerprint does not match external trust cert fingerprint.\nruntime={} ({})\ntrust={} ({})",
                runtime_fingerprint,
                cert_path.display(),
                trust_fingerprint,
                trust_cert_path.display()
            );
        }
    }

    if no_trust {
        style::info("Skipping system trust installation (--no-trust).");
        return Ok(());
    }

    if external_trust_path {
        style::info(&format!(
            "External trust path configured (source={}): {}",
            trust_source,
            trust_cert_path.display()
        ));
    } else {
        install_trust(&cert_path)?;
    }

    let os_trust = super::ca_health::check_os_trust(&trust_cert_path)
        .with_context(|| format!("failed checking OS trust for {}", trust_cert_path.display()))?;
    match os_trust.status {
        super::ca_health::OsTrustStatus::Trusted => {
            style::success(&format!(
                "CA trust verified ({}) fingerprint={} source={}",
                trust_cert_path.display(),
                runtime_fingerprint,
                trust_source
            ));
        }
        super::ca_health::OsTrustStatus::Untrusted => {
            anyhow::bail!(
                "CA is not trusted by OS at {} (source={}): {}",
                trust_cert_path.display(),
                trust_source,
                os_trust.detail
            );
        }
        super::ca_health::OsTrustStatus::Unknown => {
            style::warning(&format!(
                "Could not verify OS trust state for {}: {}",
                trust_cert_path.display(),
                os_trust.detail
            ));
        }
    }
    Ok(())
}

fn generate_ca_files(cert_path: &Path, key_path: &Path) -> Result<()> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "SOTH Proxy CA");
    dn.push(DnType::OrganizationName, "SOTH");
    params.distinguished_name = dn;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2034, 1, 1);

    let key = KeyPair::generate().context("failed generating CA keypair")?;
    let cert = params
        .self_signed(&key)
        .context("failed creating self-signed CA cert")?;

    std::fs::write(cert_path, cert.pem())
        .with_context(|| format!("failed writing {}", cert_path.display()))?;
    std::fs::write(key_path, key.serialize_pem())
        .with_context(|| format!("failed writing {}", key_path.display()))?;
    Ok(())
}

fn install_trust(cert_path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        return install_trust_macos(cert_path);
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let output = Command::new("certutil")
            .args(["-addstore", "-f", "Root"])
            .arg(cert_path)
            .creation_flags(0x08000000)
            .output()
            .context("failed executing certutil")?;
        if output.status.success() {
            style::success("CA trusted in Windows Root store.");
            return Ok(());
        }
        anyhow::bail!(
            "certutil -addstore failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    {
        style::warning("Automatic Linux trust installation is best-effort.");
        if which::which("update-ca-certificates").is_ok() {
            style::info(&format!(
                "Run with elevated privileges: sudo cp {} /usr/local/share/ca-certificates/soth-proxy-ca.crt && sudo update-ca-certificates",
                cert_path.display()
            ));
            return Ok(());
        }
        if which::which("trust").is_ok() {
            style::info(&format!(
                "Run with elevated privileges: sudo trust anchor {}",
                cert_path.display()
            ));
            return Ok(());
        }
        style::warning("Could not detect a Linux trust tool (update-ca-certificates/trust).");
        style::info(&format!(
            "Manually import {} into your system trust store.",
            cert_path.display()
        ));
        return Ok(());
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        style::warning("System trust install is not supported on this OS.");
        style::info(&format!(
            "Manually trust certificate at {}",
            cert_path.display()
        ));
        Ok(())
    }
}

/// macOS trust installation strategy:
/// 1. Add cert to login keychain (non-admin, ensures it's present)
/// 2. Verify SSL trust with `security verify-cert`
/// 3. If not trusted, elevate via `osascript` to add to system keychain with admin trust
/// 4. If elevation fails/declined, print manual instructions
#[cfg(target_os = "macos")]
fn install_trust_macos(cert_path: &Path) -> Result<()> {
    let login_keychain = dirs::home_dir()
        .map(|home| home.join("Library/Keychains/login.keychain-db"))
        .unwrap_or_else(|| PathBuf::from("login.keychain-db"));

    // Step 1: Add to login keychain (ensures cert is present, may not set trust).
    let add_output = Command::new("security")
        .args(["add-certificates", "-k"])
        .arg(&login_keychain)
        .arg(cert_path)
        .output()
        .context("failed adding certificate to login keychain")?;
    let add_stderr = String::from_utf8_lossy(&add_output.stderr).to_ascii_lowercase();
    if !add_output.status.success()
        && !add_stderr.contains("already exists")
        && !add_stderr.contains("the specified item already exists")
    {
        style::warning(&format!(
            "Could not add cert to login keychain: {}",
            String::from_utf8_lossy(&add_output.stderr).trim()
        ));
    }

    // Step 2: Check if already trusted for SSL (e.g., from a previous setup-ca or MDM).
    if macos_verify_ssl_trust(cert_path) {
        style::success("CA is already trusted for SSL.");
        return Ok(());
    }

    // Step 3: Elevate to set trust. Uses osascript which shows a native macOS
    // password dialog — no terminal sudo needed.
    style::info("Administrator privileges are required to trust the CA for SSL.");
    let cert_escaped = cert_path.display().to_string().replace('\'', "'\\''");
    let script = format!(
        "do shell script \"security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '{cert_escaped}'\" with administrator privileges"
    );
    let elevate = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .context("failed executing osascript for admin trust elevation")?;

    if elevate.status.success() {
        // Verify it actually took effect.
        if macos_verify_ssl_trust(cert_path) {
            style::success("CA trusted in macOS system keychain (SSL verified).");
            return Ok(());
        }
        style::warning("Admin trust command succeeded but SSL verification still fails.");
    } else {
        let stderr = String::from_utf8_lossy(&elevate.stderr);
        if stderr.to_ascii_lowercase().contains("user canceled") || stderr.contains("-128") {
            style::warning("Administrator elevation was cancelled.");
        } else {
            style::warning(&format!("Admin elevation failed: {}", stderr.trim()));
        }
    }

    // Step 4: Fallback instructions.
    style::info(&format!(
        "To trust the CA manually, run:\n  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
        cert_path.display()
    ));
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_verify_ssl_trust(cert_path: &Path) -> bool {
    Command::new("security")
        .args(["verify-cert", "-c"])
        .arg(cert_path)
        .args(["-p", "ssl"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

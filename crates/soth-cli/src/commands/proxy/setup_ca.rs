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
    let cert_path = output
        .as_ref()
        .map(|out| cli_config::expand_tilde(Path::new(out)).join("soth-mitm-ca.pem"))
        .unwrap_or_else(|| {
            cli_config::expand_tilde(Path::new(config.forward_proxy.ca.cert_path.as_str()))
        });
    let key_path = output
        .as_ref()
        .map(|out| cli_config::expand_tilde(Path::new(out)).join("soth-mitm-ca-key.pem"))
        .unwrap_or_else(|| {
            cli_config::expand_tilde(Path::new(config.forward_proxy.ca.key_path.as_str()))
        });

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }

    generate_ca_files(&cert_path, &key_path)?;
    style::success(&format!("CA generated: {}", cert_path.display()));

    if no_trust {
        style::info("Skipping system trust installation (--no-trust).");
        return Ok(());
    }

    install_trust(&cert_path)?;
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
        let keychain = dirs::home_dir()
            .map(|home| home.join("Library/Keychains/login.keychain-db"))
            .unwrap_or_else(|| PathBuf::from("login.keychain-db"));
        let output = Command::new("security")
            .args(["add-trusted-cert", "-d", "-r", "trustRoot", "-k"])
            .arg(&keychain)
            .arg(cert_path)
            .output()
            .context("failed executing security add-trusted-cert")?;
        if output.status.success() {
            style::success("CA trusted in macOS login keychain.");
            return Ok(());
        }
        anyhow::bail!(
            "security add-trusted-cert failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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

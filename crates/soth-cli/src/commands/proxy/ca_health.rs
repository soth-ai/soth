use crate::cli_config::{self, SothConfig};
use anyhow::{Context, Result};
#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedCaPaths {
    pub runtime_cert_path: PathBuf,
    pub runtime_key_path: PathBuf,
    pub trust_cert_path: PathBuf,
    pub trust_source: &'static str,
    pub external_trust_path: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OsTrustStatus {
    Trusted,
    Untrusted,
    Unknown,
}

impl OsTrustStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct OsTrustCheck {
    pub status: OsTrustStatus,
    pub detail: String,
}

pub(crate) fn resolve_ca_paths(config: &SothConfig) -> ResolvedCaPaths {
    let runtime_cert_path =
        cli_config::expand_tilde(Path::new(config.forward_proxy.ca.cert_path.as_str()));
    let runtime_key_path =
        cli_config::expand_tilde(Path::new(config.forward_proxy.ca.key_path.as_str()));
    let trust_cert_path = config
        .forward_proxy
        .ca
        .trust_cert_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| cli_config::expand_tilde(Path::new(value)))
        .unwrap_or_else(|| runtime_cert_path.clone());
    let external_trust_path = trust_cert_path != runtime_cert_path;
    let trust_source = if external_trust_path {
        "mdm_path"
    } else {
        "runtime_cert"
    };
    ResolvedCaPaths {
        runtime_cert_path,
        runtime_key_path,
        trust_cert_path,
        trust_source,
        external_trust_path,
    }
}

pub(crate) fn cert_fingerprint_sha256(path: &Path) -> Result<String> {
    cert_fingerprint(path, "sha256")
}

#[cfg(target_os = "macos")]
pub(crate) fn cert_fingerprint_sha1(path: &Path) -> Result<String> {
    cert_fingerprint(path, "sha1")
}

pub(crate) fn cert_matches_key(cert_path: &Path, key_path: &Path) -> Result<bool> {
    let cert_spki = cert_spki_der(cert_path)?;
    let key_spki = key_spki_der(key_path)?;
    Ok(cert_spki == key_spki)
}

pub(crate) fn check_os_trust(cert_path: &Path) -> Result<OsTrustCheck> {
    #[cfg(target_os = "macos")]
    {
        check_macos_trust(cert_path)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = cert_path;
        Ok(OsTrustCheck {
            status: OsTrustStatus::Unknown,
            detail: format!(
                "OS trust verification is not implemented for {}",
                std::env::consts::OS
            ),
        })
    }
}

fn cert_fingerprint(path: &Path, algo: &str) -> Result<String> {
    if !path.exists() {
        anyhow::bail!("certificate not found at {}", path.display());
    }
    let der = read_first_pem_block_der(path)
        .with_context(|| format!("failed reading certificate at {}", path.display()))?;
    let digest: Vec<u8> = match algo.trim().to_ascii_lowercase().as_str() {
        "sha256" => {
            use sha2::{Digest, Sha256};
            Sha256::digest(&der).to_vec()
        }
        "sha1" => {
            use sha1::{Digest as _, Sha1};
            Sha1::digest(&der).to_vec()
        }
        other => anyhow::bail!("unsupported fingerprint algorithm: {other}"),
    };
    Ok(hex_upper(&digest))
}

fn cert_spki_der(path: &Path) -> Result<Vec<u8>> {
    let der = read_first_pem_block_der(path)
        .with_context(|| format!("failed reading certificate at {}", path.display()))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow::anyhow!("failed parsing X.509 certificate: {e}"))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

fn key_spki_der(path: &Path) -> Result<Vec<u8>> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading private key at {}", path.display()))?;
    let key_pair = rcgen::KeyPair::from_pem(pem.as_str())
        .map_err(|e| anyhow::anyhow!("failed parsing private key: {e}"))?;
    Ok(key_pair.public_key_der())
}

fn read_first_pem_block_der(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes)
        .map_err(|e| anyhow::anyhow!("failed decoding PEM: {e}"))?;
    Ok(pem.contents)
}

fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(target_os = "macos")]
fn normalize_hash(raw: &str) -> Option<String> {
    let normalized: String = raw.chars().filter(|ch| ch.is_ascii_hexdigit()).collect();
    if normalized.len() == 40 || normalized.len() == 64 {
        Some(normalized.to_ascii_uppercase())
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn check_macos_trust(cert_path: &Path) -> Result<OsTrustCheck> {
    // Primary check: `security verify-cert` tests actual SSL trust policy,
    // not just keychain presence. A cert can be in the keychain but have
    // zero trust settings, which means browsers will reject it.
    let verify = Command::new("security")
        .args(["verify-cert", "-c"])
        .arg(cert_path)
        .args(["-p", "ssl"])
        .output()
        .context("failed running security verify-cert")?;

    if verify.status.success() {
        return Ok(OsTrustCheck {
            status: OsTrustStatus::Trusted,
            detail: "certificate passes SSL trust verification (security verify-cert)".to_string(),
        });
    }

    // verify-cert failed — cert is not trusted for SSL.
    // Gather extra detail: check if it's at least present in a keychain.
    let stderr = String::from_utf8_lossy(&verify.stderr);
    let keychain_detail = match macos_keychain_presence(cert_path) {
        Ok(Some(location)) => format!(
            "certificate is in {location} keychain but lacks SSL trust policy. \
             Run `soth setup-ca` to set trust."
        ),
        Ok(None) => {
            "certificate not found in any keychain. Run `soth setup-ca` to install and trust."
                .to_string()
        }
        Err(_) => format!("verify-cert failed: {}", stderr.trim()),
    };

    Ok(OsTrustCheck {
        status: OsTrustStatus::Untrusted,
        detail: keychain_detail,
    })
}

/// Check which keychains contain the certificate (for diagnostics only).
#[cfg(target_os = "macos")]
fn macos_keychain_presence(cert_path: &Path) -> Result<Option<&'static str>> {
    let expected_sha256 = cert_fingerprint_sha256(cert_path)?;
    let expected_sha1 = cert_fingerprint_sha1(cert_path)?;

    let login_keychain = dirs::home_dir()
        .map(|home| home.join("Library/Keychains/login.keychain-db"))
        .unwrap_or_else(|| PathBuf::from("login.keychain-db"));
    let system_keychain = PathBuf::from("/Library/Keychains/System.keychain");

    let login_hashes = macos_collect_keychain_hashes(login_keychain.as_path())?;
    let system_hashes = macos_collect_keychain_hashes(system_keychain.as_path())?;

    let in_login = login_hashes.contains(expected_sha256.as_str())
        || login_hashes.contains(expected_sha1.as_str());
    let in_system = system_hashes.contains(expected_sha256.as_str())
        || system_hashes.contains(expected_sha1.as_str());

    Ok(match (in_login, in_system) {
        (true, true) => Some("login+system"),
        (true, false) => Some("login"),
        (false, true) => Some("system"),
        (false, false) => None,
    })
}

#[cfg(target_os = "macos")]
fn macos_collect_keychain_hashes(keychain: &Path) -> Result<BTreeSet<String>> {
    let output = Command::new("security")
        .args(["find-certificate", "-a", "-Z"])
        .arg(keychain)
        .output()
        .with_context(|| {
            format!(
                "failed running security find-certificate for {}",
                keychain.display()
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("could not be found")
            || stderr.contains("no such keychain")
            || stderr.contains("errsecitemnotfound")
        {
            return Ok(BTreeSet::new());
        }
        anyhow::bail!(
            "security find-certificate failed for {}: {}",
            keychain.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut hashes = BTreeSet::new();
    for line in stdout.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("sha-256 hash") && !lower.contains("sha-1 hash") {
            continue;
        }
        if let Some((_, value)) = line.split_once(':') {
            if let Some(normalized) = normalize_hash(value) {
                hashes.insert(normalized);
            }
        }
    }
    Ok(hashes)
}

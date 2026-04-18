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
                "CA files are inconsistent: cert exists={cert_exists}, key exists={key_exists}. Refusing implicit rotation. Remove stale file(s) and re-run `soth setup-ca`."
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
        install_trust_macos(cert_path)
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let combined = format!("{stderr}{stdout}");
        let lower = combined.to_ascii_lowercase();
        // certutil surfaces admin failure as "access is denied" / 0x80070005 /
        // "The system cannot find the file specified" when HKLM\...\Root is blocked.
        if lower.contains("access is denied")
            || lower.contains("0x80070005")
            || lower.contains("denied")
            || output.status.code() == Some(5)
        {
            anyhow::bail!(
                "certutil -addstore failed: access denied. \
                 Trusting a CA in the Windows Root store requires Administrator privileges. \
                 Re-run `soth proxy setup-ca` from an elevated PowerShell or Command Prompt \
                 (right-click → Run as administrator).\n\nraw error: {}",
                combined.trim()
            );
        }
        anyhow::bail!("certutil -addstore failed: {}", combined.trim());
    }

    #[cfg(target_os = "linux")]
    {
        install_trust_linux(cert_path)?;
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

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxDistroFamily {
    DebianUbuntu,
    RhelFedora,
    Arch,
    Alpine,
    Suse,
    Unknown,
}

#[cfg(target_os = "linux")]
impl LinuxDistroFamily {
    fn label(self) -> &'static str {
        match self {
            Self::DebianUbuntu => "Debian/Ubuntu",
            Self::RhelFedora => "RHEL/Fedora/CentOS",
            Self::Arch => "Arch",
            Self::Alpine => "Alpine",
            Self::Suse => "openSUSE/SLE",
            Self::Unknown => "unknown",
        }
    }

    /// Absolute path where the CA cert file should be installed.
    fn anchor_path(self) -> &'static str {
        match self {
            Self::DebianUbuntu => "/usr/local/share/ca-certificates/soth-proxy-ca.crt",
            Self::RhelFedora => "/etc/pki/ca-trust/source/anchors/soth-proxy-ca.crt",
            Self::Arch => "/etc/ca-certificates/trust-source/anchors/soth-proxy-ca.crt",
            Self::Alpine => "/usr/local/share/ca-certificates/soth-proxy-ca.crt",
            Self::Suse => "/etc/pki/trust/anchors/soth-proxy-ca.crt",
            Self::Unknown => "/usr/local/share/ca-certificates/soth-proxy-ca.crt",
        }
    }

    /// Command to rebuild the system trust store after placing the anchor.
    fn update_command(self) -> &'static str {
        match self {
            Self::DebianUbuntu | Self::Alpine | Self::Suse => "update-ca-certificates",
            Self::RhelFedora => "update-ca-trust",
            Self::Arch => "update-ca-trust",
            Self::Unknown => "update-ca-certificates",
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_linux_distro() -> LinuxDistroFamily {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let lower = os_release.to_ascii_lowercase();
    // ID_LIKE often lists the parent family for derivatives (e.g. Linux Mint → "ubuntu debian").
    let id_like_line = lower
        .lines()
        .find(|line| line.starts_with("id_like="))
        .unwrap_or("");
    let id_line = lower
        .lines()
        .find(|line| line.starts_with("id="))
        .unwrap_or("");
    let combined = format!("{id_line} {id_like_line}");

    if combined.contains("alpine") {
        return LinuxDistroFamily::Alpine;
    }
    if combined.contains("arch") || combined.contains("manjaro") {
        return LinuxDistroFamily::Arch;
    }
    if combined.contains("suse") || combined.contains("sles") {
        return LinuxDistroFamily::Suse;
    }
    if combined.contains("rhel")
        || combined.contains("fedora")
        || combined.contains("centos")
        || combined.contains("rocky")
        || combined.contains("alma")
        || combined.contains("amzn")
    {
        return LinuxDistroFamily::RhelFedora;
    }
    if combined.contains("debian") || combined.contains("ubuntu") {
        return LinuxDistroFamily::DebianUbuntu;
    }
    LinuxDistroFamily::Unknown
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    // SAFETY: getuid() is always safe; it takes no arguments and returns a uid_t.
    unsafe { libc::getuid() == 0 }
}

#[cfg(target_os = "linux")]
fn install_trust_linux(cert_path: &Path) -> Result<()> {
    let family = detect_linux_distro();
    let anchor = family.anchor_path();
    let update_tool = family.update_command();

    if family == LinuxDistroFamily::Unknown {
        style::warning(
            "Could not detect Linux distro family from /etc/os-release; \
             falling back to Debian-style paths.",
        );
    } else {
        style::info(&format!("Detected distro family: {}", family.label()));
    }

    if which::which(update_tool).is_err() {
        style::warning(&format!(
            "`{update_tool}` not found in PATH. Install it first (e.g. `ca-certificates` package) \
             or set up trust manually."
        ));
        print_linux_manual_instructions(cert_path, anchor, update_tool);
        return Ok(());
    }

    if running_as_root() {
        // Automatic install path: already elevated.
        if let Some(parent) = Path::new(anchor).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create anchor dir {}", parent.display()))?;
        }
        std::fs::copy(cert_path, anchor)
            .with_context(|| format!("copy CA to {anchor}"))?;
        let status = Command::new(update_tool)
            .status()
            .with_context(|| format!("run {update_tool}"))?;
        if !status.success() {
            anyhow::bail!("{update_tool} exited with status {status}");
        }
        style::success(&format!(
            "CA installed to {anchor} and trust store refreshed via {update_tool}."
        ));
        return Ok(());
    }

    // Not root — print ready-to-copy commands. pkexec is intentionally not used
    // because it requires a polkit rule to run `cp`/`update-ca-certificates`
    // non-interactively without bypassing auth.
    style::warning("Trusting a CA on Linux requires root privileges.");
    print_linux_manual_instructions(cert_path, anchor, update_tool);
    Ok(())
}

#[cfg(target_os = "linux")]
fn print_linux_manual_instructions(cert_path: &Path, anchor: &str, update_tool: &str) {
    style::info("Run with sudo:");
    println!("  sudo cp {} {anchor}", cert_path.display());
    println!("  sudo {update_tool}");
}

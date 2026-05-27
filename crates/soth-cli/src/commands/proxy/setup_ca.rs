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
    // The CA private key is the trust root for every TLS interception the proxy
    // performs — any other local user who can read it can sign certs for any
    // domain the user later visits. Lock it down to 0600 immediately. On
    // Windows, ACLs are applied separately by the caller via
    // reapply_windows_key_acl().
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed setting 0600 permissions on {}",
                    key_path.display()
                )
            })?;
    }
    Ok(())
}

fn install_trust(cert_path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        install_trust_macos(cert_path)
    }

    #[cfg(target_os = "windows")]
    {
        install_trust_windows(cert_path)
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
/// 1. Fast path: if the cert is already in the admin trust domain (prior
///    install or MDM), succeed without prompting.
/// 2. Elevate via `sudo`, NOT `osascript with administrator privileges`.
///    `security add-trusted-cert` performs an internal `SecTrustSettingsSet`
///    call which, on Big Sur+, requires its own SecurityAgent GUI prompt
///    for the trust-settings change. AppleScript-elevated shells run in a
///    session that's isolated from SecurityAgent, so that nested prompt
///    fails with `The authorization was denied since no user interaction
///    was possible`. Plain `sudo` from a terminal-connected process tree
///    keeps the user's launchd/Aqua session reachable, so the GUI prompt
///    can appear. This is the same approach mkcert and Caddy use.
/// 3. `sudo` opens `/dev/tty` directly for its password prompt, so this
///    works even from `curl … | bash` (where stdin is the script pipe)
///    as long as the install is being driven from a real terminal.
/// 4. Explicit `-p ssl -p basic` on `add-trusted-cert` ensures the trust
///    entry contains the SSL policy explicitly — without `-p`, some macOS
///    releases write an empty policy list that's interpreted narrowly.
/// 5. Verify by reading `trust-settings-export` (authoritative since Big
///    Sur). Do NOT use `verify-cert -p ssl`: it rejects a self-signed CA
///    treated as an SSL leaf even when trust is correctly installed.
#[cfg(target_os = "macos")]
fn install_trust_macos(cert_path: &Path) -> Result<()> {
    use std::process::Stdio;

    // Step 1: Fast path. Re-running `soth up` or a `curl … | bash` upgrade
    // shouldn't re-prompt if trust is already in place.
    match super::ca_health::macos_cert_in_admin_trust(cert_path) {
        Ok(true) => {
            style::success("CA already trusted in admin trust domain.");
            return Ok(());
        }
        Ok(false) => {}
        Err(error) => {
            style::warning(&format!(
                "Could not pre-check admin trust state: {error}. Continuing."
            ));
        }
    }

    // Step 2: Decide between sudo (terminal-connected) and osascript
    // (truly headless). We probe `/dev/tty` to detect the difference —
    // `sudo` itself reads its password from `/dev/tty`, not stdin, so a
    // pipe on stdin (from `curl|bash`) does NOT prevent sudo from
    // working as long as the controlling terminal is reachable.
    let has_tty = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .is_ok();

    if has_tty {
        style::info(
            "Trusting CA. macOS may prompt for your password (sudo, then a \
             trust-settings authorization dialog).",
        );
        // Use absolute paths so a binary earlier in $PATH can't
        // impersonate sudo or `security` and capture the operator's
        // password or hijack the trust-store mutation.
        let status = Command::new("/usr/bin/sudo")
            .args([
                "/usr/bin/security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-p",
                "ssl",
                "-p",
                "basic",
                "-k",
                "/Library/Keychains/System.keychain",
            ])
            .arg(cert_path)
            // Inherit stdio so sudo can prompt and security can surface
            // any error directly to the user. sudo opens /dev/tty for the
            // password regardless of stdin, so the pipe from curl|bash
            // doesn't interfere.
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("failed launching sudo security add-trusted-cert")?;

        if !status.success() {
            anyhow::bail!(
                "sudo security add-trusted-cert exited with status {}. \
                 Manual fallback:\n  sudo security add-trusted-cert -d -r trustRoot \
                 -p ssl -p basic -k /Library/Keychains/System.keychain {}",
                status,
                cert_path.display()
            );
        }
    } else {
        // Headless / no controlling terminal. osascript "with administrator
        // privileges" is unlikely to succeed for trust-settings on Big Sur+
        // because of the nested SecurityAgent prompt, but it's the only
        // option here — try it and surface a clear message if it fails.
        style::warning(
            "No terminal detected — falling back to GUI elevation. \
             This often fails for trust-settings changes on macOS Big Sur+; \
             if it does, run from an interactive terminal.",
        );
        let cert_escaped = cert_path.display().to_string().replace('\'', "'\\''");
        let inner_command = format!(
            "security add-trusted-cert -d -r trustRoot -p ssl -p basic \
               -k /Library/Keychains/System.keychain '{cert_escaped}'"
        );
        let escaped_inner = inner_command.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!("do shell script \"{escaped_inner}\" with administrator privileges");
        let elevate = Command::new("osascript")
            .args(["-e", &script])
            .output()
            .context("failed executing osascript for admin trust elevation")?;
        if !elevate.status.success() {
            let stderr = String::from_utf8_lossy(&elevate.stderr);
            if stderr.to_ascii_lowercase().contains("user canceled") || stderr.contains("-128") {
                anyhow::bail!(
                    "Administrator elevation was cancelled. Re-run `soth setup-ca` from \
                     an interactive terminal so sudo can prompt for your password."
                );
            }
            anyhow::bail!(
                "osascript trust install failed (this is expected on Big Sur+ \
                 for trust-settings changes — re-run from a terminal): {}. \
                 Manual fallback:\n  sudo security add-trusted-cert -d -r trustRoot \
                 -p ssl -p basic -k /Library/Keychains/System.keychain {}",
                stderr.trim(),
                cert_path.display()
            );
        }
    }

    // Step 3: Verify via trust-settings-export.
    match super::ca_health::macos_cert_in_admin_trust(cert_path) {
        Ok(true) => {
            style::success("CA trusted in macOS admin trust domain.");
            Ok(())
        }
        Ok(false) => {
            anyhow::bail!(
                "security add-trusted-cert exited successfully but the cert is \
                 not in the admin trust domain. This typically means MDM or a \
                 configuration profile is blocking user-added roots. \
                 Manual workaround: open '{}' in Keychain Access, then set \
                 'Always Trust' under the Trust section.",
                cert_path.display()
            );
        }
        Err(error) => {
            style::warning(&format!(
                "Trust install command succeeded but verification read failed: {error}"
            ));
            Ok(())
        }
    }
}

/// Windows trust installation strategy:
/// 1. Try `certutil -addstore -f Root <cert>` directly. If the calling
///    shell is already elevated (or if HKLM\Root happens to be writable
///    by the user, which it isn't by default), this succeeds with no UAC.
/// 2. On access-denied, self-elevate via `powershell Start-Process -Verb
///    RunAs`. This triggers the UAC consent dialog so a `curl … | bash`
///    install from non-elevated Git Bash / MSYS still completes with one
///    user click.
/// 3. Verify by reading the LocalMachine `Root` store via
///    `windows_root_store_thumbprints`.
#[cfg(target_os = "windows")]
fn install_trust_windows(cert_path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let direct = Command::new("certutil")
        .args(["-addstore", "-f", "Root"])
        .arg(cert_path)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("failed executing certutil")?;
    if direct.status.success() {
        style::success("CA trusted in Windows Root store.");
        return Ok(());
    }

    let direct_stderr = String::from_utf8_lossy(&direct.stderr);
    let direct_stdout = String::from_utf8_lossy(&direct.stdout);
    let direct_combined = format!("{direct_stderr}{direct_stdout}");
    let lower = direct_combined.to_ascii_lowercase();

    // certutil surfaces admin failure as "access is denied" / 0x80070005.
    let is_access_denied = lower.contains("access is denied")
        || lower.contains("0x80070005")
        || lower.contains("denied")
        || direct.status.code() == Some(5);

    if !is_access_denied {
        anyhow::bail!("certutil -addstore failed: {}", direct_combined.trim());
    }

    // Self-elevate via PowerShell. `Start-Process -Verb RunAs` triggers
    // the UAC consent dialog. `-Wait -PassThru` blocks until the elevated
    // certutil exits and surfaces its exit code so we know whether the
    // install actually succeeded after the user clicked "Yes".
    style::info("Administrator privileges are required to add the CA to the Windows Root store.");

    // PowerShell single-quoted strings escape an apostrophe by doubling
    // it. Cert paths from us never contain quotes but we sanitize anyway.
    let cert_q = cert_path.display().to_string().replace('\'', "''");
    let ps_cmd = format!(
        "$ErrorActionPreference='Stop'; \
         try {{ \
           $p = Start-Process -FilePath 'certutil.exe' \
                              -ArgumentList @('-addstore','-f','Root','{cert_q}') \
                              -Verb RunAs -Wait -PassThru -WindowStyle Hidden; \
           exit $p.ExitCode \
         }} catch {{ \
           [Console]::Error.WriteLine($_.Exception.Message); exit 1 \
         }}"
    );

    let elevated = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("failed launching elevated PowerShell for certutil")?;

    if !elevated.status.success() {
        let err = String::from_utf8_lossy(&elevated.stderr);
        let err_lower = err.to_ascii_lowercase();
        // UAC dismissal raises "The operation was canceled by the user"
        // (0x800704C7) from Start-Process.
        if err_lower.contains("canceled by the user")
            || err_lower.contains("operation was canceled")
            || err.contains("0x800704C7")
        {
            anyhow::bail!(
                "UAC elevation was cancelled. Re-run `soth setup-ca` and click Yes \
                 on the Windows User Account Control prompt to trust the SOTH MITM CA."
            );
        }
        anyhow::bail!(
            "Elevated certutil failed: {}. \
             Manual fallback: open an Administrator PowerShell and run \
             `certutil -addstore -f Root \"{}\"`.",
            err.trim(),
            cert_path.display()
        );
    }

    style::success("CA trusted in Windows Root store (via UAC elevation).");
    Ok(())
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
        std::fs::copy(cert_path, anchor).with_context(|| format!("copy CA to {anchor}"))?;
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

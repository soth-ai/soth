//! Proxy runtime diagnostics command (`soth doctor`).

use crate::{cli_config, style};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const PID_META_FILE: &str = "proxy.pid.meta.json";
const PID_OWNER_TOKEN_FILE: &str = "proxy.pid.token";
const SYSTEM_PROXY_STATE_FILE: &str = "system_proxy_state.json";
const SYSTEM_PROXY_OWNER_FILE: &str = "system_proxy_owner.id";

#[derive(Debug, Serialize)]
struct DoctorReport {
    managed_runtime: String,
    daemon: DaemonDiagnostics,
    system_proxy: SystemProxyDiagnostics,
    ca: CaDiagnostics,
    loopback_bindings: LoopbackBindings,
    findings: Vec<DoctorFinding>,
}

#[derive(Debug, Serialize)]
struct DaemonDiagnostics {
    pid_file: PathDetails,
    pid_meta_file: PathDetails,
    owner_token_file: PathDetails,
    pid: Option<u32>,
    process_running: Option<bool>,
    meta_pid: Option<u32>,
    meta_port: Option<u16>,
    owner_token_matches_meta: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SystemProxyDiagnostics {
    state_file: PathDetails,
    owner_file: PathDetails,
    state_platform: Option<String>,
    state_owner_id: Option<String>,
    state_port: Option<u16>,
    owner_id: Option<String>,
    owner_matches_state: Option<bool>,
}

#[derive(Debug, Serialize)]
struct CaDiagnostics {
    cert_path: PathDetails,
    key_path: PathDetails,
    trust_cert_path: PathDetails,
    trust_source: String,
    cert_not_after: Option<String>,
    cert_parse_error: Option<String>,
    cert_fingerprint_sha256: Option<String>,
    trust_fingerprint_sha256: Option<String>,
    fingerprint_match: Option<bool>,
    key_matches_cert: Option<bool>,
    os_trust_status: Option<String>,
    os_trust_detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct LoopbackBindings {
    expected_port: u16,
    local_listener_open: bool,
    details: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
struct PathDetails {
    path: String,
    exists: bool,
}

#[derive(Debug, Serialize)]
struct DoctorFinding {
    level: String,
    code: String,
    message: String,
    remediation: String,
}

#[derive(Debug, Deserialize)]
struct PidMetadata {
    pid: u32,
    port: u16,
    #[serde(default)]
    owner_token: String,
}

#[derive(Debug, Deserialize)]
struct ProxyState {
    #[serde(default)]
    platform: String,
    #[serde(default)]
    owner_id: String,
    port: Option<u16>,
}

pub async fn run(config_path: Option<PathBuf>, json: bool) -> Result<()> {
    let report = build_report(config_path);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("DOCTOR");
    println!("----------------------------------------");
    println!("Managed runtime: {}", report.managed_runtime);

    println!();
    println!("DAEMON");
    println!("----------------------------------------");
    println!(
        "PID file:       {} ({})",
        report.daemon.pid_file.path,
        if report.daemon.pid_file.exists {
            "present"
        } else {
            "missing"
        }
    );
    println!(
        "PID meta:       {} ({})",
        report.daemon.pid_meta_file.path,
        if report.daemon.pid_meta_file.exists {
            "present"
        } else {
            "missing"
        }
    );
    println!(
        "Owner token:    {} ({})",
        report.daemon.owner_token_file.path,
        if report.daemon.owner_token_file.exists {
            "present"
        } else {
            "missing"
        }
    );
    println!(
        "PID:            {}",
        report
            .daemon
            .pid
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a (proxy not running)".to_string())
    );
    println!(
        "Running:        {}",
        report
            .daemon
            .process_running
            .map(|v| if v { "yes" } else { "no" }.to_string())
            .unwrap_or_else(|| "n/a (no PID file)".to_string())
    );
    println!(
        "Meta pid/port:  {} / {}",
        report
            .daemon
            .meta_pid
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        report
            .daemon
            .meta_port
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "Owner match:    {}",
        report
            .daemon
            .owner_token_matches_meta
            .map(|v| if v { "yes" } else { "no" }.to_string())
            .unwrap_or_else(|| "n/a (no owner token)".to_string())
    );

    println!();
    println!("SYSTEM PROXY");
    println!("----------------------------------------");
    println!(
        "State file:     {} ({})",
        report.system_proxy.state_file.path,
        if report.system_proxy.state_file.exists {
            "present"
        } else {
            "missing"
        }
    );
    println!(
        "Owner file:     {} ({})",
        report.system_proxy.owner_file.path,
        if report.system_proxy.owner_file.exists {
            "present"
        } else {
            "missing"
        }
    );
    println!(
        "State platform: {}",
        report
            .system_proxy
            .state_platform
            .clone()
            .unwrap_or_else(|| "n/a (system proxy off)".to_string())
    );
    println!(
        "State owner:    {}",
        report
            .system_proxy
            .state_owner_id
            .clone()
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "Local owner:    {}",
        report
            .system_proxy
            .owner_id
            .clone()
            .unwrap_or_else(|| "n/a".to_string())
    );
    println!(
        "Owner match:    {}",
        report
            .system_proxy
            .owner_matches_state
            .map(|v| if v { "yes" } else { "no" }.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    );

    println!();
    println!("CA");
    println!("----------------------------------------");
    println!(
        "Cert:           {} ({})",
        report.ca.cert_path.path,
        if report.ca.cert_path.exists {
            "present"
        } else {
            "missing"
        }
    );
    println!(
        "Key:            {} ({})",
        report.ca.key_path.path,
        if report.ca.key_path.exists {
            "present"
        } else {
            "missing"
        }
    );
    println!(
        "Trust cert:     {} ({})",
        report.ca.trust_cert_path.path,
        if report.ca.trust_cert_path.exists {
            "present"
        } else {
            "missing"
        }
    );
    println!("Trust source:   {}", report.ca.trust_source);
    println!(
        "Valid until:    {}",
        report
            .ca
            .cert_not_after
            .clone()
            .unwrap_or_else(|| "missing/invalid (see Parse error below)".to_string())
    );
    println!(
        "Fingerprint:    {}",
        report
            .ca
            .cert_fingerprint_sha256
            .clone()
            .unwrap_or_else(|| "missing (cert not readable)".to_string())
    );
    println!(
        "Trust fp:       {}",
        report
            .ca
            .trust_fingerprint_sha256
            .clone()
            .unwrap_or_else(|| "missing (trust cert not readable)".to_string())
    );
    println!(
        "FP match:       {}",
        report
            .ca
            .fingerprint_match
            .map(|v| if v { "yes" } else { "no" }.to_string())
            .unwrap_or_else(|| "n/a (one or both fingerprints missing)".to_string())
    );
    println!(
        "Cert/key pair:  {}",
        report
            .ca
            .key_matches_cert
            .map(|v| if v { "match" } else { "mismatch" }.to_string())
            .unwrap_or_else(|| "n/a (cert or key missing)".to_string())
    );
    println!(
        "OS trust:       {}",
        report
            .ca
            .os_trust_status
            .clone()
            .unwrap_or_else(|| "n/a (cert missing)".to_string())
    );
    if let Some(detail) = &report.ca.os_trust_detail {
        println!("Trust detail:   {detail}");
    }
    if let Some(err) = &report.ca.cert_parse_error {
        println!("Parse error:    {err}");
    }

    println!();
    println!("LOOPBACK");
    println!("----------------------------------------");
    println!("Expected port:  {}", report.loopback_bindings.expected_port);
    println!(
        "Listener open:  {}",
        if report.loopback_bindings.local_listener_open {
            "yes"
        } else {
            "no"
        }
    );
    for line in &report.loopback_bindings.details {
        println!("  - {line}");
    }

    println!();
    println!("FINDINGS");
    println!("----------------------------------------");
    for finding in &report.findings {
        println!("[{}] {}: {}", finding.level, finding.code, finding.message);
        println!("  fix: {}", finding.remediation);
    }

    let has_error = report.findings.iter().any(|f| f.level == "error");
    if has_error {
        style::warning("Doctor found issues requiring action.");
    } else {
        style::success("Doctor checks completed.");
    }

    Ok(())
}

fn build_report(config_path: Option<PathBuf>) -> DoctorReport {
    let config = cli_config::load_effective_config(config_path.as_ref(), None).unwrap_or_default();
    let managed_runtime =
        super::autostart::managed_status().unwrap_or_else(|err| format!("unavailable ({err})"));

    let run_dir = soth_home_dir().join("run");
    let pid_file = super::daemon::pid_path();
    let pid_meta_file = run_dir.join(PID_META_FILE);
    let owner_token_file = run_dir.join(PID_OWNER_TOKEN_FILE);
    let state_file = run_dir.join(SYSTEM_PROXY_STATE_FILE);
    let state_owner_file = run_dir.join(SYSTEM_PROXY_OWNER_FILE);

    let pid = read_u32(pid_file.as_path());
    let process_running = pid.map(process_running);
    let pid_meta = read_pid_meta(pid_meta_file.as_path());
    let owner_token = read_trimmed_string(owner_token_file.as_path());

    let owner_token_matches_meta = match (pid_meta.as_ref(), owner_token.as_deref()) {
        (Some(meta), Some(token)) if !meta.owner_token.is_empty() => {
            Some(meta.owner_token == token)
        }
        _ => None,
    };

    let daemon = DaemonDiagnostics {
        pid_file: PathDetails {
            path: pid_file.display().to_string(),
            exists: pid_file.exists(),
        },
        pid_meta_file: PathDetails {
            path: pid_meta_file.display().to_string(),
            exists: pid_meta_file.exists(),
        },
        owner_token_file: PathDetails {
            path: owner_token_file.display().to_string(),
            exists: owner_token_file.exists(),
        },
        pid,
        process_running,
        meta_pid: pid_meta.as_ref().map(|m| m.pid),
        meta_port: pid_meta.as_ref().map(|m| m.port),
        owner_token_matches_meta,
    };

    let state = read_proxy_state(state_file.as_path());
    let state_owner_id = state
        .as_ref()
        .map(|v| v.owner_id.trim().to_string())
        .filter(|v| !v.is_empty());
    let owner_id = read_trimmed_string(state_owner_file.as_path());
    let owner_matches_state = match (state_owner_id.as_deref(), owner_id.as_deref()) {
        (Some(a), Some(b)) => Some(a == b),
        _ => None,
    };
    let system_proxy = SystemProxyDiagnostics {
        state_file: PathDetails {
            path: state_file.display().to_string(),
            exists: state_file.exists(),
        },
        owner_file: PathDetails {
            path: state_owner_file.display().to_string(),
            exists: state_owner_file.exists(),
        },
        state_platform: state
            .as_ref()
            .map(|v| v.platform.trim().to_string())
            .filter(|v| !v.is_empty()),
        state_owner_id,
        state_port: state.as_ref().and_then(|v| v.port),
        owner_id,
        owner_matches_state,
    };

    let ca_paths = super::ca_health::resolve_ca_paths(&config);
    let cert_path = ca_paths.runtime_cert_path.clone();
    let key_path = ca_paths.runtime_key_path.clone();
    let trust_cert_path = ca_paths.trust_cert_path.clone();
    let (cert_not_after, cert_parse_error) = match parse_cert_not_after(cert_path.as_path()) {
        Ok(v) => (Some(v), None),
        Err(err) => (None, Some(err.to_string())),
    };
    let cert_fingerprint_sha256 =
        super::ca_health::cert_fingerprint_sha256(cert_path.as_path()).ok();
    let trust_fingerprint_sha256 =
        super::ca_health::cert_fingerprint_sha256(trust_cert_path.as_path()).ok();
    let fingerprint_match = match (
        cert_fingerprint_sha256.as_ref(),
        trust_fingerprint_sha256.as_ref(),
    ) {
        (Some(cert), Some(trust)) => Some(cert == trust),
        _ => None,
    };
    let key_matches_cert =
        super::ca_health::cert_matches_key(cert_path.as_path(), key_path.as_path()).ok();
    let (os_trust_status, os_trust_detail) = if trust_cert_path.exists() {
        match super::ca_health::check_os_trust(trust_cert_path.as_path()) {
            Ok(value) => (Some(value.status.as_str().to_string()), Some(value.detail)),
            Err(error) => (
                Some(
                    super::ca_health::OsTrustStatus::Unknown
                        .as_str()
                        .to_string(),
                ),
                Some(error.to_string()),
            ),
        }
    } else {
        (None, None)
    };
    let ca = CaDiagnostics {
        cert_path: PathDetails {
            path: cert_path.display().to_string(),
            exists: cert_path.exists(),
        },
        key_path: PathDetails {
            path: key_path.display().to_string(),
            exists: key_path.exists(),
        },
        trust_cert_path: PathDetails {
            path: trust_cert_path.display().to_string(),
            exists: trust_cert_path.exists(),
        },
        trust_source: ca_paths.trust_source.to_string(),
        cert_not_after,
        cert_parse_error,
        cert_fingerprint_sha256,
        trust_fingerprint_sha256,
        fingerprint_match,
        key_matches_cert,
        os_trust_status,
        os_trust_detail,
    };

    let expected_port = pid_meta
        .as_ref()
        .map(|m| m.port)
        .or_else(|| state.as_ref().and_then(|s| s.port))
        .unwrap_or(config.forward_proxy.port);
    let local_listener_open = is_loopback_listener_open(expected_port);
    let details = collect_loopback_details(expected_port);
    let loopback_bindings = LoopbackBindings {
        expected_port,
        local_listener_open,
        details,
    };

    let mut report = DoctorReport {
        managed_runtime,
        daemon,
        system_proxy,
        ca,
        loopback_bindings,
        findings: Vec::new(),
    };
    report.findings = compute_findings(&report);
    report
}

fn compute_findings(report: &DoctorReport) -> Vec<DoctorFinding> {
    let mut findings = Vec::new();

    if !report.ca.cert_path.exists || !report.ca.key_path.exists {
        findings.push(DoctorFinding {
            level: "error".to_string(),
            code: "ca_missing".to_string(),
            message: "Proxy CA cert/key is missing.".to_string(),
            remediation: "Run `soth setup-ca` and retry `soth up`.".to_string(),
        });
    } else {
        if !report.ca.trust_cert_path.exists {
            findings.push(DoctorFinding {
                level: "error".to_string(),
                code: "ca_trust_cert_missing".to_string(),
                message: format!(
                    "Configured trust cert path is missing: {}",
                    report.ca.trust_cert_path.path
                ),
                remediation:
                    "Fix `forward_proxy.ca.trust_cert_path` (or remove it) and rerun `soth setup-ca`."
                        .to_string(),
            });
        }
        if report.ca.cert_not_after.is_none() {
            findings.push(DoctorFinding {
                level: "warn".to_string(),
                code: "ca_parse_failed".to_string(),
                message: "Unable to parse CA certificate expiry.".to_string(),
                remediation: "Ensure `openssl` is installed and CA cert is valid PEM.".to_string(),
            });
        }
        if matches!(report.ca.key_matches_cert, Some(false)) {
            findings.push(DoctorFinding {
                level: "error".to_string(),
                code: "ca_key_mismatch".to_string(),
                message: "CA private key does not match CA certificate.".to_string(),
                remediation:
                    "Regenerate CA pair with `soth setup-ca` and reinstall trust before starting proxy."
                        .to_string(),
            });
        }
        if matches!(report.ca.fingerprint_match, Some(false)) {
            findings.push(DoctorFinding {
                level: "error".to_string(),
                code: "ca_fingerprint_mismatch".to_string(),
                message:
                    "Runtime CA fingerprint does not match trust cert fingerprint (possible stale/MDM drift)."
                        .to_string(),
                remediation:
                    "Install the runtime CA into MDM trust path or update forward_proxy.ca.trust_cert_path."
                        .to_string(),
            });
        }
        if matches!(report.ca.os_trust_status.as_deref(), Some("untrusted")) {
            findings.push(DoctorFinding {
                level: "error".to_string(),
                code: "ca_not_trusted".to_string(),
                message: "CA certificate is not trusted by OS trust store.".to_string(),
                remediation:
                    "Run `soth setup-ca` or deploy CA trust via MDM and ensure fingerprints match."
                        .to_string(),
            });
        } else if matches!(report.ca.os_trust_status.as_deref(), Some("unknown")) {
            findings.push(DoctorFinding {
                level: "warn".to_string(),
                code: "ca_trust_unknown".to_string(),
                message: "Unable to verify OS trust status for configured CA cert.".to_string(),
                remediation:
                    "Validate trust manually or run `soth setup-ca`; ensure openssl/security tools are available."
                        .to_string(),
            });
        }
    }

    if report.system_proxy.state_file.exists && !report.system_proxy.owner_file.exists {
        findings.push(DoctorFinding {
            level: "warn".to_string(),
            code: "state_owner_missing".to_string(),
            message: "System proxy state exists but owner file is missing.".to_string(),
            remediation: "Run `soth off` then `soth on` to regenerate ownership metadata."
                .to_string(),
        });
    }

    if matches!(report.system_proxy.owner_matches_state, Some(false)) {
        findings.push(DoctorFinding {
            level: "error".to_string(),
            code: "state_owner_mismatch".to_string(),
            message: "System proxy state owner does not match local owner.".to_string(),
            remediation:
                "Avoid blind restore; rotate state by running `soth off` with correct owner context."
                    .to_string(),
        });
    }

    if report.daemon.pid.is_some()
        && matches!(report.daemon.process_running, Some(false))
        && report.loopback_bindings.local_listener_open
    {
        findings.push(DoctorFinding {
            level: "warn".to_string(),
            code: "stale_pid_listener_active".to_string(),
            message: "Stale PID artifact detected while loopback listener is active.".to_string(),
            remediation: "Run `soth stop` then `soth start` to refresh ownership/pid metadata."
                .to_string(),
        });
    }

    if report.daemon.pid.is_none() && report.loopback_bindings.local_listener_open {
        findings.push(DoctorFinding {
            level: "warn".to_string(),
            code: "listener_without_pid".to_string(),
            message: "Loopback listener is active but daemon pid file is missing.".to_string(),
            remediation: "Run `soth stop` to reconcile state or `soth start` to adopt listener."
                .to_string(),
        });
    }

    if !report.loopback_bindings.local_listener_open {
        findings.push(DoctorFinding {
            level: "warn".to_string(),
            code: "listener_not_open".to_string(),
            message: format!(
                "No listener reachable at 127.0.0.1:{}.",
                report.loopback_bindings.expected_port
            ),
            remediation: "Start proxy with `soth start` (or `soth up`) and re-run doctor."
                .to_string(),
        });
    }

    if findings.is_empty() {
        findings.push(DoctorFinding {
            level: "ok".to_string(),
            code: "healthy".to_string(),
            message: "No blocking issues detected.".to_string(),
            remediation: "No action required.".to_string(),
        });
    }

    findings
}

fn soth_home_dir() -> PathBuf {
    if let Ok(value) = std::env::var("SOTH_HOME_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    dirs::home_dir()
        .map(|home| home.join(".soth"))
        .unwrap_or_else(|| PathBuf::from(".soth"))
}

fn read_trimmed_string(path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value = raw.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn read_u32(path: &Path) -> Option<u32> {
    read_trimmed_string(path)?.parse::<u32>().ok()
}

fn read_pid_meta(path: &Path) -> Option<PidMetadata> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn read_proxy_state(path: &Path) -> Option<ProxyState> {
    let raw = std::fs::read_to_string(path).ok()?;
    if let Ok(parsed) = serde_json::from_str::<ProxyState>(&raw) {
        return Some(parsed);
    }
    let value = serde_json::from_str::<Value>(&raw).ok()?;
    Some(ProxyState {
        platform: value
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        owner_id: value
            .get("owner_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        port: value
            .get("port")
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok()),
    })
}

fn parse_cert_not_after(path: &Path) -> Result<String> {
    if !path.exists() {
        anyhow::bail!("cert not found");
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed reading cert at {}", path.display()))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes)
        .map_err(|e| anyhow::anyhow!("failed decoding PEM: {e}"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("failed parsing X.509 certificate: {e}"))?;
    Ok(cert.tbs_certificate.validity.not_after.to_string())
}

fn process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let output = Command::new("kill").arg("-0").arg(pid.to_string()).output();
        match output {
            Ok(out) if out.status.success() => true,
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
                stderr.contains("operation not permitted")
            }
            Err(_) => false,
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let filter = format!("PID eq {}", pid);
        let output = Command::new("tasklist")
            .args(["/FI", &filter, "/FO", "CSV", "/NH"])
            .creation_flags(0x08000000)
            .output()
            .ok();
        let Some(output) = output else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .any(|line| line.contains(&format!(",\"{}\",", pid)))
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = pid;
        false
    }
}

fn is_loopback_listener_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(250),
    )
    .is_ok()
}

fn collect_loopback_details(port: u16) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        let mut details = macos_loopback_services();
        if details.is_empty() {
            details.push(format!(
                "No active macOS network services with loopback web/secure proxy on port {port}."
            ));
        }
        details
    }
    #[cfg(target_os = "linux")]
    {
        let details = linux_loopback_status();
        if details.is_empty() {
            return vec![format!(
                "No GNOME loopback proxy bindings detected for port {port}."
            )];
        }
        return details;
    }
    #[cfg(target_os = "windows")]
    {
        let details = windows_loopback_status();
        if details.is_empty() {
            return vec!["No Windows loopback proxy registry binding detected.".to_string()];
        }
        return details;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        vec!["Loopback binding inspection is unsupported on this OS.".to_string()]
    }
}

#[cfg(target_os = "macos")]
fn macos_loopback_services() -> Vec<String> {
    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut services = Vec::new();
    for line in stdout.lines() {
        let service = line.trim();
        if service.is_empty()
            || service.starts_with('*')
            || service.contains("denotes")
            || service.starts_with("** Error")
        {
            continue;
        }
        let web = networksetup_proxy(service, false);
        let secure = networksetup_proxy(service, true);
        if web.as_ref().map(is_loopback_enabled).unwrap_or(false)
            || secure.as_ref().map(is_loopback_enabled).unwrap_or(false)
        {
            services.push(format!("{service} (loopback proxy enabled)"));
        }
    }
    services
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct ProxyEndpoint {
    enabled: bool,
    host: Option<String>,
}

#[cfg(target_os = "macos")]
fn networksetup_proxy(service: &str, secure: bool) -> Option<ProxyEndpoint> {
    let args = if secure {
        vec!["-getsecurewebproxy", service]
    } else {
        vec!["-getwebproxy", service]
    };
    let output = Command::new("networksetup").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut endpoint = ProxyEndpoint {
        enabled: false,
        host: None,
    };
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Enabled:") {
            endpoint.enabled = value.trim().eq_ignore_ascii_case("yes");
        } else if let Some(value) = trimmed.strip_prefix("Server:") {
            let value = value.trim();
            if !value.is_empty() {
                endpoint.host = Some(value.to_string());
            }
        }
    }
    Some(endpoint)
}

#[cfg(target_os = "macos")]
fn is_loopback_enabled(endpoint: &ProxyEndpoint) -> bool {
    endpoint.enabled
        && endpoint
            .host
            .as_deref()
            .map(|h| {
                let lower = h.to_ascii_lowercase();
                lower == "127.0.0.1" || lower == "localhost" || lower == "::1"
            })
            .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linux_loopback_status() -> Vec<String> {
    let mut details = Vec::new();
    let mode = run_gsettings_get("org.gnome.system.proxy", "mode");
    if let Some(mode) = mode {
        details.push(format!("gsettings proxy mode = {}", mode));
    }
    for proto in ["http", "https"] {
        let schema = format!("org.gnome.system.proxy.{proto}");
        let host = run_gsettings_get(schema.as_str(), "host");
        let port = run_gsettings_get(schema.as_str(), "port");
        if let Some(host) = host {
            details.push(format!("{proto} host = {}", host));
        }
        if let Some(port) = port {
            details.push(format!("{proto} port = {}", port));
        }
    }
    details
}

#[cfg(target_os = "linux")]
fn run_gsettings_get(schema: &str, key: &str) -> Option<String> {
    let output = Command::new("gsettings")
        .args(["get", schema, key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "windows")]
fn windows_loopback_status() -> Vec<String> {
    use std::os::windows::process::CommandExt;
    let output = Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyServer",
        ])
        .creation_flags(0x08000000)
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if stdout.contains("127.0.0.1") || stdout.to_ascii_lowercase().contains("localhost") {
        return vec![stdout.trim().to_string()];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn read_trimmed_string_returns_none_for_missing_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("missing");
        assert!(read_trimmed_string(path.as_path()).is_none());
    }

    #[test]
    fn read_proxy_state_falls_back_to_value_parse() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("state.json");
        std::fs::write(
            &path,
            r#"{"schema_version":1,"platform":"macos","owner_id":"o1","port":8080,"extra":{}}"#,
        )
        .expect("write");
        let state = read_proxy_state(path.as_path()).expect("state");
        assert_eq!(state.platform, "macos");
        assert_eq!(state.owner_id, "o1");
        assert_eq!(state.port, Some(8080));
    }

    #[test]
    fn soth_home_dir_prefers_env() {
        let guard = crate::commands::proxy::lock_test_env();
        let temp = tempfile::tempdir().expect("tempdir");
        unsafe { env::set_var("SOTH_HOME_DIR", temp.path()) };
        let home = soth_home_dir();
        assert_eq!(home, temp.path());
        unsafe { env::remove_var("SOTH_HOME_DIR") };
        drop(guard);
    }

    #[test]
    fn compute_findings_flags_missing_ca() {
        let report = DoctorReport {
            managed_runtime: "unknown".to_string(),
            daemon: DaemonDiagnostics {
                pid_file: PathDetails {
                    path: "a".to_string(),
                    exists: false,
                },
                pid_meta_file: PathDetails {
                    path: "b".to_string(),
                    exists: false,
                },
                owner_token_file: PathDetails {
                    path: "c".to_string(),
                    exists: false,
                },
                pid: None,
                process_running: None,
                meta_pid: None,
                meta_port: None,
                owner_token_matches_meta: None,
            },
            system_proxy: SystemProxyDiagnostics {
                state_file: PathDetails {
                    path: "d".to_string(),
                    exists: false,
                },
                owner_file: PathDetails {
                    path: "e".to_string(),
                    exists: false,
                },
                state_platform: None,
                state_owner_id: None,
                state_port: None,
                owner_id: None,
                owner_matches_state: None,
            },
            ca: CaDiagnostics {
                cert_path: PathDetails {
                    path: "f".to_string(),
                    exists: false,
                },
                key_path: PathDetails {
                    path: "g".to_string(),
                    exists: false,
                },
                trust_cert_path: PathDetails {
                    path: "h".to_string(),
                    exists: false,
                },
                trust_source: "runtime_cert".to_string(),
                cert_not_after: None,
                cert_parse_error: None,
                cert_fingerprint_sha256: None,
                trust_fingerprint_sha256: None,
                fingerprint_match: None,
                key_matches_cert: None,
                os_trust_status: None,
                os_trust_detail: None,
            },
            loopback_bindings: LoopbackBindings {
                expected_port: 8080,
                local_listener_open: false,
                details: Vec::new(),
            },
            findings: Vec::new(),
        };

        let findings = compute_findings(&report);
        assert!(findings.iter().any(|f| f.code == "ca_missing"));
        assert!(findings.iter().any(|f| f.code == "listener_not_open"));
    }
}

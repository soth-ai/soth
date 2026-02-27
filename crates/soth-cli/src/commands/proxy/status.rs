//! Proxy status command.

use crate::cli_config;
use crate::style;
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Serialize)]
struct ProxyStatusJson {
    running: bool,
    pid: Option<u32>,
    port: u16,
    #[serde(skip_serializing)]
    uptime_secs: Option<u64>,
    #[serde(skip_serializing)]
    system_proxy_on: bool,
    #[serde(skip_serializing)]
    autostart: String,
    #[serde(skip_serializing)]
    ca_valid_until: Option<String>,
}

#[derive(Debug, Serialize)]
struct BundleStatusJson {
    version: Option<String>,
    #[serde(skip_serializing)]
    installed_at_epoch_s: Option<i64>,
    sig_valid: bool,
}

#[derive(Debug, Serialize)]
struct SyncStatusJson {
    last_heartbeat_secs: Option<i64>,
    queued: u64,
    failed: u64,
    #[serde(skip_serializing)]
    endpoint: String,
}

#[derive(Debug, Serialize)]
struct Last24hJson {
    total: u64,
    blocked: u64,
    flagged: u64,
    cost_usd: f64,
    #[serde(skip_serializing)]
    credential_blocked: u64,
    #[serde(skip_serializing)]
    policy_blocked: u64,
}

#[derive(Debug, Serialize)]
struct StatusJson {
    proxy: ProxyStatusJson,
    bundle: BundleStatusJson,
    sync: SyncStatusJson,
    last_24h: Last24hJson,
    healthy: bool,
}

pub async fn run(config_path: Option<PathBuf>, json: bool) -> Result<bool> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let db_path = cli_config::resolved_db_path(&config);
    let conn = open_db_ro(db_path.as_path())?;

    let now = Utc::now();
    let proxy = collect_proxy_status(&config, now)?;
    let bundle = collect_bundle_status(&conn)?;
    let sync = collect_sync_status(&config, &conn, now)?;
    let last_24h = collect_last_24h(&conn, now)?;

    let healthy = proxy.running
        && proxy.ca_valid_until.is_some()
        && (!config.cloud.enabled || sync.failed == 0);

    let payload = StatusJson {
        proxy,
        bundle,
        sync,
        last_24h,
        healthy,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).context("serialize status JSON")?
        );
        return Ok(payload.healthy);
    }

    render_human(&payload);
    Ok(payload.healthy)
}

fn render_human(status: &StatusJson) {
    println!("PROXY");
    println!("----------------------------------------");
    let pid_line = status
        .proxy
        .pid
        .map(|pid| format!(" (pid {pid})"))
        .unwrap_or_default();
    println!(
        "Status:        {}{}",
        if status.proxy.running {
            "running"
        } else {
            "stopped"
        },
        pid_line
    );
    println!("Port:          {}", status.proxy.port);
    println!(
        "System proxy:  {}",
        if status.proxy.system_proxy_on {
            "on"
        } else {
            "off"
        }
    );
    println!(
        "Uptime:        {}",
        status
            .proxy
            .uptime_secs
            .map(format_duration)
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!("Autostart:     {}", status.proxy.autostart);
    println!(
        "CA cert:       {}",
        status
            .proxy
            .ca_valid_until
            .as_deref()
            .map(|value| format!("valid until {value}"))
            .unwrap_or_else(|| "missing/invalid".to_string())
    );
    println!();
    println!("BUNDLE");
    println!("----------------------------------------");
    println!(
        "Version:       {}",
        status.bundle.version.as_deref().unwrap_or("not installed")
    );
    println!(
        "Installed:     {}",
        status
            .bundle
            .installed_at_epoch_s
            .map(format_epoch_secs)
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "Vendor sig:    {}",
        if status.bundle.sig_valid {
            "verified"
        } else {
            "unknown"
        }
    );
    println!();
    println!("SYNC");
    println!("----------------------------------------");
    println!(
        "Last heartbeat: {}",
        status
            .sync
            .last_heartbeat_secs
            .map(format_ago)
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "Queue:          {} queued  {} failed",
        status.sync.queued, status.sync.failed
    );
    println!("Endpoint:       {}", status.sync.endpoint);
    println!();
    println!("LAST 24 HOURS");
    println!("----------------------------------------");
    println!("Intercepted:    {} requests", status.last_24h.total);
    println!(
        "Blocked:        {} (credential: {}, policy: {})",
        status.last_24h.blocked, status.last_24h.credential_blocked, status.last_24h.policy_blocked
    );
    println!("Flagged:        {}", status.last_24h.flagged);
    println!("Est. cost:      ${:.2}", status.last_24h.cost_usd);
    println!();
    if status.healthy {
        style::success("healthy");
    } else {
        style::warning("degraded");
    }
}

fn collect_proxy_status(
    config: &cli_config::SothConfig,
    now: DateTime<Utc>,
) -> Result<ProxyStatusJson> {
    let pid = read_pid_file();
    let pid_meta = read_pid_meta();
    let active_port = pid_meta
        .as_ref()
        .and_then(|meta| meta.port)
        .unwrap_or(config.forward_proxy.port);
    let running = pid
        .map(process_running)
        .unwrap_or_else(|| is_port_open(active_port));
    let uptime_secs = pid_meta
        .as_ref()
        .filter(|meta| meta.started_at_unix_secs > 0)
        .map(|meta| {
            now.timestamp()
                .saturating_sub(meta.started_at_unix_secs as i64)
                .max(0) as u64
        });
    let system_proxy_on = system_proxy_state_path().exists();
    let autostart = super::autostart::managed_status().unwrap_or_else(|_| "unknown".to_string());
    let cert_path = cli_config::expand_tilde(Path::new(config.forward_proxy.ca.cert_path.as_str()));
    let ca_valid_until = parse_cert_not_after(cert_path.as_path()).ok();

    Ok(ProxyStatusJson {
        running,
        pid,
        port: active_port,
        uptime_secs,
        system_proxy_on,
        autostart,
        ca_valid_until,
    })
}

fn collect_bundle_status(conn: &rusqlite::Connection) -> Result<BundleStatusJson> {
    if !table_exists(conn, "intelligence_bundles")? {
        return Ok(BundleStatusJson {
            version: None,
            installed_at_epoch_s: None,
            sig_valid: false,
        });
    }

    let mut stmt = conn.prepare(
        "SELECT bundle_version, installed_at
         FROM intelligence_bundles
         WHERE status = 'ACTIVE'
         ORDER BY installed_at DESC
         LIMIT 1",
    )?;
    let mut rows = stmt.query([])?;
    if let Some(row) = rows.next()? {
        let version: String = row.get(0)?;
        let installed_at: i64 = row.get(1)?;
        return Ok(BundleStatusJson {
            version: Some(version),
            installed_at_epoch_s: Some(installed_at),
            sig_valid: true,
        });
    }

    Ok(BundleStatusJson {
        version: None,
        installed_at_epoch_s: None,
        sig_valid: false,
    })
}

fn collect_sync_status(
    config: &cli_config::SothConfig,
    conn: &rusqlite::Connection,
    now: DateTime<Utc>,
) -> Result<SyncStatusJson> {
    let queued = count_transmission_status(conn, "QUEUED").unwrap_or(0);
    let failed = count_transmission_status(conn, "FAILED").unwrap_or(0);
    let last_sync =
        read_sync_state(conn, "last_sync_timestamp")?.and_then(|value| parse_sync_age(&value, now));

    Ok(SyncStatusJson {
        last_heartbeat_secs: last_sync,
        queued,
        failed,
        endpoint: config.cloud.endpoint.clone(),
    })
}

fn collect_last_24h(conn: &rusqlite::Connection, now: DateTime<Utc>) -> Result<Last24hJson> {
    if !table_exists(conn, "intercept_records")? {
        return Ok(Last24hJson {
            total: 0,
            blocked: 0,
            flagged: 0,
            cost_usd: 0.0,
            credential_blocked: 0,
            policy_blocked: 0,
        });
    }

    let Some(timestamp_column) = intercept_timestamp_column(conn)? else {
        return Ok(Last24hJson {
            total: 0,
            blocked: 0,
            flagged: 0,
            cost_usd: 0.0,
            credential_blocked: 0,
            policy_blocked: 0,
        });
    };

    let cutoff = now.timestamp_millis() - DAY_MS;
    let sql = format!(
        "SELECT policy_kind, telemetry_json
         FROM intercept_records
         WHERE {timestamp_column} >= ?1"
    );
    let mut stmt = conn.prepare(sql.as_str())?;
    let mut rows = stmt.query([cutoff])?;

    let mut total = 0_u64;
    let mut blocked = 0_u64;
    let mut flagged = 0_u64;
    let mut credential_blocked = 0_u64;
    let mut cost_usd = 0.0_f64;

    while let Some(row) = rows.next()? {
        total += 1;
        let policy_kind: Option<String> = row.get(0)?;
        let telemetry_json: Option<String> = row.get(1)?;
        let normalized_policy = policy_kind
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if normalized_policy == "block" {
            blocked += 1;
        } else if normalized_policy == "flag" {
            flagged += 1;
        }

        if let Some(raw) = telemetry_json {
            if let Ok(value) = serde_json::from_str::<Value>(&raw) {
                if let Some(cost) = value.get("estimated_cost_usd").and_then(Value::as_f64) {
                    cost_usd += cost;
                }
                if normalized_policy == "block" && has_credential_signal(&value) {
                    credential_blocked += 1;
                }
            }
        }
    }

    let policy_blocked = blocked.saturating_sub(credential_blocked);
    Ok(Last24hJson {
        total,
        blocked,
        flagged,
        cost_usd,
        credential_blocked,
        policy_blocked,
    })
}

fn has_credential_signal(value: &Value) -> bool {
    let Some(flags) = value.get("sensitive_code_flags") else {
        return false;
    };
    flags
        .get("credential_pattern_detected")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || flags
            .get("private_key_detected")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn open_db_ro(path: &Path) -> Result<rusqlite::Connection> {
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    rusqlite::Connection::open_with_flags(path, flags)
        .with_context(|| format!("failed opening {}", path.display()))
}

fn table_exists(conn: &rusqlite::Connection, table: &str) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT 1
         FROM sqlite_master
         WHERE type = 'table' AND name = ?1
         LIMIT 1",
    )?;
    let mut rows = stmt.query([table])?;
    Ok(rows.next()?.is_some())
}

fn intercept_timestamp_column(conn: &rusqlite::Connection) -> Result<Option<&'static str>> {
    if table_has_column(conn, "intercept_records", "timestamp_utc")? {
        return Ok(Some("timestamp_utc"));
    }
    if table_has_column(conn, "intercept_records", "timestamp_epoch_ms")? {
        return Ok(Some("timestamp_epoch_ms"));
    }
    Ok(None)
}

fn table_has_column(conn: &rusqlite::Connection, table: &str, column: &str) -> Result<bool> {
    let query = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(query.as_str())?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn count_transmission_status(conn: &rusqlite::Connection, status: &str) -> Result<u64> {
    if !table_exists(conn, "transmitted_events")? {
        return Ok(0);
    }
    let mut stmt =
        conn.prepare("SELECT COUNT(*) FROM transmitted_events WHERE transmission_status = ?1")?;
    let value = stmt.query_row([status], |row| row.get::<_, i64>(0))?;
    Ok(value.max(0) as u64)
}

fn read_sync_state(conn: &rusqlite::Connection, key: &str) -> Result<Option<String>> {
    if !table_exists(conn, "sync_state")? {
        return Ok(None);
    }
    let mut stmt = conn.prepare("SELECT value FROM sync_state WHERE key = ?1 LIMIT 1")?;
    let mut rows = stmt.query([key])?;
    if let Some(row) = rows.next()? {
        let value: String = row.get(0)?;
        return Ok(Some(value));
    }
    Ok(None)
}

fn read_pid_file() -> Option<u32> {
    let path = run_dir().join("proxy.pid");
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse::<u32>().ok()
}

#[derive(serde::Deserialize)]
struct DaemonPidMetadata {
    #[serde(default)]
    #[allow(dead_code)]
    pid: Option<u32>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    started_at_unix_secs: u64,
}

fn read_pid_meta() -> Option<DaemonPidMetadata> {
    let path = run_dir().join("proxy.pid.meta.json");
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<DaemonPidMetadata>(&content).ok()
}

fn run_dir() -> PathBuf {
    soth_home_dir().join("run")
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

fn system_proxy_state_path() -> PathBuf {
    run_dir().join("system_proxy_state.json")
}

#[cfg(unix)]
fn process_running(pid: u32) -> bool {
    let status = std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status();
    status.map(|value| value.success()).unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn process_running(pid: u32) -> bool {
    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}")])
        .output();
    output
        .map(|value| String::from_utf8_lossy(&value.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn process_running(_pid: u32) -> bool {
    false
}

fn is_port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(120),
    )
    .is_ok()
}

fn parse_cert_not_after(path: &Path) -> Result<String> {
    if !path.exists() {
        anyhow::bail!("cert not found");
    }
    let output = std::process::Command::new("openssl")
        .arg("x509")
        .arg("-in")
        .arg(path)
        .arg("-noout")
        .arg("-enddate")
        .output()
        .with_context(|| "failed running openssl")?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();
    if let Some(value) = line.strip_prefix("notAfter=") {
        return Ok(value.trim().to_string());
    }
    anyhow::bail!("unexpected openssl output: {line}")
}

fn format_ago(seconds: i64) -> String {
    if seconds < 0 {
        return "in the future".to_string();
    }
    if seconds < 60 {
        return format!("{seconds} seconds ago");
    }
    if seconds < 3600 {
        return format!("{} minutes ago", seconds / 60);
    }
    if seconds < 86400 {
        return format!("{} hours ago", seconds / 3600);
    }
    format!("{} days ago", seconds / 86400)
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        return format!("{seconds}s");
    }
    if seconds < 3600 {
        return format!("{}m", seconds / 60);
    }
    if seconds < 86400 {
        return format!("{}h", seconds / 3600);
    }
    format!("{}d", seconds / 86400)
}

fn format_epoch_secs(epoch_secs: i64) -> String {
    Utc.timestamp_opt(epoch_secs, 0)
        .single()
        .map(|value| value.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "invalid".to_string())
}

fn parse_sync_age(raw: &str, now: DateTime<Utc>) -> Option<i64> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(raw) {
        return Some(now.timestamp().saturating_sub(parsed.timestamp()));
    }

    let numeric = raw.trim().parse::<i64>().ok()?;
    if numeric <= 0 {
        return None;
    }
    // Heuristic: values above 1e12 are likely epoch millis.
    let ts_secs = if numeric > 1_000_000_000_000 {
        numeric / 1000
    } else {
        numeric
    };
    Some(now.timestamp().saturating_sub(ts_secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_temp_soth_home<T>(
        f: impl FnOnce(std::path::PathBuf) -> T + std::panic::UnwindSafe,
    ) -> T {
        let guard = crate::commands::proxy::lock_test_env();
        let temp = tempfile::tempdir().expect("tempdir");
        let soth_home = temp.path().join(".soth");
        let old_home = env::var_os("HOME");
        let old_soth_home = env::var_os("SOTH_HOME_DIR");

        unsafe {
            env::set_var("HOME", temp.path());
            env::set_var("SOTH_HOME_DIR", &soth_home);
        }

        let result = std::panic::catch_unwind(|| f(soth_home));

        match old_home {
            Some(value) => unsafe { env::set_var("HOME", value) },
            None => unsafe { env::remove_var("HOME") },
        }
        match old_soth_home {
            Some(value) => unsafe { env::set_var("SOTH_HOME_DIR", value) },
            None => unsafe { env::remove_var("SOTH_HOME_DIR") },
        }

        drop(guard);
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn collect_last_24h_uses_timestamp_utc_when_present() {
        let conn = rusqlite::Connection::open_in_memory().expect("open sqlite");
        conn.execute_batch(
            "
            CREATE TABLE intercept_records (
                timestamp_utc INTEGER NOT NULL,
                policy_kind TEXT,
                telemetry_json TEXT
            );
            ",
        )
        .expect("create intercept_records");

        let now = Utc::now();
        let recent = now.timestamp_millis() - 1_000;
        let old = now.timestamp_millis() - DAY_MS - 10_000;

        conn.execute(
            "INSERT INTO intercept_records (timestamp_utc, policy_kind, telemetry_json)
             VALUES (?1, 'BLOCK', ?2)",
            [
                recent.to_string(),
                r#"{"estimated_cost_usd":1.25,"sensitive_code_flags":{"credential_pattern_detected":true,"private_key_detected":false}}"#
                    .to_string(),
            ],
        )
        .expect("insert recent block");
        conn.execute(
            "INSERT INTO intercept_records (timestamp_utc, policy_kind, telemetry_json)
             VALUES (?1, 'FLAG', ?2)",
            [
                recent.to_string(),
                r#"{"estimated_cost_usd":0.50}"#.to_string(),
            ],
        )
        .expect("insert recent flag");
        conn.execute(
            "INSERT INTO intercept_records (timestamp_utc, policy_kind, telemetry_json)
             VALUES (?1, 'BLOCK', ?2)",
            [
                old.to_string(),
                r#"{"estimated_cost_usd":9.99}"#.to_string(),
            ],
        )
        .expect("insert old block");

        let stats = collect_last_24h(&conn, now).expect("collect last 24h");
        assert_eq!(stats.total, 2);
        assert_eq!(stats.blocked, 1);
        assert_eq!(stats.flagged, 1);
        assert_eq!(stats.credential_blocked, 1);
        assert_eq!(stats.policy_blocked, 0);
        assert!((stats.cost_usd - 1.75).abs() < 1e-9);
    }

    #[test]
    fn timestamp_column_falls_back_to_legacy_name() {
        let conn = rusqlite::Connection::open_in_memory().expect("open sqlite");
        conn.execute_batch(
            "
            CREATE TABLE intercept_records (
                timestamp_epoch_ms INTEGER NOT NULL
            );
            ",
        )
        .expect("create intercept_records");

        let column = intercept_timestamp_column(&conn).expect("resolve timestamp column");
        assert_eq!(column, Some("timestamp_epoch_ms"));
    }

    #[test]
    fn collect_proxy_status_prefers_daemon_metadata_port() {
        with_temp_soth_home(|soth_home| {
            let run = soth_home.join("run");
            std::fs::create_dir_all(&run).expect("create run dir");

            std::fs::write(run.join("proxy.pid"), format!("{}\n", std::process::id()))
                .expect("write pid file");
            std::fs::write(
                run.join("proxy.pid.meta.json"),
                r#"{"schema_version":2,"pid":1,"port":9191,"started_at_unix_secs":1700000000}"#,
            )
            .expect("write pid metadata");

            let mut config = cli_config::SothConfig::default();
            config.forward_proxy.port = 8080;
            config.forward_proxy.ca.cert_path = "/non/existent/cert.pem".to_string();
            let status = collect_proxy_status(&config, Utc::now()).expect("collect status");
            assert_eq!(status.port, 9191);
        });
    }

    #[test]
    fn system_proxy_state_path_uses_soth_home_dir() {
        with_temp_soth_home(|soth_home| {
            assert_eq!(
                system_proxy_state_path(),
                soth_home.join("run").join("system_proxy_state.json")
            );
        });
    }
}

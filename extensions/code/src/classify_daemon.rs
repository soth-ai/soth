//! Long-running classify daemon for soth-code.
//!
//! ## Why
//!
//! Hook handlers are short-lived subprocesses fork-execed by the
//! agent on every action.  The real classify bundle is a 23 MB
//! ONNX model whose `ort::Session` initialization is ~50–150 ms
//! (parsing the protobuf, building the runtime graph, allocating
//! pools).  Loading per-subprocess blows the latency target on
//! every Bash command — even with the OS page cache hot.
//!
//! ## Design
//!
//! Mirror historian's supervisor / worker pattern
//! (`crates/soth-cli/src/commands/proxy/start.rs::supervise_historian`):
//!
//! - The same `soth` binary, when invoked with the
//!   `SOTH_CODE_CLASSIFY_WORKER` env, becomes the daemon worker.
//! - Worker loads `~/.soth/bundle/` once on boot, listens on a
//!   localhost TCP port, serves NDJSON-framed classify requests.
//! - `soth start` (and via it, `soth up`) supervises the daemon
//!   alongside historian — re-spawn on crash with exponential
//!   backoff.
//! - Hook subprocesses connect to localhost, send one request,
//!   read one response, close.  Round-trip ~5–15 ms warm.
//!
//! Failure mode: when the daemon isn't running OR connect fails,
//! hook subprocesses fall back to the in-process keyword fallback
//! bundle.  Classify quality degrades but the hook gate keeps
//! working.
//!
//! ## Wire format
//!
//! NDJSON (one JSON object per line, terminated by `\n`).  We
//! use a small purpose-built `ClassifySidecar`-shaped struct as
//! the response payload rather than (de)serializing the full
//! `ClassifiedResult` because the upstream type doesn't derive
//! `Deserialize` and decoupling avoids breaking the wire on
//! every classify-internal change.
//!
//! Cross-platform: localhost TCP works identically on macOS,
//! Linux, and Windows — no Unix socket / named pipe dance.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use soth_classify::{
    ClassifyBundle, ClassifyConfig, HookClassifyInput, HookContentKind,
    HookIdentity as ClassifyIdentity,
};

use crate::event::ClassifySidecar;

/// Default port file.  The daemon writes its actual port +
/// pid here on bind so hook subprocesses can find it without a
/// config knob.  Override via `SOTH_CLASSIFY_DAEMON_PORT_FILE`
/// for tests.
pub fn port_file_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SOTH_CLASSIFY_DAEMON_PORT_FILE") {
        return Some(PathBuf::from(p));
    }
    dirs::home_dir().map(|h| h.join(".soth").join("classify-daemon.json"))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortFile {
    pub port: u16,
    pub pid: u32,
    pub started_at: String,
}

/// On-the-wire request — an in-memory snapshot of what
/// `HookClassifyInput` carries, with owned strings so the
/// daemon can deserialize it once and use it for the whole
/// classify call.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClassifyRequest {
    pub agent_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The actual prompt / tool-args / tool-result text.  This
    /// is what ONNX consumes — the embedding model expects a
    /// natural-language string, not the hook payload's
    /// metadata wrapper.  Adapter's `classify_input` extracts
    /// this from the payload.
    pub content: String,
    /// Snake_case wire form of `HookContentKind` —
    /// `"prompt_text"`, `"tool_args"`, `"tool_result"`,
    /// `"assistant_turn"`.  Avoids depending on the upstream
    /// type deriving Serialize.
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ok")]
pub enum ClassifyResponse {
    #[serde(rename = "true")]
    Ok { sidecar: ClassifySidecar },
    #[serde(rename = "false")]
    Err { error: String },
}

fn kind_to_str(k: HookContentKind) -> &'static str {
    match k {
        HookContentKind::PromptText => "prompt_text",
        HookContentKind::ToolArgs => "tool_args",
        HookContentKind::ToolResult => "tool_result",
        HookContentKind::AssistantTurn => "assistant_turn",
    }
}

fn str_to_kind(s: &str) -> Option<HookContentKind> {
    match s {
        "prompt_text" => Some(HookContentKind::PromptText),
        "tool_args" => Some(HookContentKind::ToolArgs),
        "tool_result" => Some(HookContentKind::ToolResult),
        "assistant_turn" => Some(HookContentKind::AssistantTurn),
        _ => None,
    }
}

/// Convenience constructor for hook-side callers.
pub fn build_request(
    agent_name: &str,
    provider: Option<&str>,
    model: Option<&str>,
    content: &str,
    kind: HookContentKind,
) -> ClassifyRequest {
    ClassifyRequest {
        agent_name: agent_name.to_string(),
        provider: provider.map(String::from),
        model: model.map(String::from),
        content: content.to_string(),
        kind: kind_to_str(kind).to_string(),
    }
}

// ── server ────────────────────────────────────────────────

/// Run the daemon: load `~/.soth/bundle/`, bind to a localhost
/// port, serve classify requests until the listener stops.
/// Blocking call — invoke from the worker entry point.
///
/// `bind_port = 0` asks the kernel for an ephemeral port; the
/// actual port is written to the port file so clients can
/// discover us.
pub fn serve(bundle_dir: &Path, bind_port: u16) -> std::io::Result<()> {
    let bundle = soth_classify::load_bundle(bundle_dir).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("classify bundle load failed at {}: {}", bundle_dir.display(), e),
        )
    })?;

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], bind_port)))?;
    let actual_port = listener.local_addr()?.port();
    write_port_file(actual_port)?;

    eprintln!(
        "soth-code classify daemon listening on 127.0.0.1:{actual_port} (bundle={})",
        bundle_dir.display()
    );

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let bundle = Arc::clone(&bundle);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, bundle) {
                        tracing::warn!(error = ?e, "classify daemon: connection handler errored");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = ?e, "classify daemon: accept failed");
            }
        }
    }
    Ok(())
}

fn write_port_file(port: u16) -> std::io::Result<()> {
    let Some(path) = port_file_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let pf = PortFile {
        port,
        pid: std::process::id(),
        started_at: chrono::Utc::now().to_rfc3339(),
    };
    let bytes = serde_json::to_vec_pretty(&pf)
        .map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(())
}

fn handle_connection(stream: TcpStream, bundle: Arc<ClassifyBundle>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let req: ClassifyRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            return write_response(
                &stream,
                &ClassifyResponse::Err {
                    error: format!("malformed request: {e}"),
                },
            );
        }
    };
    let kind = match str_to_kind(&req.kind) {
        Some(k) => k,
        None => {
            return write_response(
                &stream,
                &ClassifyResponse::Err {
                    error: format!("unknown kind: {}", req.kind),
                },
            );
        }
    };

    let identity = ClassifyIdentity::default();
    let input = HookClassifyInput {
        agent_name: &req.agent_name,
        provider: req.provider.as_deref(),
        model: req.model.as_deref(),
        content: &req.content,
        kind,
        identity: &identity,
    };
    let config = ClassifyConfig::default();
    let result = soth_classify::classify_for_hook(input, &bundle, &config);
    let sidecar = ClassifySidecar::from(&result);
    write_response(&stream, &ClassifyResponse::Ok { sidecar })
}

fn write_response(stream: &TcpStream, resp: &ClassifyResponse) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(resp)
        .map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    let mut s = stream;
    s.write_all(&bytes)?;
    s.flush()?;
    Ok(())
}

// ── client ────────────────────────────────────────────────

/// Hook-side: send a classify request to the daemon and return
/// the resulting sidecar.  Returns `None` when the daemon isn't
/// reachable (port file missing, connect refused, timeout) —
/// caller falls through to the in-process fallback.
///
/// Tight timeouts: the daemon is local and supposed to be fast.
/// If anything stalls we bail and let the hook fall back rather
/// than blocking the gate.
pub fn try_classify(req: &ClassifyRequest) -> Option<ClassifySidecar> {
    let port_path = port_file_path()?;
    let bytes = std::fs::read(&port_path).ok()?;
    let pf: PortFile = serde_json::from_slice(&bytes).ok()?;
    let addr = SocketAddr::from(([127, 0, 0, 1], pf.port));

    let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(50)).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(500))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(50))).ok()?;

    let mut req_bytes = serde_json::to_vec(req).ok()?;
    req_bytes.push(b'\n');
    {
        let mut s = &stream;
        s.write_all(&req_bytes).ok()?;
        s.flush().ok()?;
    }

    let read_stream = stream.try_clone().ok()?;
    let mut reader = BufReader::new(read_stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let resp: ClassifyResponse = serde_json::from_str(line.trim()).ok()?;
    match resp {
        ClassifyResponse::Ok { sidecar } => Some(sidecar),
        ClassifyResponse::Err { error } => {
            tracing::debug!(error = %error, "classify daemon returned error; falling back");
            None
        }
    }
}

/// Snapshot of the daemon's runtime state, derived from the
/// port file.  Used by `soth code doctor` to surface daemon
/// status without standing up a separate IPC.
#[derive(Debug, Clone)]
pub struct DaemonStatus {
    pub port_file_path: PathBuf,
    pub port: Option<u16>,
    pub pid: Option<u32>,
    pub started_at: Option<String>,
    pub reachable: bool,
}

pub fn status() -> Option<DaemonStatus> {
    let path = port_file_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => {
            return Some(DaemonStatus {
                port_file_path: path,
                port: None,
                pid: None,
                started_at: None,
                reachable: false,
            });
        }
    };
    let pf: PortFile = match serde_json::from_slice(&bytes) {
        Ok(pf) => pf,
        Err(_) => {
            return Some(DaemonStatus {
                port_file_path: path,
                port: None,
                pid: None,
                started_at: None,
                reachable: false,
            });
        }
    };
    let addr = SocketAddr::from(([127, 0, 0, 1], pf.port));
    let reachable =
        TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok();
    Some(DaemonStatus {
        port_file_path: path,
        port: Some(pf.port),
        pid: Some(pf.pid),
        started_at: Some(pf.started_at),
        reachable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests in this module mutate the process-global
    /// `SOTH_CLASSIFY_DAEMON_PORT_FILE` env var.  cargo test runs
    /// per-binary tests in parallel, so without serialization one
    /// test's `set_var` clobbers another's.  Hold this mutex for
    /// the full duration of any test that touches the env.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn try_classify_returns_none_when_no_daemon() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Pin the no-daemon path: must NOT panic, must NOT block,
        // must return None promptly.  Hook gate reliability hinges
        // on this — a missing daemon must be a graceful degrade,
        // not a crash.
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var(
            "SOTH_CLASSIFY_DAEMON_PORT_FILE",
            tmp.path().join("nonexistent.json"),
        );
        let req = build_request(
            "claude_code",
            None,
            None,
            "hello world",
            HookContentKind::PromptText,
        );
        let start = std::time::Instant::now();
        let result = try_classify(&req);
        let elapsed = start.elapsed();
        assert!(result.is_none());
        assert!(
            elapsed.as_millis() < 100,
            "no-daemon path must return promptly; took {elapsed:?}"
        );
        std::env::remove_var("SOTH_CLASSIFY_DAEMON_PORT_FILE");
    }

    #[test]
    fn try_classify_returns_none_when_port_file_invalid_json() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let port_file = tmp.path().join("port.json");
        std::fs::write(&port_file, b"not json").unwrap();
        std::env::set_var("SOTH_CLASSIFY_DAEMON_PORT_FILE", &port_file);
        let req = build_request(
            "claude_code",
            None,
            None,
            "x",
            HookContentKind::PromptText,
        );
        assert!(try_classify(&req).is_none());
        std::env::remove_var("SOTH_CLASSIFY_DAEMON_PORT_FILE");
    }

    #[test]
    fn kind_str_round_trip_covers_all_variants() {
        for k in [
            HookContentKind::PromptText,
            HookContentKind::ToolArgs,
            HookContentKind::ToolResult,
            HookContentKind::AssistantTurn,
        ] {
            let s = kind_to_str(k);
            assert_eq!(str_to_kind(s), Some(k), "round trip for {k:?}");
        }
        assert_eq!(str_to_kind("not_a_kind"), None);
    }

    #[test]
    fn try_classify_parses_response_from_fake_daemon() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Pin the wire contract end-to-end without booting the real
        // ONNX server: a fake listener accepts one connection,
        // reads the request, writes a canned ClassifyResponse::Ok,
        // and exits.  Failure here means a future change to either
        // the request shape or the response shape will break the
        // hook → daemon path silently — exactly the regression we
        // want a test to catch.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut req_line = String::new();
            reader.read_line(&mut req_line).unwrap();
            let req: ClassifyRequest = serde_json::from_str(req_line.trim()).unwrap();
            assert_eq!(req.agent_name, "claude_code");
            assert_eq!(req.kind, "prompt_text");
            assert_eq!(req.content, "edit src/lib.rs");

            let resp = ClassifyResponse::Ok {
                sidecar: ClassifySidecar {
                    semantic_hash: "deadbeef".to_string(),
                    use_case_label: "CodeGeneration".to_string(),
                    use_case_confidence: 0.81,
                    complexity_score: 3,
                    anomaly_score: 0.0,
                    anomaly_flags: vec![],
                    estimated_input_tokens: 12,
                    topic_cluster_id: 0,
                    stage_total_us: 4321,
                },
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            let mut s = &stream;
            s.write_all(&bytes).unwrap();
            s.flush().unwrap();
        });

        let tmp = tempfile::tempdir().unwrap();
        let port_file = tmp.path().join("port.json");
        let pf = PortFile {
            port,
            pid: 0,
            started_at: "test".to_string(),
        };
        std::fs::write(&port_file, serde_json::to_vec(&pf).unwrap()).unwrap();
        std::env::set_var("SOTH_CLASSIFY_DAEMON_PORT_FILE", &port_file);

        let req = build_request(
            "claude_code",
            None,
            None,
            "edit src/lib.rs",
            HookContentKind::PromptText,
        );
        let sidecar = try_classify(&req).expect("daemon path returned a sidecar");
        assert_eq!(sidecar.semantic_hash, "deadbeef");
        assert_eq!(sidecar.use_case_label, "CodeGeneration");
        assert_eq!(sidecar.complexity_score, 3);
        assert_eq!(sidecar.estimated_input_tokens, 12);

        server.join().unwrap();
        std::env::remove_var("SOTH_CLASSIFY_DAEMON_PORT_FILE");
    }

    #[test]
    fn classify_response_serde_round_trip() {
        let sidecar = ClassifySidecar {
            semantic_hash: "abc".to_string(),
            use_case_label: "CodeGeneration".to_string(),
            use_case_confidence: 0.92,
            complexity_score: 5,
            anomaly_score: 0.1,
            anomaly_flags: vec!["topic_drift".to_string()],
            estimated_input_tokens: 42,
            topic_cluster_id: 7,
            stage_total_us: 1234,
        };
        let resp = ClassifyResponse::Ok { sidecar };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ClassifyResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            ClassifyResponse::Ok { sidecar } => {
                assert_eq!(sidecar.semantic_hash, "abc");
                assert_eq!(sidecar.use_case_label, "CodeGeneration");
            }
            ClassifyResponse::Err { .. } => panic!("expected Ok"),
        }
    }
}

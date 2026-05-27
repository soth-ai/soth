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
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lru::LruCache;
use serde::{Deserialize, Serialize};
use soth_classify::{
    ClassifyBundle, ClassifyConfig, HookClassifyInput, HookContentKind,
    HookIdentity as ClassifyIdentity,
};
use soth_core::SessionSnapshot;

use crate::event::ClassifySidecar;

/// Cap on the per-session prior-hash list so a long-running
/// session doesn't grow unbounded. Stage 5 (anomaly) compares
/// the current embedding against the most-recent N hashes; 32
/// is enough to detect drift without bloating snapshots.
const MAX_PRIOR_HASHES: usize = 32;
/// Cap on the per-session topic-cluster list. Same reasoning.
const MAX_CLUSTER_IDS: usize = 32;
/// Maximum number of distinct sessions the daemon retains state
/// for. LRU evicts the oldest when this is exceeded.  256
/// covers a heavy-IDE-user day (≪ 1 MB of snapshot memory).
const SESSION_CACHE_CAP: usize = 256;

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
    /// Agent-native session id (from the hook payload —
    /// `session_id` for Claude Code, `conversation_id` for
    /// Cursor).  Daemon keys per-session prior state by
    /// `(agent_name, session_id)` so volatility / anomaly
    /// stages compare against the same session's earlier
    /// embeddings.  `None` collapses to a one-shot call (no
    /// drift signals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
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
    session_id: Option<&str>,
) -> ClassifyRequest {
    ClassifyRequest {
        agent_name: agent_name.to_string(),
        provider: provider.map(String::from),
        model: model.map(String::from),
        content: content.to_string(),
        kind: kind_to_str(kind).to_string(),
        session_id: session_id.map(String::from),
    }
}

/// Daemon-side per-session state cache.  Keyed by
/// `"<agent_name>:<session_id>"` so two agents that happen to
/// reuse the same session id never collide.
type SessionCache = Mutex<LruCache<String, SessionSnapshot>>;

fn new_session_cache() -> SessionCache {
    Mutex::new(LruCache::new(NonZeroUsize::new(SESSION_CACHE_CAP).unwrap()))
}

fn session_key(agent_name: &str, session_id: &str) -> String {
    format!("{agent_name}:{session_id}")
}

/// After each classify call, fold the result back into the
/// session snapshot so the next call sees the prior state.
///
/// What we maintain (mirrors `soth-proxy/src/session/store.rs`'s
/// session-tracking convention):
///
///   * `prior_semantic_hashes` — for stage 2 dedup / near-dupe.
///   * `topic_cluster_ids_seen` — for cluster reuse signals.
///   * `embedding_centroid` — running mean of embeddings, the
///     primary input to stage 5's topic-drift detection.  We
///     update it as `c = (c·(n-1) + e) / n`, same formula the
///     proxy uses.
///   * `request_count`, `total_tokens`, `session_token_total` —
///     rate / volume baselines for stage 5's token-burst,
///     rapid-fire, and high-volume rules.
///   * `last_model` + `models_used_this_session` — for the
///     model-switch anomaly rule (3+ distinct models in one
///     session ⇒ flag).
///   * `last_request_timestamp` / `current_request_timestamp` —
///     for the rapid-fire rule (≤500 ms gap ⇒ flag).
///
/// Hashes / clusters are size-capped so a long session doesn't
/// grow the snapshot unboundedly.
fn update_snapshot_with_result(
    snap: &mut SessionSnapshot,
    result: &soth_classify::ClassifiedResult,
    request_model: Option<&str>,
    request_timestamp_ms: i64,
) {
    if !result.semantic_hash.is_empty()
        && result.semantic_hash != "00000000000000000000000000000000"
    {
        snap.prior_semantic_hashes
            .push(result.semantic_hash.clone());
        if snap.prior_semantic_hashes.len() > MAX_PRIOR_HASHES {
            let drop_n = snap.prior_semantic_hashes.len() - MAX_PRIOR_HASHES;
            snap.prior_semantic_hashes.drain(0..drop_n);
        }
    }
    if result.topic_cluster_id != 0
        && !snap
            .topic_cluster_ids_seen
            .contains(&result.topic_cluster_id)
    {
        snap.topic_cluster_ids_seen.push(result.topic_cluster_id);
        if snap.topic_cluster_ids_seen.len() > MAX_CLUSTER_IDS {
            let drop_n = snap.topic_cluster_ids_seen.len() - MAX_CLUSTER_IDS;
            snap.topic_cluster_ids_seen.drain(0..drop_n);
        }
    }

    // Running-mean centroid update.  Stage 5 uses cosine distance
    // between this centroid and the current embedding to detect
    // topic drift; without it the "topic drift" anomaly rule
    // never fires for soth-code events.
    if let Some(embedding) = result.embedding.as_deref() {
        let n_prev = snap.request_count as f32;
        match snap.embedding_centroid.as_mut() {
            Some(centroid) if centroid.len() == embedding.len() && n_prev > 0.0 => {
                let n_new = n_prev + 1.0;
                for (c, e) in centroid.iter_mut().zip(embedding.iter()) {
                    *c = (*c * n_prev + *e) / n_new;
                }
            }
            _ => {
                snap.embedding_centroid = Some(embedding.to_vec());
            }
        }
    }

    snap.request_count = snap.request_count.saturating_add(1);
    snap.request_count_this_hour = snap.request_count_this_hour.saturating_add(1);
    if let Some(tokens) = result.telemetry_event.estimated_input_tokens {
        snap.session_token_total = snap.session_token_total.saturating_add(tokens);
        snap.total_tokens = snap.total_tokens.saturating_add(tokens as u64);
    }

    if let Some(model) = request_model.filter(|s| !s.is_empty()) {
        snap.last_model = Some(model.to_string());
        if !snap.models_used_this_session.iter().any(|m| m == model) {
            snap.models_used_this_session.push(model.to_string());
        }
    }

    // last → current → next call's last.  Stage 5 reads
    // `last_request_timestamp` as the prior turn's time and
    // `current_request_timestamp` as this turn's time; we copy
    // the just-recorded current value into last after each call.
    snap.last_request_timestamp = if snap.current_request_timestamp != 0 {
        Some(snap.current_request_timestamp)
    } else {
        None
    };
    snap.current_request_timestamp = request_timestamp_ms;
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
            format!(
                "classify bundle load failed at {}: {}",
                bundle_dir.display(),
                e
            ),
        )
    })?;

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], bind_port)))?;
    let actual_port = listener.local_addr()?.port();
    write_port_file(actual_port)?;

    eprintln!(
        "soth-code classify daemon listening on 127.0.0.1:{actual_port} (bundle={})",
        bundle_dir.display()
    );

    let sessions: Arc<SessionCache> = Arc::new(new_session_cache());
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let bundle = Arc::clone(&bundle);
                let sessions = Arc::clone(&sessions);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, bundle, sessions) {
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
    let bytes = serde_json::to_vec_pretty(&pf).map_err(std::io::Error::other)?;
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

fn handle_connection(
    stream: TcpStream,
    bundle: Arc<ClassifyBundle>,
    sessions: Arc<SessionCache>,
) -> std::io::Result<()> {
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

    // Look up (clone out) the prior session snapshot so we can
    // pass a stable reference into the classify pipeline. Hold
    // the mutex only across the read; release before running
    // the classify pipeline (which is the expensive part) so
    // concurrent connections for *different* sessions don't
    // serialize behind ours.
    let session_key_owned = req
        .session_id
        .as_deref()
        .map(|sid| session_key(&req.agent_name, sid));
    let prior_snapshot = if let Some(key) = session_key_owned.as_deref() {
        sessions.lock().ok().and_then(|mut g| g.get(key).cloned())
    } else {
        None
    };

    // Volatility (stage 4) reads `conversation_turn` /
    // `has_tool_*` off NormalizedRequest.  Derive them from the
    // session snapshot so a long-running session crosses the
    // Static→LowVolatile→Dynamic threshold as it accumulates
    // turns.  Tool flags are heuristic — the hook payload doesn't
    // carry them directly, but a session with prior turns has
    // almost certainly been doing tool calls (Claude Code's
    // primary action shape).  Conservative: false for the first
    // turn, true once we've seen activity.
    let conversation_turn = prior_snapshot
        .as_ref()
        .and_then(|s| {
            if s.request_count == 0 {
                None
            } else {
                Some(s.request_count.saturating_add(1))
            }
        })
        .or(Some(1));
    let has_prior = prior_snapshot
        .as_ref()
        .map(|s| s.request_count > 0)
        .unwrap_or(false);

    let identity = ClassifyIdentity::default();
    let input = HookClassifyInput {
        agent_name: &req.agent_name,
        provider: req.provider.as_deref(),
        model: req.model.as_deref(),
        content: &req.content,
        kind,
        identity: &identity,
        session_snapshot: prior_snapshot.as_ref(),
        conversation_turn,
        has_tool_definitions: has_prior,
        has_tool_results: has_prior,
    };
    let config = ClassifyConfig::default();
    let result = soth_classify::classify_for_hook(input, &bundle, &config);

    // Fold this call's outputs back into the cached snapshot so
    // the *next* call for this session sees the prior. Drift
    // detection (volatility / anomaly) materializes after >=2
    // calls per session.
    if let Some(key) = session_key_owned {
        if let Ok(mut guard) = sessions.lock() {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let mut snap = prior_snapshot.unwrap_or_default();
            update_snapshot_with_result(&mut snap, &result, req.model.as_deref(), now_ms);
            guard.put(key, snap);
        }
    }

    let sidecar = ClassifySidecar::from(&result);
    write_response(&stream, &ClassifyResponse::Ok { sidecar })
}

fn write_response(stream: &TcpStream, resp: &ClassifyResponse) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(resp).map_err(std::io::Error::other)?;
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
/// Hook-side: send a classify request to the daemon and return the
/// resulting sidecar.  Returns `None` when the daemon isn't reachable
/// (port file missing, connect refused, timeout) — caller falls
/// through to the in-process bundle.
///
/// All step-by-step failure reasons are written to a per-process
/// diagnostic file at `~/.soth/queue/classify-daemon-trace.log` (one
/// line per skipped call) when the env var
/// `SOTH_CLASSIFY_DAEMON_TRACE=1` is set.  Production stays silent —
/// the file is only opened when the env is set, and the log path
/// lives next to the existing hook timings file so operators have
/// one place to look.  No eprintln in the hot path.
pub fn try_classify(req: &ClassifyRequest) -> Option<ClassifySidecar> {
    let trace = std::env::var_os("SOTH_CLASSIFY_DAEMON_TRACE").is_some();
    let log = |msg: &str| {
        if !trace {
            return;
        }
        if let Some(home) = dirs::home_dir() {
            let path = home
                .join(".soth")
                .join("queue")
                .join("classify-daemon-trace.log");
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                use std::io::Write as _;
                let _ = writeln!(
                    f,
                    "{} pid={} {}",
                    chrono::Utc::now().to_rfc3339(),
                    std::process::id(),
                    msg
                );
            }
        }
    };

    let port_path = match port_file_path() {
        Some(p) => p,
        None => {
            log("port_file_path None (HOME unresolvable)");
            return None;
        }
    };
    let bytes = match std::fs::read(&port_path) {
        Ok(b) => b,
        Err(e) => {
            log(&format!("read({}) failed: {e}", port_path.display()));
            return None;
        }
    };
    let pf: PortFile = match serde_json::from_slice(&bytes) {
        Ok(pf) => pf,
        Err(e) => {
            log(&format!("parse port file failed: {e}"));
            return None;
        }
    };
    let addr = SocketAddr::from(([127, 0, 0, 1], pf.port));

    // 200 ms connect: localhost is normally <1 ms, but macOS Defender
    // / EDR scanners occasionally insert tens of ms of latency on the
    // first connect to a fresh local port.  Tighter than that and we
    // see flaky misses in real-world hook fires that have no business
    // failing.
    let stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
        Ok(s) => s,
        Err(e) => {
            log(&format!("connect {addr} failed: {e}"));
            return None;
        }
    };
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_millis(500))) {
        log(&format!("set_read_timeout failed: {e}"));
        return None;
    }
    if let Err(e) = stream.set_write_timeout(Some(Duration::from_millis(200))) {
        log(&format!("set_write_timeout failed: {e}"));
        return None;
    }

    let mut req_bytes = match serde_json::to_vec(req) {
        Ok(b) => b,
        Err(e) => {
            log(&format!("serialize request failed: {e}"));
            return None;
        }
    };
    req_bytes.push(b'\n');
    {
        let mut s = &stream;
        if let Err(e) = s.write_all(&req_bytes) {
            log(&format!("write_all failed: {e}"));
            return None;
        }
        if let Err(e) = s.flush() {
            log(&format!("flush failed: {e}"));
            return None;
        }
    }

    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log(&format!("try_clone failed: {e}"));
            return None;
        }
    };
    let mut reader = BufReader::new(read_stream);
    let mut line = String::new();
    if let Err(e) = reader.read_line(&mut line) {
        log(&format!("read_line failed: {e}"));
        return None;
    }
    let resp: ClassifyResponse = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            log(&format!("parse response failed: {e} raw='{}'", line.trim()));
            return None;
        }
    };
    match resp {
        ClassifyResponse::Ok { sidecar } => Some(sidecar),
        ClassifyResponse::Err { error } => {
            log(&format!("daemon returned err: {error}"));
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
    let reachable = TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok();
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
            None,
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
            None,
        );
        assert!(try_classify(&req).is_none());
        std::env::remove_var("SOTH_CLASSIFY_DAEMON_PORT_FILE");
    }

    fn make_classified_result(hash: &str, cluster: u32) -> soth_classify::ClassifiedResult {
        use soth_classify::{ClassifiedResult, StageTiming};
        use soth_core::{
            PolicyDecision, PolicyDecisionKind, TelemetryEvent, UseCaseLabel, UseCaseLabelReason,
            VolatilityClass,
        };
        ClassifiedResult {
            use_case_label: UseCaseLabel::Unknown,
            use_case_confidence: 0.0,
            secondary_label: None,
            use_case_label_reason: UseCaseLabelReason::Confident,
            topic_cluster_id: cluster,
            semantic_hash: hash.to_string(),
            embedding: None,
            embedding_norm: 0.0,
            complexity_score: 0,
            embedding_skipped: false,
            volatility_class: VolatilityClass::Static,
            dynamic_fraction: 0.0,
            is_semantic_collision: false,
            collision_response_stability: None,
            prefix_repeat_signature: None,
            anomaly_score: 0.0,
            anomaly_flags: Vec::new(),
            policy_decision: PolicyDecision {
                kind: PolicyDecisionKind::Allow,
                matched_rule: None,
                warnings: Vec::new(),
                eval_latency_us: 0,
            },
            policy_enforced: false,
            telemetry_event: TelemetryEvent::default(),
            commitment_nonce: [0u8; 32],
            stage_latencies: StageTiming::default(),
        }
    }

    #[test]
    fn update_snapshot_caps_prior_hashes() {
        // The cache must not grow unbounded for a long session.
        // Push more than MAX_PRIOR_HASHES distinct hashes and
        // verify the oldest get dropped.
        let mut snap = SessionSnapshot::default();
        for i in 0..(MAX_PRIOR_HASHES + 5) {
            let h = soth_core::sha256_hex(format!("turn-{i}"));
            update_snapshot_with_result(
                &mut snap,
                &make_classified_result(&h, (i + 1) as u32),
                None,
                1_000 + i as i64,
            );
        }
        assert_eq!(snap.prior_semantic_hashes.len(), MAX_PRIOR_HASHES);
        assert_eq!(snap.request_count as usize, MAX_PRIOR_HASHES + 5);
        // Oldest hash got dropped — first surviving hash is the
        // 5th of the original sequence.
        let oldest_surviving = soth_core::sha256_hex("turn-5");
        assert_eq!(snap.prior_semantic_hashes[0], oldest_surviving);
    }

    #[test]
    fn update_snapshot_skips_zero_semantic_hash() {
        // Tool-args calls return the all-zero sentinel hash
        // (no embedding ran).  Don't pollute prior_semantic_hashes
        // with sentinels — the anomaly stage compares against
        // them and a zero hash skews drift detection.
        let mut snap = SessionSnapshot::default();
        let result = make_classified_result("00000000000000000000000000000000", 0);
        update_snapshot_with_result(&mut snap, &result, None, 0);
        assert!(snap.prior_semantic_hashes.is_empty());
        assert!(snap.topic_cluster_ids_seen.is_empty());
        // request_count still ticks — useful for rate signals.
        assert_eq!(snap.request_count, 1);
    }

    #[test]
    fn session_key_separates_agents() {
        // Two agents reusing the same session id from different
        // namespaces (Claude Code uses session_id, Cursor uses
        // conversation_id, Codex uses session_id, …) must not
        // share state.
        assert_ne!(
            session_key("claude_code", "abc"),
            session_key("cursor", "abc")
        );
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
                    use_case_secondary_label: None,
                    use_case_label_reason: "Confident".to_string(),
                    complexity_score: 3,
                    anomaly_score: 0.0,
                    anomaly_flags: vec![],
                    volatility_class: "Static".to_string(),
                    dynamic_fraction: 0.0,
                    estimated_input_tokens: 12,
                    topic_cluster_id: 0,
                    stage_total_us: 4321,
                    interaction_mode: "augmentative".to_string(),
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
            None,
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
            use_case_secondary_label: Some("CodeReview".to_string()),
            use_case_label_reason: "Confident".to_string(),
            complexity_score: 5,
            anomaly_score: 0.1,
            anomaly_flags: vec!["topic_drift".to_string()],
            estimated_input_tokens: 42,
            topic_cluster_id: 7,
            stage_total_us: 1234,
            volatility_class: "LowVolatile".to_string(),
            dynamic_fraction: 0.15,
            interaction_mode: "directive".to_string(),
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

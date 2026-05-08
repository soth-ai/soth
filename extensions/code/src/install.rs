//! `soth code install` / `uninstall` — wire the hook handler into an
//! agent's native config so each tool action triggers
//! `soth code hook --agent <name> --type <hook>`.
//!
//! Discipline (gryph PR #37 + the `settings.json` corruption class):
//!
//! 1. **Atomic write.** `tempfile::NamedTempFile::persist` does a
//!    rename over the target path; either the new content lands fully
//!    or the old content is preserved. No half-written settings.
//! 2. **`.bak` rotation.** Before write, copy the existing settings
//!    to `settings.json.bak`. If a malformed install slips through,
//!    operator can restore by hand.
//! 3. **Pre-flight JSON parse.** Refuse to write when the existing
//!    settings file is malformed — we'd otherwise overwrite a
//!    user-broken config that the user might be trying to fix.
//! 4. **Idempotent.** Running install twice is safe: re-parses,
//!    detects existing soth hooks, and reuses them.
//! 5. **Preserves unknown fields.** We only touch the `hooks` block
//!    we own; everything else round-trips through serde unchanged.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

const CLAUDE_PRE_TOOL_USE: &str = "PreToolUse";
const CLAUDE_POST_TOOL_USE: &str = "PostToolUse";
const CLAUDE_USER_PROMPT_SUBMIT: &str = "UserPromptSubmit";
const CLAUDE_STOP: &str = "Stop";
const CLAUDE_SESSION_START: &str = "SessionStart";
const CLAUDE_SESSION_END: &str = "SessionEnd";
const CLAUDE_NOTIFICATION: &str = "Notification";

const HOOK_TYPES: &[(&str, &str)] = &[
    (CLAUDE_PRE_TOOL_USE, "pre_tool_use"),
    (CLAUDE_POST_TOOL_USE, "post_tool_use"),
    (CLAUDE_USER_PROMPT_SUBMIT, "user_prompt_submit"),
    (CLAUDE_STOP, "stop"),
    (CLAUDE_SESSION_START, "session_start"),
    (CLAUDE_SESSION_END, "session_end"),
    (CLAUDE_NOTIFICATION, "notification"),
];

/// Marker placed on every hook entry we install so future
/// installs/uninstalls can find their own work and not touch
/// hand-authored entries the user added themselves.
const SOTH_MARKER_KEY: &str = "_soth_managed";

#[derive(Debug)]
pub struct InstallReport {
    pub settings_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    /// Hook event names we added to the config (empty on a no-op
    /// idempotent install).
    pub hooks_added: Vec<String>,
    /// Hook event names that already had a soth-managed entry — left
    /// alone.
    pub hooks_already_present: Vec<String>,
    /// Soth binary the hook command will invoke. Captured at install
    /// time via `std::env::current_exe()`.
    pub binary_path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("settings file at {path} is not valid JSON: {source} — refusing to overwrite a broken config")]
    Malformed {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("settings root must be a JSON object, got {kind}")]
    NotAnObject { kind: &'static str },
    #[error("write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot resolve current soth binary: {0}")]
    NoBinary(std::io::Error),
    #[error("settings.json parent {path} could not be created: {source}")]
    Mkdir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("serialize updated settings: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Default Claude Code settings file location.
pub fn default_claude_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

/// Install the soth-code hook into Claude Code's `settings.json`.
///
/// `settings_path` must be the absolute path to the settings file —
/// callers wanting the default location pass
/// [`default_claude_settings_path`]. Tests pass a tempdir-rooted path.
///
/// `binary_path_override` is for tests that want to pin the recorded
/// hook command to a known string. Production passes `None`, which
/// resolves via `std::env::current_exe()`.
pub fn install_claude_code(
    settings_path: &Path,
    binary_path_override: Option<PathBuf>,
) -> Result<InstallReport, InstallError> {
    let binary_path = match binary_path_override {
        Some(p) => p,
        None => std::env::current_exe().map_err(InstallError::NoBinary)?,
    };

    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent).map_err(|e| InstallError::Mkdir {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let original_content = read_settings_or_empty(settings_path)?;
    let mut settings: Value = if original_content.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        // Pre-flight parse: refuse to overwrite a malformed settings
        // file. The operator may have an in-progress edit they
        // haven't finished; clobbering it would be the gryph PR #37
        // class of bug.
        serde_json::from_str(&original_content).map_err(|e| InstallError::Malformed {
            path: settings_path.to_path_buf(),
            source: e,
        })?
    };

    if !settings.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(&settings),
        });
    }

    let backup_path = if Path::new(settings_path).exists() && !original_content.is_empty() {
        let bak = settings_path.with_extension("json.bak");
        // Atomic-ish: write the backup via tempfile in the same dir
        // then rename. If the rename fails, we haven't lost anything
        // — the original is still intact.
        write_atomic(&bak, original_content.as_bytes())?;
        Some(bak)
    } else {
        None
    };

    let mut hooks_added = Vec::new();
    let mut hooks_already_present = Vec::new();

    let hooks_obj = settings
        .as_object_mut()
        .expect("checked is_object above")
        .entry("hooks")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    if !hooks_obj.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(hooks_obj),
        });
    }

    for (claude_event, soth_hook_type) in HOOK_TYPES {
        let entry_added = ensure_hook_entry(hooks_obj, claude_event, soth_hook_type, &binary_path);
        if entry_added {
            hooks_added.push((*claude_event).to_string());
        } else {
            hooks_already_present.push((*claude_event).to_string());
        }
    }

    let updated = serde_json::to_string_pretty(&settings)?;
    write_atomic(settings_path, updated.as_bytes())?;

    // Cheap sanity check: re-read what we wrote and re-parse. Any
    // serializer round-trip surprise would surface here before the
    // operator's next agent invocation.
    let written = fs::read_to_string(settings_path).map_err(|e| InstallError::Read {
        path: settings_path.to_path_buf(),
        source: e,
    })?;
    serde_json::from_str::<Value>(&written).map_err(|e| InstallError::Malformed {
        path: settings_path.to_path_buf(),
        source: e,
    })?;

    Ok(InstallReport {
        settings_path: settings_path.to_path_buf(),
        backup_path,
        hooks_added,
        hooks_already_present,
        binary_path,
    })
}

/// Remove every soth-managed hook entry from Claude Code's
/// `settings.json`. Hooks the user added by hand are preserved; only
/// entries carrying [`SOTH_MARKER_KEY`] are dropped.
pub fn uninstall_claude_code(settings_path: &Path) -> Result<(), InstallError> {
    let content = read_settings_or_empty(settings_path)?;
    if content.trim().is_empty() {
        return Ok(());
    }
    let mut settings: Value = serde_json::from_str(&content).map_err(|e| InstallError::Malformed {
        path: settings_path.to_path_buf(),
        source: e,
    })?;
    if !settings.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(&settings),
        });
    }

    if let Some(hooks) = settings
        .as_object_mut()
        .and_then(|root| root.get_mut("hooks"))
        .and_then(Value::as_object_mut)
    {
        for (_, group) in hooks.iter_mut() {
            if let Some(arr) = group.as_array_mut() {
                arr.retain(|entry| !is_soth_managed(entry));
            }
        }
        // Drop the hooks key entirely if every per-event group is now
        // empty — leaves the user's settings.json clean.
        let all_empty = hooks
            .iter()
            .all(|(_, v)| v.as_array().map(|a| a.is_empty()).unwrap_or(false));
        if all_empty {
            settings.as_object_mut().unwrap().remove("hooks");
        }
    }

    let updated = serde_json::to_string_pretty(&settings)?;
    write_atomic(settings_path, updated.as_bytes())?;
    Ok(())
}

/// Idempotent insertion. Returns `true` when the hook was added,
/// `false` when an existing soth-managed entry was already present
/// (idempotent re-install).
fn ensure_hook_entry(
    hooks: &mut Value,
    claude_event: &str,
    soth_hook_type: &str,
    binary_path: &Path,
) -> bool {
    let hooks_map = hooks.as_object_mut().unwrap();
    let entries = hooks_map
        .entry(claude_event)
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = match entries.as_array_mut() {
        Some(a) => a,
        None => {
            // Existing value isn't an array (user had a single object?
            // unlikely shape). Replace conservatively with an array
            // containing the prior value as a single entry.
            *entries = Value::Array(vec![entries.clone()]);
            entries.as_array_mut().unwrap()
        }
    };

    if arr.iter().any(is_soth_managed) {
        return false;
    }

    arr.push(json!({
        SOTH_MARKER_KEY: true,
        "matcher": ".*",
        "hooks": [
            {
                "type": "command",
                "command": format!(
                    "{} code hook --agent claude_code --type {}",
                    binary_path.display(),
                    soth_hook_type
                )
            }
        ]
    }));
    true
}

fn is_soth_managed(entry: &Value) -> bool {
    entry
        .get(SOTH_MARKER_KEY)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn read_settings_or_empty(path: &Path) -> Result<String, InstallError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(InstallError::Read {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

/// Write `bytes` to `path` atomically: write to a sibling temp file
/// first, fsync, then rename over the target. Either the new content
/// lands fully or the old content is preserved.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), InstallError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| InstallError::Mkdir {
        path: dir.to_path_buf(),
        source: e,
    })?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| InstallError::Write {
        path: path.to_path_buf(),
        source: e,
    })?;
    tmp.as_file_mut()
        .write_all(bytes)
        .map_err(|e| InstallError::Write {
            path: path.to_path_buf(),
            source: e,
        })?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| InstallError::Write {
            path: path.to_path_buf(),
            source: e,
        })?;
    tmp.persist(path).map_err(|e| InstallError::Write {
        path: path.to_path_buf(),
        source: e.error,
    })?;
    Ok(())
}

fn kind_label(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_settings(content: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        if !content.is_empty() {
            fs::write(&path, content).unwrap();
        }
        (tmp, path)
    }

    fn binary_path() -> PathBuf {
        PathBuf::from("/usr/local/bin/soth")
    }

    #[test]
    fn install_into_missing_settings_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested").join("settings.json");
        let report = install_claude_code(&path, Some(binary_path())).unwrap();
        assert!(path.exists());
        assert!(report.backup_path.is_none(), "no backup needed when nothing existed");
        assert_eq!(report.hooks_added.len(), HOOK_TYPES.len());
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(body["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn install_preserves_existing_unrelated_keys() {
        let (_tmp, path) = fixture_settings(r#"{ "model": "claude-3-5-sonnet", "theme": "dark" }"#);
        install_claude_code(&path, Some(binary_path())).unwrap();
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(body["model"], "claude-3-5-sonnet");
        assert_eq!(body["theme"], "dark");
        assert!(body["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn install_preserves_user_authored_hook_entries() {
        let (_tmp, path) = fixture_settings(
            r#"{
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                { "type": "command", "command": "/usr/local/bin/my-other-hook" }
                            ]
                        }
                    ]
                }
            }"#,
        );
        install_claude_code(&path, Some(binary_path())).unwrap();
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let entries = body["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "user's existing entry preserved alongside soth's");
        assert!(entries
            .iter()
            .any(|e| e[SOTH_MARKER_KEY] == true && e["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .contains("soth code hook")));
        assert!(entries
            .iter()
            .any(|e| e["hooks"][0]["command"] == "/usr/local/bin/my-other-hook"));
    }

    #[test]
    fn install_is_idempotent() {
        let (_tmp, path) = fixture_settings("");
        let r1 = install_claude_code(&path, Some(binary_path())).unwrap();
        assert_eq!(r1.hooks_added.len(), HOOK_TYPES.len());
        let r2 = install_claude_code(&path, Some(binary_path())).unwrap();
        assert!(r2.hooks_added.is_empty(), "second install adds nothing");
        assert_eq!(r2.hooks_already_present.len(), HOOK_TYPES.len());
        // Verify exactly one soth entry per hook type — not duplicates.
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        for (claude_event, _) in HOOK_TYPES {
            let entries = body["hooks"][claude_event].as_array().unwrap();
            let soth_count = entries.iter().filter(|e| is_soth_managed(e)).count();
            assert_eq!(
                soth_count, 1,
                "expected exactly one soth-managed entry under {claude_event}, got {soth_count}"
            );
        }
    }

    #[test]
    fn install_writes_bak_when_settings_file_existed() {
        let (_tmp, path) = fixture_settings(r#"{ "theme": "dark" }"#);
        let report = install_claude_code(&path, Some(binary_path())).unwrap();
        let bak = report.backup_path.expect(".bak written");
        assert!(bak.exists());
        let bak_body = fs::read_to_string(&bak).unwrap();
        assert!(bak_body.contains("\"theme\""), "backup is the ORIGINAL content");
        assert!(
            !bak_body.contains("PreToolUse"),
            "backup must not contain new install — it's the snapshot before"
        );
    }

    #[test]
    fn install_refuses_malformed_settings() {
        let (_tmp, path) = fixture_settings(r#"{ this isn't json }"#);
        let r = install_claude_code(&path, Some(binary_path()));
        assert!(matches!(r, Err(InstallError::Malformed { .. })));
        // Critical contract: the malformed file must be left intact.
        // We never overwrite a config the operator may be in the
        // middle of editing.
        let after = fs::read_to_string(&path).unwrap();
        assert!(after.contains("this isn't json"));
    }

    #[test]
    fn install_refuses_non_object_root() {
        let (_tmp, path) = fixture_settings("[1, 2, 3]");
        let r = install_claude_code(&path, Some(binary_path()));
        assert!(matches!(r, Err(InstallError::NotAnObject { .. })));
    }

    #[test]
    fn uninstall_removes_only_soth_entries() {
        let (_tmp, path) = fixture_settings("");
        install_claude_code(&path, Some(binary_path())).unwrap();
        // Add a user-authored hook alongside the soth-managed ones.
        let mut body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        body["hooks"]["PreToolUse"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "matcher": "Read",
                "hooks": [{ "type": "command", "command": "/usr/local/bin/my-other-hook" }]
            }));
        fs::write(&path, serde_json::to_string_pretty(&body).unwrap()).unwrap();

        uninstall_claude_code(&path).unwrap();

        let after: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let pre_tool_use = after["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool_use.len(), 1, "user hook preserved");
        assert!(!is_soth_managed(&pre_tool_use[0]));
        assert_eq!(pre_tool_use[0]["hooks"][0]["command"], "/usr/local/bin/my-other-hook");
    }

    #[test]
    fn uninstall_removes_hooks_block_when_empty() {
        let (_tmp, path) = fixture_settings(r#"{ "theme": "dark" }"#);
        install_claude_code(&path, Some(binary_path())).unwrap();
        uninstall_claude_code(&path).unwrap();
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(body.get("hooks").is_none(), "empty hooks block dropped");
        assert_eq!(body["theme"], "dark", "user content preserved");
    }

    #[test]
    fn uninstall_idempotent_on_already_clean_file() {
        let (_tmp, path) = fixture_settings(r#"{ "theme": "dark" }"#);
        uninstall_claude_code(&path).unwrap();
        uninstall_claude_code(&path).unwrap();
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(body["theme"], "dark");
    }

    #[test]
    fn uninstall_refuses_malformed_settings() {
        let (_tmp, path) = fixture_settings(r#"{ broken }"#);
        let r = uninstall_claude_code(&path);
        assert!(matches!(r, Err(InstallError::Malformed { .. })));
    }

    #[test]
    fn fuzz_atomic_write_against_invalid_json_inputs() {
        // Hammer the atomic-write path with synthetic bad inputs.
        // We're not fuzzing the parser here (serde_json handles that
        // upstream); we're verifying that a malformed input never
        // overwrites a good settings.json. PRECONDITION: a valid
        // settings file with a known marker. POSTCONDITION: marker
        // still present after every malformed-input attempt.
        let (_tmp, path) = fixture_settings(r#"{ "marker": "INTACT", "theme": "dark" }"#);
        // Empty content is intentionally NOT in this list — it's
        // treated as "fresh install" by `read_settings_or_empty` and
        // is a valid initial state, not a malformed file.
        let bad_inputs = [
            "{ broken",
            "[ not an object ]",
            "null",
            "\"a string\"",
            "12345",
            "{ \"theme\": ",
        ];
        for input in bad_inputs {
            // Replace settings with the malformed content, then try to
            // install — must fail, must not corrupt the file further.
            fs::write(&path, input).unwrap();
            let r = install_claude_code(&path, Some(binary_path()));
            assert!(
                r.is_err(),
                "install must fail on input {input:?}, got: {r:?}"
            );
            let after = fs::read_to_string(&path).unwrap();
            assert_eq!(
                after, input,
                "install must NOT overwrite a malformed settings file (input was: {input:?})"
            );
        }
    }
}

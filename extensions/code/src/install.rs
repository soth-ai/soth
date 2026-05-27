//! `soth code install` / `uninstall` — wire the hook handler into an
//! agent's native config so each tool action triggers
//! `soth code hook --agent <name> --type <hook>`.
//!
//! Discipline (`settings.json` corruption class):
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
    #[error(
        "plugin file at {path} exists but lacks the soth-managed marker — refusing to overwrite \
         a hand-authored plugin. Rename it or pass --settings-path to a different location."
    )]
    NotSothManaged { path: PathBuf },
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
/// Quote a binary path so the agent's hook runner can invoke it
/// even when the path contains spaces (Windows: `C:\Users\Prabhat
/// ACER\.local\bin\soth.exe`; macOS / Linux: any user with a
/// space in their home dir name).  Without quoting, the shell
/// splits on the space, treats the first chunk as the binary and
/// the rest as args, the binary fails to launch, the hook never
/// runs, and the policy gate silently fails open — letting
/// dangerous commands like recursive force-deletes through.
///
/// Implementation note: hand-rolled wrapping (`format!("\"{}\"",
/// …)`) covered the common case but missed paths containing `"`,
/// `$`, backticks, or shell metachars.  Switched to `shlex::try_quote`
/// — battle-tested escape rules.  shlex emits POSIX
/// shell-safe single-quoted form when needed; for plain paths
/// without metachars it returns the path as-is.
///
/// On Windows we still need explicit double-quote wrapping because
/// shlex emits POSIX-style and cmd.exe / PowerShell honor double
/// quotes natively.  Forward-slash-normalize first so the resulting
/// command works whether the agent's shell is bash, cmd, or
/// PowerShell.
pub(crate) fn quote_binary_path(path: &Path) -> String {
    // Backslash → forward-slash normalization.  Looked at the
    // `path-slash` and `dunce` crates to "offload" this; they
    // both branch on the host OS's path separator at runtime,
    // which is correct file-system semantics but wrong for our
    // case where we're producing a string that always targets
    // a Windows-or-POSIX shell regardless of the host that
    // wrote it.  A 1-line `replace` is the right tool here:
    // forward slashes are accepted by cmd.exe, PowerShell, Git
    // Bash (default Windows shell for Claude Code + Cursor
    // 2.x hooks), bash, zsh, and Node — and they serialize as
    // themselves in JSON, eliminating the `\\`-escape footgun
    // engineers hit when reading a hand-edited settings.json.
    // (Anthropic Claude Code issue #16451 — `C:\Users\Burak
    // Demir` — shows backslash + space is the root failure
    // pattern; this plus the double-quote wrapping below
    // covers both axes.)
    let normalized = path.display().to_string().replace('\\', "/");

    // Defense in depth: a path containing a literal `"` would
    // corrupt the JSON string.  Drop into shlex's POSIX-quote
    // form (`'…'` wrapping) for that case.  Vanishingly rare
    // on real installed binaries.
    if normalized.contains('"') {
        return shlex::try_quote(&normalized)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| format!("\"{normalized}\""));
    }

    // Standard double-quote wrapping.  Works on bash/zsh,
    // cmd.exe (cmd `/C` preserves the leading `"` when the
    // command shape is `"executable" args` and the executable
    // is the first quoted token; cf. ss64.com/nt/cmd.html),
    // PowerShell, and Git Bash.
    format!("\"{normalized}\"")
}

pub fn default_claude_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

/// Default Cursor hooks file location. Cursor uses a separate
/// `hooks.json` file (not the larger `settings.json`) for hook
/// configuration.
pub fn default_cursor_hooks_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".cursor").join("hooks.json"))
}

/// Default Gemini CLI settings file location. Gemini embeds hooks
/// inside `~/.gemini/settings.json` (mirroring Claude Code's pattern).
pub fn default_gemini_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".gemini").join("settings.json"))
}

/// Default Codex hooks file location. Codex uses a dedicated
/// `~/.codex/hooks.json` file separate from any larger settings doc.
pub fn default_codex_hooks_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".codex").join("hooks.json"))
}

/// Default Windsurf hooks file location.
///
/// Per-OS resolution:
/// - macOS / Linux: `~/.codeium/windsurf/hooks.json`
/// - Windows: `%APPDATA%\Codeium\Windsurf\hooks.json`
///
/// Windsurf on Windows uses Codeium's `%APPDATA%`-rooted layout
/// (verified live at `C:\Users\<user>\AppData\Roaming\Codeium\
/// Windsurf\`), which differs from the macOS / Linux dotfile
/// convention.  Without the cfg(windows) branch the install
/// command would write the hook config to a path the editor
/// never reads from.  Upstream Windsurf detect paths have the same
/// bug — falls back to the dotfile path on every OS — and our fix
/// is the upstream fix.
pub fn default_windsurf_hooks_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        // %APPDATA% — config_dir() returns this on Windows
        // (Roaming AppData per Microsoft KNOWNFOLDERID spec).
        dirs::config_dir().map(|c| c.join("Codeium").join("Windsurf").join("hooks.json"))
    }
    #[cfg(not(windows))]
    {
        dirs::home_dir().map(|h| h.join(".codeium").join("windsurf").join("hooks.json"))
    }
}

/// Default Pi Agent plugin location. Pi Agent loads extensions from
/// `~/.pi/agent/extensions/`; the soth-code plugin file lands as
/// `soth-code.ts` in that directory.  Pi Agent uses the dotfile
/// convention consistently across macOS / Linux / Windows
/// (resolves to `%USERPROFILE%\.pi\agent\extensions\` on Windows
/// via `dirs::home_dir()`), so no per-OS branch needed.
pub fn default_pi_agent_plugin_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| {
        h.join(".pi")
            .join("agent")
            .join("extensions")
            .join("soth-code.ts")
    })
}

/// Default OpenCode plugin location.
///
/// Per-OS resolution:
/// - macOS / Linux: `~/.config/opencode/plugins/soth-code.mjs`
/// - Windows: `%APPDATA%\opencode\plugins\soth-code.mjs`
///
/// OpenCode on Windows explicitly bypasses the XDG /
/// `~/.config/` convention and forces `%APPDATA%\opencode\`
/// (verified upstream — see opencode-antigravity-auth issue
/// #251 / #265 / #295 acknowledging the platform-specific
/// override).  Without the cfg(windows) branch the install
/// command would write to `%USERPROFILE%\.config\opencode\
/// plugins\` which OpenCode does not read on Windows.  Upstream
/// OpenCode also misses this (single platform-agnostic
/// `~/.config/opencode` constant);
/// our fix is the upstream fix.
pub fn default_opencode_plugin_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        dirs::config_dir().map(|c| c.join("opencode").join("plugins").join("soth-code.mjs"))
    }
    #[cfg(not(windows))]
    {
        dirs::home_dir().map(|h| {
            h.join(".config")
                .join("opencode")
                .join("plugins")
                .join("soth-code.mjs")
        })
    }
}

/// One row in the auto-detection result — the agent the
/// detector recognized as "present on this host" plus the
/// canonical settings path the install would write to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedAgent {
    /// Canonical agent name (`claude_code`, `cursor`,
    /// `openai_codex`, …) — the same form historian's audit
    /// table keys on, so cross-table joins
    /// (`installed.json` ↔ `historian.adapters` ↔ doctor)
    /// don't silently miss because of name drift.  Operator-
    /// facing CLI flags accept `codex` and other friendly
    /// aliases; those collapse to canonical here.
    pub agent: &'static str,
    /// The settings / plugin file the install command would
    /// touch for this agent.
    pub settings_path: PathBuf,
    /// True when the agent's settings file already contains
    /// the soth-managed marker — i.e. hooks are already wired
    /// (possibly by a prior `soth up`).  The auto-installer
    /// uses this to skip already-configured agents and just
    /// refresh state.
    pub already_installed: bool,
}

/// Canonical agent name — one source of truth.  Operator-
/// facing CLI flags accept friendly aliases (`codex`,
/// `gemini`, `piagent`, `open-claw`); state files, audit
/// lookups, and doctor output use the canonical form so
/// cross-surface joins work without silent drift.  Pre-push
/// review surfaced that historian audit keyed on
/// `openai_codex` while soth-code state keyed on `codex` —
/// any future code that joined them would have silently
/// missed.  This helper closes that gap.
///
/// Returns `None` for genuinely unknown names so callers
/// fail loud instead of writing state under bogus keys.
pub fn canonical_agent_name(agent: &str) -> Option<&'static str> {
    match agent {
        "claude_code" => Some("claude_code"),
        "cursor" => Some("cursor"),
        // Match historian's playbook key — was the
        // longest-standing source of name drift.
        "codex" | "openai_codex" | "openai-codex" => Some("openai_codex"),
        "gemini_cli" | "gemini" => Some("gemini_cli"),
        "windsurf" => Some("windsurf"),
        "pi_agent" | "piagent" => Some("pi_agent"),
        "opencode" => Some("opencode"),
        "openclaw" | "open_claw" | "open-claw" => Some("openclaw"),
        _ => None,
    }
}

/// Detect AI coding agents on this host — defined as "the
/// canonical home directory for the agent exists or the
/// agent's settings file is already present."  Cheaper than
/// shelling out to `which`; doesn't require the agent's
/// binary to be on PATH.  Used by `soth up` to decide which
/// per-agent installers to run.
///
/// Returns one entry per supported agent that's detected.
/// Agents not on the box are simply omitted (no entry, not a
/// "missing" record).  When the agent is here AND already
/// has the soth-managed marker, the entry's
/// `already_installed = true` so the caller can skip
/// re-running the install but still update state for audit
/// trail.
///
/// OpenClaw is intentionally excluded — its install path is
/// pending upstream config-format stabilization.
pub fn detect_installable_agents() -> Vec<DetectedAgent> {
    // Each entry: (agent_name, default-path-fn, soth-managed-marker
    // string).  The marker matches what each installer writes;
    // grep-checking for it tells us if hooks are already wired.
    // Agents listed under their canonical names — same keys
    // historian audit, doctor, and state file all use.
    type AgentEntry = (&'static str, fn() -> Option<PathBuf>, &'static str);
    let candidates: &[AgentEntry] = &[
        ("claude_code", default_claude_settings_path, "_soth_managed"),
        ("cursor", default_cursor_hooks_path, "_soth_managed"),
        ("openai_codex", default_codex_hooks_path, "_soth_managed"),
        ("gemini_cli", default_gemini_settings_path, "_soth_managed"),
        ("windsurf", default_windsurf_hooks_path, "_soth_managed"),
        // For plugin-style agents we detect on the parent
        // directory rather than the plugin file itself, since
        // the file only exists post-install.  An agent whose
        // home directory is missing isn't on this host.
        ("pi_agent", default_pi_agent_plugin_path, "soth-code"),
        ("opencode", default_opencode_plugin_path, "soth-code"),
    ];
    let mut detected = Vec::new();
    for (agent, path_fn, marker) in candidates {
        let Some(path) = path_fn() else {
            continue;
        };
        if !agent_present_on_host(agent, &path) {
            continue;
        }
        let already_installed = std::fs::read_to_string(&path)
            .map(|c| c.contains(marker))
            .unwrap_or(false);
        detected.push(DetectedAgent {
            agent,
            settings_path: path,
            already_installed,
        });
    }
    detected
}

/// "Is this agent on the host?"  Two signals:
/// - The settings/plugin file already exists (most reliable).
/// - The agent's home directory exists (cheap directory probe;
///   covers the case where the operator installed the agent
///   but never opened it, so no settings file yet).
fn agent_present_on_host(agent: &str, settings_path: &Path) -> bool {
    if settings_path.exists() {
        return true;
    }
    // Walk up to the agent's home directory and probe.  Each
    // agent has a stable parent prefix we can test; matching
    // this against the path's components avoids hardcoding a
    // duplicate "where does this agent live" table.
    //
    // Per-OS branches for windsurf and opencode mirror the
    // `default_*_path` functions — Windsurf and OpenCode
    // both use `%APPDATA%`-rooted layouts on Windows that
    // differ from the macOS / Linux dotfile / XDG locations.
    let home_dir = match agent {
        "claude_code" => dirs::home_dir().map(|h| h.join(".claude")),
        "cursor" => dirs::home_dir().map(|h| h.join(".cursor")),
        "openai_codex" => dirs::home_dir().map(|h| h.join(".codex")),
        "gemini_cli" => dirs::home_dir().map(|h| h.join(".gemini")),
        "windsurf" => {
            #[cfg(windows)]
            {
                dirs::config_dir().map(|c| c.join("Codeium").join("Windsurf"))
            }
            #[cfg(not(windows))]
            {
                dirs::home_dir().map(|h| h.join(".codeium").join("windsurf"))
            }
        }
        "pi_agent" => dirs::home_dir().map(|h| h.join(".pi")),
        "opencode" => {
            #[cfg(windows)]
            {
                dirs::config_dir().map(|c| c.join("opencode"))
            }
            #[cfg(not(windows))]
            {
                dirs::home_dir().map(|h| h.join(".config").join("opencode"))
            }
        }
        _ => None,
    };
    home_dir.map(|d| d.is_dir()).unwrap_or(false)
}

/// Pi Agent plugin source — TypeScript, ~100 LOC. Embedded via
/// `include_str!` so the soth binary is self-contained: install
/// writes this file to `~/.pi/agent/extensions/soth-code.ts` with
/// the `__SOTH_BIN__` placeholder substituted to the absolute soth
/// binary path. Pi Agent loads it on next session.
const PI_AGENT_PLUGIN_SOURCE: &str = include_str!("../plugins/piagent.ts");

/// OpenCode plugin source — JS ES module, ~70 LOC. Same shipping
/// model as Pi Agent's plugin: include_str! at compile, write at
/// install with `__SOTH_BIN__` substituted.
const OPENCODE_PLUGIN_SOURCE: &str = include_str!("../plugins/opencode.mjs");

/// Marker line written into the plugin file so install/uninstall can
/// confirm we're touching a soth-managed plugin, not a hand-authored
/// one with the same filename. Mirrors `SOTH_MARKER_KEY` for JSON
/// installers but in comment form (plugin files aren't JSON).
const PLUGIN_MARKER_LINE: &str = "// __SOTH_CODE_MANAGED__";

/// Install the soth-code Pi Agent plugin. Writes the embedded TS
/// source to `plugin_path` with `__SOTH_BIN__` replaced by the soth
/// binary's absolute path.
///
/// **Pi Agent must be restarted** for the new plugin to load.
pub fn install_pi_agent(
    plugin_path: &Path,
    binary_path_override: Option<PathBuf>,
) -> Result<InstallReport, InstallError> {
    install_plugin_file(
        plugin_path,
        binary_path_override,
        "pi_agent",
        PI_AGENT_PLUGIN_SOURCE,
    )
}

pub fn uninstall_pi_agent(plugin_path: &Path) -> Result<(), InstallError> {
    uninstall_plugin_file(plugin_path)
}

/// Install the soth-code OpenCode plugin.
pub fn install_opencode(
    plugin_path: &Path,
    binary_path_override: Option<PathBuf>,
) -> Result<InstallReport, InstallError> {
    install_plugin_file(
        plugin_path,
        binary_path_override,
        "opencode",
        OPENCODE_PLUGIN_SOURCE,
    )
}

pub fn uninstall_opencode(plugin_path: &Path) -> Result<(), InstallError> {
    uninstall_plugin_file(plugin_path)
}

/// Generic plugin-file installer. Different from JSON installers in
/// shape: there's no "merge with existing config" — the plugin file
/// is wholly owned by soth-code. If a file with the same name exists
/// AND lacks the soth marker line, refuse to overwrite (operator
/// presumably has a hand-authored plugin with the same name).
fn install_plugin_file(
    plugin_path: &Path,
    binary_path_override: Option<PathBuf>,
    agent: &str,
    source_template: &str,
) -> Result<InstallReport, InstallError> {
    let binary_path = match binary_path_override {
        Some(p) => p,
        None => std::env::current_exe().map_err(InstallError::NoBinary)?,
    };
    if let Some(parent) = plugin_path.parent() {
        fs::create_dir_all(parent).map_err(|e| InstallError::Mkdir {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let backup_path = if plugin_path.exists() {
        let existing = fs::read_to_string(plugin_path).map_err(|e| InstallError::Read {
            path: plugin_path.to_path_buf(),
            source: e,
        })?;
        if !existing.contains(PLUGIN_MARKER_LINE) {
            // Hand-authored plugin with the same filename. Refuse to
            // overwrite — operator must rename theirs first or pass
            // a different --settings-path.
            return Err(InstallError::NotSothManaged {
                path: plugin_path.to_path_buf(),
            });
        }
        let bak = plugin_path.with_extension(
            plugin_path
                .extension()
                .and_then(|s| s.to_str())
                .map(|e| format!("{e}.bak"))
                .unwrap_or_else(|| "bak".to_string()),
        );
        write_atomic(&bak, existing.as_bytes())?;
        Some(bak)
    } else {
        None
    };

    // JS / TS string-literal escaping for the path.  The plugin
    // templates embed `__SOTH_BIN__` inside a JS double-quoted
    // string: `const SOTH_BIN = "__SOTH_BIN__";`.  On Windows
    // the raw path `C:\Users\Prabhat ACER\.local\bin\soth.exe`
    // contains backslashes that JS treats as escape sequences
    // (`\U`, `\b`, `\.`) — would either break the plugin parse
    // or silently produce a wrong path.  Escape `\` → `\\` and
    // `"` → `\"` before substitution so the resulting JS source
    // is valid on every platform.
    let path_str = binary_path.display().to_string();
    let js_escaped = path_str.replace('\\', "\\\\").replace('"', "\\\"");
    let source = source_template.replace("__SOTH_BIN__", &js_escaped);
    write_atomic(plugin_path, source.as_bytes())?;

    Ok(InstallReport {
        settings_path: plugin_path.to_path_buf(),
        backup_path,
        hooks_added: vec![format!("{agent} plugin")],
        hooks_already_present: Vec::new(),
        binary_path,
    })
}

fn uninstall_plugin_file(plugin_path: &Path) -> Result<(), InstallError> {
    if !plugin_path.exists() {
        return Ok(());
    }
    let existing = fs::read_to_string(plugin_path).map_err(|e| InstallError::Read {
        path: plugin_path.to_path_buf(),
        source: e,
    })?;
    if !existing.contains(PLUGIN_MARKER_LINE) {
        // Not soth-managed; don't touch it. Same defense in depth as
        // install — a user-authored plugin with the same filename
        // shouldn't be deleted by a careless uninstall.
        return Ok(());
    }
    fs::remove_file(plugin_path).map_err(|e| InstallError::Write {
        path: plugin_path.to_path_buf(),
        source: e,
    })?;
    Ok(())
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
        // haven't finished; clobbering it would be a destructive
        // overwrite of work-in-progress config.
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

/// Gemini CLI's hook events. Upstream uses PascalCase (`BeforeTool`,
/// `AfterTool`, `SessionStart`); we normalize to snake_case for the
/// soth-code CLI surface uniform across agents. Slim 5-hook set —
/// Gemini's hook protocol is younger than Claude Code's.
const GEMINI_HOOK_TYPES: &[(&str, &str)] = &[
    ("BeforeTool", "before_tool_call"),
    ("AfterTool", "after_tool_call"),
    ("SessionStart", "session_start"),
    ("SessionEnd", "session_end"),
    ("Notification", "notification"),
];

/// Codex's 5 canonical hook events (rust-codex 0.114.0). Upstream
/// PascalCase, normalized to snake_case at install. Alpha-gated —
/// Codex's protocol is the youngest of all agents we support.
const CODEX_HOOK_TYPES: &[(&str, &str)] = &[
    ("SessionStart", "session_start"),
    ("PreToolUse", "pre_tool_use"),
    ("PostToolUse", "post_tool_use"),
    ("UserPromptSubmit", "user_prompt_submit"),
    ("Stop", "stop"),
];

/// Windsurf's hook events. Already snake_case upstream — install
/// passes through identically. 11 hook types covering pre/post for
/// each tool surface (read_code, write_code, run_command, mcp,
/// user_prompt) plus `post_cascade_response` and `post_setup_worktree`
/// lifecycle hooks.
const WINDSURF_HOOK_TYPES: &[(&str, &str)] = &[
    ("pre_read_code", "pre_read_code"),
    ("post_read_code", "post_read_code"),
    ("pre_write_code", "pre_write_code"),
    ("post_write_code", "post_write_code"),
    ("pre_run_command", "pre_run_command"),
    ("post_run_command", "post_run_command"),
    ("pre_mcp_tool_use", "pre_mcp_tool_use"),
    ("post_mcp_tool_use", "post_mcp_tool_use"),
    ("pre_user_prompt", "pre_user_prompt"),
    ("post_cascade_response", "post_cascade_response"),
    ("post_setup_worktree", "post_setup_worktree"),
];

/// Cursor's hook event names paired with the snake_case form passed
/// to the soth-code subprocess via `--type`. Cursor uses camelCase
/// natively; we normalize at install time so the hook subprocess
/// accepts a uniform CLI shape across all agents.
const CURSOR_HOOK_TYPES: &[(&str, &str)] = &[
    // Pre-action (can block) — every entry here mirrors a hook the
    // adapter knows how to parse + `is_pre_action_hook()` allows.
    // Coverage gap closed: `beforeMCPExecution` (credential leak
    // surface), `beforeTabFileRead` (Cursor Tab file-read gate),
    // and `subagentStart` (subagent fan-out) were previously only
    // adapter-parseable — not installed, so they never fired.
    ("preToolUse", "pre_tool_use"),
    ("beforeShellExecution", "before_shell_execution"),
    ("beforeReadFile", "before_read_file"),
    ("beforeTabFileRead", "before_tab_file_read"),
    ("beforeMCPExecution", "before_mcp_execution"),
    ("beforeSubmitPrompt", "before_submit_prompt"),
    ("subagentStart", "subagent_start"),
    // Post-action (audit)
    ("postToolUse", "post_tool_use"),
    // `postToolUseFailure` fires when Cursor's tool call returned an
    // error — high-signal for audit (failed file writes, blocked
    // shells, denied API calls). Parser already handles it
    // (`adapter/cursor.rs:231` collapses with `post_tool_use` for
    // ActionType), so installing it just turns on the visibility.
    ("postToolUseFailure", "post_tool_use_failure"),
    ("afterFileEdit", "after_file_edit"),
    ("afterTabFileEdit", "after_tab_file_edit"),
    ("afterShellExecution", "after_shell_execution"),
    ("afterMCPExecution", "after_mcp_execution"),
    ("afterAgentResponse", "after_agent_response"),
    ("afterAgentThought", "after_agent_thought"),
    ("subagentStop", "subagent_stop"),
    // Lifecycle
    ("sessionStart", "session_start"),
    ("sessionEnd", "session_end"),
    ("stop", "stop"),
];

/// Install soth-code hooks into Cursor's `~/.cursor/hooks.json`.
///
/// Cursor's hooks.json shape:
///
/// ```json
/// {
///   "version": 1,
///   "hooks": {
///     "preToolUse": [{"command": "/path/to/binary ..."}],
///     "beforeShellExecution": [{"command": "..."}],
///     ...
///   }
/// }
/// ```
///
/// Simpler than Claude Code's nested `matcher`/`hooks` shape. We add
/// a `_soth_managed: true` marker field to each entry so future
/// install/uninstall runs can find their own work without touching
/// user-authored hook entries.
///
/// Same atomic-write + `.bak` + pre-flight-parse discipline as
/// `install_claude_code`.
pub fn install_cursor(
    hooks_path: &Path,
    binary_path_override: Option<PathBuf>,
) -> Result<InstallReport, InstallError> {
    let binary_path = match binary_path_override {
        Some(p) => p,
        None => std::env::current_exe().map_err(InstallError::NoBinary)?,
    };

    if let Some(parent) = hooks_path.parent() {
        fs::create_dir_all(parent).map_err(|e| InstallError::Mkdir {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let original_content = read_settings_or_empty(hooks_path)?;
    let mut hooks_doc: Value = if original_content.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str(&original_content).map_err(|e| InstallError::Malformed {
            path: hooks_path.to_path_buf(),
            source: e,
        })?
    };

    if !hooks_doc.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(&hooks_doc),
        });
    }

    let backup_path = if hooks_path.exists() && !original_content.is_empty() {
        let bak = hooks_path.with_extension("json.bak");
        write_atomic(&bak, original_content.as_bytes())?;
        Some(bak)
    } else {
        None
    };

    // Cursor's top-level `version` field — populate if absent.
    {
        let map = hooks_doc.as_object_mut().expect("checked");
        map.entry("version")
            .or_insert_with(|| Value::Number(1.into()));
    }

    let hooks_obj = hooks_doc
        .as_object_mut()
        .expect("checked")
        .entry("hooks")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    if !hooks_obj.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(hooks_obj),
        });
    }

    let mut hooks_added = Vec::new();
    let mut hooks_already_present = Vec::new();

    for (cursor_event, soth_hook_type) in CURSOR_HOOK_TYPES {
        let entry_added = ensure_cursor_hook_entry(
            hooks_obj,
            cursor_event,
            soth_hook_type,
            "cursor",
            &binary_path,
        );
        if entry_added {
            hooks_added.push((*cursor_event).to_string());
        } else {
            hooks_already_present.push((*cursor_event).to_string());
        }
    }

    let updated = serde_json::to_string_pretty(&hooks_doc)?;
    write_atomic(hooks_path, updated.as_bytes())?;

    // Sanity re-parse.
    let written = fs::read_to_string(hooks_path).map_err(|e| InstallError::Read {
        path: hooks_path.to_path_buf(),
        source: e,
    })?;
    serde_json::from_str::<Value>(&written).map_err(|e| InstallError::Malformed {
        path: hooks_path.to_path_buf(),
        source: e,
    })?;

    Ok(InstallReport {
        settings_path: hooks_path.to_path_buf(),
        backup_path,
        hooks_added,
        hooks_already_present,
        binary_path,
    })
}

/// Remove soth-managed hook entries from Cursor's `~/.cursor/hooks.json`.
/// User-authored entries are preserved.
pub fn uninstall_cursor(hooks_path: &Path) -> Result<(), InstallError> {
    let content = read_settings_or_empty(hooks_path)?;
    if content.trim().is_empty() {
        return Ok(());
    }
    let mut doc: Value = serde_json::from_str(&content).map_err(|e| InstallError::Malformed {
        path: hooks_path.to_path_buf(),
        source: e,
    })?;
    if !doc.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(&doc),
        });
    }

    if let Some(hooks) = doc
        .as_object_mut()
        .and_then(|root| root.get_mut("hooks"))
        .and_then(Value::as_object_mut)
    {
        for (_, group) in hooks.iter_mut() {
            if let Some(arr) = group.as_array_mut() {
                arr.retain(|entry| !is_soth_managed(entry));
            }
        }
        let all_empty = hooks
            .iter()
            .all(|(_, v)| v.as_array().map(|a| a.is_empty()).unwrap_or(false));
        if all_empty {
            doc.as_object_mut().unwrap().remove("hooks");
            // Also drop the `version` key when we're the only writer
            // (no other hook entries left), so an uninstall on a
            // soth-only file leaves an empty `{}`.
            doc.as_object_mut().unwrap().remove("version");
        }
    }

    let updated = serde_json::to_string_pretty(&doc)?;
    write_atomic(hooks_path, updated.as_bytes())?;
    Ok(())
}

/// Install soth-code hooks into Gemini CLI's `~/.gemini/settings.json`.
/// Same nested-matcher shape Claude Code uses —
/// `HookMatcher{matcher, hooks:[{type,command}]}`
/// is the wire form Gemini accepts. Reuses the Claude Code helper to
/// minimize divergent install paths.
pub fn install_gemini_cli(
    settings_path: &Path,
    binary_path_override: Option<PathBuf>,
) -> Result<InstallReport, InstallError> {
    install_matcher_style(
        settings_path,
        binary_path_override,
        "gemini_cli",
        GEMINI_HOOK_TYPES,
    )
}

/// Uninstall soth-code's gemini_cli hook entries. Drops only entries
/// carrying `_soth_managed`; user-authored hooks preserved.
pub fn uninstall_gemini_cli(settings_path: &Path) -> Result<(), InstallError> {
    uninstall_matcher_style(settings_path)
}

/// Install soth-code hooks into Codex's `~/.codex/hooks.json`.
/// Alpha-gated — Codex's hook protocol is the youngest of all
/// supported agents.
pub fn install_codex(
    hooks_path: &Path,
    binary_path_override: Option<PathBuf>,
) -> Result<InstallReport, InstallError> {
    install_matcher_style(hooks_path, binary_path_override, "codex", CODEX_HOOK_TYPES)
}

pub fn uninstall_codex(hooks_path: &Path) -> Result<(), InstallError> {
    uninstall_matcher_style(hooks_path)
}

/// Install soth-code hooks into Windsurf's
/// `~/.codeium/windsurf/hooks.json`. Cursor-style flat shape.
pub fn install_windsurf(
    hooks_path: &Path,
    binary_path_override: Option<PathBuf>,
) -> Result<InstallReport, InstallError> {
    install_flat_style(
        hooks_path,
        binary_path_override,
        "windsurf",
        WINDSURF_HOOK_TYPES,
    )
}

pub fn uninstall_windsurf(hooks_path: &Path) -> Result<(), InstallError> {
    uninstall_flat_style(hooks_path)
}

/// Generic install for matcher-style hook configs (Claude Code, Gemini,
/// Codex). The settings doc has a top-level `hooks` map of
/// `<event_name> → [{matcher, hooks: [{type, command}]}]`. Each
/// per-agent install function delegates here with its hook-type table
/// and agent name.
fn install_matcher_style(
    settings_path: &Path,
    binary_path_override: Option<PathBuf>,
    agent: &str,
    hook_types: &[(&str, &str)],
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
    let backup_path = if settings_path.exists() && !original_content.is_empty() {
        let bak = settings_path.with_extension("json.bak");
        write_atomic(&bak, original_content.as_bytes())?;
        Some(bak)
    } else {
        None
    };

    let mut hooks_added = Vec::new();
    let mut hooks_already_present = Vec::new();
    let hooks_obj = settings
        .as_object_mut()
        .expect("checked")
        .entry("hooks")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !hooks_obj.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(hooks_obj),
        });
    }

    for (upstream_event, soth_hook_type) in hook_types {
        let added = ensure_matcher_entry(
            hooks_obj,
            upstream_event,
            agent,
            soth_hook_type,
            &binary_path,
        );
        if added {
            hooks_added.push((*upstream_event).to_string());
        } else {
            hooks_already_present.push((*upstream_event).to_string());
        }
    }

    let updated = serde_json::to_string_pretty(&settings)?;
    write_atomic(settings_path, updated.as_bytes())?;
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

fn ensure_matcher_entry(
    hooks: &mut Value,
    upstream_event: &str,
    agent: &str,
    soth_hook_type: &str,
    binary_path: &Path,
) -> bool {
    let hooks_map = hooks.as_object_mut().unwrap();
    let entries = hooks_map
        .entry(upstream_event)
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = match entries.as_array_mut() {
        Some(a) => a,
        None => {
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
                    "{} code hook --agent {} --type {}",
                    quote_binary_path(binary_path),
                    agent,
                    soth_hook_type
                )
            }
        ]
    }));
    true
}

fn uninstall_matcher_style(settings_path: &Path) -> Result<(), InstallError> {
    // Same shape as uninstall_claude_code's hook removal — extracted
    // here so the matcher-style installs (Claude Code, Gemini, Codex)
    // share the cleanup path.
    let content = read_settings_or_empty(settings_path)?;
    if content.trim().is_empty() {
        return Ok(());
    }
    let mut settings: Value =
        serde_json::from_str(&content).map_err(|e| InstallError::Malformed {
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
        let all_empty = hooks
            .iter()
            .all(|(_, v)| v.as_array().map(|a| a.is_empty()).unwrap_or(false));
        if all_empty {
            settings.as_object_mut().unwrap().remove("hooks");
        }
    }
    write_atomic(
        settings_path,
        serde_json::to_string_pretty(&settings)?.as_bytes(),
    )?;
    Ok(())
}

/// Generic install for flat-style hook configs (Cursor, Windsurf).
/// The settings doc has a top-level `hooks` map of
/// `<event_name> → [{command}]` with no inner matcher level.
fn install_flat_style(
    hooks_path: &Path,
    binary_path_override: Option<PathBuf>,
    agent: &str,
    hook_types: &[(&str, &str)],
) -> Result<InstallReport, InstallError> {
    let binary_path = match binary_path_override {
        Some(p) => p,
        None => std::env::current_exe().map_err(InstallError::NoBinary)?,
    };
    if let Some(parent) = hooks_path.parent() {
        fs::create_dir_all(parent).map_err(|e| InstallError::Mkdir {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let original_content = read_settings_or_empty(hooks_path)?;
    let mut doc: Value = if original_content.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str(&original_content).map_err(|e| InstallError::Malformed {
            path: hooks_path.to_path_buf(),
            source: e,
        })?
    };
    if !doc.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(&doc),
        });
    }
    let backup_path = if hooks_path.exists() && !original_content.is_empty() {
        let bak = hooks_path.with_extension("json.bak");
        write_atomic(&bak, original_content.as_bytes())?;
        Some(bak)
    } else {
        None
    };

    // Cursor uses a top-level `version` field; Windsurf does not.
    // Add it for Cursor-shape parity when the agent is "cursor"; skip
    // for Windsurf since the upstream doesn't write it.
    if agent == "cursor" {
        doc.as_object_mut()
            .expect("checked")
            .entry("version")
            .or_insert_with(|| Value::Number(1.into()));
    }

    let hooks_obj = doc
        .as_object_mut()
        .expect("checked")
        .entry("hooks")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !hooks_obj.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(hooks_obj),
        });
    }

    let mut hooks_added = Vec::new();
    let mut hooks_already_present = Vec::new();
    for (upstream_event, soth_hook_type) in hook_types {
        let added = ensure_cursor_hook_entry(
            hooks_obj,
            upstream_event,
            soth_hook_type,
            agent,
            &binary_path,
        );
        if added {
            hooks_added.push((*upstream_event).to_string());
        } else {
            hooks_already_present.push((*upstream_event).to_string());
        }
    }

    let updated = serde_json::to_string_pretty(&doc)?;
    write_atomic(hooks_path, updated.as_bytes())?;
    let written = fs::read_to_string(hooks_path).map_err(|e| InstallError::Read {
        path: hooks_path.to_path_buf(),
        source: e,
    })?;
    serde_json::from_str::<Value>(&written).map_err(|e| InstallError::Malformed {
        path: hooks_path.to_path_buf(),
        source: e,
    })?;

    Ok(InstallReport {
        settings_path: hooks_path.to_path_buf(),
        backup_path,
        hooks_added,
        hooks_already_present,
        binary_path,
    })
}

fn uninstall_flat_style(hooks_path: &Path) -> Result<(), InstallError> {
    let content = read_settings_or_empty(hooks_path)?;
    if content.trim().is_empty() {
        return Ok(());
    }
    let mut doc: Value = serde_json::from_str(&content).map_err(|e| InstallError::Malformed {
        path: hooks_path.to_path_buf(),
        source: e,
    })?;
    if !doc.is_object() {
        return Err(InstallError::NotAnObject {
            kind: kind_label(&doc),
        });
    }
    if let Some(hooks) = doc
        .as_object_mut()
        .and_then(|root| root.get_mut("hooks"))
        .and_then(Value::as_object_mut)
    {
        for (_, group) in hooks.iter_mut() {
            if let Some(arr) = group.as_array_mut() {
                arr.retain(|entry| !is_soth_managed(entry));
            }
        }
        let all_empty = hooks
            .iter()
            .all(|(_, v)| v.as_array().map(|a| a.is_empty()).unwrap_or(false));
        if all_empty {
            doc.as_object_mut().unwrap().remove("hooks");
            doc.as_object_mut().unwrap().remove("version");
        }
    }
    write_atomic(hooks_path, serde_json::to_string_pretty(&doc)?.as_bytes())?;
    Ok(())
}

/// Cursor-specific hook entry shape: `{command: "..."}`. Simpler
/// than Claude Code's `{matcher, hooks: [{type, command}]}`. Shared
/// by both Cursor and Windsurf installs (both flat-shape).
fn ensure_cursor_hook_entry(
    hooks: &mut Value,
    cursor_event: &str,
    soth_hook_type: &str,
    agent: &str,
    binary_path: &Path,
) -> bool {
    let hooks_map = hooks.as_object_mut().unwrap();
    let entries = hooks_map
        .entry(cursor_event)
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = match entries.as_array_mut() {
        Some(a) => a,
        None => {
            *entries = Value::Array(vec![entries.clone()]);
            entries.as_array_mut().unwrap()
        }
    };

    if arr.iter().any(is_soth_managed) {
        return false;
    }

    arr.push(json!({
        SOTH_MARKER_KEY: true,
        "command": format!(
            "{} code hook --agent {} --type {}",
            quote_binary_path(binary_path),
            agent,
            soth_hook_type
        )
    }));
    true
}

/// Remove every soth-managed hook entry from Claude Code's
/// `settings.json`. Hooks the user added by hand are preserved; only
/// entries carrying [`SOTH_MARKER_KEY`] are dropped.
pub fn uninstall_claude_code(settings_path: &Path) -> Result<(), InstallError> {
    let content = read_settings_or_empty(settings_path)?;
    if content.trim().is_empty() {
        return Ok(());
    }
    let mut settings: Value =
        serde_json::from_str(&content).map_err(|e| InstallError::Malformed {
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
                    quote_binary_path(binary_path),
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

// ---------------------------------------------------------------------------
// Doctor / status helpers — exposed so the CLI can synthesize one row per
// agent that combines (settings file marker count) + (installed.json record)
// + (binary drift). Previously the doctor only grep'd for the marker
// substring, which couldn't distinguish "fully installed" from "hand-edited
// down to one entry" from "marker text appears in a user comment".
// ---------------------------------------------------------------------------

/// Number of hook entries `install_*` writes for a given agent.
/// `Some(N)` for JSON-config agents (claude_code, cursor, codex,
/// gemini_cli, windsurf); `None` for plugin-file agents
/// (opencode, pi_agent) — those don't have a per-hook count, just a
/// single managed file.
pub fn expected_hook_count(agent: &str) -> Option<usize> {
    match agent {
        "claude_code" => Some(HOOK_TYPES.len()),
        "cursor" => Some(CURSOR_HOOK_TYPES.len()),
        // The CLI surfaces codex as both names; both resolve to the
        // same install. Mapping both keeps the doctor happy whether
        // the caller passed `--target codex` or read `openai_codex`
        // from installed.json.
        "codex" | "openai_codex" => Some(CODEX_HOOK_TYPES.len()),
        "gemini_cli" => Some(GEMINI_HOOK_TYPES.len()),
        "windsurf" => Some(WINDSURF_HOOK_TYPES.len()),
        _ => None,
    }
}

/// Count the number of `_soth_managed: true` entries anywhere in the
/// settings/hooks JSON at `path`. Walks the entire tree so it works
/// uniformly across both shapes we install:
///
/// - Matcher-style (claude_code, gemini_cli): the managed marker
///   lives on the *outer* object that wraps a `matcher`+`hooks` pair.
/// - Flat-style (cursor, codex, windsurf): the managed marker lives
///   on the per-event command object.
///
/// A missing or empty file returns `Ok(0)` so the doctor can
/// distinguish that case from a parse error. Malformed JSON
/// surfaces `Err(InstallError::Malformed)` — same contract as the
/// install side, so the doctor doesn't silently report "0 hooks"
/// for a config the operator broke while editing.
pub fn count_soth_managed_entries(path: &Path) -> Result<usize, InstallError> {
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(InstallError::Read {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    if content.trim().is_empty() {
        return Ok(0);
    }
    let doc: Value = serde_json::from_str(&content).map_err(|e| InstallError::Malformed {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(count_marker_recursive(&doc))
}

fn count_marker_recursive(v: &Value) -> usize {
    match v {
        Value::Object(map) => {
            // An object with `_soth_managed: true` counts itself as
            // one entry — and we DON'T descend further, since the
            // marker lives on leaf-ish wrapper objects (Claude Code's
            // matcher object, Cursor's per-event command object) and
            // descending would double-count nested arrays we don't
            // own.
            if map.get(SOTH_MARKER_KEY) == Some(&Value::Bool(true)) {
                return 1;
            }
            map.values().map(count_marker_recursive).sum()
        }
        Value::Array(arr) => arr.iter().map(count_marker_recursive).sum(),
        _ => 0,
    }
}

/// True when the plugin file at `path` exists and contains the
/// soth-managed marker comment line. Used by the doctor for the
/// plugin-style agents (opencode, pi_agent) where there's no
/// per-hook count, only a single file-presence + marker check.
pub fn plugin_file_is_soth_managed(path: &Path) -> bool {
    match fs::read_to_string(path) {
        Ok(content) => content.contains(PLUGIN_MARKER_LINE),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_command_quotes_binary_path_with_spaces() {
        // Repro for the Windows + space-in-username bug.
        // Engineer's actual path: `C:\Users\Prabhat ACER\…`.
        // Quoted form must double-quote-wrap, normalize
        // backslashes to forward slashes (works on cmd.exe,
        // PowerShell, Git Bash, Node), and preserve the
        // space-bearing folder name as one token.
        let win_path = PathBuf::from(r"C:\Users\Prabhat ACER\.local\bin\soth.exe");
        let quoted = quote_binary_path(&win_path);
        assert_eq!(
            quoted, "\"C:/Users/Prabhat ACER/.local/bin/soth.exe\"",
            "Windows path must be forward-slash-normalized + double-quoted"
        );

        // Mac / Linux path: forward slashes already; still
        // double-quoted so a future user with a space doesn't
        // need a separate code path.
        let mac_path = PathBuf::from("/Users/dev/.local/bin/soth");
        assert_eq!(
            quote_binary_path(&mac_path),
            "\"/Users/dev/.local/bin/soth\"",
            "POSIX path must be double-quoted as-is"
        );
    }

    #[test]
    fn install_claude_code_writes_quoted_command_for_space_path() {
        // End-to-end: install on a space-bearing Windows path
        // and confirm the resulting settings.json contains the
        // forward-slash-normalized + double-quoted command.
        // After deserialization the JSON value is exactly:
        //   "C:/Users/Prabhat ACER/.local/bin/soth.exe" code hook --agent claude_code --type ...
        // — which Claude Code's Git Bash / cmd.exe shell
        // invokes correctly.
        let space_path = PathBuf::from(r"C:\Users\Prabhat ACER\.local\bin\soth.exe");
        let (_tmp, settings_path) = fixture_settings("");
        install_claude_code(&settings_path, Some(space_path)).unwrap();
        let body = fs::read_to_string(&settings_path).unwrap();
        // JSON-encoded: `\"` for inner double-quotes.  No
        // backslashes in the path so no `\\` escapes either —
        // exactly the hand-readable shape engineers want.
        assert!(
            body.contains(r#""\"C:/Users/Prabhat ACER/.local/bin/soth.exe\""#),
            "settings.json must embed forward-slashed quoted path; got: {body}"
        );
    }

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
        assert!(
            report.backup_path.is_none(),
            "no backup needed when nothing existed"
        );
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
        assert_eq!(
            entries.len(),
            2,
            "user's existing entry preserved alongside soth's"
        );
        assert!(entries.iter().any(|e| e[SOTH_MARKER_KEY] == true
            && e["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .contains("code hook --agent")));
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
        assert!(
            bak_body.contains("\"theme\""),
            "backup is the ORIGINAL content"
        );
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
        assert_eq!(
            pre_tool_use[0]["hooks"][0]["command"],
            "/usr/local/bin/my-other-hook"
        );
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
    fn gemini_install_writes_matcher_style_entries() {
        let (_tmp, path) = fixture_settings("");
        let report = install_gemini_cli(&path, Some(binary_path())).unwrap();
        assert_eq!(report.hooks_added.len(), GEMINI_HOOK_TYPES.len());
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        // Gemini uses matcher-style: hooks.<event>[].matcher + hooks[].command
        let entries = body["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let cmd = entries[0]["hooks"][0]["command"].as_str().unwrap();
        assert!(cmd.contains("--agent gemini_cli"));
        assert!(cmd.contains("--type before_tool_call"));
    }

    #[test]
    fn codex_install_writes_five_canonical_hook_types() {
        let (_tmp, path) = fixture_settings("");
        let report = install_codex(&path, Some(binary_path())).unwrap();
        // Codex's slim 5-hook set per rust-codex 0.114.0.
        assert_eq!(report.hooks_added.len(), 5);
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        for upstream in [
            "SessionStart",
            "PreToolUse",
            "PostToolUse",
            "UserPromptSubmit",
            "Stop",
        ] {
            assert!(
                body["hooks"][upstream].is_array(),
                "codex must install hook for {upstream}"
            );
        }
    }

    #[test]
    fn windsurf_install_writes_flat_style_entries() {
        let (_tmp, path) = fixture_settings("");
        let report = install_windsurf(&path, Some(binary_path())).unwrap();
        assert_eq!(report.hooks_added.len(), WINDSURF_HOOK_TYPES.len());
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        // Windsurf uses flat: hooks.<event>[].command (no matcher level)
        let entries = body["hooks"]["pre_run_command"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let cmd = entries[0]["command"].as_str().unwrap();
        assert!(cmd.contains("--agent windsurf"));
        assert!(cmd.contains("--type pre_run_command"));
        // Windsurf does not write a top-level `version` field (Cursor-only).
        assert!(body.get("version").is_none());
    }

    #[test]
    fn cursor_install_covers_all_adapter_known_hooks() {
        // Regression guard: every soth-side hook name in
        // CURSOR_HOOK_TYPES must be one the CursorAdapter recognizes
        // (returns a non-`Notification` ActionType OR is the literal
        // session_end / stop lifecycle hook). Catches the class of
        // drift bug that left `beforeMCPExecution`, `beforeTabFileRead`
        // etc. adapter-parseable but never installed.
        use crate::adapter::{Adapter as _, CursorAdapter};
        let a = CursorAdapter::new();
        for (cursor_event, soth_hook_type) in CURSOR_HOOK_TYPES {
            let parsed = a
                .parse_event(soth_hook_type, b"{\"conversation_id\":\"c\"}")
                .unwrap_or_else(|_| {
                    panic!(
                        "CursorAdapter must parse hook {cursor_event} → {soth_hook_type} \
                         that install.rs registers"
                    )
                });
            assert_eq!(
                parsed.hook_type, *soth_hook_type,
                "adapter must preserve installed hook_type verbatim"
            );
        }
    }

    #[test]
    fn cursor_install_writes_extended_hook_coverage() {
        // Pins the post-PR coverage: we install the full set
        // (pre_action + post_action + lifecycle), not just the
        // original 10. Bump intentionally if/when the set changes.
        let (_tmp, path) = fixture_settings("");
        let report = install_cursor(&path, Some(binary_path())).unwrap();
        assert_eq!(report.hooks_added.len(), CURSOR_HOOK_TYPES.len());
        assert!(
            CURSOR_HOOK_TYPES.len() >= 19,
            "cursor coverage should remain at-or-above 19 hooks (full Cursor hook surface + postToolUseFailure)"
        );
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        // Spot-check newly added hooks land in the file.
        for new_event in [
            "beforeMCPExecution",
            "beforeTabFileRead",
            "subagentStart",
            "afterAgentResponse",
            "afterMCPExecution",
            "subagentStop",
        ] {
            assert!(
                body["hooks"][new_event].is_array(),
                "cursor must install hook for {new_event}"
            );
        }
    }

    #[test]
    fn cursor_install_still_writes_version_field() {
        // Regression guard: the shared `install_flat_style` helper is
        // also used by Cursor; the `version: 1` field should only
        // appear for Cursor, not Windsurf.
        let (_tmp, path) = fixture_settings("");
        super::install_cursor(&path, Some(binary_path())).unwrap();
        let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(body["version"], 1);
    }

    #[test]
    fn expected_hook_count_matches_installed_per_agent() {
        // Pin the doctor's expected-vs-actual comparison: every
        // hook-based install must agree with `expected_hook_count`.
        // Plugin-based agents return `None` since they ship a single
        // file rather than per-event entries.
        for (agent, install_fn) in [
            (
                "claude_code",
                install_claude_code
                    as fn(&Path, Option<PathBuf>) -> Result<InstallReport, InstallError>,
            ),
            ("cursor", install_cursor),
            ("codex", install_codex),
            ("gemini_cli", install_gemini_cli),
            ("windsurf", install_windsurf),
        ] {
            let (_tmp, path) = fixture_settings("");
            let report = install_fn(&path, Some(binary_path())).unwrap();
            let expected =
                expected_hook_count(agent).expect("hook-based agent must expose a count");
            assert_eq!(
                report.hooks_added.len(),
                expected,
                "install_{agent} must add exactly expected_hook_count() entries"
            );
            let counted = count_soth_managed_entries(&path).unwrap();
            assert_eq!(
                counted, expected,
                "count_soth_managed_entries must agree with install for {agent}"
            );
        }
        // Plugin-based agents return None: there's no per-hook count
        // to compare; doctor falls back to plugin_file_is_soth_managed.
        assert_eq!(expected_hook_count("opencode"), None);
        assert_eq!(expected_hook_count("pi_agent"), None);
        // Unknown agents return None too.
        assert_eq!(expected_hook_count("unknown"), None);
    }

    #[test]
    fn count_soth_managed_entries_handles_missing_empty_and_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        // Missing file: 0, not an error.
        let missing = tmp.path().join("nope.json");
        assert_eq!(count_soth_managed_entries(&missing).unwrap(), 0);
        // Empty file: 0.
        let empty = tmp.path().join("empty.json");
        fs::write(&empty, "").unwrap();
        assert_eq!(count_soth_managed_entries(&empty).unwrap(), 0);
        // Malformed JSON: errors so the doctor surfaces the broken
        // config instead of silently reporting "0 hooks" for a file
        // the operator broke mid-edit.
        let bad = tmp.path().join("bad.json");
        fs::write(&bad, "{not json").unwrap();
        assert!(matches!(
            count_soth_managed_entries(&bad),
            Err(InstallError::Malformed { .. })
        ));
        // Unmanaged file: 0 (operator's own hook, no marker).
        let unmanaged = tmp.path().join("user.json");
        fs::write(
            &unmanaged,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/their-hook"}]}]}}"#,
        )
        .unwrap();
        assert_eq!(count_soth_managed_entries(&unmanaged).unwrap(), 0);
    }

    #[test]
    fn plugin_file_is_soth_managed_distinguishes_managed_from_unmanaged() {
        let tmp = tempfile::tempdir().unwrap();
        let managed = tmp.path().join("soth-code.mjs");
        install_opencode(&managed, Some(binary_path())).unwrap();
        assert!(plugin_file_is_soth_managed(&managed));

        let unmanaged = tmp.path().join("user.mjs");
        fs::write(
            &unmanaged,
            "// the operator's own plugin\nexport default {};",
        )
        .unwrap();
        assert!(!plugin_file_is_soth_managed(&unmanaged));

        let missing = tmp.path().join("missing.mjs");
        assert!(!plugin_file_is_soth_managed(&missing));
    }

    #[test]
    fn pi_agent_plugin_installs_with_binary_substituted() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ext").join("soth-code.ts");
        let report = install_pi_agent(&path, Some(binary_path())).unwrap();
        assert!(path.exists());
        let body = fs::read_to_string(&path).unwrap();
        // Marker line preserved so reinstall/uninstall recognizes
        // this as our file.
        assert!(body.contains(PLUGIN_MARKER_LINE));
        // Binary path substituted.
        assert!(body.contains(&binary_path().display().to_string()));
        assert!(
            !body.contains("__SOTH_BIN__"),
            "placeholder must be substituted at install"
        );
        // Hook command shape: agent + canonical hook_type. The
        // hook_type is passed as a variable in the spawnSync call,
        // but the plugin's per-event handlers reference the literals
        // (e.g. `callSoth("pre_tool_use", ...)` for the tool_call
        // handler). Check both the agent literal and any pre/post
        // hook literal lands in the file.
        assert!(body.contains("\"pi_agent\""));
        assert!(body.contains("\"pre_tool_use\""));
        assert!(body.contains("\"post_tool_use\""));
        assert_eq!(report.hooks_added, vec!["pi_agent plugin".to_string()]);
    }

    #[test]
    fn opencode_plugin_installs_with_binary_substituted() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("plugins").join("soth-code.mjs");
        let report = install_opencode(&path, Some(binary_path())).unwrap();
        assert!(path.exists());
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains(PLUGIN_MARKER_LINE));
        assert!(body.contains(&binary_path().display().to_string()));
        assert!(body.contains("\"opencode\""));
        assert!(body.contains("\"tool_execute_before\""));
        assert_eq!(report.hooks_added, vec!["opencode plugin".to_string()]);
    }

    #[test]
    fn plugin_install_refuses_to_overwrite_user_authored_file() {
        // Pre-install a hand-authored plugin without our marker. The
        // installer must refuse to overwrite — operator's plugin is
        // theirs, not ours.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("soth-code.ts");
        fs::write(
            &path,
            "// my own plugin, not soth's\nexport default () => {};",
        )
        .unwrap();
        let r = install_pi_agent(&path, Some(binary_path()));
        assert!(matches!(r, Err(InstallError::NotSothManaged { .. })));
        // File unchanged.
        let after = fs::read_to_string(&path).unwrap();
        assert!(after.contains("my own plugin"));
    }

    #[test]
    fn plugin_uninstall_idempotent_and_marker_aware() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("soth-code.ts");
        install_pi_agent(&path, Some(binary_path())).unwrap();
        assert!(path.exists());
        uninstall_pi_agent(&path).unwrap();
        assert!(!path.exists(), "uninstall removes a soth-managed plugin");
        // Idempotent: uninstall on a missing file is fine.
        uninstall_pi_agent(&path).unwrap();
    }

    #[test]
    fn plugin_uninstall_does_not_touch_user_authored_file() {
        // If somehow a non-marker file ends up at the plugin path
        // (operator hand-wrote it after we uninstalled), uninstall
        // must NOT delete it.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("soth-code.ts");
        fs::write(&path, "// user's plugin\n").unwrap();
        uninstall_pi_agent(&path).unwrap();
        // Still there.
        assert!(path.exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), "// user's plugin\n");
    }

    #[test]
    fn plugin_install_reinstall_keeps_marker_and_substitutes_binary() {
        // Re-install with a different binary path: file gets rewritten
        // with the new binary substituted, marker preserved, original
        // becomes the .bak.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("soth-code.ts");
        install_pi_agent(&path, Some(PathBuf::from("/old/path/soth"))).unwrap();
        let r = install_pi_agent(&path, Some(PathBuf::from("/new/path/soth"))).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("/new/path/soth"));
        assert!(!body.contains("/old/path/soth"));
        // Backup of the previous (also soth-managed) file.
        let bak = r.backup_path.expect(".bak created on overwrite");
        assert!(bak.exists());
        let bak_body = fs::read_to_string(&bak).unwrap();
        assert!(bak_body.contains("/old/path/soth"));
    }

    #[test]
    fn install_uninstall_idempotent_for_all_json_targets() {
        // Same idempotency contract as install_is_idempotent but
        // exercising the matcher-style and flat-style helpers
        // together. Catches "uninstall left an artifact and reinstall
        // sees ghost entries" class bugs.
        for installer in [
            (
                "gemini_cli",
                install_gemini_cli as fn(&Path, Option<PathBuf>) -> _,
                uninstall_gemini_cli as fn(&Path) -> _,
            ),
            ("codex", install_codex, uninstall_codex),
            ("windsurf", install_windsurf, uninstall_windsurf),
        ] {
            let (name, install, uninstall) = installer;
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join(format!("{name}.json"));
            install(&path, Some(binary_path())).unwrap();
            let r2 = install(&path, Some(binary_path())).unwrap();
            assert!(
                r2.hooks_added.is_empty(),
                "{name}: second install added entries (not idempotent)"
            );
            uninstall(&path).unwrap();
            uninstall(&path).unwrap();
            // After two uninstalls, no soth_managed entries remain.
            let body: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            let any_soth = body
                .as_object()
                .and_then(|m| m.get("hooks"))
                .and_then(|h| h.as_object())
                .map(|hooks| {
                    hooks.values().any(|v| {
                        v.as_array()
                            .map(|arr| arr.iter().any(is_soth_managed))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            assert!(!any_soth, "{name}: uninstall left soth-managed entries");
        }
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

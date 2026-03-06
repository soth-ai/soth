use std::path::{Path, PathBuf};
use std::time::Instant;

use tracing::{debug, warn};

use crate::types::{AiTool, DiscoveredTool, DiscoveryReport, StorageFormat};

/// Discovers locally-installed AI tools and their history locations.
pub struct ToolDiscovery {
    roots: Vec<(AiTool, PathBuf)>,
    exclude_patterns: Vec<String>,
}

impl ToolDiscovery {
    /// Create a discovery instance with hard-coded default roots for known tools.
    pub fn with_defaults() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let roots = vec![
            (AiTool::ClaudeCode, home.join(".claude").join("projects")),
            (AiTool::GeminiCli, home.join(".gemini").join("antigravity")),
            (AiTool::OpenAiCodex, home.join(".codex").join("history")),
            (
                AiTool::GithubCopilot,
                home.join(".config").join("github-copilot"),
            ),
            (AiTool::Continue, home.join(".continue")),
        ];
        Self {
            roots,
            exclude_patterns: Vec::new(),
        }
    }

    /// Add bundle-driven exclusion patterns (e.g. from detect bundle config).
    pub fn with_bundle_exclusions(mut self, exclusions: &[String]) -> Self {
        self.exclude_patterns.extend(exclusions.iter().cloned());
        self
    }

    /// Register a custom discovery root for an additional tool.
    pub fn add_custom_root(mut self, tool: AiTool, path: PathBuf) -> Self {
        self.roots.push((tool, path));
        self
    }

    /// Replace the default roots entirely — used by standalone binary `--roots` flag.
    /// Each path is probed against all known tool patterns.
    pub fn override_roots(&mut self, paths: Vec<PathBuf>) {
        self.roots.clear();
        for path in paths {
            // Heuristic: try to detect tool from path segments
            let tool = detect_tool_from_path(&path);
            self.roots.push((tool, path));
        }
    }

    /// Run a synchronous scan of all discovery roots.
    /// Returns which tools are installed and their estimated session counts.
    pub fn scan(&self) -> DiscoveryReport {
        let start = Instant::now();
        let mut report = DiscoveryReport::default();

        for (tool, root) in &self.roots {
            if self.is_excluded(root) {
                debug!(tool = %tool, root = %root.display(), "skipping excluded root");
                continue;
            }

            if !root.exists() {
                debug!(tool = %tool, root = %root.display(), "root does not exist, skipping");
                continue;
            }

            match self.probe_tool(tool, root) {
                Ok(discovered) => {
                    debug!(
                        tool = %discovered.tool,
                        root = %discovered.root_path.display(),
                        sessions = ?discovered.session_count_estimate,
                        "discovered tool"
                    );
                    report.tools.push(discovered);
                }
                Err(e) => {
                    warn!(tool = %tool, root = %root.display(), err = %e, "discovery probe failed");
                    report.errors.push(format!("{tool}: {e}"));
                }
            }
        }

        report.scan_duration_ms = start.elapsed().as_millis() as u64;
        report
    }

    /// Return the registered discovery roots (tool, path) pairs.
    pub fn roots(&self) -> &[(AiTool, PathBuf)] {
        &self.roots
    }

    fn is_excluded(&self, root: &Path) -> bool {
        let root_str = root.to_string_lossy();
        self.exclude_patterns
            .iter()
            .any(|pat| root_str.contains(pat.as_str()))
    }

    fn probe_tool(&self, tool: &AiTool, root: &Path) -> Result<DiscoveredTool, String> {
        let (format, estimate) = match tool {
            AiTool::ClaudeCode => {
                let estimate = count_jsonl_sessions(root);
                (StorageFormat::JsonLines, estimate)
            }
            AiTool::GeminiCli => {
                // The root IS the SQLite database file
                if root.is_file()
                    || root.join("db.sqlite").exists()
                    || root.join("data.db").exists()
                {
                    let db_path = if root.is_file() {
                        root.to_path_buf()
                    } else if root.join("db.sqlite").exists() {
                        root.join("db.sqlite")
                    } else {
                        root.join("data.db")
                    };
                    (
                        StorageFormat::SqliteDb {
                            db_path,
                            schema_hint: None,
                        },
                        None,
                    )
                } else {
                    return Err("no SQLite database found in Gemini root".into());
                }
            }
            AiTool::OpenAiCodex => {
                let estimate = count_json_files(root);
                (StorageFormat::JsonFiles, estimate)
            }
            AiTool::GithubCopilot | AiTool::Continue => {
                // These need schema investigation; report as mixed for now
                (StorageFormat::Mixed, None)
            }
            AiTool::Unknown(_) => (StorageFormat::Mixed, None),
        };

        Ok(DiscoveredTool {
            tool: tool.clone(),
            root_path: root.to_path_buf(),
            format,
            session_count_estimate: estimate,
        })
    }
}

/// Heuristic: detect which AI tool a directory belongs to based on path segments.
fn detect_tool_from_path(path: &Path) -> AiTool {
    let s = path.to_string_lossy();
    if s.contains(".claude") || s.contains("claude") {
        AiTool::ClaudeCode
    } else if s.contains(".gemini") || s.contains("gemini") {
        AiTool::GeminiCli
    } else if s.contains(".codex") || s.contains("codex") {
        AiTool::OpenAiCodex
    } else if s.contains("copilot") {
        AiTool::GithubCopilot
    } else if s.contains("continue") {
        AiTool::Continue
    } else {
        AiTool::Unknown(path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())
    }
}

/// Count JSONL conversation files under a Claude Code projects directory.
fn count_jsonl_sessions(root: &Path) -> Option<u64> {
    let mut count = 0u64;
    let walker = walkdir(root, "jsonl");
    count += walker;
    if count > 0 {
        Some(count)
    } else {
        None
    }
}

/// Count JSON session files under a Codex history directory.
fn count_json_files(root: &Path) -> Option<u64> {
    let count = walkdir(root, "json");
    if count > 0 {
        Some(count)
    } else {
        None
    }
}

/// Simple recursive file count by extension.
fn walkdir(root: &Path, ext: &str) -> u64 {
    let mut count = 0u64;
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            count += walkdir(&path, ext);
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_system_returns_empty_report() {
        let discovery = ToolDiscovery {
            roots: vec![
                (AiTool::ClaudeCode, PathBuf::from("/nonexistent/claude")),
                (AiTool::GeminiCli, PathBuf::from("/nonexistent/gemini")),
            ],
            exclude_patterns: Vec::new(),
        };
        let report = discovery.scan();
        assert!(report.tools.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn discovers_jsonl_files() {
        let tmp = TempDir::new().unwrap();
        let project = tmp.path().join("my-project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("conv1.jsonl"), "{}\n").unwrap();
        std::fs::write(project.join("conv2.jsonl"), "{}\n").unwrap();

        let discovery = ToolDiscovery {
            roots: vec![(AiTool::ClaudeCode, tmp.path().to_path_buf())],
            exclude_patterns: Vec::new(),
        };
        let report = discovery.scan();
        assert_eq!(report.tools.len(), 1);
        assert_eq!(report.tools[0].session_count_estimate, Some(2));
    }

    #[test]
    fn excluded_root_is_skipped() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("conv.jsonl"), "{}\n").unwrap();

        let discovery = ToolDiscovery {
            roots: vec![(AiTool::ClaudeCode, tmp.path().to_path_buf())],
            exclude_patterns: vec![tmp.path().to_string_lossy().to_string()],
        };
        let report = discovery.scan();
        assert!(report.tools.is_empty());
    }
}

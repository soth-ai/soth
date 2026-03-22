use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Classification of the *environment* (parent process) in which an AI tool runs.
/// Distinct from EntityKind/SurfaceType which classify the tool itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvironmentClass {
    Terminal,
    IDE,
    Browser,
}

/// Bundle entry describing a known environment (parent process).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BundleEnvironment {
    pub slug: String,
    pub class: EnvironmentClass,
    #[serde(default)]
    pub bundle_ids: Vec<String>,
    #[serde(default)]
    pub process_names: Vec<String>,
}

/// O(1) lookup index mapping parent process identifiers to their environment class.
/// Built at bundle load time from the `environments` array in the detect bundle.
#[derive(Debug, Clone, Default)]
pub struct EnvIndex {
    entries: HashMap<String, EnvironmentClass>,
}

impl EnvIndex {
    pub fn build(environments: &[BundleEnvironment]) -> Self {
        let mut entries = HashMap::new();
        for env in environments {
            for bid in &env.bundle_ids {
                let key = bid.trim().to_ascii_lowercase();
                if !key.is_empty() {
                    entries.insert(key, env.class);
                }
            }
            for name in &env.process_names {
                let key = name.trim().to_ascii_lowercase();
                if !key.is_empty() {
                    entries.insert(key, env.class);
                }
            }
        }
        Self { entries }
    }

    /// Resolve the environment class of the **parent** process.
    /// Call with parent_bundle_id and parent_process_name from ProcessInfo.
    pub fn resolve_parent(
        &self,
        parent_bundle_id: Option<&str>,
        parent_process_name: Option<&str>,
    ) -> Option<EnvironmentClass> {
        if let Some(bid) = parent_bundle_id {
            let key = bid.trim().to_ascii_lowercase();
            if let Some(class) = self.entries.get(&key) {
                return Some(*class);
            }
        }
        if let Some(name) = parent_process_name {
            let key = name.trim().to_ascii_lowercase();
            if let Some(class) = self.entries.get(&key) {
                return Some(*class);
            }
        }
        None
    }

    /// Number of entries in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_resolve() {
        let envs = vec![
            BundleEnvironment {
                slug: "vscode".into(),
                class: EnvironmentClass::IDE,
                bundle_ids: vec!["com.microsoft.VSCode".into()],
                process_names: vec!["code".into()],
            },
            BundleEnvironment {
                slug: "shell".into(),
                class: EnvironmentClass::Terminal,
                bundle_ids: vec![],
                process_names: vec!["zsh".into(), "bash".into()],
            },
            BundleEnvironment {
                slug: "chrome".into(),
                class: EnvironmentClass::Browser,
                bundle_ids: vec!["com.google.Chrome".into()],
                process_names: vec![],
            },
        ];

        let idx = EnvIndex::build(&envs);

        // IDE by bundle_id
        assert_eq!(
            idx.resolve_parent(Some("com.microsoft.VSCode"), None),
            Some(EnvironmentClass::IDE)
        );
        // IDE by process_name
        assert_eq!(
            idx.resolve_parent(None, Some("code")),
            Some(EnvironmentClass::IDE)
        );
        // Terminal
        assert_eq!(
            idx.resolve_parent(None, Some("zsh")),
            Some(EnvironmentClass::Terminal)
        );
        // Browser
        assert_eq!(
            idx.resolve_parent(Some("com.google.Chrome"), None),
            Some(EnvironmentClass::Browser)
        );
        // Unknown
        assert_eq!(idx.resolve_parent(None, Some("unknown-proc")), None);
        // Case insensitive
        assert_eq!(
            idx.resolve_parent(Some("COM.MICROSOFT.VSCODE"), None),
            Some(EnvironmentClass::IDE)
        );
        // bundle_id takes priority
        assert_eq!(
            idx.resolve_parent(Some("com.google.Chrome"), Some("code")),
            Some(EnvironmentClass::Browser)
        );
    }

    #[test]
    fn empty_index() {
        let idx = EnvIndex::default();
        assert!(idx.is_empty());
        assert_eq!(idx.resolve_parent(None, None), None);
    }
}

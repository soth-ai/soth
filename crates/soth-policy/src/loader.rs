//! Policy file loading

use crate::compiler::PolicyCompiler;
use soth_core::error::{Result, SothError};
use soth_core::types::policy::PolicyData;
use std::collections::HashMap;
use std::path::Path;

/// Policy loader
pub struct PolicyLoader;

impl PolicyLoader {
    /// Load Rego files from a directory
    pub fn load_rego_dir(path: impl AsRef<Path>) -> Result<HashMap<String, String>> {
        let path = path.as_ref();

        if !path.is_dir() {
            return Err(SothError::Policy(format!(
                "Policy directory not found: {}",
                path.display()
            )));
        }

        let mut modules = HashMap::new();

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            if file_path.extension().is_some_and(|e| e == "rego") {
                let name = file_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "policy".to_string());

                let content = std::fs::read_to_string(&file_path)?;
                modules.insert(name, content);
            }
        }

        if modules.is_empty() {
            return Err(SothError::Policy(format!(
                "No .rego files found in {}",
                path.display()
            )));
        }

        Ok(modules)
    }

    /// Load YAML policy files and compile to Rego
    pub fn load_yaml_dir(path: impl AsRef<Path>) -> Result<HashMap<String, String>> {
        let path = path.as_ref();

        if !path.is_dir() {
            return Err(SothError::Policy(format!(
                "Policy directory not found: {}",
                path.display()
            )));
        }

        let mut modules = HashMap::new();

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            let is_yaml = file_path.extension().is_some_and(|e| {
                e == "yaml" || e == "yml"
            });

            if is_yaml {
                let name = file_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "policy".to_string());

                let yaml_content = std::fs::read_to_string(&file_path)?;
                let rego = PolicyCompiler::compile_yaml(&yaml_content)?;
                modules.insert(name, rego);
            }
        }

        Ok(modules)
    }

    /// Load a single Rego file
    pub fn load_rego_file(path: impl AsRef<Path>) -> Result<(String, String)> {
        let path = path.as_ref();

        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "policy".to_string());

        let content = std::fs::read_to_string(path)?;

        Ok((name, content))
    }

    /// Load a single YAML policy file and compile to Rego
    pub fn load_yaml_file(path: impl AsRef<Path>) -> Result<(String, String)> {
        let path = path.as_ref();

        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "policy".to_string());

        let yaml_content = std::fs::read_to_string(path)?;
        let rego = PolicyCompiler::compile_yaml(&yaml_content)?;

        Ok((name, rego))
    }

    /// Load policy data from a JSON file
    pub fn load_policy_data(path: impl AsRef<Path>) -> Result<PolicyData> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let data: PolicyData = serde_json::from_str(&content)?;
        Ok(data)
    }

    /// Load policy data from a YAML file
    pub fn load_policy_data_yaml(path: impl AsRef<Path>) -> Result<PolicyData> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let data: PolicyData = serde_yaml::from_str(&content)
            .map_err(|e| SothError::Policy(format!("YAML parse error: {e}")))?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_load_rego_dir() {
        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("test.rego");

        std::fs::write(&policy_path, "package test\ndefault allow = false").unwrap();

        let modules = PolicyLoader::load_rego_dir(dir.path()).unwrap();
        assert!(modules.contains_key("test"));
    }

    #[test]
    fn test_load_yaml_dir() {
        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("test.yaml");

        let yaml = r#"
name: test_policy
rules:
  - name: allow_all
    condition:
      type: always
    action:
      type: allow
"#;
        std::fs::write(&policy_path, yaml).unwrap();

        let modules = PolicyLoader::load_yaml_dir(dir.path()).unwrap();
        assert!(modules.contains_key("test"));
        assert!(modules["test"].contains("package mcp.policy"));
    }

    #[test]
    fn test_load_policy_data() {
        let dir = tempdir().unwrap();
        let data_path = dir.path().join("data.json");

        let json = r#"{
            "blocked_tools": ["dangerous"],
            "blocked_agents": ["bad-agent"]
        }"#;
        std::fs::write(&data_path, json).unwrap();

        let data = PolicyLoader::load_policy_data(&data_path).unwrap();
        assert!(data.blocked_tools.contains(&"dangerous".to_string()));
        assert!(data.blocked_agents.contains(&"bad-agent".to_string()));
    }
}

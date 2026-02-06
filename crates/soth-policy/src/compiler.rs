//! YAML to Rego policy compiler
//!
//! Compiles user-friendly YAML policy definitions into Rego code.

use serde::{Deserialize, Serialize};
use soth_core::error::{Result, SothError};
use std::collections::HashMap;

/// A policy definition in YAML format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefinition {
    /// Policy name
    pub name: String,
    /// Policy description
    #[serde(default)]
    pub description: String,
    /// Rules in this policy
    pub rules: Vec<PolicyRule>,
}

/// A policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name
    pub name: String,
    /// Rule description
    #[serde(default)]
    pub description: String,
    /// Condition to match
    pub condition: RuleCondition,
    /// Action when matched
    pub action: RuleAction,
}

/// Rule condition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    /// Match all (always true)
    Always,
    /// Match specific agent
    Agent {
        id: Option<String>,
        name: Option<String>,
        #[serde(default)]
        capabilities: Vec<String>,
    },
    /// Match specific tool
    Tool {
        name: String,
        #[serde(default)]
        arguments: HashMap<String, serde_json::Value>,
    },
    /// Match method
    Method { name: String },
    /// Match identity status
    Identity {
        #[serde(default)]
        verified: Option<bool>,
        #[serde(default)]
        did_pattern: Option<String>,
    },
    /// Combined conditions (all must match)
    All { conditions: Vec<RuleCondition> },
    /// Combined conditions (any must match)
    Any { conditions: Vec<RuleCondition> },
    /// Negated condition
    Not { condition: Box<RuleCondition> },
}

/// Rule action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleAction {
    /// Allow the request
    Allow,
    /// Deny the request with a message
    Deny { message: String },
    /// Allow with obligations
    AllowWithObligations { obligations: Vec<Obligation> },
}

/// An obligation to be fulfilled
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    pub action: String,
    #[serde(default)]
    pub params: HashMap<String, String>,
}

/// Policy compiler
pub struct PolicyCompiler;

impl PolicyCompiler {
    /// Compile a policy definition to Rego
    pub fn compile(definition: &PolicyDefinition) -> Result<String> {
        let mut rego = String::new();

        // Package declaration
        rego.push_str("package mcp.policy\n\n");

        // Import common libraries
        rego.push_str("import rego.v1\n\n");

        // Default decision
        rego.push_str("default decision := {\"allow\": false, \"violations\": [], \"matched_rule\": \"default_deny\"}\n\n");

        // Generate rules
        for rule in &definition.rules {
            let rule_rego = Self::compile_rule(rule)?;
            rego.push_str(&rule_rego);
            rego.push_str("\n\n");
        }

        Ok(rego)
    }

    /// Compile a single rule to Rego
    fn compile_rule(rule: &PolicyRule) -> Result<String> {
        let condition_rego = Self::compile_condition(&rule.condition)?;
        let action_rego = Self::compile_action(&rule.action, &rule.name)?;

        Ok(format!(
            "# {}: {}\ndecision := {} if {{\n{}\n}}",
            rule.name, rule.description, action_rego, condition_rego
        ))
    }

    /// Compile a condition to Rego
    fn compile_condition(condition: &RuleCondition) -> Result<String> {
        match condition {
            RuleCondition::Always => Ok("    true".to_string()),

            RuleCondition::Agent {
                id,
                name,
                capabilities,
            } => {
                let mut checks = Vec::new();

                if let Some(id) = id {
                    checks.push(format!("    input.agent.id == \"{id}\""));
                }
                if let Some(name) = name {
                    checks.push(format!("    input.agent.name == \"{name}\""));
                }
                for cap in capabilities {
                    checks.push(format!("    \"{cap}\" in input.agent.capabilities"));
                }

                if checks.is_empty() {
                    Ok("    true".to_string())
                } else {
                    Ok(checks.join("\n"))
                }
            }

            RuleCondition::Tool { name, arguments } => {
                let mut checks = vec![format!("    input.request.tool == \"{}\"", name)];

                for (key, value) in arguments {
                    let value_str = serde_json::to_string(value).unwrap_or_default();
                    checks.push(format!(
                        "    input.request.arguments[\"{key}\"] == {value_str}"
                    ));
                }

                Ok(checks.join("\n"))
            }

            RuleCondition::Method { name } => Ok(format!("    input.request.method == \"{name}\"")),

            RuleCondition::Identity {
                verified,
                did_pattern,
            } => {
                let mut checks = Vec::new();

                if let Some(v) = verified {
                    checks.push(format!("    input.identity.verified == {v}"));
                }
                if let Some(pattern) = did_pattern {
                    checks.push(format!("    startswith(input.identity.did, \"{pattern}\")"));
                }

                if checks.is_empty() {
                    Ok("    true".to_string())
                } else {
                    Ok(checks.join("\n"))
                }
            }

            RuleCondition::All { conditions } => {
                let parts: Result<Vec<String>> =
                    conditions.iter().map(Self::compile_condition).collect();
                Ok(parts?.join("\n"))
            }

            RuleCondition::Any { conditions } => {
                let parts: Result<Vec<String>> =
                    conditions.iter().map(Self::compile_condition).collect();
                let parts = parts?;

                // Wrap each in parens and join with "or"
                let wrapped: Vec<String> = parts
                    .into_iter()
                    .map(|p| format!("    ({})", p.trim()))
                    .collect();
                Ok(wrapped.join(" else true if\n"))
            }

            RuleCondition::Not { condition } => {
                let inner = Self::compile_condition(condition)?;
                Ok(format!("    not ({})", inner.trim()))
            }
        }
    }

    /// Compile an action to Rego value
    fn compile_action(action: &RuleAction, rule_name: &str) -> Result<String> {
        match action {
            RuleAction::Allow => Ok(format!(
                "{{\"allow\": true, \"violations\": [], \"matched_rule\": \"{rule_name}\"}}"
            )),

            RuleAction::Deny { message } => Ok(format!(
                "{{\"allow\": false, \"violations\": [\"{}\"], \"matched_rule\": \"{}\"}}",
                message.replace('"', "\\\""),
                rule_name
            )),

            RuleAction::AllowWithObligations { obligations } => {
                let obs_json: Vec<String> = obligations
                    .iter()
                    .map(|o| {
                        let params = serde_json::to_string(&o.params).unwrap_or_default();
                        format!("{{\"action\": \"{}\", \"params\": {}}}", o.action, params)
                    })
                    .collect();

                Ok(format!(
                    "{{\"allow\": true, \"violations\": [], \"matched_rule\": \"{}\", \"obligations\": [{}]}}",
                    rule_name,
                    obs_json.join(", ")
                ))
            }
        }
    }

    /// Parse a YAML policy definition
    pub fn parse_yaml(yaml: &str) -> Result<PolicyDefinition> {
        serde_yaml::from_str(yaml)
            .map_err(|e| SothError::PolicyCompilation(format!("YAML parse error: {e}")))
    }

    /// Compile YAML to Rego
    pub fn compile_yaml(yaml: &str) -> Result<String> {
        let definition = Self::parse_yaml(yaml)?;
        Self::compile(&definition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_policy() {
        let yaml = r#"
name: test_policy
description: A test policy
rules:
  - name: allow_all
    description: Allow everything
    condition:
      type: always
    action:
      type: allow
"#;

        let definition = PolicyCompiler::parse_yaml(yaml).unwrap();
        assert_eq!(definition.name, "test_policy");
        assert_eq!(definition.rules.len(), 1);
    }

    #[test]
    fn test_compile_simple_policy() {
        let yaml = r#"
name: test_policy
description: A test policy
rules:
  - name: allow_all
    description: Allow everything
    condition:
      type: always
    action:
      type: allow
"#;

        let rego = PolicyCompiler::compile_yaml(yaml).unwrap();
        assert!(rego.contains("package mcp.policy"));
        assert!(rego.contains("allow_all"));
    }

    #[test]
    fn test_compile_deny_rule() {
        let yaml = r#"
name: deny_policy
rules:
  - name: block_agent
    description: Block specific agent
    condition:
      type: agent
      id: bad-agent
    action:
      type: deny
      message: Agent is blocked
"#;

        let rego = PolicyCompiler::compile_yaml(yaml).unwrap();
        assert!(rego.contains("bad-agent"));
        assert!(rego.contains("Agent is blocked"));
    }

    #[test]
    fn test_compile_tool_rule() {
        let yaml = r#"
name: tool_policy
rules:
  - name: allow_read
    description: Allow read tool
    condition:
      type: tool
      name: read_file
    action:
      type: allow
"#;

        let rego = PolicyCompiler::compile_yaml(yaml).unwrap();
        assert!(rego.contains("read_file"));
    }

    #[test]
    fn test_compile_identity_rule() {
        let yaml = r#"
name: identity_policy
rules:
  - name: require_verified
    description: Require verified identity
    condition:
      type: identity
      verified: true
    action:
      type: allow
"#;

        let rego = PolicyCompiler::compile_yaml(yaml).unwrap();
        assert!(rego.contains("input.identity.verified"));
    }

    #[test]
    fn test_compile_combined_conditions() {
        let yaml = r#"
name: combined_policy
rules:
  - name: complex_rule
    description: Complex rule with multiple conditions
    condition:
      type: all
      conditions:
        - type: agent
          capabilities:
            - admin
        - type: identity
          verified: true
    action:
      type: allow
"#;

        let rego = PolicyCompiler::compile_yaml(yaml).unwrap();
        assert!(rego.contains("admin"));
        assert!(rego.contains("verified"));
    }
}

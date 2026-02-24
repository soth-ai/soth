use crate::hash::sha256_hex;
use crate::types::{ArtifactLocation, ArtifactType, DetectWarning, SensitiveArtifact, Severity};
use std::panic::catch_unwind;
use std::time::Instant;
use tree_sitter::{Node, Parser};

pub fn detect_code_artifacts(
    content: &str,
    location: ArtifactLocation,
) -> (Vec<SensitiveArtifact>, Vec<DetectWarning>) {
    let Some(language) = heuristic_language(content) else {
        return (Vec::new(), Vec::new());
    };

    let mut warnings = Vec::new();
    let mut artifact = code_artifact(content, &language, location);

    if content.len() > 200 {
        let started = Instant::now();
        let parse = catch_unwind(|| parse_with_tree_sitter(content, &language));

        match parse {
            Ok(Some(confident_language)) => {
                artifact.artifact_type = ArtifactType::CodeBlock {
                    language: confident_language,
                };
            }
            Ok(None) => {}
            Err(_) => {
                warnings.push(DetectWarning {
                    code: "tree_sitter_panic",
                    detail: "tree-sitter parser panic captured".to_string(),
                });
            }
        }

        if started.elapsed().as_millis() > 15 {
            warnings.push(DetectWarning {
                code: "tree_sitter_timeout",
                detail: "tree-sitter parse exceeded 15ms budget".to_string(),
            });
        }
    }

    (vec![artifact], warnings)
}

fn heuristic_language(content: &str) -> Option<String> {
    let text = content.to_ascii_lowercase();

    if (text.contains("fn ") && text.contains("impl "))
        || (text.contains("use ") && text.contains("let "))
    {
        return Some("rust".to_string());
    }

    if text.contains("def ") && text.contains(":") {
        return Some("python".to_string());
    }

    if text.contains("function ") || text.contains("const ") || text.contains("=>") {
        return Some("javascript".to_string());
    }

    if text.contains("select ") && text.contains(" from ") {
        return Some("sql".to_string());
    }

    if text.contains("#!/") || text.contains("set -e") {
        return Some("bash".to_string());
    }

    None
}

fn parse_with_tree_sitter(content: &str, language: &str) -> Option<String> {
    if language != "rust" {
        return None;
    }

    let mut parser = Parser::new();
    let lang = tree_sitter_rust::language();
    if parser.set_language(&lang).is_err() {
        return None;
    }

    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    let total = root.descendant_count();
    if total == 0 {
        return None;
    }

    let error_nodes = count_error_nodes(root);
    let ratio = (error_nodes as f32) / (total as f32);
    if ratio < 0.05 {
        Some("rust".to_string())
    } else {
        None
    }
}

fn count_error_nodes(root: Node<'_>) -> u32 {
    let mut count: u32 = if root.is_error() { 1 } else { 0 };
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        count = count.saturating_add(count_error_nodes(child));
    }
    count
}

fn code_artifact(content: &str, language: &str, location: ArtifactLocation) -> SensitiveArtifact {
    SensitiveArtifact {
        artifact_type: ArtifactType::CodeBlock {
            language: language.to_string(),
        },
        commitment: sha256_hex(format!("code_block:{}:{}", language, content)),
        severity: Severity::Low,
        location,
        redacted_hint: None,
    }
}

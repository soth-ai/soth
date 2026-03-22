use crate::hash::sha256_hex;
use crate::types::{ArtifactLocation, DetectWarning, DetectedImportCategory, SensitiveArtifact};
use soth_core::{ArtifactKind, ArtifactSeverity};
#[cfg(feature = "tree-sitter")]
use std::panic::catch_unwind;
#[cfg(feature = "tree-sitter")]
use std::time::Instant;
#[cfg(feature = "tree-sitter")]
use tree_sitter::{Node, Parser};

#[derive(Clone, Debug)]
pub struct CodeDetectResult {
    pub artifacts: Vec<SensitiveArtifact>,
    pub warnings: Vec<DetectWarning>,
    pub tree_sitter: Option<TreeSitterResult>,
    pub detected_language: Option<String>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // fields populated for future classification use
pub struct TreeSitterResult {
    pub confirmed_language: Option<String>,
    pub import_categories: Vec<DetectedImportCategory>,
    pub has_auth_logic: bool,
    pub has_crypto_operations: bool,
    pub has_network_calls: bool,
    pub has_file_io: bool,
    pub function_count: u32,
    pub complexity_estimate: u8,
}

static CODE_KEYWORDS: &[&str] = &[
    "fn ",
    "def ",
    "func ",
    "function ",
    "class ",
    "struct ",
    "impl ",
    "import ",
    "require(",
    "include ",
    "return ",
    "const ",
    "let ",
    "var ",
    "if (",
    "if let ",
    "while (",
    "for ",
    "switch ",
    "async ",
    "await ",
];

pub fn has_code_content(content: &str) -> bool {
    use crate::util::{
        safe_prefix, safe_suffix, SAMPLE_PREFIX_BYTES, SAMPLE_SUFFIX_BYTES,
        SAMPLING_THRESHOLD_BYTES,
    };

    if content.len() <= SAMPLING_THRESHOLD_BYTES {
        return has_code_content_inner(content);
    }
    let head = safe_prefix(content, SAMPLE_PREFIX_BYTES);
    let tail = safe_suffix(content, SAMPLE_SUFFIX_BYTES);
    has_code_content_inner(head) || has_code_content_inner(tail)
}

fn has_code_content_inner(content: &str) -> bool {
    let mut signals: u8 = 0;

    if content.contains("```") {
        signals += 1;
    }

    let symbol_chars = content
        .chars()
        .filter(|ch| matches!(ch, '{' | '}' | '(' | ')' | '[' | ']' | ';' | '='))
        .count();
    let ratio = symbol_chars as f32 / content.len().max(1) as f32;
    if ratio > 0.04 {
        signals += 1;
    }

    let keyword_count = CODE_KEYWORDS
        .iter()
        .filter(|kw| content.contains(*kw))
        .count();
    if keyword_count >= 3 {
        signals += 1;
    }

    let indented_lines = content
        .lines()
        .filter(|line| line.starts_with("  ") || line.starts_with('\t'))
        .count();
    let total_lines = content.lines().count().max(1);
    if indented_lines * 100 / total_lines > 30 {
        signals += 1;
    }

    let special_count = content
        .chars()
        .filter(|ch| !ch.is_alphanumeric() && !ch.is_whitespace())
        .count();
    let special_ratio = special_count as f32 / content.len().max(1) as f32;
    if special_ratio > 0.08 {
        signals += 1;
    }

    signals >= 2
}

pub fn detect_code_artifacts(content: &str, location: ArtifactLocation) -> CodeDetectResult {
    let language = heuristic_language(content);

    if language.is_none() && !has_code_content(content) {
        return CodeDetectResult {
            artifacts: Vec::new(),
            warnings: Vec::new(),
            tree_sitter: None,
            detected_language: None,
        };
    }

    let detected_language = language.clone();
    #[cfg_attr(not(feature = "tree-sitter"), allow(unused_mut))]
    let mut warnings = Vec::new();
    let mut ts_result: Option<TreeSitterResult> = None;
    #[cfg_attr(not(feature = "tree-sitter"), allow(unused_mut))]
    let mut confirmed_lang = language.clone();

    if content.len() > 200 {
        if let Some(lang) = &language {
            #[cfg(feature = "tree-sitter")]
            {
                let started = Instant::now();
                let parse = catch_unwind(|| analyze_with_tree_sitter(content, lang));

                match parse {
                    Ok(Some(result)) => {
                        if let Some(ref cl) = result.confirmed_language {
                            confirmed_lang = Some(cl.clone());
                        }
                        ts_result = Some(result);
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
            #[cfg(not(feature = "tree-sitter"))]
            {
                ts_result = fallback_analysis(content, lang);
            }
        }
    }

    let artifacts = if let Some(ref lang) = confirmed_lang {
        vec![code_artifact(content, lang, location)]
    } else if has_code_content(content) {
        vec![code_artifact(content, "unknown", location)]
    } else {
        Vec::new()
    };

    CodeDetectResult {
        artifacts,
        warnings,
        tree_sitter: ts_result,
        detected_language: confirmed_lang.or(detected_language),
    }
}

pub fn heuristic_language(content: &str) -> Option<String> {
    let text = content.to_ascii_lowercase();

    let mut best: Option<(String, u32)> = None;

    macro_rules! score {
        ($lang:expr, $score:expr) => {
            match &best {
                Some((_, s)) if *s >= $score => {}
                _ => best = Some(($lang.to_string(), $score)),
            }
        };
    }

    let rust_score = count_hits(
        &text,
        &[
            "fn ",
            "impl ",
            "pub struct ",
            "use std::",
            "let mut ",
            "-> result",
            "unwrap()",
        ],
    );
    if rust_score >= 3 {
        score!("rust", rust_score);
    }

    let py_score = count_hits(
        &text,
        &[
            "def ", "import ", "class ", "self.", "elif ", "print(", "__init__",
        ],
    );
    if py_score >= 3 {
        score!("python", py_score);
    }

    let ts_score = count_hits(
        &text,
        &[
            ": string",
            ": number",
            ": boolean",
            "interface ",
            "type ",
            "=> {",
            "async function",
        ],
    );
    if ts_score >= 3 {
        score!("typescript", ts_score);
    }

    let js_score = count_hits(
        &text,
        &[
            "function ",
            "const ",
            "let ",
            "var ",
            "require(",
            "module.exports",
            "=>",
        ],
    );
    if js_score >= 3 && ts_score < 2 {
        score!("javascript", js_score);
    }

    let go_score = count_hits(
        &text,
        &[
            "func ",
            "package ",
            ":= ",
            "fmt.",
            "goroutine",
            "chan ",
            "go func",
        ],
    );
    if go_score >= 2 {
        score!("go", go_score);
    }

    let java_score = count_hits(
        &text,
        &[
            "public class ",
            "private ",
            "void ",
            "system.out",
            "throws ",
            "extends ",
            "implements ",
        ],
    );
    if java_score >= 2 {
        score!("java", java_score);
    }

    let cpp_score = count_hits(
        &text,
        &[
            "#include",
            "std::",
            "cout <<",
            "int main(",
            "namespace ",
            "::",
            "template<",
        ],
    );
    if cpp_score >= 2 {
        score!("cpp", cpp_score);
    }

    let c_score = count_hits(
        &text,
        &[
            "#include",
            "int main(",
            "printf(",
            "malloc(",
            "sizeof(",
            "typedef ",
            "struct {",
        ],
    );
    if c_score >= 2 && cpp_score < 2 {
        score!("c", c_score);
    }

    let cs_score = count_hits(
        &text,
        &[
            "using system",
            "namespace ",
            "public class ",
            "console.writeline",
            "async task",
            "var ",
            "=> {",
        ],
    );
    if cs_score >= 3 {
        score!("csharp", cs_score);
    }

    let rb_score = count_hits(
        &text,
        &[
            "def ", "end\n", "puts ", "require ", "attr_", "do |", ".each",
        ],
    );
    if rb_score >= 3 {
        score!("ruby", rb_score);
    }

    let php_score = count_hits(
        &text,
        &[
            "<?php",
            "echo ",
            "$",
            "function ",
            "->",
            "array(",
            "namespace ",
        ],
    );
    if php_score >= 3 && text.contains('$') {
        score!("php", php_score);
    }

    let swift_score = count_hits(
        &text,
        &[
            "func ", "var ", "let ", "guard ", "if let ", "class ", "struct ",
        ],
    );
    if swift_score >= 3 && text.contains("guard ") {
        score!("swift", swift_score);
    }

    let kt_score = count_hits(
        &text,
        &[
            "fun ",
            "val ",
            "var ",
            "data class ",
            "companion object",
            "?.let",
            "coroutine",
        ],
    );
    if kt_score >= 2 {
        score!("kotlin", kt_score);
    }

    let sql_score = count_hits(
        &text,
        &[
            "select ",
            " from ",
            "where ",
            "insert into",
            "create table",
            "join ",
            "group by",
        ],
    );
    if sql_score >= 2 {
        score!("sql", sql_score);
    }

    let sh_score = count_hits(
        &text,
        &["#!/", "echo ", "export ", "if [ ", "fi\n", "for ", "grep "],
    );
    if sh_score >= 2 || text.starts_with("#!/") {
        score!("bash", sh_score.max(2));
    }

    let tf_score = count_hits(
        &text,
        &[
            "resource \"",
            "variable \"",
            "provider \"",
            "terraform {",
            "data \"",
            ".tf\"",
        ],
    );
    if tf_score >= 2 {
        score!("terraform", tf_score);
    }

    let sol_score = count_hits(
        &text,
        &[
            "pragma solidity",
            "contract ",
            "function ",
            "mapping(",
            "address ",
            "emit ",
            "modifier ",
        ],
    );
    if sol_score >= 2 && text.contains("pragma solidity") {
        score!("solidity", sol_score);
    }

    if is_yaml(&text) {
        score!("yaml", 3);
    }

    if is_likely_json(content) {
        score!("json", 2);
    }

    best.map(|(lang, _)| lang)
}

pub fn ast_normalized_hash(content: &str, language: &str) -> Option<String> {
    let normalized = normalize_code_for_hash(content, language)?;
    Some(sha256_hex(&normalized)[..32].to_string())
}

fn normalize_code_for_hash(content: &str, language: &str) -> Option<String> {
    let mut out = String::with_capacity(content.len());

    let comment_prefix = match language {
        "python" | "bash" | "ruby" | "yaml" | "terraform" => "#",
        "sql" => "--",
        _ => "//",
    };

    for line in content.lines() {
        let stripped = if let Some(idx) = line.find(comment_prefix) {
            &line[..idx]
        } else {
            line
        };
        let trimmed = stripped.trim();
        if !trimmed.is_empty() {
            out.push_str(trimmed);
            out.push('\n');
        }
    }

    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }

    let de_strung = replace_string_literals(&collapsed);
    let de_numbed = replace_numeric_literals(&de_strung);

    Some(de_numbed)
}

fn replace_string_literals(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '"' || ch == '\'' {
            out.push_str("STR");
            let mut prev = ch;
            for inner in chars.by_ref() {
                if inner == ch && prev != '\\' {
                    break;
                }
                prev = inner;
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn replace_numeric_literals(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_num = false;
    for ch in input.chars() {
        if ch.is_ascii_digit() {
            if !in_num {
                out.push_str("NUM");
                in_num = true;
            }
        } else {
            if ch != '.' {
                in_num = false;
            }
            out.push(ch);
        }
    }
    out
}

#[cfg(feature = "tree-sitter")]
fn analyze_with_tree_sitter(content: &str, language: &str) -> Option<TreeSitterResult> {
    macro_rules! try_lang {
        ($lang_const:expr) => {{
            let mut parser = Parser::new();
            if parser.set_language(&$lang_const.into()).is_err() {
                return fallback_analysis(content, language);
            }
            parser
        }};
    }

    let mut parser = match language {
        "rust" => try_lang!(tree_sitter_rust::LANGUAGE),
        "python" => try_lang!(tree_sitter_python::LANGUAGE),
        "javascript" => try_lang!(tree_sitter_javascript::LANGUAGE),
        "typescript" => try_lang!(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
        "go" => try_lang!(tree_sitter_go::LANGUAGE),
        "java" => try_lang!(tree_sitter_java::LANGUAGE),
        _ => return fallback_analysis(content, language),
    };

    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    let total = root.descendant_count();
    if total == 0 {
        return fallback_analysis(content, language);
    }

    let error_nodes = count_error_nodes(root);
    let ratio = (error_nodes as f32) / (total as f32);
    let confirmed_language = if ratio < 0.05 {
        Some(language.to_string())
    } else {
        None
    };

    let import_strings = extract_import_strings(root, content);
    let import_categories = classify_imports(&import_strings);
    let function_count = count_functions(root);

    let has_auth_logic = import_categories
        .iter()
        .any(|c| matches!(c, DetectedImportCategory::Auth));
    let has_crypto_operations = import_categories
        .iter()
        .any(|c| matches!(c, DetectedImportCategory::Crypto));
    let has_network_calls = import_categories
        .iter()
        .any(|c| matches!(c, DetectedImportCategory::Network));
    let has_file_io = import_categories
        .iter()
        .any(|c| matches!(c, DetectedImportCategory::Filesystem));

    let complexity_estimate = estimate_complexity(
        function_count,
        &import_categories,
        has_auth_logic,
        has_crypto_operations,
        has_network_calls,
    );

    Some(TreeSitterResult {
        confirmed_language,
        import_categories,
        has_auth_logic,
        has_crypto_operations,
        has_network_calls,
        has_file_io,
        function_count,
        complexity_estimate,
    })
}

fn fallback_analysis(content: &str, language: &str) -> Option<TreeSitterResult> {
    let text_lc = content.to_ascii_lowercase();

    let import_strings = extract_import_strings_regex(content, language);
    let import_categories = classify_imports(&import_strings);
    let function_count = count_functions_regex(content, language);

    let has_auth_logic = import_categories
        .iter()
        .any(|c| matches!(c, DetectedImportCategory::Auth));
    let has_crypto_operations = import_categories
        .iter()
        .any(|c| matches!(c, DetectedImportCategory::Crypto));
    let has_network_calls = import_categories
        .iter()
        .any(|c| matches!(c, DetectedImportCategory::Network));
    let has_file_io = import_categories
        .iter()
        .any(|c| matches!(c, DetectedImportCategory::Filesystem));

    let _ = &text_lc; // suppress warning

    let complexity_estimate = estimate_complexity(
        function_count,
        &import_categories,
        has_auth_logic,
        has_crypto_operations,
        has_network_calls,
    );

    Some(TreeSitterResult {
        confirmed_language: None,
        import_categories,
        has_auth_logic,
        has_crypto_operations,
        has_network_calls,
        has_file_io,
        function_count,
        complexity_estimate,
    })
}

#[cfg(feature = "tree-sitter")]
fn extract_import_strings(root: Node<'_>, source: &str) -> Vec<String> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();
    collect_import_nodes(root, &mut cursor, source, &mut imports);
    imports
}

#[cfg(feature = "tree-sitter")]
#[allow(clippy::only_used_in_recursion)]
fn collect_import_nodes(
    node: Node<'_>,
    cursor: &mut tree_sitter::TreeCursor<'_>,
    source: &str,
    imports: &mut Vec<String>,
) {
    let kind = node.kind();
    if matches!(
        kind,
        "use_declaration"
            | "import_statement"
            | "import_declaration"
            | "import_spec"
            | "import_from_statement"
            | "package_clause"
    ) {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            imports.push(text.to_string());
        }
    }

    if node.child_count() > 0 {
        let mut child_cursor = node.walk();
        for child in node.children(&mut child_cursor) {
            collect_import_nodes(child, cursor, source, imports);
        }
    }
}

fn extract_import_strings_regex(content: &str, language: &str) -> Vec<String> {
    let mut imports = Vec::new();
    let patterns: &[&str] = match language {
        "rust" => &["use "],
        "python" => &["import ", "from "],
        "javascript" | "typescript" => &["import ", "require("],
        "go" => &["import "],
        "java" | "kotlin" => &["import "],
        "csharp" => &["using "],
        "ruby" => &["require "],
        "php" => &["use ", "require "],
        "cpp" | "c" => &["#include"],
        _ => &[],
    };

    for line in content.lines() {
        let trimmed = line.trim();
        for pattern in patterns {
            if trimmed.starts_with(pattern) || trimmed.contains(pattern) {
                imports.push(trimmed.to_string());
                break;
            }
        }
    }
    imports
}

fn classify_imports(imports: &[String]) -> Vec<DetectedImportCategory> {
    let mut categories = Vec::new();

    let crypto_keywords = [
        "openssl",
        "crypto",
        "cipher",
        "aes",
        "rsa",
        "hmac",
        "sha",
        "bcrypt",
        "argon",
        "pbkdf",
        "ed25519",
        "secp256k1",
        "nacl",
        "libsodium",
        "ring",
        "rustls",
        "mbedtls",
    ];
    let auth_keywords = [
        "oauth",
        "jwt",
        "auth",
        "session",
        "passport",
        "devise",
        "cancan",
        "pundit",
        "firebase_auth",
        "cognito",
        "keycloak",
        "ldap",
        "saml",
        "openid",
    ];
    let network_keywords = [
        "http",
        "https",
        "fetch",
        "axios",
        "reqwest",
        "hyper",
        "curl",
        "socket",
        "tcp",
        "udp",
        "websocket",
        "grpc",
        "net",
        "requests",
        "urllib",
        "aiohttp",
        "httpx",
    ];
    let database_keywords = [
        "sql",
        "postgres",
        "mysql",
        "sqlite",
        "mongodb",
        "redis",
        "dynamo",
        "cassandra",
        "diesel",
        "sqlx",
        "prisma",
        "sequelize",
        "mongoose",
        "typeorm",
        "orm",
    ];
    let filesystem_keywords = [
        "fs",
        "file",
        "path",
        "std::fs",
        "tokio::fs",
        "os.path",
        "pathlib",
        "shutil",
    ];
    let serialization_keywords = [
        "serde",
        "json",
        "xml",
        "yaml",
        "protobuf",
        "msgpack",
        "avro",
        "cbor",
        "flatbuffers",
    ];

    let joined = imports.join(" ").to_ascii_lowercase();

    if crypto_keywords.iter().any(|k| joined.contains(k)) {
        categories.push(DetectedImportCategory::Crypto);
    }
    if auth_keywords.iter().any(|k| joined.contains(k)) {
        categories.push(DetectedImportCategory::Auth);
    }
    if network_keywords.iter().any(|k| joined.contains(k)) {
        categories.push(DetectedImportCategory::Network);
    }
    if database_keywords.iter().any(|k| joined.contains(k)) {
        categories.push(DetectedImportCategory::Database);
    }
    if filesystem_keywords.iter().any(|k| joined.contains(k)) {
        categories.push(DetectedImportCategory::Filesystem);
    }
    if serialization_keywords.iter().any(|k| joined.contains(k)) {
        categories.push(DetectedImportCategory::Serialization);
    }

    categories
}

#[cfg(feature = "tree-sitter")]
fn count_functions(root: Node<'_>) -> u32 {
    let mut count = 0u32;
    count_functions_recursive(root, &mut count);
    count
}

#[cfg(feature = "tree-sitter")]
fn count_functions_recursive(node: Node<'_>, count: &mut u32) {
    let kind = node.kind();
    if matches!(
        kind,
        "function_item"
            | "function_definition"
            | "method_definition"
            | "function_declaration"
            | "method_declaration"
            | "arrow_function"
    ) {
        *count += 1;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        count_functions_recursive(child, count);
    }
}

fn count_functions_regex(content: &str, language: &str) -> u32 {
    let patterns: &[&str] = match language {
        "rust" => &["fn "],
        "python" => &["def "],
        "javascript" | "typescript" => &["function ", "=> "],
        "go" => &["func "],
        "java" | "kotlin" => &["void ", "fun "],
        "csharp" => &["void ", "async "],
        "ruby" => &["def "],
        "php" => &["function "],
        _ => &["function ", "fn ", "def ", "func "],
    };

    let mut count = 0u32;
    for line in content.lines() {
        let trimmed = line.trim();
        for pattern in patterns {
            if trimmed.contains(pattern) {
                count += 1;
                break;
            }
        }
    }
    count
}

fn estimate_complexity(
    function_count: u32,
    import_categories: &[DetectedImportCategory],
    has_auth: bool,
    has_crypto: bool,
    has_network: bool,
) -> u8 {
    let cat_count = import_categories.len();
    let has_db = import_categories
        .iter()
        .any(|c| matches!(c, DetectedImportCategory::Database));

    if (function_count >= 40 && has_auth && has_crypto) || (has_network && has_db && has_auth) {
        return 5;
    }
    if function_count >= 40 || cat_count >= 4 || (has_auth && has_crypto) {
        return 4;
    }
    if function_count >= 15 || cat_count >= 3 {
        return 3;
    }
    if function_count >= 5 || cat_count >= 1 {
        return 2;
    }
    1
}

fn count_hits(text: &str, patterns: &[&str]) -> u32 {
    patterns.iter().filter(|p| text.contains(*p)).count() as u32
}

fn is_yaml(text: &str) -> bool {
    let yaml_line_count = text
        .lines()
        .filter(|line| {
            let t = line.trim();
            !t.is_empty() && !t.starts_with('#') && (t.contains(": ") || t.starts_with("- "))
        })
        .count();
    let total_lines = text.lines().filter(|l| !l.trim().is_empty()).count().max(1);
    yaml_line_count * 100 / total_lines > 60
}

fn is_likely_json(content: &str) -> bool {
    let trimmed = content.trim();
    (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
}

#[cfg(feature = "tree-sitter")]
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
        kind: ArtifactKind::CodeBlock {
            language: language.to_string(),
        },
        commitment: Some(sha256_hex(format!("code_block:{language}:{content}"))),
        severity: ArtifactSeverity::Low,
        location,
        redacted_hint: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristic_language_detects_rust() {
        let code = "fn main() { let mut x = 5; impl Foo { pub struct Bar; } }";
        assert_eq!(heuristic_language(code), Some("rust".to_string()));
    }

    #[test]
    fn heuristic_language_detects_python() {
        let code = "import os\ndef main():\n    class Foo:\n        self.x = 1\n    print('hello')";
        assert_eq!(heuristic_language(code), Some("python".to_string()));
    }

    #[test]
    fn heuristic_language_detects_go() {
        let code = "package main\nfunc main() {\n    x := 5\n    fmt.Println(x)\n}";
        assert_eq!(heuristic_language(code), Some("go".to_string()));
    }

    #[test]
    fn heuristic_language_detects_sql() {
        let code = "SELECT * FROM users WHERE id = 1 GROUP BY name";
        assert_eq!(heuristic_language(code), Some("sql".to_string()));
    }

    #[test]
    fn heuristic_language_returns_none_for_prose() {
        let prose = "The quick brown fox jumps over the lazy dog. This is just plain text.";
        assert_eq!(heuristic_language(prose), None);
    }

    #[test]
    fn has_code_content_detects_code() {
        let code = "```rust\nfn main() {\n    let x = 5;\n    if (x > 0) {\n        return x;\n    }\n}\n```";
        assert!(has_code_content(code));
    }

    #[test]
    fn has_code_content_rejects_prose() {
        let prose = "Hello world, this is a simple sentence about something.";
        assert!(!has_code_content(prose));
    }

    #[test]
    fn ast_normalized_hash_stable_across_comments() {
        let code1 = "fn main() {\n    let x = 5; // comment\n}\n";
        let code2 = "fn main() {\n    let x = 5; // different comment\n}\n";
        let h1 = ast_normalized_hash(code1, "rust");
        let h2 = ast_normalized_hash(code2, "rust");
        assert!(h1.is_some());
        assert_eq!(h1, h2);
    }

    #[test]
    fn ast_normalized_hash_stable_across_whitespace() {
        let code1 = "fn  main()  {\n    let  x  =  5;\n}\n";
        let code2 = "fn main() {\n  let x = 5;\n}\n";
        let h1 = ast_normalized_hash(code1, "rust");
        let h2 = ast_normalized_hash(code2, "rust");
        assert!(h1.is_some());
        assert_eq!(h1, h2);
    }

    #[test]
    fn ast_normalized_hash_replaces_strings() {
        let code1 = "let x = \"hello\";";
        let code2 = "let x = \"world\";";
        let h1 = ast_normalized_hash(code1, "rust");
        let h2 = ast_normalized_hash(code2, "rust");
        assert!(h1.is_some());
        assert_eq!(h1, h2);
    }

    #[test]
    fn detect_code_artifacts_returns_full_result() {
        let code = "fn main() {\n    let mut x = 5;\n    impl Foo { pub struct Bar; }\n    use std::io;\n}";
        let result = detect_code_artifacts(code, ArtifactLocation::Unknown);
        assert!(result.detected_language.is_some());
        assert!(!result.artifacts.is_empty());
    }

    #[test]
    fn detect_code_artifacts_empty_for_prose() {
        let prose = "Hello world, this is a simple sentence.";
        let result = detect_code_artifacts(prose, ArtifactLocation::Unknown);
        assert!(result.artifacts.is_empty());
        assert!(result.detected_language.is_none());
    }
}

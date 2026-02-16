use super::*;

#[test]
fn test_strip_managed_block() {
    let input =
        "line1\n# >>> SOTH Setup Wizard >>>\nexport A=1\n# <<< SOTH Setup Wizard <<<\nline2\n";
    let output = setup_helpers::strip_managed_block(input);
    assert!(output.contains("line1"));
    assert!(output.contains("line2"));
    assert!(!output.contains("export A=1"));
}

#[test]
fn test_render_shell_block_contains_markers() {
    let block = setup_helpers::render_shell_block("zsh", "http://127.0.0.1:8080");
    assert!(block.contains(WIZARD_BEGIN_MARKER));
    assert!(block.contains(WIZARD_END_MARKER));
    assert!(block.contains("HTTP_PROXY"));
    assert!(block.contains("CURL_CA_BUNDLE"));
    assert!(block.contains("GIT_SSL_CAINFO"));
    assert!(block.contains("AWS_CA_BUNDLE"));
    assert!(block.contains("NO_PROXY"));
    assert!(block.contains("no_proxy"));
}

#[test]
fn test_normalize_shell_name() {
    assert_eq!(setup_helpers::normalize_shell_name("zsh"), "zsh");
    assert_eq!(setup_helpers::normalize_shell_name("BASH"), "bash");
}

#[test]
fn test_expand_user_path_tilde() {
    let path = setup_helpers::expand_user_path(Path::new("~/tmp/file.json"));
    assert!(path.is_absolute());
    assert!(path.display().to_string().contains("tmp/file.json"));
}

#[test]
fn test_resolve_mcp_config_paths_dedupes() {
    let paths = vec![
        PathBuf::from("~/tmp/a.json"),
        PathBuf::from("~/tmp/a.json"),
        PathBuf::from("./tmp/b.json"),
    ];
    let resolved = resolve_mcp_config_paths(&paths);
    assert_eq!(resolved.len(), 2);
}

#[test]
fn test_restore_backup_entries_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("file.txt");
    let backup = temp.path().join("backup.txt");
    let created = temp.path().join("created.txt");

    fs::write(&original, "old").unwrap();
    fs::copy(&original, &backup).unwrap();
    fs::write(&original, "new").unwrap();
    fs::write(&created, "temporary").unwrap();

    let entries = vec![
        BackupEntry {
            original_path: original.display().to_string(),
            backup_path: Some(backup.display().to_string()),
            existed_before: true,
        },
        BackupEntry {
            original_path: created.display().to_string(),
            backup_path: None,
            existed_before: false,
        },
    ];

    restore_backup_entries(&entries).unwrap();

    assert_eq!(fs::read_to_string(&original).unwrap(), "old");
    assert!(!created.exists());
}

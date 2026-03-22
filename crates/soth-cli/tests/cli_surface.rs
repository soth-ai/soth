use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_soth"))
        .args(args)
        .output()
        .expect("failed to execute soth binary")
}

#[test]
fn help_lists_supported_commands() {
    let out = run_cli(&["--help"]);
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    for token in [
        "start", "stop", "up", "down", "on", "off", "logs", "status", "init", "enroll", "setup-ca",
        "doctor", "env", "events", "bundle",
    ] {
        assert!(
            stdout.contains(token),
            "expected `--help` output to contain `{token}`"
        );
    }
}

#[test]
fn removed_wrap_command_is_not_available() {
    let out = run_cli(&["wrap", "--help"]);
    assert!(!out.status.success());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unrecognized subcommand") || stderr.contains("unexpected argument"),
        "expected clap parse error in stderr, got: {stderr}"
    );
}

#[test]
fn events_help_lists_list_and_stream() {
    let out = run_cli(&["events", "--help"]);
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("list"));
    assert!(stdout.contains("stream"));
}

#[test]
fn bundle_help_lists_status_and_verify() {
    let out = run_cli(&["bundle", "--help"]);
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("status"));
    assert!(stdout.contains("verify"));
}

#[test]
fn doctor_help_lists_json_flag() {
    let out = run_cli(&["doctor", "--help"]);
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--json"));
}

#[test]
fn status_schema_doc_contains_stable_fields() {
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("STATUS_JSON_SCHEMA.md");
    let schema = fs::read_to_string(&schema_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", schema_path.display()));

    for field in [
        "\"proxy\"",
        "\"bundle\"",
        "\"sync\"",
        "\"last_24h\"",
        "\"healthy\"",
        "\"running\"",
        "\"sig_valid\"",
        "\"queued\"",
        "\"failed\"",
        "\"cost_usd\"",
    ] {
        assert!(
            schema.contains(field),
            "expected STATUS_JSON_SCHEMA.md to contain {field}"
        );
    }
}

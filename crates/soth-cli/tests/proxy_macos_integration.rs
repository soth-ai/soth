#[cfg(target_os = "macos")]
mod macos_proxy_integration {
    use std::process::Command;

    fn run_cli(args: &[&str], soth_home: &std::path::Path) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_soth"))
            .args(args)
            .env("SOTH_HOME_DIR", soth_home)
            .output()
            .expect("failed to execute soth binary")
    }

    fn should_run() -> bool {
        std::env::var("SOTH_RUN_MACOS_PROXY_IT")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    #[test]
    #[ignore = "opt-in integration test; modifies macOS system proxy settings"]
    fn on_off_roundtrip_is_idempotent() {
        if !should_run() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let on = run_cli(&["on", "--port", "18880"], temp.path());
        assert!(
            on.status.success(),
            "soth on failed: {}",
            String::from_utf8_lossy(&on.stderr)
        );

        let off = run_cli(&["off"], temp.path());
        assert!(
            off.status.success(),
            "soth off failed: {}",
            String::from_utf8_lossy(&off.stderr)
        );

        let off_again = run_cli(&["off"], temp.path());
        assert!(
            off_again.status.success(),
            "second soth off failed: {}",
            String::from_utf8_lossy(&off_again.stderr)
        );
    }

    #[test]
    #[ignore = "opt-in integration test; requires macOS networksetup access"]
    fn doctor_json_reports_expected_fields() {
        if !should_run() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let out = run_cli(&["doctor", "--json"], temp.path());
        assert!(
            out.status.success(),
            "soth doctor failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let json: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("doctor output should be valid JSON");
        assert!(json.get("daemon").is_some());
        assert!(json.get("system_proxy").is_some());
        assert!(json.get("loopback_bindings").is_some());
        assert!(json.get("findings").is_some());
    }
}

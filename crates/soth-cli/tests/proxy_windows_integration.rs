#[cfg(target_os = "windows")]
mod windows_proxy_integration {
    use std::process::Command;

    fn run_cli(args: &[&str], soth_home: &std::path::Path) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_soth"))
            .args(args)
            .env("SOTH_HOME_DIR", soth_home)
            .output()
            .expect("failed to execute soth binary")
    }

    fn should_run() -> bool {
        std::env::var("SOTH_RUN_WINDOWS_PROXY_IT")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    #[test]
    #[ignore = "opt-in integration test; modifies Windows proxy registry settings"]
    fn on_off_roundtrip_and_doctor_json() {
        if !should_run() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let on = run_cli(&["on", "--port", "18881"], temp.path());
        assert!(
            on.status.success(),
            "soth on failed: {}",
            String::from_utf8_lossy(&on.stderr)
        );

        let doctor = run_cli(&["doctor", "--json"], temp.path());
        assert!(
            doctor.status.success(),
            "soth doctor failed: {}",
            String::from_utf8_lossy(&doctor.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&doctor.stdout).expect("doctor output should be JSON");
        assert!(json.get("system_proxy").is_some());

        let off = run_cli(&["off"], temp.path());
        assert!(
            off.status.success(),
            "soth off failed: {}",
            String::from_utf8_lossy(&off.stderr)
        );
    }
}

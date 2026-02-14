//! Proxy UI command

use crate::cli_config;
use crate::style;
use anyhow::Context;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const DEFAULT_UI_DIR: &str = "dashboard";
const DEFAULT_UI_URL: &str = "http://localhost:3002";

/// Run `soth proxy ui start`.
pub async fn run_start(
    config_path: Option<PathBuf>,
    api_port: Option<u16>,
    dir: Option<PathBuf>,
    quiet: bool,
) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let resolved_api_port = api_port.unwrap_or(config.dashboard.port);
    let ui_dir = dir.unwrap_or_else(|| PathBuf::from(DEFAULT_UI_DIR));

    if !ui_dir.exists() {
        anyhow::bail!("UI directory not found: {}", ui_dir.display());
    }
    if !ui_dir.join("package.json").exists() {
        anyhow::bail!(
            "No package.json found in UI directory: {}",
            ui_dir.display()
        );
    }

    let mut cmd = Command::new(npm_executable());
    cmd.arg("run")
        .arg("dev")
        .current_dir(&ui_dir)
        .stdin(Stdio::null())
        .stdout(if quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .stderr(if quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .env(
            "NEXT_PUBLIC_SOTH_API_BASE",
            format!("http://localhost:{resolved_api_port}/api"),
        )
        .env(
            "NEXT_PUBLIC_SOTH_WS_BASE",
            format!("ws://localhost:{resolved_api_port}"),
        );
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| "failed to spawn UI dev server (`npm run dev`)")?;

    if !quiet {
        style::header("SOTH UI");
        style::kv("URL", DEFAULT_UI_URL);
        style::kv("API", &format!("http://localhost:{resolved_api_port}/api"));
        style::kv("PID", &child.id().to_string());
        style::info("Press Ctrl+C to stop.");
        println!();
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                stop_ui_process(&mut child, quiet);
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        if status.success() {
                            return Ok(());
                        }
                        anyhow::bail!("UI process exited with status {}", status);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        anyhow::bail!("failed checking UI process status: {}", error);
                    }
                }
            }
        }
    }

    if !quiet {
        style::success("UI stopped.");
    }

    Ok(())
}

fn npm_executable() -> &'static str {
    if cfg!(target_os = "windows") {
        "npm.cmd"
    } else {
        "npm"
    }
}

fn stop_ui_process(child: &mut Child, quiet: bool) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(error) => {
            if !quiet {
                style::warning(&format!("Failed to check UI process status: {}", error));
            }
            return;
        }
    }

    #[cfg(unix)]
    {
        let process_group = format!("-{}", child.id());
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(&process_group)
            .status();
        for _ in 0..10 {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(120)),
                Err(_) => break,
            }
        }
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(&process_group)
            .status();
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
    }

    if let Err(error) = child.kill() {
        if !quiet {
            style::warning(&format!("Failed to stop UI process: {}", error));
        }
        return;
    }

    if let Err(error) = child.wait() {
        if !quiet {
            style::warning(&format!(
                "Failed waiting for UI process shutdown: {}",
                error
            ));
        }
    }
}

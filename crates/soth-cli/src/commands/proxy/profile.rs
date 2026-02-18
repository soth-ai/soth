//! Proxy runtime profiles

use crate::style;
use clap::ValueEnum;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::{api, start, ui};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RuntimeProfile {
    SensorOnly,
    ApiOnly,
    UiOnly,
    DevStack,
}

pub async fn run_start(
    profile: RuntimeProfile,
    sensor_port: Option<u16>,
    api_port: Option<u16>,
    config_path: Option<PathBuf>,
    ui_dir: Option<PathBuf>,
    no_ui: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    match profile {
        RuntimeProfile::SensorOnly => {
            start::run(
                sensor_port,
                config_path,
                quiet,
                true,
                false,
                None,
                false,
                false,
            )
            .await
        }
        RuntimeProfile::ApiOnly => api::run_start(api_port, config_path, quiet).await,
        RuntimeProfile::UiOnly => ui::run_start(config_path, api_port, ui_dir, quiet).await,
        RuntimeProfile::DevStack => {
            run_dev_stack(sensor_port, api_port, config_path, ui_dir, no_ui, quiet).await
        }
    }
}

async fn run_dev_stack(
    sensor_port: Option<u16>,
    api_port: Option<u16>,
    config_path: Option<PathBuf>,
    ui_dir: Option<PathBuf>,
    no_ui: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    let mut children: Vec<ManagedChild> = Vec::new();

    let mut sensor_args = vec![
        "proxy".to_string(),
        "start".to_string(),
        "--foreground".to_string(),
        "--quiet".to_string(),
    ];
    if let Some(port) = sensor_port {
        sensor_args.push("--port".to_string());
        sensor_args.push(port.to_string());
    }
    if let Some(ref config) = config_path {
        sensor_args.push("--config".to_string());
        sensor_args.push(config.display().to_string());
    }
    children.push(spawn_child("sensor", &sensor_args)?);

    let mut api_args = vec![
        "proxy".to_string(),
        "api".to_string(),
        "start".to_string(),
        "--quiet".to_string(),
    ];
    if let Some(port) = api_port {
        api_args.push("--port".to_string());
        api_args.push(port.to_string());
    }
    if let Some(ref config) = config_path {
        api_args.push("--config".to_string());
        api_args.push(config.display().to_string());
    }
    children.push(spawn_child("api", &api_args)?);

    if !no_ui {
        let mut ui_args = vec![
            "proxy".to_string(),
            "ui".to_string(),
            "start".to_string(),
            "--quiet".to_string(),
        ];
        if let Some(port) = api_port {
            ui_args.push("--api-port".to_string());
            ui_args.push(port.to_string());
        }
        if let Some(ref dir) = ui_dir {
            ui_args.push("--dir".to_string());
            ui_args.push(dir.display().to_string());
        }
        if let Some(ref config) = config_path {
            ui_args.push("--config".to_string());
            ui_args.push(config.display().to_string());
        }
        children.push(spawn_child("ui", &ui_args)?);
    }

    if !quiet {
        style::header("SOTH Runtime Profile");
        style::kv("Profile", "dev-stack");
        for child in &children {
            style::kv(
                &format!("{} pid", child.name.to_uppercase()),
                &child.pid().to_string(),
            );
        }
        style::info("Press Ctrl+C to stop all profile services.");
        println!();
    }

    let tick = Duration::from_millis(250);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                for child in children.iter_mut().rev() {
                    stop_child(child, quiet);
                }
                if !quiet {
                    style::success("Profile stopped.");
                }
                return Ok(());
            }
            _ = tokio::time::sleep(tick) => {
                for idx in 0..children.len() {
                    if let Some(status) = children[idx].child.try_wait()? {
                        let exited = children.remove(idx);
                        for child in children.iter_mut().rev() {
                            stop_child(child, quiet);
                        }
                        anyhow::bail!(
                            "{} runtime exited unexpectedly with status {}",
                            exited.name,
                            status
                        );
                    }
                }
            }
        }
    }
}

struct ManagedChild {
    name: &'static str,
    child: Child,
}

impl ManagedChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

fn spawn_child(name: &'static str, args: &[String]) -> anyhow::Result<ManagedChild> {
    let current = std::env::current_exe()?;
    let mut cmd = Command::new(current);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let child = cmd.spawn()?;
    Ok(ManagedChild { name, child })
}

fn stop_child(child: &mut ManagedChild, quiet: bool) {
    match child.child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(error) => {
            if !quiet {
                style::warning(&format!(
                    "Failed checking {} runtime status: {}",
                    child.name, error
                ));
            }
            return;
        }
    }

    #[cfg(unix)]
    {
        let process_group = format!("-{}", child.pid());
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(&process_group)
            .status();
        for _ in 0..10 {
            match child.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(120)),
                Err(_) => break,
            }
        }
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(&process_group)
            .status();
        if child.child.try_wait().ok().flatten().is_some() {
            return;
        }
    }

    if let Err(error) = child.child.kill() {
        if !quiet {
            style::warning(&format!(
                "Failed stopping {} runtime: {}",
                child.name, error
            ));
        }
        return;
    }
    if let Err(error) = child.child.wait() {
        if !quiet {
            style::warning(&format!(
                "Failed waiting for {} runtime shutdown: {}",
                child.name, error
            ));
        }
    }
}

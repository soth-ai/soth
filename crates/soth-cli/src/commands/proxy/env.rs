//! Environment variable output command

use crate::cli_config;
use std::path::PathBuf;

const ENV_VARS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "CURL_CA_BUNDLE",
];

/// Run the env command
pub async fn run(
    shell: &str,
    ca_only: bool,
    unset: bool,
    hook: bool,
    config_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    if hook {
        let kind = match shell.to_ascii_lowercase().as_str() {
            "bash" | "sh" => super::shell_env::ShellKind::Bash,
            "zsh" => super::shell_env::ShellKind::Zsh,
            "fish" => super::shell_env::ShellKind::Fish,
            other => {
                anyhow::bail!(
                    "`soth env --hook` is supported for bash, zsh, and fish (got: {other})"
                );
            }
        };
        println!("{}", super::shell_env::render_hook(kind));
        return Ok(());
    }

    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let ca_paths = super::ca_health::resolve_ca_paths(&config);
    let ca_path = ca_paths.trust_cert_path.display().to_string();
    let proxy_addr = format!("http://{}", config.forward_proxy.socket_addr());

    if ca_only {
        println!("{ca_path}");
        return Ok(());
    }

    match shell.to_lowercase().as_str() {
        "bash" | "zsh" | "sh" => {
            if unset {
                println!("unset {}", ENV_VARS.join(" "));
                println!("# Run: eval \"$(soth env --unset)\"");
            } else {
                println!("export HTTP_PROXY={proxy_addr}");
                println!("export HTTPS_PROXY={proxy_addr}");
                println!("export http_proxy={proxy_addr}");
                println!("export https_proxy={proxy_addr}");
                println!("export NO_PROXY=localhost,127.0.0.1,::1");
                println!("export no_proxy=localhost,127.0.0.1,::1");
                println!("export SSL_CERT_FILE={ca_path}");
                println!("export REQUESTS_CA_BUNDLE={ca_path}");
                println!("export NODE_EXTRA_CA_CERTS={ca_path}");
                println!("export CURL_CA_BUNDLE={ca_path}");
                println!("# Run: eval \"$(soth env)\"");
            }
        }
        "fish" => {
            if unset {
                for key in ENV_VARS {
                    println!("set -e {key}");
                    println!("set -e -g {key}");
                    println!("set -e -U {key}");
                }
                println!("# Run: eval (soth env --shell fish --unset)");
            } else {
                println!("set -gx HTTP_PROXY {proxy_addr}");
                println!("set -gx HTTPS_PROXY {proxy_addr}");
                println!("set -gx http_proxy {proxy_addr}");
                println!("set -gx https_proxy {proxy_addr}");
                println!("set -gx NO_PROXY localhost,127.0.0.1,::1");
                println!("set -gx no_proxy localhost,127.0.0.1,::1");
                println!("set -gx SSL_CERT_FILE {ca_path}");
                println!("set -gx REQUESTS_CA_BUNDLE {ca_path}");
                println!("set -gx NODE_EXTRA_CA_CERTS {ca_path}");
                println!("set -gx CURL_CA_BUNDLE {ca_path}");
                println!("# Run: eval (soth env --shell fish)");
            }
        }
        "powershell" | "pwsh" => {
            if unset {
                for key in ENV_VARS {
                    println!("Remove-Item Env:{key} -ErrorAction SilentlyContinue");
                }
                println!("# Run in PowerShell to clear variables");
            } else {
                println!("$env:HTTP_PROXY = \"{proxy_addr}\"");
                println!("$env:HTTPS_PROXY = \"{proxy_addr}\"");
                println!("$env:NO_PROXY = \"localhost,127.0.0.1,::1\"");
                println!("$env:no_proxy = \"localhost,127.0.0.1,::1\"");
                println!("$env:SSL_CERT_FILE = \"{ca_path}\"");
                println!("$env:REQUESTS_CA_BUNDLE = \"{ca_path}\"");
                println!("$env:NODE_EXTRA_CA_CERTS = \"{ca_path}\"");
                println!("$env:CURL_CA_BUNDLE = \"{ca_path}\"");
                println!("# Run in PowerShell to set variables");
            }
        }
        "cmd" => {
            if unset {
                for key in ENV_VARS {
                    println!("set {key}=");
                }
                println!("REM Run each line in Command Prompt to clear variables");
            } else {
                println!("set HTTP_PROXY={proxy_addr}");
                println!("set HTTPS_PROXY={proxy_addr}");
                println!("set NO_PROXY=localhost,127.0.0.1,::1");
                println!("set no_proxy=localhost,127.0.0.1,::1");
                println!("set SSL_CERT_FILE={ca_path}");
                println!("set REQUESTS_CA_BUNDLE={ca_path}");
                println!("set NODE_EXTRA_CA_CERTS={ca_path}");
                println!("set CURL_CA_BUNDLE={ca_path}");
                println!("REM Run each line in Command Prompt");
            }
        }
        _ => {
            println!("# Unknown shell: {shell}");
            println!("# Environment variables needed:");
            if unset {
                println!("# unset {}", ENV_VARS.join(" "));
            } else {
                println!("# HTTP_PROXY={proxy_addr}");
                println!("# HTTPS_PROXY={proxy_addr}");
                println!("# SSL_CERT_FILE={ca_path}");
                println!("# REQUESTS_CA_BUNDLE={ca_path}");
                println!("# NODE_EXTRA_CA_CERTS={ca_path}");
                println!("# CURL_CA_BUNDLE={ca_path}");
            }
        }
    }

    Ok(())
}

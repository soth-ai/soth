//! Environment variable output command

use crate::cli_config;
use std::path::PathBuf;

/// Run the env command
pub async fn run(shell: &str, ca_only: bool, config_path: Option<PathBuf>) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let ca_path = cli_config::expand_tilde(&config.forward_proxy.ca.cert_path)
        .display()
        .to_string();
    let proxy_addr = format!("http://{}", config.forward_proxy.socket_addr());

    if ca_only {
        println!("{}", ca_path);
        return Ok(());
    }

    match shell.to_lowercase().as_str() {
        "bash" | "zsh" | "sh" => {
            println!("export HTTP_PROXY={}", proxy_addr);
            println!("export HTTPS_PROXY={}", proxy_addr);
            println!("export http_proxy={}", proxy_addr);
            println!("export https_proxy={}", proxy_addr);
            println!("export NO_PROXY=localhost,127.0.0.1,::1");
            println!("export no_proxy=localhost,127.0.0.1,::1");
            println!("export SSL_CERT_FILE={}", ca_path);
            println!("export REQUESTS_CA_BUNDLE={}", ca_path);
            println!("export NODE_EXTRA_CA_CERTS={}", ca_path);
            println!("export CURL_CA_BUNDLE={}", ca_path);
            println!("export GIT_SSL_CAINFO={}", ca_path);
            println!("export AWS_CA_BUNDLE={}", ca_path);
            println!("# Run: eval $(soth runtime env)");
        }
        "fish" => {
            println!("set -gx HTTP_PROXY {}", proxy_addr);
            println!("set -gx HTTPS_PROXY {}", proxy_addr);
            println!("set -gx http_proxy {}", proxy_addr);
            println!("set -gx https_proxy {}", proxy_addr);
            println!("set -gx NO_PROXY localhost,127.0.0.1,::1");
            println!("set -gx no_proxy localhost,127.0.0.1,::1");
            println!("set -gx SSL_CERT_FILE {}", ca_path);
            println!("set -gx REQUESTS_CA_BUNDLE {}", ca_path);
            println!("set -gx NODE_EXTRA_CA_CERTS {}", ca_path);
            println!("set -gx CURL_CA_BUNDLE {}", ca_path);
            println!("set -gx GIT_SSL_CAINFO {}", ca_path);
            println!("set -gx AWS_CA_BUNDLE {}", ca_path);
            println!("# Run: eval (soth runtime env --shell fish)");
        }
        "powershell" | "pwsh" => {
            println!("$env:HTTP_PROXY = \"{}\"", proxy_addr);
            println!("$env:HTTPS_PROXY = \"{}\"", proxy_addr);
            println!("$env:NO_PROXY = \"localhost,127.0.0.1,::1\"");
            println!("$env:no_proxy = \"localhost,127.0.0.1,::1\"");
            println!("$env:SSL_CERT_FILE = \"{}\"", ca_path);
            println!("$env:REQUESTS_CA_BUNDLE = \"{}\"", ca_path);
            println!("$env:NODE_EXTRA_CA_CERTS = \"{}\"", ca_path);
            println!("$env:CURL_CA_BUNDLE = \"{}\"", ca_path);
            println!("$env:GIT_SSL_CAINFO = \"{}\"", ca_path);
            println!("$env:AWS_CA_BUNDLE = \"{}\"", ca_path);
            println!("# Run in PowerShell to set variables");
        }
        "cmd" => {
            println!("set HTTP_PROXY={}", proxy_addr);
            println!("set HTTPS_PROXY={}", proxy_addr);
            println!("set NO_PROXY=localhost,127.0.0.1,::1");
            println!("set no_proxy=localhost,127.0.0.1,::1");
            println!("set SSL_CERT_FILE={}", ca_path);
            println!("set REQUESTS_CA_BUNDLE={}", ca_path);
            println!("set NODE_EXTRA_CA_CERTS={}", ca_path);
            println!("set CURL_CA_BUNDLE={}", ca_path);
            println!("set GIT_SSL_CAINFO={}", ca_path);
            println!("set AWS_CA_BUNDLE={}", ca_path);
            println!("REM Run each line in Command Prompt");
        }
        _ => {
            println!("# Unknown shell: {}", shell);
            println!("# Environment variables needed:");
            println!("# HTTP_PROXY={}", proxy_addr);
            println!("# HTTPS_PROXY={}", proxy_addr);
            println!("# SSL_CERT_FILE={}", ca_path);
            println!("# REQUESTS_CA_BUNDLE={}", ca_path);
            println!("# NODE_EXTRA_CA_CERTS={}", ca_path);
            println!("# CURL_CA_BUNDLE={}", ca_path);
            println!("# GIT_SSL_CAINFO={}", ca_path);
            println!("# AWS_CA_BUNDLE={}", ca_path);
        }
    }

    Ok(())
}

//! Environment variable output command

/// Expand tilde in path
fn expand_path(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]).display().to_string();
        }
    }
    path.to_string()
}

/// Run the env command
pub async fn run(shell: &str, ca_only: bool) -> anyhow::Result<()> {
    let ca_path = expand_path("~/.soth/ca/ca.crt");
    let proxy_addr = "http://127.0.0.1:8080";

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
            println!("export SSL_CERT_FILE={}", ca_path);
            println!("export REQUESTS_CA_BUNDLE={}", ca_path);
            println!("export NODE_EXTRA_CA_CERTS={}", ca_path);
            println!("# Run: eval $(soth proxy env)");
        }
        "fish" => {
            println!("set -gx HTTP_PROXY {}", proxy_addr);
            println!("set -gx HTTPS_PROXY {}", proxy_addr);
            println!("set -gx http_proxy {}", proxy_addr);
            println!("set -gx https_proxy {}", proxy_addr);
            println!("set -gx SSL_CERT_FILE {}", ca_path);
            println!("set -gx REQUESTS_CA_BUNDLE {}", ca_path);
            println!("set -gx NODE_EXTRA_CA_CERTS {}", ca_path);
            println!("# Run: eval (soth proxy env --shell fish)");
        }
        "powershell" | "pwsh" => {
            println!("$env:HTTP_PROXY = \"{}\"", proxy_addr);
            println!("$env:HTTPS_PROXY = \"{}\"", proxy_addr);
            println!("$env:SSL_CERT_FILE = \"{}\"", ca_path);
            println!("$env:REQUESTS_CA_BUNDLE = \"{}\"", ca_path);
            println!("$env:NODE_EXTRA_CA_CERTS = \"{}\"", ca_path);
            println!("# Run in PowerShell to set variables");
        }
        "cmd" => {
            println!("set HTTP_PROXY={}", proxy_addr);
            println!("set HTTPS_PROXY={}", proxy_addr);
            println!("set SSL_CERT_FILE={}", ca_path);
            println!("set REQUESTS_CA_BUNDLE={}", ca_path);
            println!("set NODE_EXTRA_CA_CERTS={}", ca_path);
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
        }
    }

    Ok(())
}

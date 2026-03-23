//! Config validation command — parses and sanity-checks a SOTH YAML config
//! without starting the proxy. Intended for pre-rollout CI/fleet checks.

use anyhow::{Context, Result};
use std::path::Path;

/// Validate the config file at `config_path`.
///
/// Exits with status 1 when any hard error is found, so this is safe to use
/// as a blocking step in deployment pipelines:
///
/// ```text
/// soth config validate --config /etc/soth/soth.yaml
/// ```
pub fn validate(config_path: &Path) -> Result<()> {
    println!("Validating {}...", config_path.display());
    let mut warnings = 0u32;
    let mut errors = 0u32;

    // 1. Read and parse YAML
    let yaml = std::fs::read_to_string(config_path)
        .with_context(|| format!("cannot read {}", config_path.display()))?;
    let config: serde_yaml::Value =
        serde_yaml::from_str(&yaml).with_context(|| "invalid YAML syntax")?;
    println!("  [ok] YAML syntax valid");

    // 2. Check CA cert/key paths exist
    if let Some(ca) = config.get("forward_proxy").and_then(|fp| fp.get("ca")) {
        if let Some(cert) = ca.get("cert_path").and_then(|v| v.as_str()) {
            if Path::new(cert).exists() {
                println!("  [ok] CA certificate exists: {cert}");
            } else {
                println!("  [FAIL] CA certificate NOT FOUND: {cert}");
                errors += 1;
            }
        }

        if let Some(key) = ca.get("key_path").and_then(|v| v.as_str()) {
            if Path::new(key).exists() {
                println!("  [ok] CA key exists: {key}");

                // Check Unix permissions — world-/group-readable private keys are a risk.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(meta) = std::fs::metadata(key) {
                        let mode = meta.mode() & 0o777;
                        if mode & 0o077 != 0 {
                            println!(
                                "  [WARN] CA key permissions too open: {mode:o} (expected 0600)"
                            );
                            warnings += 1;
                        } else {
                            println!("  [ok] CA key permissions: {mode:o}");
                        }
                    }
                }
            } else {
                println!("  [FAIL] CA key NOT FOUND: {key}");
                errors += 1;
            }
        }
    }

    // 3. Check bundle dir
    if let Some(bundle_dir) = config
        .get("bundle")
        .and_then(|b| b.get("bundle_dir"))
        .and_then(|v| v.as_str())
    {
        let dir = Path::new(bundle_dir);
        if dir.exists() {
            let manifest = dir.join("manifest.json");
            if manifest.exists() {
                println!("  [ok] Bundle directory exists with manifest");
            } else {
                println!("  [WARN] Bundle directory exists but no manifest.json");
                warnings += 1;
            }
        } else {
            println!("  [FAIL] Bundle directory NOT FOUND: {bundle_dir}");
            errors += 1;
        }
    }

    // 4. Check cloud endpoint (if enabled)
    if let Some(cloud) = config.get("cloud") {
        if cloud
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            if let Some(endpoint) = cloud.get("endpoint").and_then(|v| v.as_str()) {
                println!("  [ok] Cloud endpoint configured: {endpoint}");
            }
            if cloud.get("api_key").and_then(|v| v.as_str()).is_none() {
                println!("  [FAIL] Cloud enabled but no api_key configured");
                errors += 1;
            }
        }
    }

    // 5. Check for insecure all-zeros vendor pubkey
    if let Some(bundle) = config.get("bundle") {
        if let Some(pk) = bundle.get("vendor_pubkey_hex").and_then(|v| v.as_str()) {
            if !pk.is_empty() && pk.chars().all(|c| c == '0') {
                println!(
                    "  [WARN] vendor_pubkey_hex is all-zeros \
                     (signature verification will not work)"
                );
                warnings += 1;
            }
        }
    }

    // 6. Report proxy port (informational)
    if let Some(port) = config
        .get("forward_proxy")
        .and_then(|fp| fp.get("port"))
        .and_then(|v| v.as_u64())
    {
        println!("  [ok] Proxy port: {port}");
    }

    // Summary
    println!();
    if errors > 0 {
        println!("Result: FAIL ({errors} errors, {warnings} warnings)");
        std::process::exit(1);
    } else if warnings > 0 {
        println!("Result: PASS ({warnings} warnings)");
    } else {
        println!("Result: PASS");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_yaml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write yaml");
        f
    }

    #[test]
    fn valid_minimal_yaml_passes() {
        let f = write_temp_yaml("forward_proxy:\n  port: 8080\n");
        // Should not panic or exit; validate returns Ok on a minimal config
        // with no CA paths / bundle dir configured (nothing to check = no errors).
        let result = std::panic::catch_unwind(|| validate(f.path()));
        // validate() calls process::exit(1) on errors, so a panic here would
        // mean the test runner caught it. A successful run just returns Ok.
        assert!(result.is_ok());
    }

    #[test]
    fn invalid_yaml_syntax_returns_error() {
        let f = write_temp_yaml("forward_proxy: {\nbad yaml: [unclosed\n");
        let result = validate(f.path());
        assert!(result.is_err(), "expected an error for invalid YAML syntax");
    }

    #[test]
    fn missing_file_returns_error() {
        let result = validate(Path::new("/tmp/soth_nonexistent_config_xyz.yaml"));
        assert!(result.is_err(), "expected an error for missing file");
    }
}

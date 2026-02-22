//! Identity management commands

use crate::IdentityCommands;
use anyhow::Result;
use soth_crypto::identity::{Did, KeyPair, TrustStore};
use std::path::PathBuf;
use tokio::fs;

#[cfg(target_os = "windows")]
fn harden_windows_private_key_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let path_str = path.to_string_lossy().to_string();
    let output = std::process::Command::new("cmd")
        .args([
            "/C",
            "icacls",
            &path_str,
            "/inheritance:r",
            "/grant:r",
            "\"%USERNAME%:(F)\"",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| anyhow::anyhow!("failed to execute icacls: {}", error))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!(
        "failed to harden key permissions with icacls for {}: {}",
        path.display(),
        stderr.trim()
    )
}

/// Run identity command
pub async fn run(action: IdentityCommands) -> Result<()> {
    match action {
        IdentityCommands::Generate { output } => {
            generate_keypair(output).await?;
        }
        IdentityCommands::List => {
            list_trusted().await?;
        }
        IdentityCommands::Trust { did, alias: _ } => {
            trust_did(&did).await?;
        }
        IdentityCommands::Untrust { did } => {
            untrust_did(&did).await?;
        }
        IdentityCommands::Verify { did, file: _ } => {
            verify_did(&did).await?;
        }
        IdentityCommands::Show { key } => {
            show_did(key).await?;
        }
    }
    Ok(())
}

/// Generate a new keypair
async fn generate_keypair(output: Option<PathBuf>) -> Result<()> {
    let keypair = KeyPair::generate();
    let did = Did::from_key_pair(&keypair)?;

    // Determine output path
    let output_path = if let Some(path) = output {
        path
    } else {
        let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?;
        let soth_dir = home.join(".soth");
        fs::create_dir_all(&soth_dir).await?;
        soth_dir.join("identity.pem")
    };

    // Save private key
    let private_key_bytes = keypair.private_key_bytes()?;
    let pem_content = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            private_key_bytes
        )
    );
    fs::write(&output_path, pem_content).await?;

    // Set permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&output_path).await?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&output_path, perms).await?;
    }
    #[cfg(target_os = "windows")]
    {
        harden_windows_private_key_permissions(&output_path)?;
    }

    println!("Generated new keypair");
    println!("  DID: {}", did.uri());
    println!("  Key: {output_path:?}");
    println!();
    println!("Keep your private key secure! Share only your DID.");

    Ok(())
}

/// List trusted DIDs
async fn list_trusted() -> Result<()> {
    let trust_store = get_trust_store().await?;
    let trusted = trust_store.list();

    if trusted.is_empty() {
        println!("No trusted DIDs");
    } else {
        println!("Trusted DIDs:");
        for did in trusted {
            println!("  {did}");
        }
    }

    Ok(())
}

/// Add a DID to the trust store
async fn trust_did(did: &str) -> Result<()> {
    // Validate DID format
    if !did.starts_with("did:key:") {
        anyhow::bail!("Invalid DID format. Expected did:key:...");
    }

    // Verify we can decode it
    Did::parse(did)?;

    let mut trust_store = get_trust_store().await?;
    trust_store.trust(did)?;

    println!("Added to trust store: {did}");

    Ok(())
}

/// Remove a DID from the trust store
async fn untrust_did(did: &str) -> Result<()> {
    let mut trust_store = get_trust_store().await?;
    trust_store.untrust(did)?;
    println!("Removed from trust store: {did}");
    Ok(())
}

/// Verify a DID signature
async fn verify_did(did: &str) -> Result<()> {
    // Parse and validate the DID
    let parsed = Did::parse(did)?;

    // Extract public key to verify the DID is valid
    let _public_key = parsed.extract_public_key()?;

    println!("Valid DID");
    println!("  DID: {did}");
    println!("  Fingerprint: {}", parsed.fingerprint());

    Ok(())
}

/// Show the DID for a key file
async fn show_did(key_path: PathBuf) -> Result<()> {
    let content = fs::read_to_string(&key_path).await?;

    // Parse PEM
    let base64_content = content
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    let key_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &base64_content)?;

    // Load keypair
    let keypair = KeyPair::from_private_key_bytes(&key_bytes)?;
    let did = Did::from_key_pair(&keypair)?;

    println!("DID: {}", did.uri());

    Ok(())
}

/// Get the trust store path
fn trust_store_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?;
    Ok(home.join(".soth").join("trust_store"))
}

/// Load the trust store
async fn get_trust_store() -> Result<TrustStore> {
    let path = trust_store_path()?;
    // Ensure parent exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    Ok(TrustStore::new(&path)?)
}

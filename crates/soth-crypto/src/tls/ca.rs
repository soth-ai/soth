//! Certificate Authority management

use super::cert_cache::CertCache;
use super::cert_gen::{CertGenerator, DEFAULT_CA_VALIDITY};
use super::error::{Result, TlsError};
use chrono::Utc;
use rcgen::{Certificate, CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::rustls::{self, ServerConfig};
use tracing::{debug, info};

/// Default CA common name
const DEFAULT_CA_CN: &str = "SOTH Proxy CA";
const DEFAULT_CACHE_ENTRIES: usize = 10_000;
const IDENTITY_METADATA_FILE: &str = "ca.identity.json";

#[cfg(windows)]
fn harden_windows_private_key_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let path_str = path.to_string_lossy().to_string();
    let mut cmd = std::process::Command::new("cmd");
    cmd.args([
        "/C",
        "icacls",
        &path_str,
        "/inheritance:r",
        "/grant:r",
        "\"%USERNAME%:(F)\"",
    ])
    .creation_flags(CREATE_NO_WINDOW);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "failed to harden CA private key ACL with icacls for {}: {}",
            path.display(),
            stderr.trim()
        ),
    ))
}

/// Persisted CA identity metadata for TLS key lifecycle traceability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaIdentityMetadata {
    /// Stable CA key identifier.
    pub ca_key_id: String,
    /// Whether TLS lifecycle is bound to org identity controls.
    pub bind_to_org_identity: bool,
    /// Leaf TTL in seconds.
    pub leaf_ttl_secs: u64,
    /// Optional active org key id/version reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_key_id: Option<String>,
    /// Last metadata update timestamp.
    pub updated_at: String,
}

/// Certificate Authority for generating TLS certificates
pub struct CertificateAuthority {
    /// CA certificate
    ca_cert: Certificate,
    /// CA private key
    ca_key: KeyPair,
    /// Certificate cache
    cache: CertCache,
    /// Certificate generator
    generator: CertGenerator,
    /// Storage path for CA files
    storage_path: PathBuf,
    /// Identity metadata for CA/leaf issuance tracking
    identity: CaIdentityMetadata,
}

impl CertificateAuthority {
    /// Generate a new CA and save to disk
    pub fn generate_new(storage_path: PathBuf) -> Result<Self> {
        info!("Generating new CA certificate at {:?}", storage_path);

        // Create directory if it doesn't exist
        fs::create_dir_all(&storage_path)?;

        // Generate CA
        let (ca_cert, ca_key) = CertGenerator::generate_ca(DEFAULT_CA_CN, None)?;

        // Save CA certificate and key
        let cert_path = storage_path.join("ca.crt");
        let key_path = storage_path.join("ca.key");

        fs::write(&cert_path, ca_cert.pem())?;
        fs::write(&key_path, ca_key.serialize_pem())?;

        // Set restrictive permissions on key file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_path, perms)?;
        }
        #[cfg(windows)]
        {
            harden_windows_private_key_permissions(&key_path)?;
        }

        info!("CA certificate generated: {:?}", cert_path);

        let identity = Self::load_or_create_identity_metadata(&storage_path, &ca_key)?;

        Ok(Self {
            ca_cert,
            ca_key,
            cache: CertCache::default(),
            generator: CertGenerator::new(),
            storage_path,
            identity,
        })
    }

    /// Load CA from disk
    pub fn load_from_path(storage_path: PathBuf) -> Result<Self> {
        let cert_path = storage_path.join("ca.crt");
        let key_path = storage_path.join("ca.key");

        debug!("Loading CA from {:?}", storage_path);

        // Read and parse CA certificate
        let cert_pem = fs::read_to_string(&cert_path)
            .map_err(|e| TlsError::cert_load(format!("Failed to read CA cert: {}", e)))?;

        // Read and parse CA key
        let key_pem = fs::read_to_string(&key_path)
            .map_err(|e| TlsError::key_load(format!("Failed to read CA key: {}", e)))?;

        // Parse the key
        let ca_key = KeyPair::from_pem(&key_pem)
            .map_err(|e| TlsError::key_load(format!("Failed to parse CA key: {}", e)))?;

        // Reconstruct the certificate from PEM
        // We need to parse the existing cert and recreate it with the key
        let ca_cert = Self::load_ca_cert_from_pem(&cert_pem, &ca_key)?;

        info!("CA certificate loaded from {:?}", cert_path);

        let identity = Self::load_or_create_identity_metadata(&storage_path, &ca_key)?;

        Ok(Self {
            ca_cert,
            ca_key,
            cache: CertCache::default(),
            generator: CertGenerator::new(),
            storage_path,
            identity,
        })
    }

    /// Helper to load CA certificate from PEM
    fn load_ca_cert_from_pem(pem: &str, key: &KeyPair) -> Result<Certificate> {
        // Parse the PEM to get the certificate bytes
        let mut reader = BufReader::new(pem.as_bytes());
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(TlsError::cert_load("No certificates found in PEM"));
        }

        // Parse the certificate to extract subject info
        let (_, cert) = x509_parser::parse_x509_certificate(&certs[0])
            .map_err(|e| TlsError::cert_load(format!("Failed to parse X.509: {}", e)))?;

        // Reconstruct CertificateParams from the parsed certificate
        let mut params = CertificateParams::default();

        // Copy subject from original cert
        let mut dn = rcgen::DistinguishedName::new();
        for rdn in cert.subject().iter() {
            for attr in rdn.iter() {
                if let Ok(s) = attr.as_str() {
                    if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                        dn.push(rcgen::DnType::CommonName, s);
                    } else if attr.attr_type()
                        == &x509_parser::oid_registry::OID_X509_ORGANIZATION_NAME
                    {
                        dn.push(rcgen::DnType::OrganizationName, s);
                    }
                }
            }
        }
        params.distinguished_name = dn;

        // CA-specific settings
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        // Set validity to match original or extend
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        params.not_after = time::OffsetDateTime::now_utc() + DEFAULT_CA_VALIDITY;

        // Create self-signed cert with the existing key
        let ca_cert = params
            .self_signed(key)
            .map_err(|e| TlsError::cert_generation(format!("Failed to reconstruct CA: {}", e)))?;

        Ok(ca_cert)
    }

    /// Load or generate CA
    pub fn load_or_generate(storage_path: PathBuf) -> Result<Self> {
        let cert_path = storage_path.join("ca.crt");
        let key_path = storage_path.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            Self::load_from_path(storage_path)
        } else {
            Self::generate_new(storage_path)
        }
    }

    /// Get or create a certificate for a domain
    ///
    /// Returns (cert_der, key_der) tuple
    pub fn get_or_create_cert(&self, domain: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        // Check cache first
        if let Some(cached) = self.cache.get(domain) {
            debug!("Using cached certificate for: {}", domain);
            return Ok((cached.cert_der, cached.key_der));
        }

        // Generate new certificate
        let (cert_der, key_der) =
            self.generator
                .generate_domain_cert(domain, &self.ca_cert, &self.ca_key)?;
        let leaf_key_id = leaf_key_id_from_der(&key_der);

        // Cache it
        self.cache.insert_with_identity(
            domain.to_string(),
            cert_der.clone(),
            key_der.clone(),
            self.generator.validity(),
            self.identity.ca_key_id.clone(),
            leaf_key_id,
        );

        Ok((cert_der, key_der))
    }

    /// Get rustls ServerConfig for a domain
    pub fn get_server_config(&self, domain: &str) -> Result<Arc<ServerConfig>> {
        let (cert_der, key_der) = self.get_or_create_cert(domain)?;

        // Convert to rustls types
        let cert = CertificateDer::from(cert_der);
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| {
                TlsError::cert_generation(format!("Failed to build ServerConfig: {}", e))
            })?;

        Ok(Arc::new(config))
    }

    /// Get the CA certificate in PEM format
    pub fn ca_cert_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// Get the CA certificate in DER format
    pub fn ca_cert_der(&self) -> Vec<u8> {
        self.ca_cert.der().to_vec()
    }

    /// Get the storage path
    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> super::cert_cache::CacheStats {
        self.cache.stats()
    }

    /// Clear the certificate cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Set certificate validity duration
    pub fn set_cert_validity(&mut self, validity: Duration) {
        self.generator = CertGenerator::with_validity(validity);
    }

    /// Set cache TTL and max entries
    pub fn set_cache_params(&mut self, ttl: Duration, max_entries: usize) {
        self.cache = CertCache::new(ttl, max_entries);
    }

    /// Apply crypto identity TLS settings and persist metadata.
    pub fn apply_crypto_tls_binding(
        &mut self,
        bind_to_org_identity: bool,
        leaf_ttl: Duration,
        org_key_id: Option<String>,
    ) -> Result<()> {
        self.identity.bind_to_org_identity = bind_to_org_identity;
        self.identity.leaf_ttl_secs = leaf_ttl.as_secs();
        self.identity.org_key_id = org_key_id;
        self.identity.updated_at = Utc::now().to_rfc3339();

        self.set_cert_validity(leaf_ttl);
        self.set_cache_params(leaf_ttl, DEFAULT_CACHE_ENTRIES);
        self.persist_identity_metadata()?;
        Ok(())
    }

    /// Apply crypto identity TLS settings from global config.
    pub fn apply_crypto_tls_config(
        &mut self,
        cfg: &soth_core::config::types::CryptoTlsBindingConfig,
        org_key_id: Option<String>,
    ) -> Result<()> {
        self.apply_crypto_tls_binding(cfg.bind_to_org_identity, cfg.leaf_ttl, org_key_id)
    }

    /// Read-only CA identity metadata.
    pub fn identity_metadata(&self) -> &CaIdentityMetadata {
        &self.identity
    }

    fn load_or_create_identity_metadata(
        storage_path: &Path,
        ca_key: &KeyPair,
    ) -> Result<CaIdentityMetadata> {
        let path = storage_path.join(IDENTITY_METADATA_FILE);
        if path.exists() {
            let data = fs::read_to_string(&path)?;
            let parsed: CaIdentityMetadata = serde_json::from_str(&data)
                .map_err(|e| TlsError::cert_load(format!("Failed to parse CA metadata: {}", e)))?;
            return Ok(parsed);
        }

        let metadata = CaIdentityMetadata {
            ca_key_id: ca_key_id(ca_key),
            bind_to_org_identity: true,
            leaf_ttl_secs: Duration::from_secs(24 * 60 * 60).as_secs(),
            org_key_id: None,
            updated_at: Utc::now().to_rfc3339(),
        };
        let json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| TlsError::cert_load(format!("Failed to serialize CA metadata: {}", e)))?;
        fs::write(path, json)?;
        Ok(metadata)
    }

    fn persist_identity_metadata(&self) -> Result<()> {
        let path = self.storage_path.join(IDENTITY_METADATA_FILE);
        let json = serde_json::to_string_pretty(&self.identity)
            .map_err(|e| TlsError::cert_load(format!("Failed to serialize CA metadata: {}", e)))?;
        fs::write(path, json)?;
        Ok(())
    }
}

fn ca_key_id(ca_key: &KeyPair) -> String {
    let digest = Sha256::digest(ca_key.serialize_der());
    format!("ca:{}", hex::encode(&digest[..8]))
}

fn leaf_key_id_from_der(key_der: &[u8]) -> String {
    let digest = Sha256::digest(key_der);
    format!("leaf:{}", hex::encode(&digest[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_new() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

        // Check files were created
        assert!(temp_dir.path().join("ca.crt").exists());
        assert!(temp_dir.path().join("ca.key").exists());

        // Check PEM is valid
        let pem = ca.ca_cert_pem();
        assert!(pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_load_from_path() {
        let temp_dir = TempDir::new().unwrap();

        // Generate first
        let _ca1 = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

        // Load it back
        let ca2 = CertificateAuthority::load_from_path(temp_dir.path().to_path_buf()).unwrap();
        assert!(!ca2.ca_cert_pem().is_empty());
    }

    #[test]
    fn test_get_or_create_cert() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

        let (cert1, key1) = ca.get_or_create_cert("example.com").unwrap();
        assert!(!cert1.is_empty());
        assert!(!key1.is_empty());

        // Second call should return cached
        let (cert2, key2) = ca.get_or_create_cert("example.com").unwrap();
        assert_eq!(cert1, cert2);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_get_server_config() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

        let config = ca.get_server_config("example.com").unwrap();
        // Just verify it doesn't panic and returns something
        assert!(Arc::strong_count(&config) >= 1);
    }

    #[test]
    fn test_cache_stats() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();

        ca.get_or_create_cert("domain1.com").unwrap();
        ca.get_or_create_cert("domain2.com").unwrap();

        let stats = ca.cache_stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.identity_bound_entries, 2);
        assert_eq!(stats.distinct_ca_key_ids, 1);
    }

    #[test]
    fn test_ca_identity_metadata_is_persisted() {
        let temp_dir = TempDir::new().unwrap();
        let ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();
        let metadata_path = temp_dir.path().join("ca.identity.json");
        assert!(metadata_path.exists());
        assert!(ca.identity_metadata().ca_key_id.starts_with("ca:"));
    }

    #[test]
    fn test_apply_crypto_tls_binding_updates_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let mut ca = CertificateAuthority::generate_new(temp_dir.path().to_path_buf()).unwrap();
        ca.apply_crypto_tls_binding(
            true,
            Duration::from_secs(2 * 60 * 60),
            Some("org:root:v3".to_string()),
        )
        .unwrap();

        let loaded = CertificateAuthority::load_from_path(temp_dir.path().to_path_buf()).unwrap();
        assert_eq!(
            loaded.identity_metadata().leaf_ttl_secs,
            Duration::from_secs(2 * 60 * 60).as_secs()
        );
        assert_eq!(
            loaded.identity_metadata().org_key_id.as_deref(),
            Some("org:root:v3")
        );
    }
}

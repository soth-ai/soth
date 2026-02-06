//! Certificate Authority management

use crate::cert_cache::CertCache;
use crate::cert_gen::{CertGenerator, DEFAULT_CA_VALIDITY};
use crate::error::{Result, TlsError};
use rcgen::{Certificate, CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::rustls::{self, ServerConfig};
use tracing::{debug, info};

/// Default CA common name
const DEFAULT_CA_CN: &str = "SOTH Proxy CA";

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

        info!("CA certificate generated: {:?}", cert_path);

        Ok(Self {
            ca_cert,
            ca_key,
            cache: CertCache::default(),
            generator: CertGenerator::new(),
            storage_path,
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

        Ok(Self {
            ca_cert,
            ca_key,
            cache: CertCache::default(),
            generator: CertGenerator::new(),
            storage_path,
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

        // Cache it
        self.cache
            .insert(domain.to_string(), cert_der.clone(), key_der.clone());

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
    pub fn cache_stats(&self) -> crate::cert_cache::CacheStats {
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
    }
}

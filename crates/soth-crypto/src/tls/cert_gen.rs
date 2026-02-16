//! Certificate generation utilities

use super::error::{Result, TlsError};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use std::time::Duration;
use tracing::debug;

/// Default certificate validity period (24 hours)
pub const DEFAULT_CERT_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);

/// Default CA validity period (10 years)
pub const DEFAULT_CA_VALIDITY: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// Certificate generator for creating domain certificates
pub struct CertGenerator {
    /// Certificate validity duration
    validity: Duration,
}

impl CertGenerator {
    /// Create a new certificate generator with default validity
    pub fn new() -> Self {
        Self {
            validity: DEFAULT_CERT_VALIDITY,
        }
    }

    /// Create with custom validity duration
    pub fn with_validity(validity: Duration) -> Self {
        Self { validity }
    }

    /// Current leaf certificate validity duration.
    pub fn validity(&self) -> Duration {
        self.validity
    }

    /// Generate a self-signed CA certificate
    pub fn generate_ca(
        common_name: &str,
        validity: Option<Duration>,
    ) -> Result<(Certificate, KeyPair)> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        dn.push(DnType::OrganizationName, "SOTH Proxy");
        params.distinguished_name = dn;

        // Set validity
        let validity = validity.unwrap_or(DEFAULT_CA_VALIDITY);
        let not_after = time::OffsetDateTime::now_utc() + validity;
        params.not_after = not_after;

        // CA-specific settings
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Generate keypair
        let key_pair = KeyPair::generate().map_err(|e| TlsError::key_generation(e.to_string()))?;

        // Generate certificate
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| TlsError::cert_generation(e.to_string()))?;

        debug!("Generated CA certificate: CN={}", common_name);
        Ok((cert, key_pair))
    }

    /// Generate a certificate for a domain, signed by a CA
    pub fn generate_domain_cert(
        &self,
        domain: &str,
        ca_cert: &Certificate,
        ca_key: &KeyPair,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        dn.push(DnType::OrganizationName, "SOTH Proxy");
        params.distinguished_name = dn;

        // Set validity
        let not_after = time::OffsetDateTime::now_utc() + self.validity;
        params.not_after = not_after;

        // Server certificate settings
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Add SAN for the domain
        params.subject_alt_names = vec![SanType::DnsName(domain.try_into().map_err(|e| {
            TlsError::cert_generation(format!("Invalid domain name '{}': {:?}", domain, e))
        })?)];

        // Generate keypair for the domain cert
        let key_pair = KeyPair::generate().map_err(|e| TlsError::key_generation(e.to_string()))?;

        // Sign with CA
        let cert = params
            .signed_by(&key_pair, ca_cert, ca_key)
            .map_err(|e| TlsError::cert_generation(e.to_string()))?;

        debug!("Generated domain certificate: {}", domain);

        // Return DER-encoded certificate and key
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        Ok((cert_der, key_der))
    }

    /// Generate a certificate for multiple domains (SANs)
    pub fn generate_multi_domain_cert(
        &self,
        domains: &[&str],
        ca_cert: &Certificate,
        ca_key: &KeyPair,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if domains.is_empty() {
            return Err(TlsError::cert_generation("No domains provided"));
        }

        let primary_domain = domains[0];
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, primary_domain);
        dn.push(DnType::OrganizationName, "SOTH Proxy");
        params.distinguished_name = dn;

        // Set validity
        let not_after = time::OffsetDateTime::now_utc() + self.validity;
        params.not_after = not_after;

        // Server certificate settings
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Add all SANs
        let mut sans = Vec::new();
        for domain in domains {
            sans.push(SanType::DnsName((*domain).try_into().map_err(|e| {
                TlsError::cert_generation(format!("Invalid domain name '{}': {:?}", domain, e))
            })?));
        }
        params.subject_alt_names = sans;

        // Generate keypair
        let key_pair = KeyPair::generate().map_err(|e| TlsError::key_generation(e.to_string()))?;

        // Sign with CA
        let cert = params
            .signed_by(&key_pair, ca_cert, ca_key)
            .map_err(|e| TlsError::cert_generation(e.to_string()))?;

        debug!("Generated multi-domain certificate: {:?}", domains);

        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        Ok((cert_der, key_der))
    }
}

impl Default for CertGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca() {
        let (cert, _key) = CertGenerator::generate_ca("Test CA", None).unwrap();
        let pem = cert.pem();
        assert!(pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_generate_domain_cert() {
        let (ca_cert, ca_key) = CertGenerator::generate_ca("Test CA", None).unwrap();
        let gen = CertGenerator::new();
        let (cert_der, key_der) = gen
            .generate_domain_cert("example.com", &ca_cert, &ca_key)
            .unwrap();

        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());
    }

    #[test]
    fn test_generate_multi_domain_cert() {
        let (ca_cert, ca_key) = CertGenerator::generate_ca("Test CA", None).unwrap();
        let gen = CertGenerator::new();
        let domains = vec!["example.com", "www.example.com", "api.example.com"];
        let (cert_der, key_der) = gen
            .generate_multi_domain_cert(&domains, &ca_cert, &ca_key)
            .unwrap();

        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());
    }

    #[test]
    fn test_empty_domains() {
        let (ca_cert, ca_key) = CertGenerator::generate_ca("Test CA", None).unwrap();
        let gen = CertGenerator::new();
        let result = gen.generate_multi_domain_cert(&[], &ca_cert, &ca_key);
        assert!(result.is_err());
    }
}

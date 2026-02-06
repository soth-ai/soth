//! TLS certificate management for SOTH forward proxy
//!
//! This crate provides:
//! - Certificate Authority (CA) generation and management
//! - Dynamic certificate generation for TLS interception
//! - Certificate caching with TTL-based expiration
//! - SNI extraction from TLS ClientHello
//!
//! # Example
//!
//! ```rust,ignore
//! use soth_tls::CertificateAuthority;
//! use std::path::PathBuf;
//!
//! // Generate a new CA
//! let ca = CertificateAuthority::generate_new(PathBuf::from("~/.soth/ca"))?;
//!
//! // Get or create a certificate for a domain
//! let (cert_der, key_der) = ca.get_or_create_cert("api.openai.com")?;
//! ```

pub mod ca;
pub mod cert_cache;
pub mod cert_gen;
pub mod error;
pub mod sni;

pub use ca::CertificateAuthority;
pub use cert_cache::CertCache;
pub use cert_gen::CertGenerator;
pub use error::{TlsError, Result};
pub use sni::extract_sni;

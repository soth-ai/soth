//! TLS certificate management for SOTH forward proxy.

pub mod ca;
pub mod cert_cache;
pub mod cert_gen;
pub mod error;
pub mod learned_passthrough;
pub mod sni;

pub use ca::{CaIdentityMetadata, CertificateAuthority};
pub use cert_cache::CertCache;
pub use cert_gen::CertGenerator;
pub use error::{Result, TlsError};
pub use learned_passthrough::LearnedPassthrough;
pub use sni::extract_sni;

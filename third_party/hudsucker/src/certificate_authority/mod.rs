#[cfg(feature = "openssl-ca")]
mod openssl_authority;
#[cfg(feature = "rcgen-ca")]
mod rcgen_authority;

use http::uri::Authority;
use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;

#[cfg(feature = "openssl-ca")]
pub use openssl_authority::*;
#[cfg(feature = "rcgen-ca")]
pub use rcgen_authority::*;

const TTL_SECS: i64 = 365 * 24 * 60 * 60;
const CACHE_TTL: u64 = TTL_SECS as u64 / 2;
const NOT_BEFORE_OFFSET: i64 = 60;

/// Metadata sniffed from an upstream server certificate.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpstreamCertificateInfo {
    /// DNS names from SAN.
    pub dns_names: Vec<String>,
    /// Subject common name.
    pub common_name: Option<String>,
}

/// Issues certificates for use when communicating with clients.
///
/// Clients should be configured to either trust the provided root certificate, or to ignore
/// certificate errors.
pub trait CertificateAuthority: Send + Sync + 'static {
    /// Generate ServerConfig for use with rustls.
    fn gen_server_config(
        &self,
        authority: &Authority,
    ) -> impl Future<Output = Arc<ServerConfig>> + Send;

    /// Generate ServerConfig using optional upstream certificate hints.
    ///
    /// Default implementation ignores upstream hints and delegates to [`Self::gen_server_config`].
    fn gen_server_config_with_upstream<'a>(
        &'a self,
        authority: &'a Authority,
        upstream: Option<&'a UpstreamCertificateInfo>,
    ) -> impl Future<Output = Arc<ServerConfig>> + Send + 'a {
        async move {
            let _ = upstream;
            self.gen_server_config(authority).await
        }
    }
}

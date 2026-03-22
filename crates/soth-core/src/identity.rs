use crate::artifacts::CaptureMode;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMeta {
    pub connection_id: Uuid,
    pub socket_family: SocketFamily,
    pub process_info: Option<ProcessInfo>,
    pub tls_info: Option<TlsInfo>,
    pub app_identity: Option<AppIdentity>,
    pub capture_mode: Option<CaptureMode>,
    pub matched_provider: Option<String>,
    pub matched_application: Option<String>,
}

impl ConnectionMeta {
    pub fn from_transport(
        connection_id: Uuid,
        socket_family: SocketFamily,
        process_info: Option<ProcessInfo>,
        tls_info: Option<TlsInfo>,
    ) -> Self {
        Self {
            connection_id,
            socket_family,
            process_info,
            tls_info,
            app_identity: None,
            capture_mode: None,
            matched_provider: None,
            matched_application: None,
        }
    }

    pub fn is_proxy_enriched(&self) -> bool {
        self.capture_mode.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketFamily {
    TcpV4 {
        local: SocketAddrV4,
        remote: SocketAddrV4,
    },
    TcpV6 {
        local: SocketAddrV6,
        remote: SocketAddrV6,
    },
    UnixDomain {
        path: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bundle_id: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_process_name: Option<String>,
    pub parent_bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppIdentity {
    pub app_id: String,
    pub display_name: String,
    pub app_kind: AppKind,
    pub is_known: bool,
    pub confidence: f32,
}

impl Default for AppIdentity {
    fn default() -> Self {
        Self {
            app_id: "unknown".to_string(),
            display_name: "unknown".to_string(),
            app_kind: AppKind::Unknown,
            is_known: false,
            confidence: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppKind {
    Browser,
    AgentApp,
    Ide,
    Cli,
    Unknown,
}

impl AppKind {
    /// Parse an app_type string from bundle data into an `AppKind`.
    /// Accepts all known variants including legacy / alternate spellings.
    pub fn from_type_str(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "browser" | "host" => Self::Browser,
            "ide" => Self::Ide,
            "cli" => Self::Cli,
            "agent_app" | "agent-app" | "non_host" => Self::AgentApp,
            _ => Self::Unknown,
        }
    }

    /// Convert to the coarser `AppType` used by the gating layer.
    /// `Browser` → `Host`, everything else → `NonHost`, `Unknown` → `Unknown`.
    pub fn to_app_type(self) -> crate::AppType {
        match self {
            Self::Browser => crate::AppType::Host,
            Self::AgentApp | Self::Ide | Self::Cli => crate::AppType::NonHost,
            Self::Unknown => crate::AppType::Unknown,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub protocol: Option<String>,
}

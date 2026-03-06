/// Declares which pipeline stages an extension requires.
#[derive(Debug, Clone, Copy)]
pub struct ExtensionCapabilities {
    /// Run soth-detect on incoming events to produce NormalizedRequest + artifacts.
    pub needs_detect: bool,
    /// Run full soth-classify (embedding + cluster + anomaly + policy).
    pub needs_classify: bool,
    /// Whether this extension's policy decisions can block requests.
    pub can_block: bool,
    /// Emit TelemetryEvents through the telemetry pipeline.
    pub emits_telemetry: bool,
}

impl Default for ExtensionCapabilities {
    fn default() -> Self {
        Self {
            needs_detect: false,
            needs_classify: false,
            can_block: false,
            emits_telemetry: true,
        }
    }
}

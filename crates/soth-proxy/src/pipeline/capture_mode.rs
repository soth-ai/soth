use soth_core::{CaptureMode, ProcessResolution};

use crate::pipeline::registry::Registry;

pub fn derive_capture_mode(
    process: &ProcessResolution,
    matched_provider: Option<&str>,
    discovery_capture: bool,
    registry: &Registry,
) -> CaptureMode {
    if discovery_capture {
        return CaptureMode::MetadataOnly;
    }

    if let Some(mode) = process.capture_mode {
        return mode;
    }

    registry.capture_mode_for_provider(matched_provider)
}

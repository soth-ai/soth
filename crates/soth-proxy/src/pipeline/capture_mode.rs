use soth_core::{CaptureMode, ProcessResolution};

use crate::pipeline::registry::Registry;

pub fn derive_capture_mode(
    process: &ProcessResolution,
    matched_provider: Option<&str>,
    discovery_capture: bool,
    registry: &Registry,
) -> CaptureMode {
    let mut mode = process
        .capture_mode
        .unwrap_or_else(|| registry.capture_default_mode());

    if matched_provider.is_some() {
        mode = registry.capture_mode_for_provider(matched_provider);
    }

    if discovery_capture {
        CaptureMode::MetadataOnly
    } else {
        mode
    }
}

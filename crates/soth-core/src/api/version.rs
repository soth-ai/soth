//! Cloud API version negotiation constants.

/// Header used for API version negotiation between edge and cloud.
pub const API_VERSION_HEADER: &str = "X-Soth-Api-Version";

/// Current API version expected by edge and cloud.
pub const API_VERSION: &str = "2026-02-01";

/// Minimum supported API version (validated on cloud side).
pub const API_VERSION_MIN: &str = "2026-02-01";

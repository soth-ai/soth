//! PII detection module

mod detector;
mod patterns;
mod redactor;

pub use detector::{PiiDetector, PiiMatch};
pub use redactor::PiiRedactor;

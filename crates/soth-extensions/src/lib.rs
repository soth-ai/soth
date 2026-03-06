#![forbid(unsafe_code)]

pub mod builder;
pub mod capabilities;
pub mod error;
pub mod handle;
pub mod manager;
pub mod traits;

pub use builder::ExtensionManagerBuilder;
pub use capabilities::ExtensionCapabilities;
pub use error::ExtensionError;
pub use handle::ExtensionHandle;
pub use manager::ExtensionManager;
pub use traits::{Extension, ExtensionHealth};

// Re-export core extension types for convenience
pub use soth_core::{ExtensionContext, ExtensionType, EventSource, GovernableEvent};

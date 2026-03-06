use std::path::Path;
use std::pin::Pin;

use async_trait::async_trait;
use tokio_stream::Stream;

use crate::error::ReaderError;
use crate::types::{AiTool, Cursor, HistoricalSession};

/// Trait for per-tool format readers.
///
/// Each AI tool stores conversations differently. A `FormatReader` knows how to
/// detect whether a root path belongs to its tool and how to stream sessions
/// from it incrementally.
#[async_trait]
pub trait FormatReader: Send + Sync {
    /// Which tool this reader handles.
    fn tool_type(&self) -> AiTool;

    /// Check whether `root` contains data for this tool.
    fn detect(&self, root: &Path) -> bool;

    /// Stream sessions from `root`, optionally starting from `since` epoch-ms.
    /// Sessions are yielded in chronological order where possible.
    fn read_sessions(
        &self,
        root: &Path,
        since: Option<i64>,
    ) -> Pin<Box<dyn Stream<Item = Result<HistoricalSession, ReaderError>> + Send + '_>>;

    /// Return the last persisted cursor, if any, for resumable reads.
    fn last_cursor(&self) -> Option<Cursor>;
}

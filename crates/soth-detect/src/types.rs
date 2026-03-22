// soth-parse internal types — part of soth-detect's public API.
pub use soth_parse::types::{
    empty_heuristic_request, ArtifactLocation, ArtifactType, ChunkArtifact, CoreArtifactLocation,
    DetectResult, DetectWarning, DetectedFormat, DetectedImportCategory, EndpointType, FormatMeta,
    GqlOpType, HeaderMap, NormalizedRequest, ParseError, ParseResult, ParseSource, ParseWarning,
    SensitiveArtifact, Severity, StreamSession, StreamSummary, StreamTurn, StreamUsage,
};

// Transport types from soth-core — appear in soth-detect's public API signatures.
pub use soth_core::{
    AppIdentity, AppKind, CaptureMode, ConnectionMeta, FrameDirection, FrameKind,
    ParseConfidence, ProcessInfo, RawRequest, RequestHeaders, SocketFamily, StreamChunk, TlsInfo,
};

// Bundle schema types from soth-core — available within this crate but NOT
// re-exported. Consumers should import these directly from soth_core.
// The allow(unused_imports) is needed because rustc cannot see that crate-internal
// modules consume these names via `crate::types::X`.
#[allow(unused_imports)]
pub(crate) use soth_core::{
    AppPolicy, ApplicationEntry, ProductEntry, BrowserPolicies, CaptureOverrides, CaptureRules,
    DetectBundleSlice, Filters, GraphQLHeuristicPattern, GraphQLOperationRegistry,
    GraphQLOperationSpec, GrpcFieldSpec, GrpcServiceRegistry, GrpcServiceSpec, OwnedDetectBundle,
    PreprocessOp, ProviderEntry, RequestEncoding, RestFormatDescriptor, RestRequestPaths,
    RestResponsePaths, StreamFormat, StreamOptions,
};

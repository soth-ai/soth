#![allow(
    clippy::result_large_err,
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::large_enum_variant,
    clippy::if_same_then_else,
    clippy::field_reassign_with_default,
    clippy::approx_constant,
    clippy::duplicated_attributes
)]
pub mod fingerprint;
pub mod graphql;
pub mod grpc;
pub mod hash;
pub mod heuristic;
pub mod jsonrpc;
pub mod proto;
pub mod rest;
pub mod types;
pub mod util;

pub use fingerprint::{
    classify_request, classify_request_pair, fingerprint, ClassifyPairResult, ClassifyResult,
};
pub use graphql::{parse_graphql, ApqStore, NoopApqStore};
pub use grpc::parse_grpc;
pub use hash::{canonical_hash, estimate_tokens, hash_content, sha256_hex};
pub use heuristic::parse as parse_heuristic;
pub use jsonrpc::parse_jsonrpc;
pub use proto::scan_proto_strings;
pub use rest::parse_rest;
pub use types::*;
pub use util::glob_match;

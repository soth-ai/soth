use crate::provider::{FieldPath, RequestParser, ResponseParser};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormatDefinition {
    pub format_id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub endpoints: BTreeMap<String, EndpointDefinition>,
    #[serde(default)]
    pub protocol: Option<ProtocolSpec>,
    #[serde(default)]
    pub methods: BTreeMap<String, MethodDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointDefinition {
    pub pattern: String,
    #[serde(default)]
    pub request: Option<RequestParser>,
    #[serde(default)]
    pub response: Option<ResponseParser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolSpec {
    Http,
    JsonRpc,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MethodDefinition {
    #[serde(default)]
    pub request: BTreeMap<String, FieldPath>,
    #[serde(default)]
    pub response: BTreeMap<String, FieldPath>,
}

use crate::api_types::{BlobUploadRequest, BlobUploadResponse};

#[derive(Clone)]
pub struct BodyUploader;

impl BodyUploader {
    pub fn new(_endpoint: impl Into<String>, _api_key: impl Into<String>) -> Self {
        Self
    }

    pub async fn upload_blob(
        &self,
        request: &BlobUploadRequest,
    ) -> anyhow::Result<Option<BlobUploadResponse>> {
        let _ = request;
        Ok(None)
    }
}

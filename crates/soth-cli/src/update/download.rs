//! Sha256-checked binary download.
//!
//! Streams the new binary from the manifest-supplied URL into a staging
//! file (default `~/.soth/run/soth.new`), computing sha256 incrementally.
//! On size or hash mismatch the partial file is removed and an error is
//! returned. The caller is responsible for `chmod +x` on Unix and for
//! the platform-specific atomic swap.

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(180);
const PROGRESS_INTERVAL_BYTES: u64 = 4 * 1024 * 1024; // log every 4 MiB

/// Where the freshly-downloaded binary should land before swap.
pub struct BinarySink {
    pub stage_path: PathBuf,
}

impl BinarySink {
    pub fn default_for_user() -> Result<Self> {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home directory"))?;
        let stage = home.join(".soth").join("run").join(soth_new_filename());
        Ok(Self { stage_path: stage })
    }
}

#[cfg(windows)]
fn soth_new_filename() -> &'static str {
    "soth.exe.new"
}
#[cfg(not(windows))]
fn soth_new_filename() -> &'static str {
    "soth.new"
}

/// Stream `url` to `sink.stage_path`, computing sha256 as bytes flow.
/// Returns the resolved stage path on success. On any failure the
/// partial file is removed.
pub async fn download_binary(
    url: &str,
    expected_sha256: &str,
    sink: &BinarySink,
) -> Result<PathBuf> {
    if let Some(parent) = sink.stage_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating staging dir {}", parent.display()))?;
    }

    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .context("building http client")?;

    let mut resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {}", url))?
        .error_for_status()
        .with_context(|| format!("download returned non-2xx: {}", url))?;

    let content_length = resp.content_length();
    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut next_progress = PROGRESS_INTERVAL_BYTES;

    let mut file = File::create(&sink.stage_path)
        .await
        .with_context(|| format!("creating {}", sink.stage_path.display()))?;

    while let Some(chunk) = resp
        .chunk()
        .await
        .context("reading next chunk from download")?
    {
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .with_context(|| format!("writing to {}", sink.stage_path.display()))?;
        downloaded += chunk.len() as u64;
        if downloaded >= next_progress {
            next_progress = downloaded + PROGRESS_INTERVAL_BYTES;
            match content_length {
                Some(total) => tracing::info!(
                    downloaded_mib = downloaded / (1024 * 1024),
                    total_mib = total / (1024 * 1024),
                    "downloading update"
                ),
                None => tracing::info!(
                    downloaded_mib = downloaded / (1024 * 1024),
                    "downloading update"
                ),
            }
        }
    }

    file.flush().await.context("flush staging file")?;
    drop(file);

    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        let _ = tokio::fs::remove_file(&sink.stage_path).await;
        bail!(
            "sha256 mismatch: expected {}, got {} (binary discarded)",
            expected_sha256,
            actual,
        );
    }

    if let Some(total) = content_length {
        if downloaded != total {
            let _ = tokio::fs::remove_file(&sink.stage_path).await;
            bail!(
                "download size mismatch: expected {} bytes (Content-Length), got {}",
                total,
                downloaded
            );
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(&sink.stage_path)
            .await
            .context("stat staging file")?
            .permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(&sink.stage_path, perms)
            .await
            .context("chmod 0755 on staging file")?;
    }

    Ok(sink.stage_path.clone())
}

/// Convenience: stream-hash an existing file (used to verify a
/// previously-downloaded staging artifact, e.g. on rollback paths).
#[allow(dead_code)]
pub async fn sha256_of_file(path: &Path) -> Result<String> {
    use tokio::io::AsyncReadExt;

    let mut file = File::open(path)
        .await
        .with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await.context("reading file")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a one-shot HTTP/1.1 server that serves `body` to the first
    /// connection, then exits. Returns the bound URL. Used by download
    /// tests to avoid pulling in a full HTTP test framework.
    async fn serve_once(body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain the request line + headers.
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(header.as_bytes()).await.unwrap();
            sock.write_all(&body).await.unwrap();
            sock.flush().await.unwrap();
        });
        format!("http://{}/binary", addr)
    }

    #[tokio::test]
    async fn download_succeeds_on_matching_sha() {
        let body = b"the-fake-soth-binary-bytes".to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let expected = hex::encode(hasher.finalize());
        let url = serve_once(body.clone()).await;

        let dir = tempfile::tempdir().unwrap();
        let sink = BinarySink {
            stage_path: dir.path().join("soth.new"),
        };
        let staged = download_binary(&url, &expected, &sink).await.unwrap();
        let read = tokio::fs::read(&staged).await.unwrap();
        assert_eq!(read, body);
    }

    #[tokio::test]
    async fn download_rejects_sha_mismatch_and_cleans_up() {
        let body = b"actual-bytes".to_vec();
        let url = serve_once(body).await;

        let dir = tempfile::tempdir().unwrap();
        let sink = BinarySink {
            stage_path: dir.path().join("soth.new"),
        };
        let bogus = "0".repeat(64);
        let err = download_binary(&url, &bogus, &sink).await.unwrap_err();
        assert!(format!("{:#}", err).contains("sha256 mismatch"));
        // Partial file must have been removed.
        assert!(!sink.stage_path.exists());
    }

    #[tokio::test]
    async fn sha256_of_file_matches_streaming_hash() {
        let body = b"some bytes for hashing";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let expected = hex::encode(hasher.finalize());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        tokio::fs::write(&path, body).await.unwrap();
        let actual = sha256_of_file(&path).await.unwrap();
        assert_eq!(actual, expected);
    }
}

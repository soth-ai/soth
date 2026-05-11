//! Release-manifest fetch + ed25519 signature verification.
//!
//! The server (ops/release.sh::cmd_generate_manifest + cmd_sign_manifest)
//! publishes:
//!   <base>/manifest/<channel>.json        — canonical JSON, sort_keys=True
//!   <base>/manifest/<channel>.json.sig    — raw 64-byte ed25519 signature
//!
//! Public keys are baked into the binary via `include_bytes!` from
//! `ops/keys/{stable,canary}.public.pem`. The verifier signs over the
//! exact downloaded bytes — never re-serialized — so a single trailing
//! whitespace difference does not break trust.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

const PROD_BASE_URL: &str = "https://storage.soth.ai/release";
const STAGING_BASE_URL: &str = "https://storage.staging.soth.xyz/release";
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

// Public keys live in ops/keys/. CARGO_MANIFEST_DIR is crates/soth-cli/,
// so `../../ops/keys/` reaches the workspace root's keys directory.
const STABLE_PUBKEY_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ops/keys/stable.public.pem"
));
const CANARY_PUBKEY_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ops/keys/canary.public.pem"
));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Stable,
    Canary,
    Staging,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Canary => "canary",
            Channel::Staging => "staging",
        }
    }

    /// Map channel → which baked-in public key verifies its manifests.
    /// Mirrors `ops/release.sh::key_basename_for_channel`.
    fn pubkey_pem(self) -> &'static [u8] {
        match self {
            Channel::Stable => STABLE_PUBKEY_PEM,
            Channel::Canary | Channel::Staging => CANARY_PUBKEY_PEM,
        }
    }

    /// Default base URL for this channel. Override via `VerifyOptions::base_url`.
    fn default_base_url(self) -> &'static str {
        match self {
            Channel::Stable | Channel::Canary => PROD_BASE_URL,
            Channel::Staging => STAGING_BASE_URL,
        }
    }
}

impl std::str::FromStr for Channel {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "stable" => Ok(Channel::Stable),
            "canary" => Ok(Channel::Canary),
            "staging" => Ok(Channel::Staging),
            other => bail!(
                "unknown channel '{}' (expected stable|canary|staging)",
                other
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub schema_version: u32,
    pub channel: String,
    pub version: String,
    pub release_seq: u64,
    pub released_at: String,
    pub min_supported_version: String,
    pub release_notes_url: Option<String>,
    pub platforms: BTreeMap<String, PlatformEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformEntry {
    pub url: String,
    pub sha256: String,
}

/// Tunables for [`fetch_and_verify_manifest`]. All have sensible defaults.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Override the per-channel default base URL. Used by tests and by
    /// future `--manifest-url` flags. None = use channel default.
    pub base_url: Option<String>,
    /// Highest already-applied release_seq for this channel. The verifier
    /// rejects manifests with `release_seq <= last_seen` unless
    /// `force_downgrade` is set. `None` skips the check (first run).
    pub last_release_seq: Option<u64>,
    /// Bypass anti-rollback. Operator-only escape hatch.
    pub force_downgrade: bool,
    /// Override the locally-running version for the min-supported check.
    /// Useful for tests; production callers leave this `None` so the
    /// real `CARGO_PKG_VERSION` is used.
    pub current_version_override: Option<String>,
    /// When set, fetch the frozen per-version manifest at
    /// `<base>/manifest/<channel>.v<version>.json{,.sig}` instead of
    /// the channel-current pointer. Lets `soth update --version 0.1.0`
    /// and rollback paths target a specific historical release whose
    /// binary URLs and sha256s never change.
    pub pinned_version: Option<String>,
}

/// Fetch `<base>/manifest/<channel>.json{,.sig}`, verify the signature,
/// parse, and return the manifest. Network errors bubble; signature or
/// schema problems return a clear `anyhow::Error`.
///
/// Always verifies the signature over the **exact downloaded bytes**;
/// re-serializing the parsed manifest would silently strip JSON whitespace
/// and break verification.
pub async fn fetch_and_verify_manifest(
    channel: Channel,
    opts: &VerifyOptions,
) -> Result<UpdateManifest> {
    let base = opts
        .base_url
        .as_deref()
        .unwrap_or(channel.default_base_url())
        .trim_end_matches('/');

    // Channel-current pointer:   <base>/manifest/<channel>.json
    // Frozen per-version:         <base>/manifest/<channel>.v<version>.json
    let manifest_url = match &opts.pinned_version {
        Some(v) => format!("{}/manifest/{}.v{}.json", base, channel.as_str(), v),
        None => format!("{}/manifest/{}.json", base, channel.as_str()),
    };
    let sig_url = format!("{}.sig", manifest_url);

    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .context("building http client")?;

    let manifest_bytes = client
        .get(&manifest_url)
        .send()
        .await
        .with_context(|| format!("fetching {}", manifest_url))?
        .error_for_status()
        .with_context(|| format!("manifest fetch returned non-2xx: {}", manifest_url))?
        .bytes()
        .await
        .context("reading manifest body")?;

    let sig_bytes = client
        .get(&sig_url)
        .send()
        .await
        .with_context(|| format!("fetching {}", sig_url))?
        .error_for_status()
        .with_context(|| format!("signature fetch returned non-2xx: {}", sig_url))?
        .bytes()
        .await
        .context("reading signature body")?;

    verify_manifest_bytes(&manifest_bytes, &sig_bytes, channel, opts)
}

/// Test-friendly: take raw bytes (e.g. from a fixture or a spawned
/// HTTP server) and run the same verification path as the network fetch.
pub fn verify_manifest_bytes(
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    channel: Channel,
    opts: &VerifyOptions,
) -> Result<UpdateManifest> {
    let pubkey_pem =
        std::str::from_utf8(channel.pubkey_pem()).context("baked-in public key is not UTF-8")?;
    verify_manifest_bytes_with_pubkey(
        manifest_bytes,
        sig_bytes,
        pubkey_pem,
        channel.as_str(),
        opts,
    )
}

/// Verify a manifest with a caller-supplied public key (PEM-encoded
/// SubjectPublicKeyInfo). Test-only entry — production callers must use
/// [`verify_manifest_bytes`] or [`fetch_and_verify_manifest`] which pin
/// the baked-in channel keys.
#[doc(hidden)]
pub fn verify_manifest_bytes_with_pubkey(
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    pubkey_pem: &str,
    expected_channel: &str,
    opts: &VerifyOptions,
) -> Result<UpdateManifest> {
    verify_signature_with_pem(manifest_bytes, sig_bytes, pubkey_pem)
        .context("manifest signature verification failed")?;

    let manifest: UpdateManifest = serde_json::from_slice(manifest_bytes)
        .context("manifest JSON malformed (signature OK but body unparseable)")?;

    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        bail!(
            "manifest schema_version {} not supported by this client (expected {}); \
             upgrade soth or wait for a compatible manifest",
            manifest.schema_version,
            MANIFEST_SCHEMA_VERSION
        );
    }

    if manifest.channel != expected_channel {
        bail!(
            "manifest channel '{}' does not match requested channel '{}'",
            manifest.channel,
            expected_channel
        );
    }

    // When a pinned version was requested, the manifest we fetched
    // MUST be that exact frozen snapshot — refuse a server that
    // signs-and-serves a manifest with a different version under the
    // pinned URL. Belt-and-braces; in practice the frozen URL is
    // immutable, but a wrong-cache-key or storage bug shouldn't
    // silently surface as "we installed something else."
    if let Some(pinned) = opts.pinned_version.as_deref() {
        if manifest.version != pinned {
            bail!(
                "manifest version '{}' does not match pinned --version '{}'",
                manifest.version,
                pinned
            );
        }
    }

    let current_str = opts
        .current_version_override
        .as_deref()
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let current = Version::parse(current_str)
        .with_context(|| format!("local CARGO_PKG_VERSION '{}' is not semver", current_str))?;
    let min_supported = Version::parse(&manifest.min_supported_version).with_context(|| {
        format!(
            "manifest min_supported_version '{}' is not semver",
            manifest.min_supported_version
        )
    })?;
    if current < min_supported {
        bail!(
            "this client (v{}) is below min_supported_version v{}; manual upgrade required",
            current,
            min_supported
        );
    }

    // Anti-rollback gate. Skipped when the operator either explicitly
    // passed --force-downgrade, OR pinned a specific version (the
    // version-pin is itself the explicit operator authorization).
    if !opts.force_downgrade && opts.pinned_version.is_none() {
        if let Some(last) = opts.last_release_seq {
            if manifest.release_seq <= last {
                bail!(
                    "manifest release_seq {} is not greater than last-applied {} \
                     (anti-rollback gate; pass --force-downgrade or --version <X> \
                     to override)",
                    manifest.release_seq,
                    last
                );
            }
        }
    }

    Ok(manifest)
}

fn verify_signature_with_pem(
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    pubkey_pem: &str,
) -> Result<()> {
    if sig_bytes.len() != Signature::BYTE_SIZE {
        bail!(
            "signature length {} != ed25519 expected {} (corrupt or wrong file)",
            sig_bytes.len(),
            Signature::BYTE_SIZE
        );
    }
    let sig_array: [u8; Signature::BYTE_SIZE] = sig_bytes
        .try_into()
        .map_err(|_| anyhow!("signature length conversion failed"))?;
    let signature = Signature::from_bytes(&sig_array);

    let verifying_key = parse_pem_pubkey(pubkey_pem).context("parsing public key")?;

    verifying_key
        .verify(manifest_bytes, &signature)
        .map_err(|e| anyhow!("ed25519 verify failed: {}", e))
}

/// Parse an `-----BEGIN PUBLIC KEY-----` PEM containing an ed25519
/// SubjectPublicKeyInfo. We use ed25519-dalek's `pkcs8` feature directly
/// to avoid pulling in another PEM parsing crate.
fn parse_pem_pubkey(pem: &str) -> Result<VerifyingKey> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    VerifyingKey::from_public_key_pem(pem.trim()).map_err(|e| anyhow!("PEM parse: {}", e))
}

/// Map (target_os, target_arch) at compile-time → manifest platform key.
/// Mirrors `ops/release.sh::binary_to_platform_key`.
pub const fn platform_key() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "darwin-arm64"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "darwin-amd64"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-amd64"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "linux-arm64"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "windows-amd64"
    } else {
        "unsupported"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    /// Generate a fresh test keypair + return (signing, public-PEM).
    /// PEM is what verify_manifest_bytes_with_pubkey expects.
    fn fixture_keypair() -> (SigningKey, String) {
        let signing = SigningKey::generate(&mut OsRng);
        let pem = signing
            .verifying_key()
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        (signing, pem)
    }

    /// Build a canonical-JSON manifest body matching what
    /// ops/release.sh::cmd_generate_manifest produces.
    fn fixture_manifest_bytes(
        channel: &str,
        version: &str,
        release_seq: u64,
        min_supported: &str,
    ) -> Vec<u8> {
        let body = format!(
            r#"{{"channel":"{ch}","min_supported_version":"{ms}","platforms":{{"darwin-arm64":{{"sha256":"abc","url":"https://example/x"}},"darwin-amd64":{{"sha256":"def","url":"https://example/y"}},"linux-amd64":{{"sha256":"ghi","url":"https://example/z"}},"linux-arm64":{{"sha256":"jkl","url":"https://example/w"}},"windows-amd64":{{"sha256":"mno","url":"https://example/v"}}}},"release_notes_url":"https://example/notes","release_seq":{seq},"released_at":"2026-05-11T00:00:00Z","schema_version":1,"version":"{ver}"}}
"#,
            ch = channel,
            ms = min_supported,
            ver = version,
            seq = release_seq,
        );
        body.into_bytes()
    }

    fn sign_fixture(signing: &SigningKey, body: &[u8]) -> Vec<u8> {
        signing.sign(body).to_bytes().to_vec()
    }

    #[test]
    fn platform_key_resolves_to_known_target() {
        let k = platform_key();
        assert!(
            k == "darwin-arm64"
                || k == "darwin-amd64"
                || k == "linux-amd64"
                || k == "linux-arm64"
                || k == "windows-amd64"
                || k == "unsupported",
            "got {}",
            k
        );
    }

    #[test]
    fn channel_roundtrips_via_str() {
        for c in [Channel::Stable, Channel::Canary, Channel::Staging] {
            let s = c.as_str();
            let parsed: Channel = s.parse().unwrap();
            assert_eq!(parsed, c);
        }
        assert!("bogus".parse::<Channel>().is_err());
    }

    #[test]
    fn parse_pem_rejects_garbage() {
        assert!(parse_pem_pubkey("not a pem").is_err());
    }

    #[test]
    fn happy_path_verifies_and_parses() {
        let (signing, pem) = fixture_keypair();
        let body = fixture_manifest_bytes("stable", "0.1.2", 5, "0.1.0");
        let sig = sign_fixture(&signing, &body);
        let opts = VerifyOptions {
            current_version_override: Some("0.1.1".into()),
            ..Default::default()
        };
        let m = verify_manifest_bytes_with_pubkey(&body, &sig, &pem, "stable", &opts).unwrap();
        assert_eq!(m.version, "0.1.2");
        assert_eq!(m.release_seq, 5);
        assert_eq!(m.platforms.len(), 5);
    }

    #[test]
    fn tampered_manifest_fails_verify() {
        let (signing, pem) = fixture_keypair();
        let body = fixture_manifest_bytes("stable", "0.1.2", 5, "0.1.0");
        let sig = sign_fixture(&signing, &body);
        let mut tampered = body.clone();
        tampered[10] ^= 0x01;
        let opts = VerifyOptions {
            current_version_override: Some("0.1.1".into()),
            ..Default::default()
        };
        let err =
            verify_manifest_bytes_with_pubkey(&tampered, &sig, &pem, "stable", &opts).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("signature verification failed"), "got {}", msg);
    }

    #[test]
    fn wrong_channel_label_rejected() {
        let (signing, pem) = fixture_keypair();
        let body = fixture_manifest_bytes("stable", "0.1.2", 5, "0.1.0");
        let sig = sign_fixture(&signing, &body);
        // Manifest claims "stable", but caller asked for "canary".
        let opts = VerifyOptions {
            current_version_override: Some("0.1.1".into()),
            ..Default::default()
        };
        let err =
            verify_manifest_bytes_with_pubkey(&body, &sig, &pem, "canary", &opts).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("does not match"), "got {}", msg);
    }

    #[test]
    fn schema_version_mismatch_rejected() {
        let (signing, pem) = fixture_keypair();
        // Manually swap schema_version to 99 to simulate forward-incompatible.
        let body = br#"{"channel":"stable","min_supported_version":"0.1.0","platforms":{"darwin-arm64":{"sha256":"a","url":"u"}},"release_notes_url":null,"release_seq":1,"released_at":"x","schema_version":99,"version":"0.1.2"}
"#;
        let sig = sign_fixture(&signing, body);
        let err = verify_manifest_bytes_with_pubkey(
            body,
            &sig,
            &pem,
            "stable",
            &VerifyOptions::default(),
        )
        .unwrap_err();
        assert!(format!("{:#}", err).contains("schema_version 99"));
    }

    #[test]
    fn anti_rollback_blocks_lower_or_equal_seq() {
        let (signing, pem) = fixture_keypair();
        let body = fixture_manifest_bytes("stable", "0.1.2", 5, "0.1.0");
        let sig = sign_fixture(&signing, &body);

        // last_release_seq = 5 (== current); should reject without force.
        let opts = VerifyOptions {
            last_release_seq: Some(5),
            current_version_override: Some("0.1.1".into()),
            ..Default::default()
        };
        let err =
            verify_manifest_bytes_with_pubkey(&body, &sig, &pem, "stable", &opts).unwrap_err();
        assert!(format!("{:#}", err).contains("anti-rollback"));

        // last_release_seq = 5, force_downgrade = true; should accept.
        let opts = VerifyOptions {
            last_release_seq: Some(5),
            force_downgrade: true,
            current_version_override: Some("0.1.1".into()),
            ..Default::default()
        };
        let m = verify_manifest_bytes_with_pubkey(&body, &sig, &pem, "stable", &opts).unwrap();
        assert_eq!(m.release_seq, 5);

        // last_release_seq = 4 (< current); should accept.
        let opts = VerifyOptions {
            last_release_seq: Some(4),
            current_version_override: Some("0.1.1".into()),
            ..Default::default()
        };
        let m = verify_manifest_bytes_with_pubkey(&body, &sig, &pem, "stable", &opts).unwrap();
        assert_eq!(m.release_seq, 5);
    }

    #[test]
    fn min_supported_blocks_old_clients() {
        let (signing, pem) = fixture_keypair();
        // Manifest demands ≥ 0.5.0; we're on 0.1.1.
        let body = fixture_manifest_bytes("stable", "0.5.1", 1, "0.5.0");
        let sig = sign_fixture(&signing, &body);
        let opts = VerifyOptions {
            current_version_override: Some("0.1.1".into()),
            ..Default::default()
        };
        let err =
            verify_manifest_bytes_with_pubkey(&body, &sig, &pem, "stable", &opts).unwrap_err();
        assert!(format!("{:#}", err).contains("min_supported_version"));
    }

    #[test]
    fn signature_length_mismatch_rejected() {
        let (_signing, pem) = fixture_keypair();
        let body = fixture_manifest_bytes("stable", "0.1.2", 5, "0.1.0");
        let bad_sig = vec![0u8; 32]; // half the right size
        let err = verify_manifest_bytes_with_pubkey(
            &body,
            &bad_sig,
            &pem,
            "stable",
            &VerifyOptions::default(),
        )
        .unwrap_err();
        assert!(format!("{:#}", err).contains("signature length"));
    }
}

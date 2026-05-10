#!/usr/bin/env bash
# SOTH installer (BETA, ships with 0.1.1+)
#
# Usage:
#   curl -fsSL https://soth.ai/install.sh | bash
#   curl -fsSL https://soth.ai/install.sh | bash -s -- --channel canary
#   curl -fsSL https://soth.ai/install.sh | bash -s -- --version 0.1.4
#
# Or, from a checkout of the source repo:
#   ./scripts/install.sh
#
# Environment overrides:
#   SOTH_INSTALL_DIR   default: ~/.local/bin
#   SOTH_CHANNEL       default: stable     (or pass --channel)
#   SOTH_BASE_URL      default: https://storage.soth.ai/release
#   SOTH_VERSION       default: latest from manifest (or pass --version)
#
# Trust path: the script downloads
#   $SOTH_BASE_URL/manifest/$SOTH_CHANNEL.json
#   $SOTH_BASE_URL/manifest/$SOTH_CHANNEL.json.sig
# and verifies the ed25519 signature against a public key baked in
# below. The binary URL + sha256 come from the verified manifest.
# Without the manifest's signature gate, an attacker who hijacked the
# storage bucket could swap in malicious binaries. The signing keys
# are operator-controlled and rotated independently of cloud auth —
# see ops/keys/README.md.

set -euo pipefail

# ---------------------------------------------------------------------------
# Embedded public keys
# ---------------------------------------------------------------------------
# These match ops/keys/{stable,canary}.public.pem in the source repo.
# When rotating a key, update both.

read -r -d '' STABLE_PUBKEY_PEM <<'PEM' || true
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPs/hhy1okfWqaV9TewGde4zYicDy81nCVMTZD9Tr2iw=
-----END PUBLIC KEY-----
PEM

read -r -d '' CANARY_PUBKEY_PEM <<'PEM' || true
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAqIwNCeIA1rYkAoJwE/nRatDFRQui4yoGmL45yovQg34=
-----END PUBLIC KEY-----
PEM

# ---------------------------------------------------------------------------
# Defaults + arg parsing
# ---------------------------------------------------------------------------
: "${SOTH_INSTALL_DIR:=$HOME/.local/bin}"
: "${SOTH_CHANNEL:=stable}"
: "${SOTH_BASE_URL:=https://storage.soth.ai/release}"
: "${SOTH_VERSION:=}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --channel)
      [ "$#" -ge 2 ] || { echo "ERROR: --channel needs a value" >&2; exit 1; }
      SOTH_CHANNEL="$2"; shift 2 ;;
    --version)
      [ "$#" -ge 2 ] || { echo "ERROR: --version needs a value" >&2; exit 1; }
      SOTH_VERSION="$2"; shift 2 ;;
    --install-dir)
      [ "$#" -ge 2 ] || { echo "ERROR: --install-dir needs a value" >&2; exit 1; }
      SOTH_INSTALL_DIR="$2"; shift 2 ;;
    --base-url)
      [ "$#" -ge 2 ] || { echo "ERROR: --base-url needs a value" >&2; exit 1; }
      SOTH_BASE_URL="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,32p' "$0"
      exit 0 ;;
    *)
      echo "ERROR: unknown flag '$1'. Try --help." >&2
      exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
err() { echo "ERROR: $*" >&2; exit 1; }
log() { printf "==> %s\n" "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || err "$1 is required but not on PATH"
}

# curl wrapper that pins HTTPS + TLS 1.2+ when the URL is https://, but
# allows plain http when the user explicitly opted into it via
# --base-url http://… (used by local integration tests; never by the
# curl-pipe install path against soth.ai). Keeping the pin on the
# default base URL closes a downgrade-attack vector.
curl_secure() {
  if [[ "$SOTH_BASE_URL" == https://* ]]; then
    curl --proto '=https' --tlsv1.2 "$@"
  else
    curl "$@"
  fi
}

# Compute sha256 of a file. Use shasum on macOS / sha256sum on Linux —
# at least one must be present.
sha256_of() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    err "neither shasum nor sha256sum available"
  fi
}

# Map (uname -s, uname -m) → manifest platform key. Mirrors
# ops/release.sh::binary_to_platform_key in reverse.
detect_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$arch" in
    aarch64|arm64) arch=arm64 ;;
    x86_64|amd64)  arch=amd64 ;;
    *) err "unsupported architecture: $arch" ;;
  esac
  case "$os" in
    darwin) echo "darwin-${arch}" ;;
    linux)  echo "linux-${arch}" ;;
    *) err "unsupported OS '$os'; this installer covers macOS + Linux. \
For Windows use install.ps1." ;;
  esac
}

pubkey_for_channel() {
  case "$1" in
    stable) printf "%s" "$STABLE_PUBKEY_PEM" ;;
    # The "staging" channel is signed with the canary key (it's
    # internally-unstable, same trust class as canary).
    canary|staging) printf "%s" "$CANARY_PUBKEY_PEM" ;;
    *) err "unknown channel '$1' (expected stable|canary|staging)" ;;
  esac
}

binary_filename() {
  case "$1" in
    darwin-arm64|darwin-amd64|linux-amd64|linux-arm64) echo "soth-$1" ;;
    windows-amd64) echo "soth-windows-amd64.exe" ;;
    *) err "no binary filename for platform '$1'" ;;
  esac
}

# Pull a JSON field out of the manifest. We use python3 because
# `jq` isn't present on a fresh Linux install everywhere, and the
# manifest is canonical-JSON so python's parser is fine.
manifest_field() {
  local manifest="$1" path="$2"
  python3 - "$manifest" "$path" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as fh:
    obj = json.load(fh)
for key in sys.argv[2].split('.'):
    obj = obj[key]
print(obj)
PYEOF
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

require_cmd curl
require_cmd python3
require_cmd openssl
require_cmd uname
require_cmd awk

# OpenSSL 3.0+ is required for `pkeyutl -rawin` (ed25519 verification).
# Older OpenSSL builds will fail here with "Unknown option '-rawin'"
# rather than silently skipping signature verification.
openssl_version=$(openssl version | awk '{print $2}')
case "$openssl_version" in
  3.*|4.*) ;;
  *) err "OpenSSL 3.0+ required (found $openssl_version). Update openssl and retry." ;;
esac

PLATFORM=$(detect_platform)
log "SOTH installer (channel=$SOTH_CHANNEL, platform=$PLATFORM)"
log "install dir: $SOTH_INSTALL_DIR"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# 1. Fetch + verify manifest
log "fetching manifest"
curl_secure -fsSL \
  "${SOTH_BASE_URL%/}/manifest/${SOTH_CHANNEL}.json" \
  -o "$TMPDIR/manifest.json"
curl_secure -fsSL \
  "${SOTH_BASE_URL%/}/manifest/${SOTH_CHANNEL}.json.sig" \
  -o "$TMPDIR/manifest.json.sig"

pubkey_for_channel "$SOTH_CHANNEL" > "$TMPDIR/pubkey.pem"
if ! openssl pkeyutl -verify -pubin -inkey "$TMPDIR/pubkey.pem" -rawin \
     -in "$TMPDIR/manifest.json" -sigfile "$TMPDIR/manifest.json.sig" \
     >/dev/null 2>&1; then
  err "manifest signature verification FAILED — refusing to install. \
The manifest at $SOTH_BASE_URL is either tampered, served by an attacker, \
or signed with a key the installer doesn't recognize."
fi

# 2. Pick version + verify channel match
manifest_channel=$(manifest_field "$TMPDIR/manifest.json" "channel")
[ "$manifest_channel" = "$SOTH_CHANNEL" ] \
  || err "manifest channel '$manifest_channel' != requested '$SOTH_CHANNEL'"

manifest_version=$(manifest_field "$TMPDIR/manifest.json" "version")
if [ -n "$SOTH_VERSION" ] && [ "$SOTH_VERSION" != "$manifest_version" ]; then
  # The current manifest is per-channel-current; pinning a specific
  # historical version isn't supported by this installer (would need
  # a separate per-version manifest URL). Surface the limitation
  # rather than silently installing the wrong thing.
  err "manifest is on $manifest_version but you asked for $SOTH_VERSION. \
Pinning a non-current version is not supported by install.sh; download \
the binary directly from $SOTH_BASE_URL or downgrade the channel."
fi

# 3. Pull platform entry
binary_url=$(manifest_field "$TMPDIR/manifest.json" "platforms.${PLATFORM}.url")
binary_sha=$(manifest_field "$TMPDIR/manifest.json" "platforms.${PLATFORM}.sha256")

log "version $manifest_version"
log "downloading $binary_url"
curl_secure -fsSL "$binary_url" -o "$TMPDIR/soth"

actual_sha=$(sha256_of "$TMPDIR/soth")
[ "$actual_sha" = "$binary_sha" ] \
  || err "sha256 mismatch: expected $binary_sha got $actual_sha (binary discarded)"

# 4. Install
mkdir -p "$SOTH_INSTALL_DIR"
target="$SOTH_INSTALL_DIR/soth"
if [ -f "$target" ]; then
  log "backing up existing $target → $target.previous"
  mv "$target" "$target.previous"
fi
mv "$TMPDIR/soth" "$target"
chmod 0755 "$target"

# macOS-specific post-install: clear quarantine + adhoc-resign.
# Without this, Gatekeeper kills the binary with "soth cannot be opened
# because the developer cannot be verified" or (on macOS 26) hits the
# Taskgated SIGKILL we documented in PR #76 (May 6).
if [ "$(uname -s)" = "Darwin" ]; then
  if command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$target" 2>/dev/null || true
  fi
  if command -v codesign >/dev/null 2>&1; then
    codesign --force --sign - "$target" 2>/dev/null || true
  fi
fi

log "installed v${manifest_version} → $target"

# 5. PATH hint
case ":$PATH:" in
  *":$SOTH_INSTALL_DIR:"*) ;;
  *)
    echo
    echo "WARN: $SOTH_INSTALL_DIR is not on \$PATH."
    echo "      Add to your shell profile:"
    echo "        export PATH=\"$SOTH_INSTALL_DIR:\$PATH\""
    ;;
esac

echo
echo "Next steps:"
echo "  soth init"
echo "  soth setup-ca"
echo "  soth up"
echo
echo "To check for updates: soth update --check"
echo "To uninstall: rm $target $target.previous"

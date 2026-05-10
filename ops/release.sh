#!/usr/bin/env bash
# SOTH ops release driver.
#
# Invoked from the top-level Makefile. Reads ops/.env.<env> if present
# (gitignored, sourced from your secret store), then dispatches.
#
# Usage:
#   ./ops/release.sh <verb> [ENV]
#
# Phase 1 verbs:
#   help         show this help
#   build-cli    build all 5 platform binaries with embedded creds → dist/
#   publish-cli  push dist/ binaries to ENV destination + verify
#   release-cli  build-cli + publish-cli
#   verify-cli   re-run sha verification only (no build, no publish)
#   diff         local sha vs ENV currently-served sha
#   clean-dist   rm -rf dist/

set -euo pipefail

# --- Resolve repo root (script lives in ops/) -------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# --- Args -------------------------------------------------------------------
VERB="${1:-help}"
ENV="${2:-staging}"

# --- Defaults (overridden by ops/.env.<env> and shell) ----------------------
: "${SOTH_HONEYCOMB_API_KEY:=}"
: "${SOTH_HONEYCOMB_DATASET:=soth-edge-proxy}"
: "${SOTH_SENTRY_DSN:=}"

: "${R2_BUCKET:=storage}"
: "${R2_PREFIX:=release/}"

: "${MINIO_ENDPOINT_URL:=https://storage.staging.soth.xyz}"
: "${MINIO_BUCKET:=release}"
: "${MINIO_ACCESS_KEY:=}"
: "${MINIO_SECRET_KEY:=}"
: "${AWS_CA_BUNDLE:=/etc/ssl/cert.pem}"

: "${DIST_DIR:=./dist}"
: "${DATA_DIR:=$HOME/labterminal/soth/data}"

# Phase 2 / 3 (admin API)
: "${PLATFORM_ADMIN_TOKEN:=}"
: "${ADMIN_API:=}"
# VERSION default for classify + catalog. Today's prod is `v1-2026-04-28`,
# matched here so the auto-default lines up with the existing convention.
: "${VERSION:=v1-$(date +%Y-%m-%d)}"

# Release-manifest signing (Phase 1 hot-update).
# Privates live outside the repo (1Password / operator vault); operator
# pulls the active key into SOTH_RELEASE_KEY_DIR before `make release-cli`.
: "${SOTH_RELEASE_KEY_DIR:=$HOME/.soth/keys/release}"
# Override to publish a non-default channel for an ENV (e.g. CHANNEL=canary
# from prod). Default is derived from ENV via default_channel_for_env.
: "${CHANNEL:=}"
# Floor for the client-side min_supported_version anti-rollback gate.
# Bump only when shipping a release that intentionally drops support for
# older clients (e.g. breaking the heartbeat protocol).
: "${MIN_SUPPORTED_VERSION:=0.1.0}"
# Where release notes live. Manifest stores the URL; clients open it.
: "${RELEASE_NOTES_URL_TEMPLATE:=https://github.com/soth-ai/soth/releases/tag/v%VERSION%}"

PROD_BASE_URL="https://storage.soth.ai/release"
STAGING_BASE_URL="https://storage.staging.soth.xyz/release"

# Default admin API per env, applied if ADMIN_API isn't already set above
# (env file or shell). Local assumes a docker-compose'd soth-api on :8081.
default_admin_api_for_env() {
  case "$ENV" in
    staging) echo "https://api.staging.soth.xyz" ;;
    prod)    echo "https://api.soth.ai" ;;
    local)   echo "http://localhost:8081" ;;
    *)       echo "" ;;
  esac
}

CLI_BINARIES=(
  soth-darwin-arm64
  soth-darwin-amd64
  soth-linux-amd64
  soth-linux-arm64
  soth-windows-amd64.exe
)

# --- Per-env file load ------------------------------------------------------
ENV_FILE="ops/.env.${ENV}"
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

# Apply admin-API default after env-file load, so per-env overrides win.
if [ -z "$ADMIN_API" ]; then
  ADMIN_API="$(default_admin_api_for_env)"
fi

# --- Helpers ----------------------------------------------------------------

err() {
  echo "ERROR: $*" >&2
  exit 1
}

require_var() {
  local name="$1"
  local hint="${2:-set it in ops/.env.${ENV} or the shell}"
  if [ -z "${!name:-}" ]; then
    err "$name is empty ($hint)"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || err "$1 not on PATH"
}

# --- help -------------------------------------------------------------------
cmd_help() {
  cat <<-EOF
	SOTH ops Makefile

	Usage: make <target> [ENV=local|staging|prod] [VERSION=…]
	  ENV defaults to staging; auto-loads ops/.env.\$ENV if present.
	  VERSION defaults to v1-\$(date +%Y-%m-%d) for classify + catalog.

	CLI binaries (Phase 1):
	  build-cli              Build all 5 platform binaries (embedded creds) → ${DIST_DIR}/
	  publish-cli            Push ${DIST_DIR}/ binaries to ENV destination + verify
	  release-cli            build-cli + publish-cli + manifest gen/sign/publish/verify
	  verify-cli             Re-verify remote sha matches ${DIST_DIR}/ (no build/publish)
	  diff                   Local sha vs ENV's currently-served sha

	Hot-update manifest (Phase 1):
	  generate-manifest      Build ${DIST_DIR}/manifest/<channel>.json from sha sidecars
	  sign-manifest          ed25519-sign manifest with SOTH_RELEASE_KEY_DIR/<key>.private.pem
	  publish-manifest       Upload manifest.json + .sig to ENV's storage URL
	  verify-manifest        Round-trip: re-fetch, re-verify against ops/keys/<key>.public.pem
	  register-release       POST manifest metadata to ADMIN_API/api/v1/admin/cli/releases

	Classify bundle (Phase 2):
	  build-classify         tar -czf ${DIST_DIR}/classify-\$VERSION.tar.gz from \$DATA_DIR/classify/
	  publish-classify       POST tarball to \$ADMIN_API/v1/admin/classify/upload?version=…
	  release-classify       build-classify + publish-classify
	  verify-classify        ENV=local: re-shasum the tarball

	Tool catalog (Phase 3):
	  import-catalog         Refresh server raw_bundle.json + POST /admin/registry/import/current
	                         (staging: ssh+scp+ssh-cp; prod: prints soth-cloud-commit guidance)
	  compile-catalog        POST /admin/registry/compile, capture compilation_id
	  publish-catalog        POST /admin/registry/compilations/{id}/publish
	  release-catalog        compile-catalog + publish-catalog (import is separate)

	Inventory (Phase 4):
	  status                 Single-env: live CLI shas + last-published classify + live catalog
	  status-all             Walk staging + prod side by side
	  diff                   Local ${DIST_DIR}/ vs ENV: CLI shas + classify (vs last-published sidecar)

	Maintenance:
	  clean-dist             rm -rf ${DIST_DIR}

	Required env (set in ops/.env.\$ENV; see ops/.env.example):
	  SOTH_HONEYCOMB_API_KEY  build-cli (option_env! at compile time)
	  SOTH_SENTRY_DSN         build-cli
	  MINIO_ACCESS_KEY        publish-cli ENV=staging
	  MINIO_SECRET_KEY        publish-cli ENV=staging
	  PLATFORM_ADMIN_TOKEN    publish-classify, *-catalog
	  ADMIN_API               publish-classify, *-catalog (auto-defaults per ENV)
	  SOTH_RELEASE_KEY_DIR    sign-manifest (default ~/.soth/keys/release)
	  CHANNEL                 override channel for ENV (staging→staging, prod→stable)
	  (prod CLI publish uses \`npx -y wrangler@4.75.0 login\` — no extra creds.)

	Phase 4 (status/diff cross-env) and Phase 5 (GHA wrappers) follow.
	EOF
}

# --- build-cli --------------------------------------------------------------

require_build_creds() {
  require_var SOTH_HONEYCOMB_API_KEY
  require_var SOTH_SENTRY_DSN
}

# Build one target; uses zigbuild for linux glibc baselines, cargo for the rest.
# Args: bin_name target builder [src_name=soth] [rust_target_dir=$target]
build_one() {
  local bin="$1"
  local target="$2"
  local builder="$3"
  local src_name="${4:-soth}"
  local rust_target_dir="${5:-$target}"

  echo
  echo "==> $bin  (target=$target builder=$builder)"

  rustup target add "$rust_target_dir" >/dev/null

  export SOTH_HONEYCOMB_API_KEY SOTH_HONEYCOMB_DATASET SOTH_SENTRY_DSN

  case "$builder" in
    cargo)
      cargo build -p soth-cli --bin soth --release --target "$target"
      ;;
    zigbuild)
      cargo zigbuild -p soth-cli --bin soth --release --target "$target"
      ;;
    *) err "unknown builder: $builder" ;;
  esac

  cp "target/${rust_target_dir}/release/${src_name}" "${DIST_DIR}/${bin}"
}

cmd_build_cli() {
  require_build_creds
  mkdir -p "$DIST_DIR"

  build_one soth-darwin-arm64       aarch64-apple-darwin                  cargo
  build_one soth-darwin-amd64       x86_64-apple-darwin                   cargo
  build_one soth-linux-amd64        x86_64-unknown-linux-gnu.2.17         zigbuild  soth  x86_64-unknown-linux-gnu
  build_one soth-linux-arm64        aarch64-unknown-linux-gnu.2.17        zigbuild  soth  aarch64-unknown-linux-gnu
  build_one soth-windows-amd64.exe  x86_64-pc-windows-gnu                 cargo     soth.exe

  echo
  echo "==> sha256 manifests"
  (
    cd "$DIST_DIR"
    for f in "${CLI_BINARIES[@]}"; do
      shasum -a 256 "$f" > "$f.sha256"
    done
  )

  echo
  echo "=== ${DIST_DIR}/ ==="
  ls -la "$DIST_DIR"
}

# --- publish-cli ------------------------------------------------------------

ensure_dist_present() {
  for f in "${CLI_BINARIES[@]}"; do
    [ -f "${DIST_DIR}/$f" ] || err "missing ${DIST_DIR}/$f (run \`make build-cli\` first)"
    [ -f "${DIST_DIR}/$f.sha256" ] || err "missing ${DIST_DIR}/$f.sha256 (run \`make build-cli\` first)"
  done
}

cmd_publish_cli() {
  case "$ENV" in
    local) cmd_publish_cli_local ;;
    staging) cmd_publish_cli_staging ;;
    prod) cmd_publish_cli_prod ;;
    *) err "ENV must be local|staging|prod (got '$ENV')" ;;
  esac
}

cmd_publish_cli_local() {
  ensure_dist_present
  echo "==> ENV=local: artifacts already in ${DIST_DIR}/, no remote publish."
  ls -la "$DIST_DIR"
}

cmd_publish_cli_staging() {
  ensure_dist_present
  require_var MINIO_ACCESS_KEY
  require_var MINIO_SECRET_KEY
  require_cmd aws

  export AWS_ACCESS_KEY_ID="$MINIO_ACCESS_KEY"
  export AWS_SECRET_ACCESS_KEY="$MINIO_SECRET_KEY"
  export AWS_CA_BUNDLE

  for f in "${CLI_BINARIES[@]}" "${CLI_BINARIES[@]/%/.sha256}"; do
    echo "==> S3 put s3://${MINIO_BUCKET}/${f}"
    aws s3 cp "${DIST_DIR}/${f}" "s3://${MINIO_BUCKET}/${f}" \
      --endpoint-url "$MINIO_ENDPOINT_URL" \
      --cache-control "no-store, max-age=0" \
      --no-progress
  done

  cmd_verify_against "$STAGING_BASE_URL"
}

cmd_publish_cli_prod() {
  ensure_dist_present
  require_cmd npx

  # Pin wrangler via npx instead of relying on the globally installed
  # version. Two reasons:
  #   1) The Homebrew-installed wrangler 4.60.x consistently 504s on R2
  #      uploads of binaries >30 MiB (saw it on soth-linux-amd64 and
  #      soth-windows-amd64.exe during the 2026-05-06 staging→prod cut).
  #      4.75.x landed an upload retry/timeout fix that resolves it.
  #   2) wrangler 4.88+ requires Node 22; 4.75.0 is the highest line that
  #      still works on the Node 20 we ship with. Pin here so the version
  #      bump doesn't surprise anyone running this from a fresh checkout.
  local WRANGLER="npx -y wrangler@4.75.0"

  $WRANGLER whoami >/dev/null 2>&1 || err "wrangler not logged in (run \`npx -y wrangler@4.75.0 login\`)"

  unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy

  for f in "${CLI_BINARIES[@]}" "${CLI_BINARIES[@]/%/.sha256}"; do
    echo "==> R2 put ${R2_BUCKET}/${R2_PREFIX}${f}"
    $WRANGLER r2 object put "${R2_BUCKET}/${R2_PREFIX}${f}" \
      --file="${DIST_DIR}/${f}" \
      --remote \
      --cache-control "no-store, max-age=0"
  done

  cmd_verify_against "$PROD_BASE_URL"
}

# --- release manifest (Phase 1 hot-update) ----------------------------------
#
# After publish-cli has uploaded the per-platform binaries + .sha256
# sidecars, generate-manifest assembles a signed manifest that clients
# fetch via `soth update --check`. The manifest is the source of truth
# for "what's the latest version on channel X?" — clients only trust
# what's signed.
#
# Schema is documented in docs/common/2026-05-09/hot-update-plan.md §2.1.
# Signature is raw ed25519 (64 bytes) over the manifest.json bytes.
# OpenSSL 3.0+ is required (-rawin support).

default_channel_for_env() {
  case "$1" in
    staging) echo "staging" ;;
    prod)    echo "stable" ;;
    local)   echo "staging" ;;
    *)       echo "" ;;
  esac
}

# Map channel → which keypair signs it. Stable releases use the stable
# key; staging-internal and explicit canary cuts share the canary key
# (they're both "unstable" from a customer trust perspective).
key_basename_for_channel() {
  case "$1" in
    stable)            echo "stable" ;;
    canary | staging)  echo "canary" ;;
    *) err "unknown channel '$1' (expected stable|canary|staging)" ;;
  esac
}

base_url_for_env() {
  case "$1" in
    staging) echo "$STAGING_BASE_URL" ;;
    prod)    echo "$PROD_BASE_URL" ;;
    local)   echo "" ;;
    *)       echo "" ;;
  esac
}

# Map a publish-cli filename to the manifest's platform key.
# soth-darwin-arm64           → darwin-arm64
# soth-windows-amd64.exe      → windows-amd64
binary_to_platform_key() {
  local f="$1"
  f="${f#soth-}"
  f="${f%.exe}"
  echo "$f"
}

extract_workspace_version() {
  awk '
    /^\[workspace\.package\]/ { in_wp=1; next }
    /^\[/                     { in_wp=0 }
    in_wp && /^version[[:space:]]*=/ {
      gsub(/[\"[:space:]]/, "", $0)
      sub(/^version=/, "")
      print
      exit
    }
  ' Cargo.toml
}

# Pull the current channel manifest's release_seq so we can monotonically
# increment. Returns 0 if no manifest exists yet (first publish to channel).
fetch_current_release_seq() {
  local base="$1" channel="$2"
  local url="${base}/manifest/${channel}.json?cb=$(date +%s)"
  local body
  body=$(curl -sfL "$url" 2>/dev/null || true)
  if [ -z "$body" ]; then
    echo 0
    return
  fi
  echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("release_seq", 0))' 2>/dev/null || echo 0
}

# Resolve the channel: explicit $CHANNEL wins, else env-derived default.
resolve_channel() {
  if [ -n "$CHANNEL" ]; then
    echo "$CHANNEL"
  else
    default_channel_for_env "$ENV"
  fi
}

cmd_generate_manifest() {
  ensure_dist_present
  require_cmd python3
  require_cmd shasum
  require_cmd curl

  local channel
  channel=$(resolve_channel)
  [ -n "$channel" ] || err "could not resolve channel for ENV=$ENV (set CHANNEL explicitly)"

  local base
  base=$(base_url_for_env "$ENV")
  [ -n "$base" ] || err "no base URL for ENV=$ENV (only staging|prod produce remote manifests)"

  local version
  version=$(extract_workspace_version)
  [ -n "$version" ] || err "could not extract workspace version from Cargo.toml"

  local current_seq next_seq
  current_seq=$(fetch_current_release_seq "$base" "$channel")
  next_seq=$((current_seq + 1))

  local released_at
  released_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  local notes_url="${RELEASE_NOTES_URL_TEMPLATE/\%VERSION\%/$version}"

  mkdir -p "${DIST_DIR}/manifest"
  local out="${DIST_DIR}/manifest/${channel}.json"

  echo "==> generate manifest (channel=${channel}, version=${version}, release_seq=${next_seq})"

  # Build platforms map by walking CLI_BINARIES + their .sha256 sidecars.
  local platforms_json="{"
  local first=1
  for f in "${CLI_BINARIES[@]}"; do
    local key sha
    key=$(binary_to_platform_key "$f")
    sha=$(awk '{print $1}' "${DIST_DIR}/${f}.sha256")
    [ -n "$sha" ] || err "empty sha256 for ${f}"
    if [ "$first" = 1 ]; then first=0; else platforms_json+=", "; fi
    platforms_json+="\"${key}\": {\"url\": \"${base}/${f}\", \"sha256\": \"${sha}\"}"
  done
  platforms_json+="}"

  # python3 emits the canonical JSON (sorted keys, no trailing whitespace)
  # so the signing input is byte-stable across operator machines.
  python3 - "$out" <<-PYEOF
	import json, os, sys
	out = sys.argv[1]
	manifest = {
	    "schema_version": 1,
	    "channel": "${channel}",
	    "version": "${version}",
	    "release_seq": ${next_seq},
	    "released_at": "${released_at}",
	    "min_supported_version": "${MIN_SUPPORTED_VERSION}",
	    "release_notes_url": "${notes_url}",
	    "platforms": ${platforms_json},
	}
	with open(out, "w") as fh:
	    json.dump(manifest, fh, sort_keys=True, separators=(",", ":"))
	    fh.write("\n")
	size = os.path.getsize(out)
	print(f"  wrote {out} ({size} bytes, {len(manifest['platforms'])} platforms)")
PYEOF
}

cmd_sign_manifest() {
  require_cmd openssl
  local channel key_basename key_path manifest sig pubkey
  channel=$(resolve_channel)
  [ -n "$channel" ] || err "could not resolve channel for ENV=$ENV"
  key_basename=$(key_basename_for_channel "$channel")

  key_path="${SOTH_RELEASE_KEY_DIR}/${key_basename}.private.pem"
  manifest="${DIST_DIR}/manifest/${channel}.json"
  sig="${manifest}.sig"
  pubkey="ops/keys/${key_basename}.public.pem"

  [ -f "$key_path" ] || err "private key missing: $key_path (pull from 1Password)"
  [ -f "$manifest" ] || err "manifest missing: $manifest (run generate-manifest first)"
  [ -f "$pubkey" ] || err "public key missing: $pubkey"

  echo "==> sign manifest (channel=${channel}, key=${key_basename})"
  openssl pkeyutl -sign -inkey "$key_path" -rawin -in "$manifest" -out "$sig"

  # Self-verify before publishing — guarantees the signature roundtrips
  # against the public key that ships in the binary.
  openssl pkeyutl -verify -pubin -inkey "$pubkey" -rawin \
    -in "$manifest" -sigfile "$sig" >/dev/null \
    || err "self-verify failed; aborting publish"

  printf "  manifest:  %s\n" "$manifest"
  printf "  signature: %s (%s bytes)\n" "$sig" "$(wc -c < "$sig" | tr -d ' ')"
  printf "  pubkey:    %s\n" "$pubkey"
}

cmd_publish_manifest() {
  local channel manifest sig
  channel=$(resolve_channel)
  manifest="${DIST_DIR}/manifest/${channel}.json"
  sig="${manifest}.sig"

  [ -f "$manifest" ] || err "manifest missing: $manifest"
  [ -f "$sig" ]      || err "signature missing: $sig"

  case "$ENV" in
    local)
      echo "==> ENV=local: manifest stays in ${manifest}, no remote publish."
      ;;
    staging)
      require_var MINIO_ACCESS_KEY
      require_var MINIO_SECRET_KEY
      require_cmd aws
      export AWS_ACCESS_KEY_ID="$MINIO_ACCESS_KEY"
      export AWS_SECRET_ACCESS_KEY="$MINIO_SECRET_KEY"
      export AWS_CA_BUNDLE
      for f in "${channel}.json" "${channel}.json.sig"; do
        echo "==> S3 put s3://${MINIO_BUCKET}/manifest/${f}"
        aws s3 cp "${DIST_DIR}/manifest/${f}" "s3://${MINIO_BUCKET}/manifest/${f}" \
          --endpoint-url "$MINIO_ENDPOINT_URL" \
          --cache-control "no-store, max-age=0" \
          --no-progress
      done
      ;;
    prod)
      require_cmd npx
      local WRANGLER="npx -y wrangler@4.75.0"
      $WRANGLER whoami >/dev/null 2>&1 \
        || err "wrangler not logged in (run \`npx -y wrangler@4.75.0 login\`)"
      unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy
      for f in "${channel}.json" "${channel}.json.sig"; do
        echo "==> R2 put ${R2_BUCKET}/${R2_PREFIX}manifest/${f}"
        $WRANGLER r2 object put "${R2_BUCKET}/${R2_PREFIX}manifest/${f}" \
          --file="${DIST_DIR}/manifest/${f}" \
          --remote \
          --cache-control "no-store, max-age=0"
      done
      ;;
    *) err "ENV must be local|staging|prod (got '$ENV')" ;;
  esac
}

# Register the just-published release with soth-cloud's admin API
# (Phase 3a). The hot-update resolver reads `cli_releases` on every
# heartbeat; without this row, a channel pointing at this version will
# never emit an offer.
#
# Idempotent: re-posting the same (version, platform) overwrites url +
# sha256. Soft-fail (warn) — the manifest is the trust root, so a
# registration failure means "fleet won't auto-discover this version
# yet" not "this release is broken".
#
# Requires PLATFORM_ADMIN_TOKEN + ADMIN_API. Skipped for ENV=local.
cmd_register_release() {
  case "$ENV" in
    local)
      echo "==> ENV=local: skipping release registration."
      return 0
      ;;
    staging | prod) ;;
    *) err "ENV must be local|staging|prod (got '$ENV')" ;;
  esac

  if [ -z "$PLATFORM_ADMIN_TOKEN" ] || [ -z "$ADMIN_API" ]; then
    echo "==> WARN: PLATFORM_ADMIN_TOKEN or ADMIN_API empty; skipping release registration."
    echo "         The release is published but won't be served by the heartbeat resolver"
    echo "         until you POST it to ${ADMIN_API:-<unset>}/api/v1/admin/cli/releases."
    return 0
  fi

  require_cmd python3
  require_cmd curl

  local channel manifest
  channel=$(resolve_channel)
  manifest="${DIST_DIR}/manifest/${channel}.json"
  [ -f "$manifest" ] || err "manifest missing: $manifest (run generate-manifest first)"

  echo "==> register release ${ADMIN_API}/api/v1/admin/cli/releases"

  # The admin API's request body is a strict subset of the manifest
  # (no channel, schema_version, min_supported_version, released_at).
  # python3 transforms the existing manifest into the registration
  # payload to avoid drift between the two shapes.
  local body
  body=$(python3 - "$manifest" <<-'PYEOF'
	import json, sys
	with open(sys.argv[1]) as fh:
	    m = json.load(fh)
	out = {
	    "version": m["version"],
	    "release_seq": m["release_seq"],
	    "platforms": m["platforms"],
	}
	if m.get("release_notes_url"):
	    out["release_notes_url"] = m["release_notes_url"]
	print(json.dumps(out, separators=(",", ":")))
PYEOF
  )

  local http_code
  http_code=$(curl -sS -o /tmp/soth-release-register-resp.json -w "%{http_code}" \
    -X POST "${ADMIN_API}/api/v1/admin/cli/releases" \
    -H "Authorization: Bearer ${PLATFORM_ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    --data-raw "$body" 2>&1) || true

  if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
    printf "  HTTP %s\n" "$http_code"
    python3 - <<-'PYEOF'
	import json
	with open("/tmp/soth-release-register-resp.json") as fh:
	    r = json.load(fh)
	print(f"  registered version={r['version']} release_seq={r['release_seq']} platforms={len(r['platforms'])}")
PYEOF
  else
    echo "  WARN: release registration returned HTTP ${http_code}; body:"
    sed 's/^/    /' /tmp/soth-release-register-resp.json 2>/dev/null || true
    echo "  Manifest is published; resolver won't serve this version until /admin/cli/releases is populated."
  fi
}

# Round-trip verify: download the freshly-published manifest, verify the
# sig with the committed public key, ensure version + sha entries match
# what we just uploaded. Belt-and-braces — same idea as cmd_verify_against
# for binaries.
cmd_verify_manifest() {
  require_cmd curl
  require_cmd openssl

  local channel base manifest_url sig_url tmpdir
  channel=$(resolve_channel)
  base=$(base_url_for_env "$ENV")
  [ -n "$base" ] || err "ENV=$ENV has no remote (use staging|prod)"

  manifest_url="${base}/manifest/${channel}.json?cb=$(date +%s)"
  sig_url="${base}/manifest/${channel}.json.sig?cb=$(date +%s)"

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' RETURN

  echo "==> fetch ${manifest_url}"
  curl -sfL "$manifest_url" -o "$tmpdir/manifest.json" \
    || err "manifest fetch failed"
  curl -sfL "$sig_url" -o "$tmpdir/manifest.json.sig" \
    || err "signature fetch failed"

  local key_basename pubkey
  key_basename=$(key_basename_for_channel "$channel")
  pubkey="ops/keys/${key_basename}.public.pem"
  [ -f "$pubkey" ] || err "public key missing: $pubkey"

  openssl pkeyutl -verify -pubin -inkey "$pubkey" -rawin \
    -in "$tmpdir/manifest.json" -sigfile "$tmpdir/manifest.json.sig" >/dev/null \
    || err "remote signature verification FAILED"

  printf "  channel:   %s\n" "$channel"
  printf "  signature: OK (verified with %s)\n" "$pubkey"
  python3 - "$tmpdir/manifest.json" <<-'PYEOF'
	import json, sys
	with open(sys.argv[1]) as fh: m = json.load(fh)
	print(f"  version:   {m['version']}")
	print(f"  release_seq: {m['release_seq']}")
	print(f"  released_at: {m['released_at']}")
	print(f"  platforms: {len(m['platforms'])} entries")
PYEOF
}

# --- verify-cli -------------------------------------------------------------

cmd_verify_cli() {
  case "$ENV" in
    staging) cmd_verify_against "$STAGING_BASE_URL" ;;
    prod) cmd_verify_against "$PROD_BASE_URL" ;;
    *) err "verify-cli only supported for ENV=staging|prod" ;;
  esac
}

# Walk the binaries, compare local sha to remote sha (cache-busted).
cmd_verify_against() {
  local base="$1"
  echo
  echo "=== verifying ${ENV} (${base}) against ${DIST_DIR}/ ==="
  local fail=0
  for f in "${CLI_BINARIES[@]}"; do
    local local_sha remote_sha
    local_sha=$(shasum -a 256 "${DIST_DIR}/${f}" | awk '{print $1}')
    remote_sha=$(curl -sL "${base}/${f}?cb=$(date +%s)" | shasum -a 256 | awk '{print $1}')
    if [ "$local_sha" = "$remote_sha" ]; then
      printf "  %-30s OK    %s\n" "$f" "$local_sha"
    else
      printf "  %-30s MISMATCH local=%s remote=%s\n" "$f" "$local_sha" "$remote_sha"
      fail=1
    fi
  done
  if [ "$fail" != 0 ]; then
    echo
    err "verification failed"
  fi
}

# --- diff -------------------------------------------------------------------

# Walk all artifacts that have a local-vs-remote distinction and print
# OK / DIFF / missing / unreachable per artifact. Catalog has no
# local pre-publish artifact (its source is server-side DB state), so
# `cmd_status` reports it instead of `cmd_diff`.
cmd_diff() {
  local base
  case "$ENV" in
    staging) base="$STAGING_BASE_URL" ;;
    prod)    base="$PROD_BASE_URL" ;;
    *) err "diff requires ENV=staging|prod" ;;
  esac
  echo "=== local ${DIST_DIR}/ vs ${ENV} (${base}) ==="
  echo
  echo "CLI binaries:"
  for f in "${CLI_BINARIES[@]}"; do
    local local_sha remote_sha status
    local_sha=$(shasum -a 256 "${DIST_DIR}/${f}" 2>/dev/null | awk '{print $1}' || echo "missing")
    remote_sha=$(curl -sL "${base}/${f}?cb=$(date +%s)" 2>/dev/null | shasum -a 256 | awk '{print $1}' || echo "unreachable")
    if [ "$local_sha" = "$remote_sha" ]; then status="OK"; else status="DIFF"; fi
    printf "  %-30s local=%-12s remote=%-12s %s\n" \
      "$f" "${local_sha:0:12}" "${remote_sha:0:12}" "$status"
  done

  # Classify: compare local tarball sha to whatever this dist last
  # published to ENV (the cached sidecar). True remote state requires
  # an authenticated probe of the edge endpoint, but the sidecar is a
  # solid proxy when this machine is the publisher.
  echo
  echo "Classify bundle:"
  local classify_local classify_local_sha classify_remote_sidecar
  classify_local="${DIST_DIR}/classify-${VERSION}.tar.gz"
  classify_local_sha=$(shasum -a 256 "$classify_local" 2>/dev/null | awk '{print $1}' || echo "missing")
  classify_remote_sidecar="${DIST_DIR}/classify-published.${ENV}.json"
  if [ -f "$classify_remote_sidecar" ]; then
    local remote_sha remote_version remote_status
    remote_sha=$(python3 -c "import sys,json; print(json.load(open('$classify_remote_sidecar'))['sha256'])" 2>/dev/null || echo "")
    remote_version=$(python3 -c "import sys,json; print(json.load(open('$classify_remote_sidecar'))['version'])" 2>/dev/null || echo "")
    if [ "$classify_local_sha" = "$remote_sha" ]; then remote_status="OK"; else remote_status="DIFF"; fi
    printf "  classify-%-21s local=%-12s remote=%-12s %s\n" \
      "${VERSION}.tar.gz" \
      "${classify_local_sha:0:12}" "${remote_sha:0:12}" "$remote_status"
    printf "  (last published from this machine: version=%s)\n" "$remote_version"
  else
    printf "  classify-%-21s local=%-12s remote=%-12s %s\n" \
      "${VERSION}.tar.gz" \
      "${classify_local_sha:0:12}" "no-record" "?"
    echo "  (no sidecar yet — publish from this machine to populate)"
  fi
}

# --- status -----------------------------------------------------------------

# Single-env detailed view: what's actually live in $ENV right now,
# across CLI / classify / catalog.
cmd_status() {
  case "$ENV" in
    local)   cmd_status_local ;;
    staging|prod) cmd_status_remote ;;
    *) err "ENV must be local|staging|prod" ;;
  esac
}

cmd_status_local() {
  echo "=== local (${DIST_DIR}/) ==="
  echo
  if [ -d "$DIST_DIR" ]; then
    ls -la "$DIST_DIR" 2>/dev/null | tail -n +2
  else
    echo "  ${DIST_DIR} does not exist"
  fi
}

cmd_status_remote() {
  local base
  case "$ENV" in
    staging) base="$STAGING_BASE_URL" ;;
    prod)    base="$PROD_BASE_URL" ;;
  esac
  echo "=== ${ENV} status ==="

  echo
  echo "CLI binaries (${base}):"
  for f in "${CLI_BINARIES[@]}"; do
    local sha
    sha=$(curl -sL "${base}/${f}?cb=$(date +%s)" 2>/dev/null | shasum -a 256 | awk '{print $1}' || echo "unreachable")
    printf "  %-30s %s\n" "$f" "${sha:0:12}"
  done

  echo
  echo "Classify bundle (last published from this machine):"
  local sidecar="${DIST_DIR}/classify-published.${ENV}.json"
  if [ -f "$sidecar" ]; then
    python3 -c "
import json
d = json.load(open('$sidecar'))
print(f\"  version:        {d.get('version','?')}\")
print(f\"  sha256:         {d.get('sha256','?')[:32]}…\")
print(f\"  published_at:   {d.get('published_at','?')}\")
"
  else
    echo "  (no sidecar — never published from this dist/. Edge probe requires api_key auth.)"
  fi

  echo
  echo "Tool catalog (live from admin API):"
  if [ -z "$ADMIN_API" ] || [ -z "$PLATFORM_ADMIN_TOKEN" ]; then
    echo "  (need PLATFORM_ADMIN_TOKEN + ADMIN_API in ops/.env.${ENV})"
    return
  fi
  local resp_file resp_status
  resp_file=$(mktemp)
  resp_status=$(curl -sS -o "$resp_file" -w "%{http_code}" \
    -H "Authorization: Bearer ${PLATFORM_ADMIN_TOKEN}" \
    "${ADMIN_API}/v1/admin/registry/current")
  if [ "$resp_status" = "200" ]; then
    python3 -c "
import json
b = json.load(open('$resp_file'))
c = b.get('compilation', b)
print(f\"  version:           {c.get('version','?')}\")
print(f\"  compilation_id:    {c.get('id','?')}\")
print(f\"  compiled_sha256:   {c.get('compiled_sha256','?')[:32]}…\")
print(f\"  vendors:           {c.get('vendor_count','?')}\")
print(f\"  llm providers:     {c.get('llm_provider_count','?')}\")
"
  else
    echo "  (admin API returned $resp_status: $(cat "$resp_file"))"
  fi
  rm -f "$resp_file"
}

# Cross-env summary. Walks staging + prod and prints each env's status
# block. Re-execs the script per env so each invocation freshly loads
# ops/.env.<env> — same env-file contract as a direct `status ENV=…`
# call. Useful for "what's where?" before a release.
cmd_status_all() {
  echo "=== cross-env release status ==="
  for one_env in staging prod; do
    echo
    echo "--- ${one_env} ---"
    # Don't break the outer loop on a per-env failure (e.g. token
    # missing for one env but not the other).
    "$0" status "$one_env" || true
  done
}

# --- release-cli (composite) ------------------------------------------------

cmd_release_cli() {
  cmd_build_cli
  cmd_publish_cli
  # Hot-update manifest pipeline. Skipped for ENV=local — local releases
  # don't need a signed manifest, and the private key may not be present.
  if [ "$ENV" != "local" ]; then
    cmd_generate_manifest
    cmd_sign_manifest
    cmd_publish_manifest
    cmd_verify_manifest
    # Phase 3a: register the artifact metadata with soth-cloud's
    # admin API so the heartbeat resolver can serve it. Soft-fail.
    cmd_register_release
  fi
}

# --- classify bundle: build + publish + verify ------------------------------
#
# Source layout in $DATA_DIR/classify/:
#   manifest.json         (declares version + per-asset sha256)
#   embedding.onnx
#   centroids.bin
#   lsh_projection.bin
#   use_case_mlp.bin
#   tokenizer.json
#
# `build-classify` packs the whole dir into one gzip-compressed tar
# (the format the admin upload handler expects:
# crates/soth-api/src/handlers/bundles.rs:72), pinned to the resolved
# VERSION (default `v1-YYYY-MM-DD`, overridable via env).
#
# `publish-classify` POSTs the tarball to /v1/admin/classify/upload?version=…
# with the bearer token. Verification compares the sha returned in the
# upload response body against the local sha — the server stores bytes
# as-is, so a match proves what we sent landed intact.

require_classify_admin_creds() {
  require_var PLATFORM_ADMIN_TOKEN
  if [ -z "$ADMIN_API" ]; then
    err "ADMIN_API is empty (no default for ENV=$ENV; set ADMIN_API explicitly)"
  fi
}

# Resolve the version label and the on-disk tarball path, in one place,
# so build / publish / verify all agree.
classify_bundle_path() {
  echo "${DIST_DIR}/classify-${VERSION}.tar.gz"
}

cmd_build_classify() {
  local src="${DATA_DIR}/classify"
  local out
  out="$(classify_bundle_path)"

  [ -d "$src" ] || err "classify source dir missing: $src"
  [ -f "$src/manifest.json" ] || err "classify manifest missing: $src/manifest.json"

  mkdir -p "$DIST_DIR"

  echo "==> packaging classify bundle ${VERSION}"
  echo "    source: $src"
  echo "    target: $out"
  # `-C $src .` keeps paths relative to the classify dir so the tar
  # extracts back to `manifest.json`, `embedding.onnx`, etc. — no
  # leading directory.
  tar -czf "$out" -C "$src" .

  local sha size
  sha=$(shasum -a 256 "$out" | awk '{print $1}')
  if [ "$(uname -s)" = "Darwin" ]; then
    size=$(stat -f%z "$out")
  else
    size=$(stat -c%s "$out")
  fi
  printf "  size=%s sha256=%s\n" "$size" "$sha"

  # Sidecar so re-running publish-classify without re-build still picks
  # up the right version.
  echo "$VERSION" > "${DIST_DIR}/classify-version.txt"
}

cmd_publish_classify() {
  case "$ENV" in
    local) cmd_publish_classify_local ;;
    staging|prod) cmd_publish_classify_remote ;;
    *) err "ENV must be local|staging|prod (got '$ENV')" ;;
  esac
}

cmd_publish_classify_local() {
  local out
  out="$(classify_bundle_path)"
  [ -f "$out" ] || err "missing $out (run \`make build-classify\` first)"
  echo "==> ENV=local: classify bundle stays in ${out}, no remote publish."
  ls -la "$out"
}

cmd_publish_classify_remote() {
  require_classify_admin_creds
  local out
  out="$(classify_bundle_path)"
  [ -f "$out" ] || err "missing $out (run \`make build-classify\` first)"

  local local_sha
  local_sha=$(shasum -a 256 "$out" | awk '{print $1}')

  echo "==> POST ${ADMIN_API}/v1/admin/classify/upload?version=${VERSION}"
  echo "    body: ${out}  (local sha256=${local_sha})"

  # Capture body + status separately. Inline cleanup (no EXIT trap) so
  # `set -u` doesn't choke on the local going out of scope before the
  # trap fires.
  local response_file status body remote_sha
  response_file=$(mktemp)
  status=$(curl -sS \
    -o "$response_file" \
    -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${PLATFORM_ADMIN_TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${out}" \
    "${ADMIN_API}/v1/admin/classify/upload?version=${VERSION}")

  echo "  -> http=${status}"
  if [ "$status" != "200" ]; then
    echo "    body: $(cat "$response_file")"
    rm -f "$response_file"
    err "upload failed (http $status)"
  fi

  # Server response format (handlers/bundles.rs):
  #   classify bundle <version> uploaded (sha256=<hex>)
  body=$(cat "$response_file")
  rm -f "$response_file"
  echo "    body: ${body}"
  remote_sha=$(printf "%s" "$body" | sed -n 's/.*sha256=\([0-9a-f]\{64\}\).*/\1/p')

  if [ -z "$remote_sha" ]; then
    err "could not parse sha from upload response: ${body}"
  fi

  if [ "$local_sha" != "$remote_sha" ]; then
    err "sha mismatch after upload: local=${local_sha} remote=${remote_sha}"
  fi
  printf "  OK  classify ${VERSION} stored on ${ENV} (sha256=%s)\n" "$remote_sha"

  # Sidecar so `make status ENV=$ENV` can report what was last
  # published from this dist/ without needing api_key auth on the
  # edge endpoint. Reflects "last published from this machine" — if
  # someone else published from another machine, we won't see that
  # here. Good enough for the common case.
  cat > "${DIST_DIR}/classify-published.${ENV}.json" <<JSON
{"version":"${VERSION}","sha256":"${remote_sha}","published_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JSON
}

cmd_verify_classify() {
  case "$ENV" in
    local)
      local out
      out="$(classify_bundle_path)"
      [ -f "$out" ] || err "missing $out"
      shasum -a 256 "$out"
      ;;
    staging|prod)
      err "verify-classify on remote envs requires re-uploading; use \`make publish-classify\` which verifies inline, or implement an authenticated /v1/admin/classify/current probe (TODO)"
      ;;
    *) err "ENV must be local|staging|prod" ;;
  esac
}

cmd_release_classify() {
  cmd_build_classify
  cmd_publish_classify
}

# --- tool catalog: import + compile + publish ------------------------------
#
# Three sub-verbs, one per stage. They're separate because each has very
# different behavior across envs and the natural composite (compile +
# publish) doesn't include import.
#
#   import-catalog    refresh server's raw_bundle.json source-of-truth.
#                     - staging: scp + ssh sudo cp + POST /import/current
#                     - prod:    requires soth-cloud commit + CI deploy
#                                (Railway has no writable fs from outside)
#   compile-catalog   POST /v1/admin/registry/compile, capture compilation_id
#   publish-catalog   POST /v1/admin/registry/compilations/{id}/publish
#   release-catalog   compile-catalog + publish-catalog
#
# Parsers (`SOTH_Complete_Governance_Dataset.json`) are out of scope for
# this phase — the file's top-level shape is `{metadata, tools}` but
# the admin endpoint expects `{parsers: {...}}`. Untangling the mapping
# is its own ticket.

require_catalog_admin_creds() {
  require_var PLATFORM_ADMIN_TOKEN
  if [ -z "$ADMIN_API" ]; then
    err "ADMIN_API is empty (no default for ENV=$ENV; set in ops/.env.$ENV or shell)"
  fi
}

# Hetzner staging deploy — ssh target + on-disk path.
STAGING_SSH_HOST="ubuntu@65.108.45.248"
STAGING_RAW_BUNDLE_PATH="/opt/soth/soth-cloud/data/runtime/local-bundle/registry/raw_bundle.json"

cmd_import_catalog() {
  case "$ENV" in
    staging) cmd_import_catalog_staging ;;
    prod)    cmd_import_catalog_prod ;;
    local)   err "import-catalog ENV=local not supported (use compile-catalog directly against your dev API)" ;;
    *)       err "ENV must be staging|prod (got '$ENV')" ;;
  esac
}

cmd_import_catalog_staging() {
  require_catalog_admin_creds

  local src="${DATA_DIR}/raw_bundle.json"
  [ -f "$src" ] || err "missing $src"

  local local_sha
  local_sha=$(shasum -a 256 "$src" | awk '{print $1}')

  echo "==> sync raw_bundle.json → staging server"
  echo "    src: $src (sha256=${local_sha:0:12}…)"
  echo "    dst: ${STAGING_SSH_HOST}:${STAGING_RAW_BUNDLE_PATH}"

  # Two-step: scp to /tmp (ubuntu user owns it), then sudo cp into the
  # soth-owned deploy tree. Avoids needing ubuntu to write the deploy
  # tree directly.
  scp -q "$src" "${STAGING_SSH_HOST}:/tmp/raw_bundle.json.new"
  ssh "$STAGING_SSH_HOST" "sudo -u soth cp /tmp/raw_bundle.json.new ${STAGING_RAW_BUNDLE_PATH} && rm -f /tmp/raw_bundle.json.new"

  local remote_sha
  remote_sha=$(ssh "$STAGING_SSH_HOST" "sha256sum ${STAGING_RAW_BUNDLE_PATH}" 2>/dev/null | awk '{print $1}')
  [ "$local_sha" = "$remote_sha" ] || err "post-scp sha mismatch: local=$local_sha staging=$remote_sha"
  echo "  -> server sha matches local"

  echo
  echo "==> POST ${ADMIN_API}/v1/admin/registry/import/current"
  local response_file status body
  response_file=$(mktemp)
  status=$(curl -sS \
    -o "$response_file" \
    -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${PLATFORM_ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{}' \
    "${ADMIN_API}/v1/admin/registry/import/current")
  body=$(cat "$response_file")
  rm -f "$response_file"
  echo "  -> http=${status}"
  if [ "$status" != "200" ]; then
    echo "    body: $body"
    err "import failed (http $status)"
  fi
  echo "    body: $body"
  echo "  OK  raw_bundle imported into ${ENV} admin DB"
}

cmd_import_catalog_prod() {
  cat >&2 <<-EOF
	==> ENV=prod uses the soth-cloud deploy path:
	    1. cp ${DATA_DIR}/raw_bundle.json \\
	         <soth-cloud>/data/runtime/local-bundle/registry/raw_bundle.json
	    2. (cd soth-cloud && git add data/runtime/local-bundle/registry/raw_bundle.json \\
	         && git commit -m "data: refresh raw_bundle" && git push)
	    3. Wait for Railway CI to deploy.
	    4. make compile-catalog ENV=prod && make publish-catalog ENV=prod

	    Direct file injection is not available because Railway containers
	    don't expose a writable filesystem from outside.
	EOF
  err "import-catalog ENV=prod requires the soth-cloud commit flow above"
}

cmd_compile_catalog() {
  require_catalog_admin_creds

  echo "==> POST ${ADMIN_API}/v1/admin/registry/compile  (version=${VERSION})"

  local response_file status body
  response_file=$(mktemp)
  status=$(curl -sS \
    -o "$response_file" \
    -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${PLATFORM_ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"version\": \"${VERSION}\", \"notes\": \"compiled via ops/release.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
    "${ADMIN_API}/v1/admin/registry/compile")
  body=$(cat "$response_file")
  rm -f "$response_file"
  echo "  -> http=${status}"
  if [ "$status" != "200" ]; then
    echo "    body: $body"
    err "compile failed (http $status)"
  fi

  # Extract compilation.id with python's stdlib json (already a dep elsewhere).
  local compilation_id compiled_sha
  compilation_id=$(printf "%s" "$body" | python3 -c "import sys,json; print(json.load(sys.stdin)['compilation']['id'])" 2>/dev/null || true)
  compiled_sha=$(printf "%s" "$body" | python3 -c "import sys,json; print(json.load(sys.stdin)['compilation']['compiled_sha256'])" 2>/dev/null || true)

  if [ -z "$compilation_id" ]; then
    err "could not parse compilation.id from response: $body"
  fi

  mkdir -p "$DIST_DIR"
  echo "$compilation_id" > "${DIST_DIR}/catalog-compilation-id.${ENV}.txt"

  echo "  OK  compilation_id=${compilation_id}"
  echo "       compiled_sha256=${compiled_sha}"
  echo "       saved to ${DIST_DIR}/catalog-compilation-id.${ENV}.txt"
}

cmd_publish_catalog() {
  require_catalog_admin_creds

  local id_file="${DIST_DIR}/catalog-compilation-id.${ENV}.txt"
  if [ ! -f "$id_file" ]; then
    err "missing ${id_file} (run \`make compile-catalog ENV=${ENV}\` first)"
  fi

  local compilation_id
  compilation_id=$(cat "$id_file")
  [ -n "$compilation_id" ] || err "${id_file} is empty"

  echo "==> POST ${ADMIN_API}/v1/admin/registry/compilations/${compilation_id}/publish"
  local response_file status body
  response_file=$(mktemp)
  status=$(curl -sS \
    -o "$response_file" \
    -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${PLATFORM_ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"bundle_type": "cloud"}' \
    "${ADMIN_API}/v1/admin/registry/compilations/${compilation_id}/publish")
  body=$(cat "$response_file")
  rm -f "$response_file"
  echo "  -> http=${status}"
  if [ "$status" != "200" ]; then
    echo "    body: $body"
    err "publish failed (http $status)"
  fi
  echo "    body: $body"
  echo "  OK  catalog compilation ${compilation_id} published on ${ENV}"

  # Sidecar with version + published_at so `make status` can report
  # the last publish without re-hitting the admin API. Source of
  # truth is still GET /admin/registry/current — this is a cache.
  local published_version published_at
  published_version=$(printf "%s" "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',''))" 2>/dev/null || echo "")
  published_at=$(printf "%s" "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('published_at',''))" 2>/dev/null || echo "")
  cat > "${DIST_DIR}/catalog-published.${ENV}.json" <<JSON
{"version":"${published_version}","compilation_id":"${compilation_id}","published_at":"${published_at}"}
JSON
}

cmd_release_catalog() {
  cmd_compile_catalog
  cmd_publish_catalog
}

# --- clean-dist -------------------------------------------------------------

cmd_clean_dist() {
  rm -rf "$DIST_DIR"
}

# --- Dispatch ---------------------------------------------------------------

case "$VERB" in
  help)              cmd_help ;;
  build-cli)         cmd_build_cli ;;
  publish-cli)       cmd_publish_cli ;;
  release-cli)       cmd_release_cli ;;
  verify-cli)        cmd_verify_cli ;;
  generate-manifest) cmd_generate_manifest ;;
  sign-manifest)     cmd_sign_manifest ;;
  publish-manifest)  cmd_publish_manifest ;;
  verify-manifest)   cmd_verify_manifest ;;
  register-release)  cmd_register_release ;;
  build-classify)    cmd_build_classify ;;
  publish-classify)  cmd_publish_classify ;;
  release-classify)  cmd_release_classify ;;
  verify-classify)   cmd_verify_classify ;;
  import-catalog)    cmd_import_catalog ;;
  compile-catalog)   cmd_compile_catalog ;;
  publish-catalog)   cmd_publish_catalog ;;
  release-catalog)   cmd_release_catalog ;;
  status)            cmd_status ;;
  status-all)        cmd_status_all ;;
  diff)              cmd_diff ;;
  clean-dist)        cmd_clean_dist ;;
  *)                 err "unknown verb: $VERB (try \`make help\`)" ;;
esac

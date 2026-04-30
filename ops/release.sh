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
	  release-cli            build-cli + publish-cli
	  verify-cli             Re-verify remote sha matches ${DIST_DIR}/ (no build/publish)
	  diff                   Local sha vs ENV's currently-served sha

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
	  (prod CLI publish uses \`wrangler login\` — no extra creds.)

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
  require_cmd wrangler
  wrangler whoami >/dev/null 2>&1 || err "wrangler not logged in (run \`wrangler login\`)"

  unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy

  for f in "${CLI_BINARIES[@]}" "${CLI_BINARIES[@]/%/.sha256}"; do
    echo "==> R2 put ${R2_BUCKET}/${R2_PREFIX}${f}"
    wrangler r2 object put "${R2_BUCKET}/${R2_PREFIX}${f}" \
      --file="${DIST_DIR}/${f}" \
      --remote \
      --cache-control "no-store, max-age=0"
  done

  cmd_verify_against "$PROD_BASE_URL"
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

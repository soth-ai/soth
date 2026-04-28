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

PROD_BASE_URL="https://storage.soth.ai/release"
STAGING_BASE_URL="https://storage.staging.soth.xyz/release"

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
	SOTH ops Makefile (Phase 1: CLI binaries)

	Usage: make <target> [ENV=local|staging|prod]
	  ENV defaults to staging; auto-loads ops/.env.\$ENV if present.

	CLI binaries:
	  build-cli              Build all 5 platform binaries (embedded creds) → ${DIST_DIR}/
	  publish-cli            Push ${DIST_DIR}/ binaries to ENV destination + verify
	  release-cli            build-cli + publish-cli
	  verify-cli             Re-verify remote sha matches ${DIST_DIR}/ (no build/publish)
	  diff                   Local sha vs ENV's currently-served sha

	Maintenance:
	  clean-dist             rm -rf ${DIST_DIR}

	Required env (set in ops/.env.\$ENV; see ops/.env.example):
	  SOTH_HONEYCOMB_API_KEY  build-cli (option_env! at compile time)
	  SOTH_SENTRY_DSN         build-cli
	  MINIO_ACCESS_KEY        publish-cli ENV=staging
	  MINIO_SECRET_KEY        publish-cli ENV=staging
	  (prod uses \`wrangler login\` — no extra creds.)

	Phase 2 (classify) + Phase 3 (tool catalog) coming next; see ops/README.md.
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

cmd_diff() {
  local base
  case "$ENV" in
    staging) base="$STAGING_BASE_URL" ;;
    prod)    base="$PROD_BASE_URL" ;;
    *) err "diff requires ENV=staging|prod" ;;
  esac
  echo "=== local ${DIST_DIR}/ vs ${ENV} (${base}) ==="
  for f in "${CLI_BINARIES[@]}"; do
    local local_sha remote_sha status
    local_sha=$(shasum -a 256 "${DIST_DIR}/${f}" 2>/dev/null | awk '{print $1}' || echo "missing")
    remote_sha=$(curl -sL "${base}/${f}?cb=$(date +%s)" 2>/dev/null | shasum -a 256 | awk '{print $1}' || echo "unreachable")
    if [ "$local_sha" = "$remote_sha" ]; then
      status="OK"
    else
      status="DIFF"
    fi
    printf "  %-30s local=%-12s remote=%-12s %s\n" \
      "$f" "${local_sha:0:12}" "${remote_sha:0:12}" "$status"
  done
}

# --- release-cli (composite) ------------------------------------------------

cmd_release_cli() {
  cmd_build_cli
  cmd_publish_cli
}

# --- clean-dist -------------------------------------------------------------

cmd_clean_dist() {
  rm -rf "$DIST_DIR"
}

# --- Dispatch ---------------------------------------------------------------

case "$VERB" in
  help)         cmd_help ;;
  build-cli)    cmd_build_cli ;;
  publish-cli)  cmd_publish_cli ;;
  release-cli)  cmd_release_cli ;;
  verify-cli)   cmd_verify_cli ;;
  diff)         cmd_diff ;;
  clean-dist)   cmd_clean_dist ;;
  *)            err "unknown verb: $VERB (try \`make help\`)" ;;
esac

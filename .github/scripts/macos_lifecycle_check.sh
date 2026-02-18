#!/usr/bin/env bash
set -euo pipefail

# macOS lifecycle validation harness for SOTH sensor.
#
# Phases:
#   prepare   - clean state, CA/setup, proxy on/off rollback validation, daemon lifecycle checks
#   post-boot - verify launchd autostart after reboot/login
#   anomaly   - summarize anomaly/reliability signals from logs + sync_state
#   cleanup   - stop runtime, disable autostart, clear system proxy
#
# Usage:
#   .github/scripts/macos_lifecycle_check.sh prepare
#   .github/scripts/macos_lifecycle_check.sh post-boot
#   .github/scripts/macos_lifecycle_check.sh anomaly
#   .github/scripts/macos_lifecycle_check.sh cleanup
#
# Optional environment:
#   SOTH_BIN=./target/debug/soth
#   SOTH_CONFIG=~/.soth/soth.yaml
#   SOTH_PORT=8080
#   SOTH_LOG_FILE=~/.soth/logs/proxy.log
#   SOTH_DB=~/.soth/logs/events.db

PHASE="${1:-prepare}"
SOTH_BIN="${SOTH_BIN:-./target/debug/soth}"
SOTH_CONFIG="${SOTH_CONFIG:-$HOME/.soth/soth.yaml}"
SOTH_PORT="${SOTH_PORT:-8080}"
SOTH_LOG_FILE="${SOTH_LOG_FILE:-$HOME/.soth/logs/proxy.log}"
SOTH_DB="${SOTH_DB:-$HOME/.soth/logs/events.db}"
RUN_DIR="${HOME}/.soth/run"
STATE_FILE="${RUN_DIR}/system_proxy_state.json"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] $*"
}

warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] $*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "[FAIL] $*"
}

info() {
  echo "[INFO] $*"
}

step() {
  echo
  echo "==> $*"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command not found: ${cmd}" >&2
    exit 1
  fi
}

require_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script is macOS-only" >&2
    exit 1
  fi
}

proxy_listener_pid() {
  lsof -nP -iTCP:"${SOTH_PORT}" -sTCP:LISTEN -Fp 2>/dev/null | sed -n 's/^p//p' | head -n1 || true
}

assert_listener_running() {
  local pid
  pid="$(proxy_listener_pid)"
  if [[ -n "${pid}" ]]; then
    pass "listener active on 127.0.0.1:${SOTH_PORT} (pid=${pid})"
  else
    fail "listener missing on 127.0.0.1:${SOTH_PORT}"
  fi
}

assert_listener_stopped() {
  local pid
  pid="$(proxy_listener_pid)"
  if [[ -z "${pid}" ]]; then
    pass "listener not active on 127.0.0.1:${SOTH_PORT}"
  else
    fail "listener still active on 127.0.0.1:${SOTH_PORT} (pid=${pid})"
  fi
}

list_macos_services() {
  networksetup -listallnetworkservices 2>/dev/null \
    | tail -n +2 \
    | sed '/^An asterisk (\*) denotes/d' \
    | sed 's/^\*//' \
    | sed '/^[[:space:]]*$/d'
}

sanitize_service_name() {
  echo "$1" | tr ' /' '__' | tr -cd '[:alnum:]_.-'
}

snapshot_proxy_state() {
  local out_dir="$1"
  mkdir -p "${out_dir}"
  while IFS= read -r service; do
    local key
    key="$(sanitize_service_name "${service}")"
    {
      echo "SERVICE=${service}"
      echo "--- web ---"
      networksetup -getwebproxy "${service}" 2>/dev/null || true
      echo "--- secure ---"
      networksetup -getsecurewebproxy "${service}" 2>/dev/null || true
      echo "--- bypass ---"
      networksetup -getproxybypassdomains "${service}" 2>/dev/null || true
    } >"${out_dir}/${key}.txt"
  done < <(list_macos_services)
}

assert_proxy_enabled_for_all_services() {
  local all_ok=1
  while IFS= read -r service; do
    local web secure
    web="$(networksetup -getwebproxy "${service}" 2>/dev/null || true)"
    secure="$(networksetup -getsecurewebproxy "${service}" 2>/dev/null || true)"
    if [[ "${web}" == *"Enabled: Yes"* && "${web}" == *"Server: 127.0.0.1"* && "${web}" == *"Port: ${SOTH_PORT}"* \
      && "${secure}" == *"Enabled: Yes"* && "${secure}" == *"Server: 127.0.0.1"* && "${secure}" == *"Port: ${SOTH_PORT}"* ]]; then
      pass "proxy patched for service '${service}'"
    else
      all_ok=0
      fail "proxy patch mismatch for service '${service}'"
    fi
  done < <(list_macos_services)
  return "${all_ok}"
}

assert_proxy_restored_from_snapshot() {
  local before_dir="$1"
  local after_dir="$2"
  local all_ok=1
  while IFS= read -r service; do
    local key before_file after_file
    key="$(sanitize_service_name "${service}")"
    before_file="${before_dir}/${key}.txt"
    after_file="${after_dir}/${key}.txt"
    if [[ ! -f "${before_file}" || ! -f "${after_file}" ]]; then
      all_ok=0
      fail "missing snapshot file for service '${service}'"
      continue
    fi
    if diff -u "${before_file}" "${after_file}" >/dev/null; then
      pass "proxy rollback restored service '${service}'"
    else
      all_ok=0
      fail "proxy rollback drift for service '${service}'"
    fi
  done < <(list_macos_services)
  return "${all_ok}"
}

autostart_status_text() {
  "${SOTH_BIN}" runtime autostart status 2>/dev/null || true
}

assert_autostart_enabled() {
  local out
  out="$(autostart_status_text)"
  if echo "${out}" | grep -qi "enabled"; then
    pass "autostart registration is enabled"
  else
    fail "autostart not enabled; output='${out}'"
  fi
}

assert_autostart_disabled() {
  local out
  out="$(autostart_status_text)"
  if echo "${out}" | grep -qi "disabled"; then
    pass "autostart registration is disabled"
  else
    fail "autostart still enabled; output='${out}'"
  fi
}

ensure_prereqs() {
  require_macos
  require_cmd networksetup
  require_cmd lsof
  require_cmd sqlite3
  if [[ ! -x "${SOTH_BIN}" ]]; then
    echo "error: soth binary not executable at ${SOTH_BIN}" >&2
    exit 1
  fi
  if [[ ! -f "${SOTH_CONFIG}" ]]; then
    echo "error: config not found at ${SOTH_CONFIG}" >&2
    exit 1
  fi
}

phase_prepare() {
  step "Clean state"
  "${SOTH_BIN}" down >/dev/null 2>&1 || true
  "${SOTH_BIN}" off >/dev/null 2>&1 || true
  "${SOTH_BIN}" runtime autostart disable >/dev/null 2>&1 || true
  assert_listener_stopped
  assert_autostart_disabled

  step "Snapshot system proxy state before patching"
  local workdir
  workdir="$(mktemp -d)"
  local before_dir="${workdir}/before"
  local after_dir="${workdir}/after"
  snapshot_proxy_state "${before_dir}"

  step "Setup CA + patch system proxy"
  "${SOTH_BIN}" runtime setup-ca --output "${HOME}/.soth/ca"
  "${SOTH_BIN}" on --port "${SOTH_PORT}"
  assert_proxy_enabled_for_all_services || true

  step "Rollback/cleanup validation (proxy off restore)"
  "${SOTH_BIN}" off
  snapshot_proxy_state "${after_dir}"
  assert_proxy_restored_from_snapshot "${before_dir}" "${after_dir}" || true
  if [[ ! -f "${STATE_FILE}" ]]; then
    pass "system proxy state file cleaned (${STATE_FILE})"
  else
    fail "system proxy state file still present (${STATE_FILE})"
  fi

  step "Lifecycle: managed startup + persistence (without reboot)"
  "${SOTH_BIN}" runtime autostart enable --config "${SOTH_CONFIG}" --port "${SOTH_PORT}"
  assert_autostart_enabled
  "${SOTH_BIN}" up -c "${SOTH_CONFIG}" --port "${SOTH_PORT}" --quiet
  assert_listener_running
  pass "'soth up' returned while runtime stayed active (daemon persistence in-session)"

  step "Lifecycle: down should stop runtime but keep boot registration"
  "${SOTH_BIN}" down
  assert_listener_stopped
  assert_autostart_enabled

  echo
  info "Next manual step for start-on-boot:"
  info "  1) Reboot or log out/in."
  info "  2) Run: .github/scripts/macos_lifecycle_check.sh post-boot"
}

phase_post_boot() {
  step "Post-boot autostart verification"
  assert_autostart_enabled
  assert_listener_running
  "${SOTH_BIN}" runtime status -c "${SOTH_CONFIG}" || true
  pass "post-boot checks executed (verify status output above)"
}

phase_anomaly() {
  step "Anomaly signal summary (local evidence)"
  if [[ -f "${SOTH_LOG_FILE}" ]]; then
    local deferred dropped fdpressure syncfail schemarej
    deferred="$(rg -n "Exchange upload deferred with retry backoff" "${SOTH_LOG_FILE}" | wc -l | tr -d ' ')"
    dropped="$(rg -n "Dropping malformed exchange upload entry" "${SOTH_LOG_FILE}" | wc -l | tr -d ' ')"
    fdpressure="$(rg -n "FD pressure fail-open|Too many open files|EMFILE" "${SOTH_LOG_FILE}" | wc -l | tr -d ' ')"
    syncfail="$(rg -n "Cloud sync tick failed|Cloud heartbeat failed|exchange_upload_status_" "${SOTH_LOG_FILE}" | wc -l | tr -d ' ')"
    schemarej="$(rg -n "exchange_rejected" "${SOTH_LOG_FILE}" | wc -l | tr -d ' ')"
    info "log counters:"
    info "  deferred_uploads=${deferred}"
    info "  dropped_malformed=${dropped}"
    info "  fd_pressure_events=${fdpressure}"
    info "  sync_failures=${syncfail}"
    info "  schema_rejections=${schemarej}"
    pass "anomaly counters collected from ${SOTH_LOG_FILE}"
  else
    warn "proxy log file not found at ${SOTH_LOG_FILE}"
  fi

  if [[ -f "${SOTH_DB}" ]]; then
    info "sync_state snapshot:"
    sqlite3 "${SOTH_DB}" \
      "SELECT key, value FROM sync_state WHERE key IN ('last_sync_timestamp','sync_errors') ORDER BY key;" || true
    pass "sync_state anomaly fields read from ${SOTH_DB}"
  else
    warn "events DB not found at ${SOTH_DB}"
  fi

  info "Server-side anomaly reception should be confirmed in cloud telemetry/dashboard using the same time window."
}

phase_cleanup() {
  step "Cleanup runtime + system patching"
  "${SOTH_BIN}" down >/dev/null 2>&1 || true
  "${SOTH_BIN}" off >/dev/null 2>&1 || true
  "${SOTH_BIN}" runtime autostart disable >/dev/null 2>&1 || true
  assert_listener_stopped
  assert_autostart_disabled
  if [[ ! -f "${STATE_FILE}" ]]; then
    pass "system proxy state file cleaned (${STATE_FILE})"
  else
    fail "system proxy state file still present (${STATE_FILE})"
  fi
}

print_summary_and_exit() {
  echo
  echo "Summary: pass=${PASS_COUNT} warn=${WARN_COUNT} fail=${FAIL_COUNT}"
  if (( FAIL_COUNT > 0 )); then
    exit 1
  fi
}

main() {
  ensure_prereqs
  case "${PHASE}" in
    prepare)
      phase_prepare
      ;;
    post-boot)
      phase_post_boot
      ;;
    anomaly)
      phase_anomaly
      ;;
    cleanup)
      phase_cleanup
      ;;
    *)
      echo "usage: $0 {prepare|post-boot|anomaly|cleanup}" >&2
      exit 2
      ;;
  esac
  print_summary_and_exit
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail

# P3 E2E smoke:
# 1) create enrollment token
# 2) soth up --enroll-token ...
# 3) send one proxied AI request
# 4) assert cloud proxy/exchange metrics advance
#
# Required:
#   SOTH_E2E_DASHBOARD_TOKEN=... (WorkOS dashboard bearer token)
#
# Optional:
#   SOTH_E2E_CLOUD_ENDPOINT=https://api.staging.soth.xyz
#   SOTH_E2E_TEAM_ID=<uuid>              # auto-discovered from /bootstrap if omitted
#   SOTH_E2E_SENSOR_PORT=18080
#   SOTH_E2E_CONFIG=~/.soth/soth.yaml
#   SOTH_E2E_SOTH_BIN=./target/debug/soth
#   SOTH_E2E_TIMEOUT_SECS=120
#
# Usage:
#   SOTH_E2E_DASHBOARD_TOKEN=... ./.github/scripts/e2e_enroll_up_smoke.sh

CLOUD_ENDPOINT="${SOTH_E2E_CLOUD_ENDPOINT:-https://api.staging.soth.xyz}"
DASHBOARD_TOKEN="${SOTH_E2E_DASHBOARD_TOKEN:-}"
TEAM_ID="${SOTH_E2E_TEAM_ID:-}"
SENSOR_PORT="${SOTH_E2E_SENSOR_PORT:-18080}"
CONFIG_PATH="${SOTH_E2E_CONFIG:-$HOME/.soth/soth.yaml}"
SOTH_BIN="${SOTH_E2E_SOTH_BIN:-./target/debug/soth}"
TIMEOUT_SECS="${SOTH_E2E_TIMEOUT_SECS:-120}"

if [[ -z "${DASHBOARD_TOKEN}" ]]; then
  echo "error: SOTH_E2E_DASHBOARD_TOKEN is required" >&2
  exit 1
fi

if [[ ! -x "${SOTH_BIN}" ]] && ! command -v "${SOTH_BIN}" >/dev/null 2>&1; then
  echo "error: soth binary not found at '${SOTH_BIN}'" >&2
  exit 1
fi

api_get() {
  local path="$1"
  curl -fsS \
    -H "Authorization: Bearer ${DASHBOARD_TOKEN}" \
    "${CLOUD_ENDPOINT}/api/v1${path}"
}

api_post() {
  local path="$1"
  local body="$2"
  curl -fsS \
    -X POST \
    -H "Authorization: Bearer ${DASHBOARD_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "${body}" \
    "${CLOUD_ENDPOINT}/api/v1${path}"
}

json_get() {
  local path="$1"
  python3 - "$path" <<'PY'
import json
import sys

path = sys.argv[1].split(".")
data = json.load(sys.stdin)
cur = data
for key in path:
    if key == "":
        continue
    if isinstance(cur, dict):
        cur = cur.get(key)
    elif isinstance(cur, list):
        try:
            cur = cur[int(key)]
        except Exception:
            cur = None
    else:
        cur = None
    if cur is None:
        break
if cur is None:
    print("")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(str(cur))
PY
}

rfc3339_after_days() {
  local days="$1"
  python3 - "$days" <<'PY'
import datetime
import sys
days = int(sys.argv[1])
print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)).isoformat().replace("+00:00","Z"))
PY
}

teardown() {
  set +e
  "${SOTH_BIN}" down >/dev/null 2>&1 || true
}
trap teardown EXIT

echo "==> Cloud endpoint: ${CLOUD_ENDPOINT}"
echo "==> Config path: ${CONFIG_PATH}"
echo "==> Sensor port: ${SENSOR_PORT}"

if [[ -z "${TEAM_ID}" ]]; then
  echo "==> Resolving team_id via /bootstrap"
  BOOTSTRAP_JSON="$(api_post "/bootstrap" "{}")"
  TEAM_ID="$(printf '%s' "${BOOTSTRAP_JSON}" | json_get "team_id")"
  if [[ -z "${TEAM_ID}" ]]; then
    echo "error: unable to resolve team_id from /bootstrap" >&2
    exit 1
  fi
fi

echo "==> Team ID: ${TEAM_ID}"

PROXY_PATH="/proxy?scope=team&team_id=${TEAM_ID}&range=24h"
BASE_PROXY="$(api_get "${PROXY_PATH}")"
BASE_TOTAL="$(printf '%s' "${BASE_PROXY}" | json_get "data.total_requests")"
if [[ -z "${BASE_TOTAL}" ]]; then
  BASE_TOTAL="0"
fi
echo "==> Baseline total_requests=${BASE_TOTAL}"

EXPIRES_AT="$(rfc3339_after_days 1)"
TOKEN_BODY="$(cat <<JSON
{
  "team_id": "${TEAM_ID}",
  "expires_at": "${EXPIRES_AT}",
  "max_uses": 1,
  "tags": {
    "source": "p3-e2e-smoke",
    "role": "member"
  }
}
JSON
)"

echo "==> Creating enrollment token"
TOKEN_JSON="$(api_post "/enroll/tokens" "${TOKEN_BODY}")"
ENROLL_TOKEN="$(printf '%s' "${TOKEN_JSON}" | json_get "token")"
TOKEN_ID="$(printf '%s' "${TOKEN_JSON}" | json_get "record.id")"
if [[ -z "${ENROLL_TOKEN}" || -z "${TOKEN_ID}" ]]; then
  echo "error: failed to create enrollment token" >&2
  echo "${TOKEN_JSON}" >&2
  exit 1
fi
echo "==> Enrollment token created id=${TOKEN_ID}"

echo "==> Starting lifecycle via enroll-on-up"
"${SOTH_BIN}" down >/dev/null 2>&1 || true
"${SOTH_BIN}" up \
  --config "${CONFIG_PATH}" \
  --port "${SENSOR_PORT}" \
  --quiet \
  --enroll-token "${ENROLL_TOKEN}" \
  --enroll-endpoint "${CLOUD_ENDPOINT}"

echo "==> Sending one proxied AI request"
# api.anthropic.com/api/hello is low-cost and publicly reachable; we only need one captured exchange.
curl -ksS --proxy "http://127.0.0.1:${SENSOR_PORT}" "https://api.anthropic.com/api/hello" -o /dev/null || true

echo "==> Waiting for cloud metrics to advance (timeout ${TIMEOUT_SECS}s)"
START_TS="$(date +%s)"
PASSED=0
while true; do
  NOW_TS="$(date +%s)"
  ELAPSED="$((NOW_TS - START_TS))"
  if (( ELAPSED > TIMEOUT_SECS )); then
    break
  fi

  CUR_PROXY="$(api_get "${PROXY_PATH}" || true)"
  CUR_TOTAL="$(printf '%s' "${CUR_PROXY}" | json_get "data.total_requests")"
  CUR_ACTIVE="$(printf '%s' "${CUR_PROXY}" | json_get "data.active_connections")"
  [[ -z "${CUR_TOTAL}" ]] && CUR_TOTAL="0"
  [[ -z "${CUR_ACTIVE}" ]] && CUR_ACTIVE="0"

  if (( CUR_TOTAL > BASE_TOTAL )); then
    echo "==> PASS total_requests advanced ${BASE_TOTAL} -> ${CUR_TOTAL}"
    echo "==> Active connections (team-scoped): ${CUR_ACTIVE}"
    PASSED=1
    break
  fi
  sleep 3
done

if (( PASSED != 1 )); then
  echo "error: P3 smoke failed; total_requests did not advance within timeout" >&2
  echo "hint: check '${SOTH_BIN} logs -f' and cloud /api/v1/ingest/health" >&2
  exit 1
fi

echo "==> P3 smoke succeeded"

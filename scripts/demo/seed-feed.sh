#!/usr/bin/env bash
# Deterministic demo feed for the hero recording (scripts/demo/hero.tape).
#
# Drips a small, representative set of events into the local SQLite store so a
# real `soth events stream` has something to render. Rows are inserted on a
# timer AFTER the stream is live (the stream tails new rowids), so they scroll
# in one at a time like genuine captured traffic.
#
# Honesty note: these rows go through the real `soth events stream` renderer —
# we control *when* they're written, not *how* they're displayed. The values
# mirror real captured events. Keep exactly one `deny … credential detected`
# line: one is a story, three looks staged.
#
#   Usage: seed-feed.sh [initial_delay_seconds] [step_seconds]
#   DB location follows the binary: $HOME/.soth/logs/events.db
set -euo pipefail

INITIAL_DELAY="${1:-6}"
STEP="${2:-1.3}"
DB="$HOME/.soth/logs/events.db"

mkdir -p "$(dirname "$DB")"
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS intercept_records (
  timestamp_utc INTEGER NOT NULL,
  provider TEXT,
  model TEXT,
  telemetry_json TEXT,
  policy_kind TEXT,
  anomaly_score REAL
);"

insert() { # provider model use_case policy cost credential
  local prov="$1" model="$2" uc="$3" pol="$4" cost="$5" cred="$6"
  local now tj
  now=$(( $(date +%s) * 1000 ))
  if [ "$cred" = "1" ]; then
    tj="{\"use_case_label\":\"$uc\",\"sensitive_code_flags\":{\"credential_pattern_detected\":true}}"
  else
    tj="{\"use_case_label\":\"$uc\",\"estimated_cost_usd\":$cost}"
  fi
  sqlite3 "$DB" "INSERT INTO intercept_records
    (timestamp_utc, provider, model, telemetry_json, policy_kind, anomaly_score)
    VALUES ($now,'$prov','$model','$tj','$pol',0.1);"
}

sleep "$INITIAL_DELAY"

#       provider     model                use_case           policy  cost  cred
insert  openai       gpt-4o               "code generation"  ALLOW   0.03  0 ; sleep "$STEP"
insert  anthropic    claude-sonnet        "tool call"        ALLOW   0.01  0 ; sleep "$STEP"
insert  google       gemini-1.5-pro       "q&a"              ALLOW   0.02  0 ; sleep "$STEP"
insert  openai       gpt-4o-mini          "summarization"    ALLOW   0.01  0 ; sleep "$STEP"
insert  anthropic    claude-opus          "code generation"  DENY    0     1 ; sleep "$STEP"
insert  openai       gpt-4o               "tool call"        ALLOW   0.04  0 ; sleep "$STEP"
insert  anthropic    claude-sonnet        "summarization"    ALLOW   0.01  0 ; sleep "$STEP"
insert  openai       gpt-4o               "q&a"              ALLOW   0.02  0

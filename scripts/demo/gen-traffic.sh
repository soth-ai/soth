#!/usr/bin/env bash
# Live demo traffic generator for hero-live.tape.
# ---------------------------------------------------------------------------
# Fires a small, representative set of AI-provider requests THROUGH the running
# soth proxy so that a real `soth events stream` has genuine classified events
# to render. No seeding, no faking — these are real intercepts.
#
# It waits for the proxy to accept connections, then drips requests on a timer
# so they scroll in one at a time. One request embeds a fake secret in the
# prompt so soth-detect fires `credential_pattern_detected` and policy denies it
# — that's the authentic `deny … credential detected` payoff.
#
# Auth: requests use $OPENAI_API_KEY / $ANTHROPIC_API_KEY / $GEMINI_API_KEY if
# set, else a harmless placeholder. The proxy classifies the OUTBOUND request
# before the upstream reply, so an upstream 401 still produces a real event.
#
#   Usage: gen-traffic.sh [proxy_port] [step_seconds]
set -euo pipefail

PORT="${1:-8080}"
STEP="${2:-1.3}"
PROXY="http://127.0.0.1:${PORT}"

OPENAI_KEY="${OPENAI_API_KEY:-sk-demo-placeholder}"
ANTHROPIC_KEY="${ANTHROPIC_API_KEY:-sk-ant-demo-placeholder}"
GEMINI_KEY="${GEMINI_API_KEY:-demo-placeholder}"

# Wait (≤15s) for the proxy listener to come up.
for _ in $(seq 1 30); do
  if curl -s -o /dev/null -x "$PROXY" --max-time 2 https://api.openai.com 2>/dev/null; then break; fi
  sleep 0.5
done
# Small head start so the stream is live before the first row lands.
sleep 1.5

openai() { # model prompt
  curl -s -o /dev/null --max-time 8 -x "$PROXY" https://api.openai.com/v1/chat/completions \
    -H "Authorization: Bearer ${OPENAI_KEY}" -H "Content-Type: application/json" \
    -d "{\"model\":\"$1\",\"messages\":[{\"role\":\"user\",\"content\":\"$2\"}]}" || true
}
anthropic() { # model prompt
  curl -s -o /dev/null --max-time 8 -x "$PROXY" https://api.anthropic.com/v1/messages \
    -H "x-api-key: ${ANTHROPIC_KEY}" -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \
    -d "{\"model\":\"$1\",\"max_tokens\":256,\"messages\":[{\"role\":\"user\",\"content\":\"$2\"}]}" || true
}
gemini() { # model prompt
  curl -s -o /dev/null --max-time 8 -x "$PROXY" \
    "https://generativelanguage.googleapis.com/v1beta/models/$1:generateContent?key=${GEMINI_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"contents\":[{\"parts\":[{\"text\":\"$2\"}]}]}" || true
}

openai    gpt-4o          "Refactor this function to use async/await."   ; sleep "$STEP"
anthropic claude-sonnet-4 "Summarize the call-tool result for the user." ; sleep "$STEP"
gemini    gemini-1.5-pro  "What does this stack trace mean?"             ; sleep "$STEP"
openai    gpt-4o-mini     "Write a one-line commit message."             ; sleep "$STEP"
# Credential payoff: a real secret-shaped string in the prompt -> soth-detect
# flags it, policy denies, stream prints `deny … credential detected`.
anthropic claude-opus-4   "Commit this to git: aws_secret=AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; sleep "$STEP"
openai    gpt-4o          "Add a null check before the deref."           ; sleep "$STEP"
anthropic claude-sonnet-4 "Explain this regression in plain English."    ; sleep "$STEP"
openai    gpt-4o          "What are the tradeoffs of these two designs?"

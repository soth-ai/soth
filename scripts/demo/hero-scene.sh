#!/usr/bin/env bash
# Hero Scene 1 — bring Soth online, then hand off to the LIVE event stream.
# ---------------------------------------------------------------------------
# Honesty note: the three setup commands (setup-ca / start / on) are reproduced
# here with the CLI's REAL success strings — captured verbatim from actual runs
# (`soth start` daemon-start block; `soth on` enable block). They are replayed
# rather than executed live because a real `soth start` needs a keychain-trusted
# CA (sudo, persistent) and `soth on` rewrites the host's system proxy — neither
# is safe or reproducible inside a headless VHS render.
#
# The payoff — `soth events stream` — is NOT faked: this script `exec`s the real
# binary, which renders the seeded feed from the local SQLite store (see
# seed-feed.sh). What you see scroll in is the genuine render_compact_line()
# output.
# ---------------------------------------------------------------------------
set -euo pipefail

P='~ ❯ '
G=$'\033[32m'; C=$'\033[36m'; D=$'\033[2m'; R=$'\033[0m'

type_pause() { sleep 1.2; }

sleep 0.5
printf '%ssoth setup-ca\n' "$P"; sleep 0.5
printf '%s✓%s CA generated and trusted  (~/.soth/certs/soth-mitm-ca.pem)\n' "$G" "$R"
type_pause

printf '%ssoth start\n' "$P"; sleep 0.5
printf '%s✓%s Proxy daemon started (pid 41207).\n' "$G" "$R"
printf '  %sLogs%s: ~/.soth/logs/proxy.log\n' "$D" "$R"
printf '  %sControl%s: soth stop\n' "$D" "$R"
type_pause

printf '%ssoth on\n' "$P"; sleep 0.5
printf '%s●%s System proxy enabled\n' "$C" "$R"
printf '   All HTTPS traffic will now route through SOTH proxy\n'
printf '   %s↳%s AI traffic: MITM intercepted (inspection enabled)\n' "$C" "$R"
printf '   %s→%s Other traffic: tunneled (no inspection)\n' "$C" "$R"
type_pause

printf '%ssoth events stream\n' "$P"; sleep 0.3

# Hand off to the REAL binary. HOME points at the isolated demo profile whose
# SQLite store seed-feed.sh is dripping rows into.
exec soth events stream

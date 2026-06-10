# Soth hero recording — reproducible VHS tape
# ---------------------------------------------------------------------------
# Produces the animated terminal hero embedded at the top of the README.
# VHS (https://github.com/charmbracelet/vhs) scripts the whole take, so every
# recording is identical.
#
#   Render (from repo root):  vhs scripts/demo/hero.tape   -> .github/assets/hero.gif
#
# Structure (see scripts/demo/hero-scene.sh for the honesty notes):
#   Scene 1  setup-ca -> start -> on   — reproduced with the CLI's REAL success
#            strings (a live `start` needs a keychain-trusted CA and `on`
#            rewrites the host system proxy; neither is safe in a headless
#            render, so they're replayed verbatim, not executed).
#   Scene 2  soth events stream        — the REAL binary, rendering a seeded
#            local store (scripts/demo/seed-feed.sh). Genuine output, one
#            `deny … credential detected` payoff.
#
# Fully non-invasive: HOME is redirected to a throwaway dir, no system proxy is
# touched, no API calls are made, your real ~/.soth/ is never read or written.
#
# Pre-flight: `soth` + `sqlite3` on PATH; vhs, ffmpeg, ttyd; a ligature mono
# font (JetBrains Mono here).
# ---------------------------------------------------------------------------

Output .github/assets/hero.gif

Require soth
Require sqlite3

Set Shell "bash"
Set Theme "Dracula"
Set FontFamily "JetBrainsMono Nerd Font"
Set FontSize 16
Set Width 1000
Set Height 600
Set Padding 24
Set TypingSpeed 55ms
Set PlaybackSpeed 1.0

# --- setup + deterministic feed (hidden) -----------------------------------
Hide
Type "REPO=$PWD; export HOME=/tmp/soth-demo-$$; mkdir -p $HOME/.soth/logs"
Enter
# Create the events table up front so `events stream` never races the feeder.
Type "sqlite3 $HOME/.soth/logs/events.db 'CREATE TABLE IF NOT EXISTS intercept_records (timestamp_utc INTEGER NOT NULL, provider TEXT, model TEXT, telemetry_json TEXT, policy_kind TEXT, anomaly_score REAL);'"
Enter
# Feeder drips rows ~6s in — landing just as Scene 1 hands off to the stream.
Type "( bash $REPO/scripts/demo/seed-feed.sh 6 1.3 >/dev/null 2>&1 & )"
Enter
# Launch the scene (its own fake prompt is the only prompt shown).
Type "export PS1=''; clear; bash $REPO/scripts/demo/hero-scene.sh"
Enter
Show

# Scene 1 (~6s) then the live stream drips in. Hold for the credential-detected
# payoff and a couple of calm allow lines after it (clean loop point).
Sleep 17s

# Stop the stream, settle on a calm last frame.
Ctrl+C
Sleep 1s

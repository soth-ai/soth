# Soth hero recording — reproducible VHS tape
# ---------------------------------------------------------------------------
# Produces the animated terminal hero embedded at the top of the README.
# VHS (https://github.com/charmbracelet/vhs) scripts the whole take, so every
# recording is identical — no hand-driving a live terminal.
#
#   Render (from repo root):  vhs scripts/demo/hero.tape   -> .github/assets/hero.gif
#
# What you see is the REAL CLI: commands match crates/soth-cli/src/command_graph.rs
# and the event lines come straight from render_compact_line() in
# commands/events.rs. It is fully non-invasive:
#   - HOME is redirected to a throwaway dir, so your real ~/.soth/ is untouched.
#   - `setup-ca --no-trust` generates a CA without touching the system keychain.
#   - It does NOT run `soth on` (which would rewrite your system proxy) and makes
#     no live API calls. The live feed is seeded deterministically by
#     scripts/demo/seed-feed.sh, then rendered by the real `soth events stream`.
#
# Pre-flight:
#   - `soth` on PATH        (cargo build --release; put target/release/soth on PATH)
#   - vhs, ffmpeg, ttyd, sqlite3
#   - a ligature mono font installed (JetBrains Mono here)
# ---------------------------------------------------------------------------

Output .github/assets/hero.gif

Require soth
Require sqlite3

Set Shell "bash"
Set Theme "Dracula"
Set FontFamily "JetBrains Mono"
Set FontSize 16
Set Width 1000
Set Height 600
Set Padding 24
Set TypingSpeed 55ms
Set PlaybackSpeed 1.0

# --- isolate + start the deterministic feed (hidden from the recording) ----
Hide
Type "REPO=$PWD; export HOME=/tmp/soth-demo; rm -rf $HOME; mkdir -p $HOME/.soth/logs"
Enter
# Detached subshell so no job-control noise ([1] … Done) leaks into the take.
# The feeder sleeps ~6s, then drips rows — landing just as the stream goes live.
Type "( bash $REPO/scripts/demo/seed-feed.sh 6 1.3 >/dev/null 2>&1 & )"
Enter
Type "export PS1='~ ❯ '; clear"
Enter
Show

# --- Scene 1: bring Soth online --------------------------------------------
Type "soth setup-ca --no-trust"
Sleep 600ms
Enter
Sleep 2s

# --- Scene 2: watch the live feed (the payoff) -----------------------------
Type "soth events stream"
Sleep 400ms
Enter
# Rows drip in one at a time. The `deny … credential detected` line is the
# payoff — the window stays open long enough for it to land and for a couple
# of calm `allow` lines to follow (clean loop point).
Sleep 12s

# --- Scene 3: stop, calm last frame ----------------------------------------
Ctrl+C
Sleep 1s

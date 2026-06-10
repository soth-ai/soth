# Soth hero recording — reproducible VHS tape
# ---------------------------------------------------------------------------
# Produces the animated terminal hero embedded at the top of the README.
# VHS (https://github.com/charmbracelet/vhs) scripts the whole take, so every
# recording is identical — no hand-driving a live terminal.
#
#   Render:  vhs scripts/demo/hero.tape      # writes .github/assets/hero.gif
#
# This drives the REAL CLI (commands match crates/soth-cli/src/command_graph.rs;
# event lines match render_compact_line() in commands/events.rs). It runs against
# an isolated demo profile via SOTH_HOME so your real ~/.soth/ is never touched.
#
# Getting a feed: `soth events stream` tails the local SQLite store. Before
# rendering, seed the demo profile with a representative set of events — see
# "Getting clean demo data" in scripts/demo/hero-recording.md. Keep exactly one
# `deny … credential detected` line: one is a story, three looks staged.
#
# Pre-flight:
#   - `soth` on PATH (cargo build --release && put target/release/soth on PATH)
#   - vhs, plus a ligature mono font installed (JetBrains Mono here)
# ---------------------------------------------------------------------------

Output .github/assets/hero.gif

Require soth

Set Shell "bash"
Set Theme "Dracula"
Set FontFamily "JetBrains Mono"
Set FontSize 16
Set Width 1000
Set Height 600
Set Padding 24
Set TypingSpeed 55ms
Set PlaybackSpeed 1.0

# --- isolate to a throwaway profile (hidden from the recording) ------------
Hide
Type "export SOTH_HOME=$(mktemp -d)/.soth && export PS1='~ ❯ ' && clear"
Enter
Show

# --- Scene 1: bring Soth online --------------------------------------------
Type "soth setup-ca"
Sleep 500ms
Enter
Sleep 1.5s

Type "soth start"
Sleep 500ms
Enter
Sleep 1.5s

Type "soth on"
Sleep 500ms
Enter
Sleep 1.5s

# --- Scene 2: watch the live feed ------------------------------------------
Type "soth events stream"
Sleep 500ms
Enter
# Let the classified events stream in. The `deny … credential detected`
# line is the payoff — the long sleep lets it land before the loop cuts.
Sleep 9s

# --- Scene 3: calm last frame, then cut for a clean loop -------------------
Sleep 1.5s
Ctrl+C
Sleep 800ms

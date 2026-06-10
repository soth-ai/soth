# Soth hero recording — FULLY LIVE variant
# ===========================================================================
# Everything here is the real binary doing real work: it trusts the CA in the
# system keychain, starts the daemon, turns the system proxy ON, and drives
# genuine AI-provider requests through the proxy so `soth events stream` renders
# real intercepts (including a real credential-detected denial).
#
#   Render (from repo root):  vhs scripts/demo/hero-live.tape  -> .github/assets/hero.gif
#
# ⚠️  RUN ON A THROWAWAY VM / DISPOSABLE BOX ONLY. Unlike hero.tape, this is
#     INVASIVE and PERSISTENT on the host it runs on:
#       - `soth setup-ca` installs + trusts a CA in the system trust store
#         (needs sudo / admin; on a VM use passwordless sudo or run as root).
#       - `soth on` rewrites the system HTTP/HTTPS proxy for real.
#       - it makes outbound calls to api.openai.com / api.anthropic.com /
#         generativelanguage.googleapis.com.
#     Always finish with `soth off && soth stop` (the tape does this at the end).
#
# Cleaner event rows if real keys are exported before rendering (optional):
#     export OPENAI_API_KEY=... ANTHROPIC_API_KEY=... GEMINI_API_KEY=...
#   Without them the requests 401 upstream, but the proxy still classifies the
#   outbound request, so the stream still populates.
#
# Pre-flight: soth on PATH; vhs, ffmpeg, ttyd; curl; a ligature mono font.
# ===========================================================================

Output .github/assets/hero.gif

Require soth
Require curl

Set Shell "bash"
Set Theme "Dracula"
Set FontFamily "JetBrainsMono Nerd Font"
Set FontSize 16
Set Width 1000
Set Height 600
Set Padding 24
Set TypingSpeed 55ms
Set PlaybackSpeed 1.0

Type "export PS1='~ ❯ '; clear"
Enter
Hide
Show

# --- Scene 1: bring Soth online (REAL) -------------------------------------
Type "soth setup-ca"
Sleep 600ms
Enter
# CA generation + system-trust install (sudo/admin). Give it room.
Sleep 4s

Type "soth start"
Sleep 600ms
Enter
Sleep 3s

Type "soth on"
Sleep 600ms
Enter
Sleep 2.5s

# --- Launch real traffic in the background (hidden) ------------------------
Hide
Type "( bash scripts/demo/gen-traffic.sh 8080 1.3 >/dev/null 2>&1 & )"
Enter
Show

# --- Scene 2: live event stream (REAL intercepts) --------------------------
Type "soth events stream"
Sleep 400ms
Enter
# Real requests are classified and stream in; the credential-laden one denies.
Sleep 14s

Ctrl+C
Sleep 800ms

# --- Cleanup: restore the host (REAL) --------------------------------------
Hide
Type "soth off; soth stop"
Enter
Sleep 2s

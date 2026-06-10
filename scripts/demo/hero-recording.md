# Hero recording — `soth events stream`

Storyboard and production guide for the animated terminal hero used at the top
of the README. The goal is a short, looping cast that shows Soth coming online
and live-classifying AI traffic — the equivalent of a product screenshot for a
tool that lives in the terminal.

## Two reproducible tapes

There are two [VHS](https://github.com/charmbracelet/vhs) tapes — both produce
`.github/assets/hero.gif`:

| Tape | What's real | Safe to run where |
|------|-------------|-------------------|
| `hero.tape` (default) | `events stream` is the real binary over a **seeded** store (`seed-feed.sh`); Scene 1 setup lines are replayed real strings (`hero-scene.sh`) | **Any machine** — non-invasive: isolated `HOME`, no system-proxy change, no network calls |
| `hero-live.tape` | **Everything** — real CA trust, `start`, `on`, and live AI-provider requests (`gen-traffic.sh`) classified by the real proxy | **Throwaway VM / root box only** — installs system CA trust and rewrites the system proxy |

Render: `vhs scripts/demo/hero.tape` (or `hero-live.tape`).

> All on-screen output below uses Soth's **real** formats:
> - quickstart commands from `crates/soth-cli/src/command_graph.rs`
> - the compact event line from `render_compact_line()` in
>   `crates/soth-cli/src/commands/events.rs`:
>   `[HH:MM:SS] provider/model  use_case  policy   $cost`
>   (credential hits render `… policy   credential detected`).
> Don't hand-edit lines into shapes the binary can't actually print.

---

## Specs

| Property | Value |
|---|---|
| Aspect | ~900px wide (matches README image width), ~20–24 rows tall |
| Length | 18–25s, seamless loop |
| Format | Primary: **SVG** (`svg-term`, crisp + tiny). Fallback: **GIF** (`agg`). |
| Output path | `.github/assets/hero.svg` (and/or `hero.gif`) |
| Theme | Dark background (renders on both GitHub themes); high-contrast |
| Font | A ligature mono (JetBrains Mono / Berkeley Mono / Fira Code), 14–16pt |
| Prompt | Minimal — `~ ❯ ` (no machine name / no secrets / no real cwd) |

---

## Scene-by-scene script

Total ~22s. Typed commands appear at a human pace (~30–40 wpm); output streams
on its own. Pauses are where the eye rests.

### Scene 1 — Bring Soth online (0:00–0:07)

```
~ ❯ soth setup-ca
✓ CA generated and trusted  (~/.soth/ca.pem)

~ ❯ soth start
✓ proxy listening on 127.0.0.1:8888  ·  pid 48213

~ ❯ soth on
✓ system proxy enabled  →  all traffic routed through Soth
```

*Beat (~1s).* Three commands, three green checks. Establishes "drop-in, on in
seconds." (Match the exact success strings to what `start`/`on` print at
record time — update this script if the wording differs.)

### Scene 2 — Watch the live feed (0:07–0:20)

```
~ ❯ soth events stream
Streaming events. Press Ctrl+C to stop.
[14:23:01] openai/gpt-4o            Code generation   allow   $0.03
[14:23:03] anthropic/claude-sonnet  Tool call         allow   $0.01
[14:23:05] openai/gpt-4o-mini       Summarization     allow   $0.00
[14:23:08] google/gemini-1.5-pro    Q&A               allow   $0.02
[14:23:11] anthropic/claude-opus    Code generation   deny    credential detected
[14:23:14] openai/gpt-4o            Tool call         allow   $0.04
```

*The `deny … credential detected` line is the payoff* — let it land for ~2s.
Optional: the recording terminal's theme colors `deny` red and `allow` dim, so
the denial pops without any annotation. Keep one credential hit, not three —
one is a story, three looks staged.

### Scene 3 — Loop reset (0:20–0:22)

Let two or three more `allow` lines scroll, then cut. Keep the last frame on a
calm `allow` line so the loop restart from Scene 1 isn't jarring.

---

## Getting clean demo data

`soth events stream` reads from the local SQLite store, so the feed reflects
real captured traffic. Two ways to get a tidy, repeatable feed:

1. **Live (most honest):** with the proxy on, run a handful of scripted
   requests against AI providers (or a coding agent) so genuine events land,
   then start the recording on `soth events stream`. Best fidelity; least
   deterministic.
2. **Seeded (most repeatable):** point Soth at a throwaway data dir and
   pre-insert a small set of representative `intercept_records` rows, then
   record. Use `--config` to isolate the demo profile so your real
   `~/.soth/` is untouched. This gives identical takes every time.

Either way: **use a throwaway profile** and scrub anything real — no live API
keys, no real hostnames, no personal paths in the prompt.

---

## Recording toolchain

```bash
# 1. Record (fixed window keeps framing consistent)
#    Resize the terminal to ~100x24 before recording.
asciinema rec hero.cast --cols 100 --rows 24 --idle-time-limit 1.5

#    ...drive the scenes above, then Ctrl-D to stop.

# 2a. Preferred: SVG (sharp, ~tens of KB, scales on any display)
npx svg-term-cli --in hero.cast --out .github/assets/hero.svg \
  --window --no-cursor --width 100 --height 24

# 2b. Fallback: GIF
agg hero.cast .github/assets/hero.gif --font-size 16 --theme dracula
gifsicle -O3 --lossy=60 -o .github/assets/hero.gif .github/assets/hero.gif
```

Tuning notes:
- `--idle-time-limit 1.5` trims dead air so the loop stays tight.
- For a true loop, top-and-tail in the cast file (it's plain JSON) so the first
  and last frames match, or re-record cleanly rather than fighting it.
- Keep the SVG under ~200 KB and the GIF under ~1 MB so the README stays fast.

---

## Embedding in the README

Replace the centered logo/hero block, or add directly under the nav links:

```html
<p align="center">
  <img src=".github/assets/hero.svg" alt="Soth live event stream" width="900" />
</p>
```

Use a relative path (not a `raw.githubusercontent.com` URL) so it also renders
on forks and in the PR preview. Add concise alt text — it's what screen readers
and broken-image states show.

---

## Checklist before committing the asset

- [ ] No real API keys, tokens, hostnames, or personal paths visible in any frame
- [ ] Commands match the current CLI (`soth setup-ca` / `start` / `on` / `events stream`)
- [ ] Event lines match `render_compact_line()` output exactly
- [ ] Loop restart is not jarring (calm last frame)
- [ ] SVG < ~200 KB / GIF < ~1 MB
- [ ] Renders correctly on both light and dark GitHub themes

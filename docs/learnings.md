# Learnings — the "first session is black" saga (2026-09-11/12)

One user-visible symptom — *first connection after a linrdp restart shows a
black screen, reconnecting always works* — turned out to be an onion of six
independent server-side defects stacked on the same trigger. Every fix
peeled one layer and re-exposed the symptom until the last one matched the
pattern 1:1. This file records the defects, the mstsc behaviors they
revealed, and the debugging techniques that finally cracked it — so nobody
has to re-derive them from scratch.

## The layers, in the order they were peeled

| # | Defect | Symptom variant | Fix (commit) |
|---|--------|-----------------|--------------|
| 1 | Xvfb (the desktop's X server, a separate unit) crashed on a 17 GB XFCE memory leak; linrdp held its startup X11 connection forever — every grab failed silently, no surface was ever created, **zero frames sent** | black screen until linrdp restart, even though X had been revived by systemd long ago | auto-reconnect the grabber after ~30 failed polls, clear `prev_frame` → next grab repaints everything (`a7227ef`) |
| 2 | Input injection went to the stale X socket: clicks/keys silently dropped | "static picture that ignores input" while frames flowed | reconnect input on first failed XTEST event + retry that event (`a7227ef`) |
| 3 | A **frozen** X server (alive socket, zero replies) hung `reply()` forever — no errors, so no reconnect ever fired; a stalled encode/lock could hang the display loop permanently (heartbeats degraded 83→16→0) | frozen session; every later client connects to a dead loop (black) | hard timeouts: grab 3 s (spawn_blocking + abandon), connect 3 s, frame processing 5 s (drop future, reset encoders); poison-recover all mutexes (`9cd7639`) |
| 4 | On mstsc's caps re-advertise (decoder reset) we blasted surface+1.1 MB repaint into the same tick; a channel re-open briefly cleared `ready` and the loop could emit a legacy bitmap update mid-EGFX-session | protocol error 0xD06, client RST ~1 s after connect | hold frames 250 ms after re-advertise; latch EGFX sessions (never legacy) (`ac56e7a`) |
| 5 | H.264 pushed during the 1–2 s of desktop churn after a RandR resize: mstsc **decodes** it (frame acks flow!) but never **composes** it | session shows one static/frozen frame forever | `RESIZE_SETTLE`: lossless-only for 1.5 s after any resize; first ClearCodec paint goes out immediately (`378a1c0` + `36b1757`) |
| 6 | The killer matching the pattern exactly: the process-global `GfxSession` holds **no graphics handle until the first client opens the EGFX channel** (~300 ms into the session). Only the *first* session of a process therefore emitted **legacy bitmap updates while mstsc was negotiating the graphics pipeline** — log signature: `frame ack overdue` *before* surface creation. mstsc stopped composing the mixed stream; every EGFX frame kept decoding but the picture never appeared. Every *later* session found the previous handle already present → never sent legacy → worked. Hence "first black, second works", 1:1. | the original complaint, surviving every fix above | channel present but caps not landed → hold frames, never legacy; no channel at all → 1.5 s grace, then legacy for genuinely non-EGFX clients (`legacy_grace_until`) |

Related smaller fixes from the same nights: XTEST release-all (keycode 0) at
startup/reconnect/client-sync — a restart while a key is held leaves it
pressed in X forever (auto-repeat terminal-scrolling bug, `ed968c1`);
deferred clipboard image fetch (a 20 MB screenshot in the client clipboard
was hauled through the young session's control channel at every connect —
black during setup; text/mid-session copies stay eager); rate-limiting the
audio-loop liveness log (half a million noise lines were burying the real
diagnostics).

## mstsc behaviors worth remembering

- **Double connection per attempt**: mstsc opens a probe TCP connection,
  stalls ~2.5–2.9 s before ClientHello (Kerberos/DC-discovery timeout in the
  client), kills it at its own ~3 s budget mid-CredSSP (our final write hits
  `BrokenPipe`), then instantly retries. The retry is the user-visible
  session. Don't mistake the probe's death for a server bug.
- **Caps re-advertise = full decoder reset** right after connect and on
  errors: the client deletes every surface. Frames sent into the reset are
  dropped or fatal (0xD06). Detect via `get_surface(id)` liveness; give the
  client ~250 ms to settle before the repaint.
- **Decoded ≠ composed.** A `FrameAcknowledge` means the client *processed*
  a frame; it says nothing about the picture appearing. The black sessions
  had hundreds of acks. When acks flow but the user sees black/frozen, the
  problem is client-side composition triggered by something in *what* we
  send and *when*: mixed update streams (legacy bitmap + EGFX), or lossy
  video arriving during pipeline negotiation/reset churn.
- **mstsc announces its whole clipboard at session start** — including
  multi-megabyte screenshot DIBs. Never fetch clipboard payload eagerly in
  the connect critical path; real RDP transfers clipboard data lazily.
- `SuppressOutput(true)` mid-session is the client minimizing/hidden — pause
  emission, resume on `RefreshRectangle`.

## Debugging techniques that paid off

- **A self-service repro rig** beats waiting for the user: Xvfb `:90` +
  `sdl-freerdp3` + `xdotool` (click/move through the client to test input) +
  `ffmpeg -f x11grab` screenshots of both displays + a PNG pixel-histogram
  script to tell "real desktop" from "black window". Watch the footguns:
  `pkill -f sdl-freerdp3` kills your own shell (pattern matches the
  command line) — use `pkill -x`; never start your test Xvfb on the
  desktop's display number.
- **SIGSTOP/SIGCONT of Xvfb** simulates a frozen X server without touching
  systemd or the user's session — the only honest test for freeze handling
  (a restart tests the crash path instead).
- **gdb on the live process** (`thread apply all bt`) settles any "which
  thread is stuck" debate instantly — if you catch it before the session
  dies. All-parked workers + a dead task = the future was dropped, not
  blocked.
- **journalctl vs application log**: journald timestamps are local time,
  naive `--since` is local too; the app log was UTC with ANSI color codes —
  strip them (`sed 's/\x1b\[[0-9;]*m//g'`) before grepping, and beware awk
  timestamp comparisons passing non-timestamp lines (`"39:" > "2026-…"`).
- **Rate-limit every periodic debug line.** Two liveness logs (audio loop,
  X11 selection poller) produced hundreds of thousands of lines that buried
  the single WARN that mattered.
- **The user's test protocol is part of the system under test.** "Restart,
  connect" — but mstsc's auto-reconnect raced the restart twice, and one
  "black 2 s session" was the user's own second restart killing their
  healthy fresh session (journal proof: `Stopping…` 2 s after
  `Client Info`). Always pull the systemd journal *and* the app log before
  believing a repro.
- **"Works on the second try" is a state hint, not noise**: something
  differs between attempt 1 and 2 — per-process state (here: the graphics
  handle), warm caches (clipboard already synced), settled desktop (X
  already resized). Enumerate the differences; one of them is the bug.
- **Don't hardcode a workaround for the user's monitor** when a general
  mechanism exists — `--fixed-size` stays an opt-in; the default path
  (resize to client + settle) works for any resolution.

## Invariants now enforced in code (keep them)

1. A graphics-capable client (its EGFX channel exists — or might, within
   `LEGACY_GRACE`) never sees a legacy bitmap update. Bitmap and EGFX
   streams must never mix in one session.
2. Nothing in the display path may block unbounded: grab/connect/process
   all run under timeouts; a wedged anything costs at most a frame.
3. X server death is expected: capture and input reconnect on their own;
   after recovery a full lossless repaint pays the pixel debt.
4. After any RandR resize, 1.5 s of lossless-only (no H.264) until the
   desktop churn settles; the first paint itself goes out immediately.
5. Clipboard payload is never fetched eagerly in the session-start window.
6. XTEST release-all runs at startup, X reconnect, and every client
   Synchronize — held keys from dead sessions must not leak into X.

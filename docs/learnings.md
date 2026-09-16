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

---

# Learnings — "mstsc disconnects 1-3 s after connect" (2026-09-16)

A second onion, same shape as the black-screen saga: one symptom, three
independent spec violations stacked on the same trigger. Each fix let the
session live longer and exposed the next. All three were found by reading
[MS-RDPEGFX] properly — every one of them is an explicit MUST that the code
contradicted, twice with a comment asserting the opposite of the spec.

| # | Defect | Spec | Symptom |
|---|--------|------|---------|
| 1 | Two x264 encoders, one per AVC444v2 subframe | 2.2.4.5/2.2.4.6: both bitstreams "MUST be encoded using the same MPEG-4 AVC/H.264 encoder and decoded by a single MPEG-4 AVC/H.264 decoder as one stream" | The chroma IDR flushed the client's single decoder DPB; the next luma P-frame referenced a picture that was gone -> decoder fault |
| 2 | Mid-session CapsAdvertise answered with CapsConfirm and nothing else | 3.2.5.18: the server "MUST also reset the protocol to the initial state and assume that the client has disregarded all the messages sent by the server prior to RDPGFX_CAPS_CONFIRM_PDU" | Frames kept addressing a surface the client had dropped; `unacknowledged` stayed pinned so backpressure wedged. RST ~70 ms after the re-advertise |
| 3 | ClearCodec `seqNumber` restarted whenever the encoder was rebuilt | 2.2.4.1: "the value of the seqNumber field MUST be equal to the value of the seqNumber field in the previous ClearCodec message plus one" | Adaptive bitrate rebuilt the encoder 7x in 26 s; each rebuild reset the counter to 0, so the next full repaint carried an impossible number -> decoder fault -> (2) -> RST |

Plus the bottom band at 1800 px: the 16-macroblock padding was baked into the
*surface* and into the region rects, so 8 rows of padding were composited and
flipped between black and replicated edge content. 3.3.8.3.3 says regionRects
are a mask applied *after* whole-macroblock conversion — alignment belongs to
the encoder, and a region may end on an unaligned row.

## What made this take so long

- **A comment in the code asserted the opposite of the spec.**
  `gfx_display.rs` claimed "[MS-RDPEGFX 2.2.4.6]: each substream is decoded by
  its own decoder instance", and a unit test *asserted that behavior*. Both
  had to be deleted before the real fix could compile. A confident citation in
  a comment is not evidence — open the spec file and read the sentence.
- **"MS-RDPEGFX does not document the recovery flow explicitly"** was written
  next to the caps-re-advertise handler. It does, in 3.2.5.18. Grep the spec
  before concluding it is silent.
- **390k lines of clipboard polling buried the diagnostics** (1.5 GB of log in
  five days). The one WARN that mattered was unfindable. Rate-limit really
  does mean every periodic line.

## Techniques that cracked it

- **Read the live log, not the code's story about itself.** Every fix was
  pinned to a timestamp: the client's CapsAdvertise 36 ms after a specific
  frame, the RST 16 ms after the next one.
- **`queueDepth` in FrameAcknowledge is the client's real health.** A healthy
  session runs at `queue_depth=0` and ~17 ms ack latency. The dying one showed
  1.18 MB queued and 650 ms latency.
- **Correlate the journal with the app log.** x264 prints on every encoder
  creation, which is how "7 rebuilds in 26 s" — the smoking gun for defect 3 —
  became visible at all.
- **Let the fix prove itself in the log.** One `debug!` line per ClearCodec
  frame carrying its seqNumber turned "is it fixed?" into a glance:
  `seq=0,1,2,...,36`, no CapsAdvertise, `had_error=false` after 46 s.
- **Session state vs. object lifetime.** Defect 3 is the general trap: a
  protocol counter (or cache) that the spec scopes to the *session* must not
  live inside an object the implementation rebuilds for unrelated reasons. The
  same rule caught two more instances — a frame dropped by backpressure must
  not consume a sequence number, and a caps reset must restart it at 0.

## Invariants now enforced (keep them)

7. Both AVC444/AVC444v2 subframes come from ONE H.264 encoder, as consecutive
   frames of one stream.
8. A mid-session CapsAdvertise resets the pipeline to its initial state:
   queued output dropped, surfaces and frame tracker cleared, ResetGraphics
   forced before the next CreateSurface — and no DeleteSurface on the wire.
9. The EGFX surface is the real desktop size. Codec alignment padding never
   leaves the encoder and never appears in a regionRect.
10. ClearCodec `seqNumber` is session state: stamped per encode, committed
    only when the frame reaches the wire, carried across encoder rebuilds,
    reset to 0 (with the glyph cache) only on a client pipeline reset.

---

# Learnings — "high bandwidth, low FPS" and the two false X deaths (2026-09-16)

The tail of the disconnect saga above. With the session finally staying up,
what was left was a stream that cost ~1.7 MB/s for a desktop doing almost
nothing, at 4 fps. Two defects, and a third suspect that turned out innocent.

| # | Defect | Symptom | Evidence that found it |
|---|--------|---------|------------------------|
| 1 | The MIT-SHM segment was created mode 0600. linrdp runs as root, the desktop's X server as the user, so `ShmAttach` returned `BadAccess` every time and every grab fell back to a core-protocol `GetImage` of the whole screen (~20 MB at 2880x1800) | grabs cost 4-6 ms and the X socket carried ~1 GB/s | `examples/shm_probe.rs` against the live display: 0600 FAILED (X11Error Access), 0666 OK |
| 2 | `poll_inner()` returned a bare `None` both for "the damage gate saw no change" and for "the grab failed"; `poll()` counted every `None` as a failure | 30 undamaged polls (~0.5 s of a static screen) tripped "X server connection was dead", which drops the diff baseline and forces a full-screen lossless repaint — 32 spurious reconnects and 37 repaints of ~1.2 MB in one quiet session | reconnects exactly 0.72 s apart (30 polls x 17 ms), and `grab_ms=0` — no grab is even attempted when the damage gate says idle |
| — | UDP (MS-RDPEMT) — **not guilty** | had been disabled with a code comment blaming it for mstsc's CapsAdvertise | with the graphics faults fixed, UDP ran a 100 s session with no recovery and no reset; mstsc reported "transport protocol: UDP" |

## What this cost, and why it hid so long

Defect 2 is invisible in an *active* session: with damage on nearly every
poll the counter never reaches 30. The test that looked perfect
(`damaged=256/292 polls`, 0 reconnects) and the test that looked broken
(`damaged=21/290`, 32 reconnects) ran the same binary minutes apart. The
difference was whether the user happened to be moving the mouse.

Net effect once both were fixed, same desktop, same client:
27x less bandwidth at 5x the frame rate (42 frames / 16.9 MB per 10 s ->
230 frames / 0.63 MB per 10 s), and the session stopped repainting itself.

## Traps worth remembering

- **`None` is not a diagnosis.** Two callers of one `Option` meant "nothing
  to do" and "something is broken", and the bug lived in the gap. The fix
  put the distinction in the type system (`PollOutcome::{Idle, Frame,
  Failed}` plus `GrabFailures`) rather than in a convention, because a
  convention is exactly what got lost.
- **A wrong fix can still be a real improvement.** The SHM fix was measured
  and large (636 KB/s -> 41 KB/s, 20 MB per grab gone), but the reconnect
  churn it was credited with had a different cause entirely. Re-check the
  attribution after the numbers move, not just the numbers.
- **Run the experiment instead of reasoning about permissions.** "root
  process, user-owned X server, 0600 segment" is an obvious story once
  written down, but it took a 60-line probe to turn it into a fact. Keep the
  probe (`examples/shm_probe.rs`); it is cheaper than the next argument.
- **Suspect the component that was disabled during an earlier hunt.** UDP
  had been switched off to bisect the disconnects and then stayed off, with
  a comment that hardened the guess into documentation. When the real cause
  is found, go back and re-test everything that was disabled along the way.
- **mstsc's connection-info dialog is a free measurement**: transport
  protocol, RTT, estimated bandwidth and the refresh rate the client is
  actually achieving. "6 FPS" there against `frames=289` in our stats is a
  sentence-long diagnosis.

## Invariants now enforced (keep them)

11. An idle poll is not a grab failure. Only a failed grab counts toward the
    reconnect threshold; a genuinely dead connection still surfaces because
    `damage_pending()` returns true on a connection error.
12. The MIT-SHM segment uses the strict mode where it works and widens only
    when the server refuses, with `IPC_RMID` as soon as both sides are
    attached — so the permissive window is closed and a crash cannot leak a
    20 MB segment.

---

# Learnings — "the first screen paints top-to-bottom over 30 s" (2026-09-16)

Direct descendant of the section above. With the stream finally cheap and the
session stable, connecting still felt like a 3G modem: the first full screen
crawled down from the top over ~30 seconds on a 1 Gbit LAN, and on a screen
nobody touched it never finished at all.

| # | Defect | Symptom | Evidence that found it |
|---|--------|---------|------------------------|
| 1 | The lossless-debt repayment lives inside `egfx_frame`, which only runs when a poll returns a `Grab`. After the `PollOutcome::Idle` split (previous section, defect 2) an unchanged screen returns no grab at all, so the debt could only advance on somebody *else's* damage event | first paint ~30 s; a genuinely static screen never completes | `polls=292 damaged=8` per 5 s against `frames=16` per 10 s — damage events and sent frames were the same 1.6/s number, and `pending_full=true` persisted across 5 consecutive heartbeats |
| 2 | `lossless_budget_px()` sized bands from a fixed H.264 bitrate anchor (2880x1800 → nearest anchor 2560x1440 → 6328 kbit/s → 98 877 px), and `CLEARCODEC_BYTES_PER_PX = 1` overstated the real cost ~5x | 53 bands of 34 rows for one screen | `EGFX ClearCodec frame sent seq=80..99 full=false w=2880 h=34` — 100 consecutive bands, every one exactly 34 rows, never `full=true` |
| 3 | `client_queue_depth` gates sending at ≥250 KB but is refreshed only by an ack, and an ack only answers a frame we sent — a latched value can never decay | (latent) permanent freeze on the last frame | highest observed in a real session was 156 865 B, i.e. ~60% of the way to a deadlock nothing could clear |
| 4 | `send_h264` returned `()`, so the caller entered motion mode even for a frame the pipeline rejected; motion mode then suppresses the lossless path | dropped pixels nothing later delivers — permanently when AVC is disabled | read while tracing why `in_motion` was true with `h264=0` in the stats |
| 5 | `backpressure_events` counted only pre-encode `should_backpressure()` polls, never an actual rejected send; `producer_frames` counted deliveries, below the very window it sizes | quality loop blind to real drops; starved producer pinned the window at `MIN_IN_FLIGHT` | the comment on `update_in_flight_window` claims the rate is measured upstream of the window — it was not |

## What the specification actually said

Every fix here is anchored in a MUST/SHOULD we were contradicting or ignoring.

- **MS-RDPEGFX 3.2.5.13**: the server SHOULD throttle on `queueDepth` *"in the
  range 0x00000001 to 0xFFFFFFFE"*. That range is the whole mandate. Our client
  reported `queue_depth=0` in **2256 of 2265** acks, `suspended=false` always,
  `in_flight_after=0` in 2253 of 2263 — it was idle and waiting, and we throttled
  it anyway against a number the protocol never asked us to invent.
- **MS-RDPEGFX 2.2.2.13**: `queueDepth` is *"the number of unprocessed bytes
  buffered at the client"* — a byte count, and one that only exists at the
  moment an ack carries it.
- **MS-RDPBCGR 3.2.5.14**: autodetected bandwidth is `(byteCount * 8) / timeDelta`
  over *"the PDUs sent from server to client"* — on a quiet session it measures
  our own output, so it must never steer our output. (`bandwidth_kbps=0` in the
  log is this, not a broken link.)
- **MS-RDPEGFX 3.2.5.21**: QoE timings *"SHOULD only be used for informational
  and debugging purposes"* — not as a control input, however tempting.

## Traps worth remembering

- **A correct fix can starve the thing that was accidentally feeding it.** The
  `Idle`/`Failed` split was right, measured, and shipped with an invariant. It
  also removed the spurious full repaints that had been the debt's only source
  of progress. Nothing in the old code said "the repaint depends on this
  misbehaviour" — because nobody knew it did. After a fix lands, ask what was
  *benefiting* from the bug.
- **The type already described the case the code could not produce.** `Grab.damage`
  was documented as "`None` when nothing changed", and `egfx_frame` already had a
  branch repaying the debt from exactly that shape. `poll()` simply never built
  one. The fix was a forcing flag, not new logic — when a handler for a state
  exists but is unreachable, suspect the producer, not the consumer.
- **A conservative constant is still a guess.** `CLEARCODEC_BYTES_PER_PX = 1` was
  commented as "4x the measured rate" and treated as safe because it only ever
  *under*-fills a band. Multiplied by a budget that was already 50x too small it
  was a 5x error on top of a 50x one. The encoder knows the real ratio on every
  frame; measure it instead.
- **Check the justification, not just the number.** The 1/8-second band budget
  existed so "audio never queues behind one". Measured on this path:
  `SharedWriter` `lock_wait_ms` was **0 across 34 113 samples**, largest single
  write 448 KB at `write_ms` ≤ 1. The hazard it was defending against was not
  present, and the defence cost 30 seconds of every connect.
- **A backpressure signal that only arrives in replies is a deadlock waiting to
  latch.** Anything gated on a value refreshed solely by the traffic that value
  gates needs an expiry. Ours had none.

## Invariants now enforced (keep them)

13. Throttling follows the client's own reported `queueDepth`, per MS-RDPEGFX
    3.2.5.13, never a locally invented capacity figure. Autodetected bandwidth
    and QoE timings are explicitly not control inputs.
14. Any backpressure sample refreshed only by acks expires
    (`CLIENT_QUEUE_DEPTH_STALE_AFTER`). A reading that can only be cleared by
    traffic it is blocking must never be able to block forever.
15. While the display owes the client pixels, the frame source hands back the
    current screen with `damage: None` rather than reporting "nothing changed".
    A repaint must never depend on unrelated damage to make progress.
16. Every send path reports whether the frame reached the wire, and callers act
    on it: motion mode only on a delivered H.264 frame, and a rejected send
    counts as backpressure.
17. Producer rate is counted on offer, above the in-flight window it sizes —
    otherwise the window starves the producer whose rate sets the window.

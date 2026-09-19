//! Real audio output: captures the session's audio via PulseAudio (the
//! monitor of [`SINK`], in that session's own daemon) and streams Wave PDUs
//! to the RDP client through MS-RDPSND — the same role a Windows session
//! server plays (MS-RDPSND server captures the session mixer and sends Wave
//! PDUs).
//!
//! *Which* daemon is not this file's decision. It comes from the session gate
//! (`session::gate::audio_target`), the same place the display comes from, so
//! a worker can only ever capture the desktop it is serving. Answering that
//! question from the environment instead is what made every session on port
//! 3389 record one account's mixer, and what left port 3390 with no sound at
//! all.
//!
//! Uses `libpulse-binding` — safe Rust binding to the libpulse shared
//! library already present on the system. No external binaries: the daemon's
//! sink and source are created here, through libpulse, not by shelling out to
//! `pactl` from a setup script.

use core::time::Duration;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicIsize, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ironrdp_rdpsnd::pdu::{AudioFormat, WaveFormat};
use ironrdp_rdpsnd::server::{NegotiatedFormat, RdpsndError};
use ironrdp_server::{RdpsndServerHandler, RdpsndServerMessage, ServerEvent, ServerEventSender, SoundServerFactory};
use libpulse_binding as pulse;
use tokio::sync::mpsc::UnboundedSender;

type PaMainloop = pulse::mainloop::standard::Mainloop;
type PaContext = pulse::context::Context;

/// The sink this session's desktop plays into, and the source its
/// applications see as a microphone.
///
/// Unqualified names on purpose: every session has a PulseAudio daemon of its
/// own, so every session has a `linrdp_audio` of its own and they never meet.
/// The arrangement being replaced had one sink in one account's daemon, which
/// is exactly how a second user came to hear the first user's desktop.
const SINK: &str = "linrdp_audio";
const MIC_SOURCE: &str = "linrdp_mic";

/// How long to wait before asking the gate again.
///
/// Having nothing to attach to is the normal state for part of a connection's
/// life: RDPSND negotiates while the logon screen is still up, so on the
/// greeter port this is where the capture thread sits until someone logs in.
const ATTACH_RETRY: Duration = Duration::from_millis(500);

/// How long any one step of attaching may take before it counts as failed.
///
/// Every wait on the daemon is bounded. An unbounded one would turn a daemon
/// that accepts the socket but never answers into a capture thread that hangs
/// for the life of the session with nothing in the log.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(5);

const SAMPLE_RATE: u32 = 48000;
const CHANNELS: u16 = 2;
const CHUNK_MS: u64 = 40;
const CHUNK_BYTES: usize = SAMPLE_RATE as usize / 1000 * CHUNK_MS as usize * 4; // 40ms stereo s16le
// ~320 ms of audio; drop backlog beyond that so latency can never grow
// unbounded between the PA monitor and the sender
const MAX_QUEUE: usize = 8;
const OPUS_MAX_PACKET: usize = 4000;

// Same shape the ironrdp-rdpsnd-native client advertises for Opus, so
// `matches_for_negotiation` (which compares every field for non-PCM formats)
// lines up with mstsc/FreeRDP clients built on that list.
const OPUS_FORMAT: AudioFormat = AudioFormat {
    format: WaveFormat::OPUS,
    n_channels: CHANNELS,
    n_samples_per_sec: SAMPLE_RATE,
    n_avg_bytes_per_sec: 192000,
    n_block_align: 4,
    bits_per_sample: 16,
    data: None,
};

const PCM_FORMAT: AudioFormat = AudioFormat {
    format: WaveFormat::PCM,
    n_channels: CHANNELS,
    n_samples_per_sec: SAMPLE_RATE,
    n_avg_bytes_per_sec: SAMPLE_RATE * 2 * 2,
    n_block_align: 4,
    bits_per_sample: 16,
    data: None,
};

fn formats() -> Vec<AudioFormat> {
    // Preference order: OPUS first (~64 kbit/s), PCM as fallback for clients
    // that don't advertise WAVE_FORMAT_OPUS.
    vec![OPUS_FORMAT, PCM_FORMAT]
}

type Shared<T> = Arc<Mutex<T>>;

fn new_shared<T>(v: T) -> Shared<T> {
    Arc::new(Mutex::new(v))
}

#[derive(Debug, Default)]
pub(crate) struct SystemSoundFactory {
    sender: Shared<Option<UnboundedSender<ServerEvent>>>,
}

impl ServerEventSender for SystemSoundFactory {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self.sender.lock().expect("poisoned") = Some(sender);
    }
}

/// Waves sent but not yet confirmed played by the client (Wave Confirm PDU).
///
/// The classic RDPSND flow control: cap the unconfirmed count, and when the
/// cap is exceeded DROP the wave instead of queueing it. This bounds the
/// audio buffered anywhere on the path (server queues, TCP, client jitter
/// buffer) to roughly `MAX_IN_FLIGHT` × CHUNK_MS regardless of how badly the
/// shared TCP transport stalls under bitmap traffic. Without it, waves pile
/// up behind a stalled socket and the client plays seconds of stale audio
/// after the source goes silent (e.g. pausing a video).
const MAX_IN_FLIGHT: isize = 5;

impl SoundServerFactory for SystemSoundFactory {
    fn build_backend(&self) -> Box<dyn RdpsndServerHandler> {
        Box::new(SystemSoundHandler {
            task: None,
            stop: new_shared(false),
            sender: Arc::clone(&self.sender),
            formats: formats(),
            in_flight: Arc::new(AtomicIsize::new(0)),
            last_confirm_ms: Arc::new(AtomicU64::new(0)),
            clock: new_shared(None),
            sent: new_shared(std::array::from_fn(|_| None)),
            held_ewma_ms: Arc::new(AtomicU32::new(0)),
        })
    }
}

#[derive(Debug)]
struct SystemSoundHandler {
    task: Option<tokio::task::JoinHandle<()>>,
    stop: Shared<bool>,
    sender: Shared<Option<UnboundedSender<ServerEvent>>>,
    formats: Vec<AudioFormat>,
    /// RDPSND flow control: waves sent minus waves confirmed by the client.
    in_flight: Arc<AtomicIsize>,
    /// When the last Wave Confirm arrived (ms since the handler's `start`),
    /// for un-wedging the flow control after waves were dropped without a
    /// matching confirm.
    last_confirm_ms: Arc<AtomicU64>,
    /// Origin of `last_confirm_ms`, set in `start`.
    clock: Shared<Option<Instant>>,
    /// Per-block record of sent waves, indexed by cBlockNo (mod 256), for
    /// matching Wave Confirms to the wave they answer. mstsc confirms each
    /// block up to twice — once on enqueue, once after playback — so a FIFO
    /// of sent timestamps desyncs after the first confirm; the play-confirm
    /// (the one carrying the real client backlog) must land on ITS wave.
    sent: Shared<[Option<SentWave>; 256]>,
    /// EWMA of the client residence time (ms): how long the client held a
    /// wave between receiving and playing it — the spec's direct measure of
    /// audio backlog at the client.
    held_ewma_ms: Arc<AtomicU32>,
}

/// One sent wave's confirm-matching state (MS-RDPEA 2.2.3.8).
#[derive(Debug, Copy, Clone)]
struct SentWave {
    /// The wire `wTimeStamp` the wave carried.
    wire_ts: u16,
    /// Largest held time observed across the confirm(s) for this block so far
    /// (the play-confirm reports a larger value than the enqueue-confirm).
    best_held: u16,
    /// Whether any confirm was already counted against `in_flight` for this
    /// block — a block confirmed twice must only free one slot.
    confirmed: bool,
}

impl ServerEventSender for SystemSoundHandler {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self.sender.lock().expect("poisoned") = Some(sender);
    }
}

impl RdpsndServerHandler for SystemSoundHandler {
    fn get_formats(&self) -> &[AudioFormat] {
        &self.formats
    }

    fn choose_format<'a>(&mut self, common: &'a [NegotiatedFormat]) -> Option<&'a NegotiatedFormat> {
        // `common` is in our preference order: OPUS (if the client supports
        // it) first, PCM as fallback.
        common.first()
    }

    fn start(&mut self, format: &NegotiatedFormat) -> Result<(), Box<dyn RdpsndError>> {
        *self.stop.lock().expect("poisoned") = false;
        self.in_flight.store(0, Ordering::Relaxed);
        self.last_confirm_ms.store(0, Ordering::Relaxed);
        // Origin for the confirm clock, shared with wave_confirm.
        *self.clock.lock().expect("poisoned") = Some(Instant::now());

        // If Opus was negotiated, encode every PCM chunk before it goes out.
        let encoder = if format.format().format == WaveFormat::OPUS {
            let enc = opus2::Encoder::new(SAMPLE_RATE, opus2::Channels::Stereo, opus2::Application::Audio)
                .map_err(|e| -> Box<dyn RdpsndError> { Box::new(std::io::Error::other(format!("opus encoder: {e}"))) })?;
            tracing::info!("[rdpsnd] OPUS negotiated — encoding 48 kHz stereo at ~64 kbit/s");
            Some(enc)
        } else {
            tracing::info!("[rdpsnd] PCM negotiated — sending uncompressed");
            None
        }
        .map(|mut enc| {
            let _ = enc.set_bitrate(opus2::Bitrate::Bits(64000));
            Arc::new(Mutex::new(enc))
        });

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let stop = Arc::clone(&self.stop);

        // Blocking capture thread (PulseAudio mainloop is synchronous here).
        //
        // Its error is logged, not discarded. Discarding it is how a session
        // came to have no sound at all with nothing in the log at any level
        // to say so: PulseAudio refused the connection, `capture_thread`
        // returned that refusal, and `let _ =` threw it away. The only trace
        // was the line libpulse itself writes to stderr. Audio failing is
        // never so unimportant that the reason should be unavailable.
        std::thread::spawn(move || {
            if let Err(error) = capture_thread(tx, Arc::clone(&stop)) {
                tracing::error!(
                    error = format!("{error:#}"),
                    "[audio-capture] capture stopped — this session has no sound"
                );
            }
        });

        let sender = Arc::clone(&self.sender);
        let in_flight = Arc::clone(&self.in_flight);
        let last_confirm_ms = Arc::clone(&self.last_confirm_ms);
        let held_ewma_ms = Arc::clone(&self.held_ewma_ms);
        let sent = Arc::clone(&self.sent);
        let started = Instant::now();
        self.task = Some(tokio::spawn(async move {
            let mut chunk_count: u64 = 0;
            // Mirror of RdpsndServer's cBlockNo sequence (starts at 1, wraps).
            let mut send_block_no: u8 = 1;
            // Current Opus bitrate (i32 bits/s) for the dynamic quality logic.
            let mut opus_bitrate: i32 = 64_000;
            while let Some(chunk) = rx.recv().await {
                // Skip pure digital silence: streaming silence forever keeps
                // the client's audio path permanently buffered and wastes
                // ~150 kB/s of transport; the client needs no idle carrier.
                if chunk.iter().all(|&b| b == 0) {
                    continue;
                }
                chunk_count += 1;
                // Adaptive pacing (MS-RDPEA 2.2.3.8): the confirm's held time
                // is how much audio sits buffered at the client. If it grows
                // past the comfort threshold, skip this wave — the client
                // already has more than it can play on time.
                //
                // The gauge is only refreshed by confirms, and confirms only
                // come for waves we actually send — so while the threshold is
                // dropping waves it would freeze at its last reading forever.
                // Age it with wall time instead: while nothing is being sent
                // the client drains its buffer in real time, so the backlog
                // implied by a stale reading shrinks second for second. The
                // 150 ms grace keeps normal-flow readings (a confirm every
                // ~40-80 ms) untouched.
                let now_ms = started.elapsed().as_millis() as u64;
                let since_confirm = now_ms.saturating_sub(last_confirm_ms.load(Ordering::Relaxed));
                let held = held_ewma_ms
                    .load(Ordering::Relaxed)
                    .saturating_sub(u32::try_from(since_confirm.saturating_sub(150)).unwrap_or(u32::MAX));
                if held > 400 {
                    tracing::debug!(held_ms = held, stale_ms = since_confirm, "[rdpsnd-sender] dropping wave — client backlog high");
                    continue;
                }

                // Flow control: if the client hasn't confirmed enough of the
                // recent waves, this one would only add to a growing backlog
                // — drop it. Live audio tolerates a dropped 40 ms chunk far
                // better than seconds of accumulating latency.
                if in_flight.load(Ordering::Relaxed) >= MAX_IN_FLIGHT {
                    // Self-heal: waves dropped downstream of us are never
                    // confirmed, so the count can wedge high while the client
                    // is actually keeping up. If no confirm arrived recently,
                    // assume the count is stale and restart it.
                    let now_ms = started.elapsed().as_millis() as u64;
                    let last = last_confirm_ms.load(Ordering::Relaxed);
                    if now_ms.saturating_sub(last) > 1500 {
                        tracing::debug!("[rdpsnd-sender] flow control wedged (no confirms in 1.5 s) — resetting");
                        in_flight.store(0, Ordering::Relaxed);
                    } else {
                        tracing::debug!(
                            in_flight = in_flight.load(Ordering::Relaxed),
                            "[rdpsnd-sender] dropping wave — client behind (flow control)"
                        );
                        continue;
                    }
                }
                // Real capture time: gives the client (and Wave Confirm) a
                // time reference — a constant zero timestamp makes the client
                // buffer without reference and inflate latency.
                let ts = started.elapsed().as_millis() as u32;

                let payload = if let Some(enc) = encoder.as_ref() {
                    let mut enc = enc.lock().expect("poisoned");
                    // Dynamic audio quality (the QualityMode::Dynamic behaviour
                    // from MS-RDPEA): scale the codec bitrate with the link —
                    // high client backlog means the link can't carry 64 kbit/s,
                    // a healthy backlog means it can.
                    let target = if held > 250 { 32_000 } else if held < 120 { 64_000 } else { opus_bitrate };
                    if target != opus_bitrate {
                        if enc.set_bitrate(opus2::Bitrate::Bits(target)).is_ok() {
                            tracing::info!(from_bps = opus_bitrate, to_bps = target, held_ms = held, "Opus bitrate adapted");
                            opus_bitrate = target;
                        }
                    }
                    let samples: Vec<i16> = chunk
                        .chunks_exact(2)
                        .map(|b| i16::from_le_bytes([b[0], b[1]]))
                        .collect();
                    let mut out = vec![0u8; OPUS_MAX_PACKET];
                    match enc.encode(&samples, &mut out) {
                        Ok(n) => {
                            out.truncate(n);
                            out
                        }
                        Err(e) => {
                            tracing::warn!("[rdpsnd-sender] opus encode failed: {e}");
                            continue;
                        }
                    }
                } else {
                    chunk
                };

                if chunk_count % 25 == 1 {
                    tracing::info!(
                        chunk = chunk_count,
                        bytes = payload.len(),
                        held_ms = held,
                        "rdpsnd wave sent"
                    );
                }
                let sender_guard = sender.lock().expect("poisoned");
                let Some(ev_sender) = sender_guard.as_ref() else {
                    tracing::warn!("[rdpsnd-sender] sender is None, cannot send");
                    break;
                };
                let _ = ev_sender.send(ServerEvent::Rdpsnd(RdpsndServerMessage::Wave(payload, ts)));
                in_flight.fetch_add(1, Ordering::Relaxed);
                // Record the wave under the cBlockNo `RdpsndServer::wave()`
                // will stamp on it, so `wave_confirm(block_no, ts)` can match
                // the confirm to ITS wave. The mirror counter follows the same
                // 1-based wrapping sequence the crate uses (MS-RDPEA
                // 3.3.5.2.1.1); nothing may drop waves between this point and
                // `wave()` or the mapping desyncs.
                {
                    let mut ring = sent.lock().expect("poisoned");
                    ring[usize::from(send_block_no)] = Some(SentWave {
                        wire_ts: ts as u16,
                        best_held: 0,
                        confirmed: false,
                    });
                }
                send_block_no = send_block_no.overflowing_add(1).0;
            }
        }));
        Ok(())
    }

    fn stop(&mut self) {
        tracing::info!("[SOUND-STOP] stop() called — stopping audio");
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::debug!(%backtrace, "stop() backtrace");
        *self.stop.lock().expect("poisoned") = true;
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }

    /// Client finished playing (or dropped) a wave — release flow control.
    ///
    /// Per MS-RDPSND 2.2.3.8 the returned `timestamp` is the wave's own
    /// `wTimeStamp` plus how long the client held it, so
    /// `timestamp - wave_timestamp` is the client-side residence time. Used
    /// Client finished playing (or dropped) a wave — release flow control.
    ///
    /// Per MS-RDPEA 2.2.3.8 the returned `timestamp` is the wave's own
    /// `wTimeStamp` plus how long the client held it, so
    /// `timestamp - wave_timestamp` is the client-side residence time.
    ///
    /// mstsc confirms each block up to TWICE (once on enqueue with a small
    /// held time, once after playback with the real one), so matching is by
    /// the confirm's `block_no` against the per-block ring filled at send
    /// time — a plain FIFO desyncs on the second confirm and both the
    /// in-flight count and the backlog gauge go silent.
    fn wave_confirm(&mut self, block_no: u8, timestamp: u16) {
        if let Some(entry) = self.sent.lock().expect("poisoned")[usize::from(block_no)].as_mut() {
            // Held time for THIS wave: the play-confirm reports the full
            // client residence time; keep the best (largest) per block.
            let held_raw = timestamp.wrapping_sub(entry.wire_ts);
            let held = if held_raw > 5_000 { 0 } else { u32::from(held_raw) }; // discard wraps/garbage
            let best = held.max(u32::from(entry.best_held));
            entry.best_held = best as u16;

            if !entry.confirmed {
                // A block confirmed twice frees exactly one in-flight slot.
                entry.confirmed = true;
                let prev = self.in_flight.fetch_sub(1, Ordering::Relaxed);
                if prev <= 0 {
                    // A confirm without a matching in-flight wave (e.g. after
                    // a drop storm or a channel restart) — reset so the
                    // counter can't go negative.
                    self.in_flight.store(0, Ordering::Relaxed);
                }
            }

            let ewma = self.held_ewma_ms.load(Ordering::Relaxed);
            let next = if ewma == 0 { best } else { ewma - ewma / 4 + best / 4 };
            self.held_ewma_ms.store(next, Ordering::Relaxed);
            tracing::trace!(block_no, held_ms = held, best_ms = best, ewma_ms = next, "wave confirm");
        }
        if let Some(origin) = *self.clock.lock().expect("poisoned") {
            self.last_confirm_ms.store(origin.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
    }
}

/// What this worker may capture right now.
enum Attach {
    /// Single-session, or console mode: whatever the environment names, as
    /// before. There the unit's description of the desktop is a correct one,
    /// because there is only ever one desktop to describe.
    Ambient,
    /// A bound session's own daemon, named by the gate.
    Session(crate::session::gate::AudioTarget),
    /// Armed, but there is nothing to capture yet.
    ///
    /// Not an error, and deliberately not a fallback: RDPSND negotiates while
    /// the logon screen is still up, so on the greeter port every connection
    /// passes through this state before anyone has logged in. The old code
    /// had no such state — it connected to the ambient daemon immediately,
    /// which is how one user's audio reached another's client.
    Nothing,
}

fn attach_point() -> Attach {
    if !crate::session::gate::is_armed() {
        return Attach::Ambient;
    }
    match crate::session::gate::audio_target() {
        Some(target) => Attach::Session(target),
        None => Attach::Nothing,
    }
}

/// Capture audio for as long as the handler lives, following the session gate.
///
/// The gate moves under this thread: RDPSND starts at negotiation, which on
/// the greeter port is before the user exists, and the desktop's daemon is
/// only reachable once they have logged in. So attaching is a loop, not a
/// step — the same shape the X capture path uses when the bound display moves
/// (see `capture.rs`, "the bound display moved — reconnecting capture").
fn capture_thread(tx: UnboundedSender<Vec<u8>>, stop: Shared<bool>) -> anyhow::Result<()> {
    let mut waiting = false;
    let mut reported: Option<String> = None;

    loop {
        if stop.lock().map(|g| *g).unwrap_or(true) {
            tracing::info!("[audio-capture] stop requested — not attaching again");
            return Ok(());
        }

        let generation = crate::session::gate::generation();
        let target = match attach_point() {
            Attach::Nothing => {
                if !waiting {
                    waiting = true;
                    tracing::info!("[audio-capture] no session bound yet — waiting for one");
                }
                std::thread::sleep(ATTACH_RETRY);
                continue;
            }
            Attach::Ambient => None,
            Attach::Session(target) => Some(target),
        };
        waiting = false;

        match stream_from(target.as_ref(), &tx, &stop, generation) {
            Ok(()) => reported = None,
            Err(error) => {
                // A session is bound as soon as its X server answers, but its
                // PulseAudio starts with its desktop — so on a fresh login
                // this lands here a few times before the daemon exists, and
                // again if the daemon is ever restarted under us. That is a
                // recoverable state, not a fault. Report each distinct
                // failure once: logging every attempt at this cadence would
                // bury the one that matters.
                let text = format!("{error:#}");
                if reported.as_deref() != Some(text.as_str()) {
                    tracing::warn!(error = %text, "[audio-capture] cannot attach yet — retrying");
                    reported = Some(text);
                }
                std::thread::sleep(ATTACH_RETRY);
            }
        }
    }
}

/// What to say when a session has no sound server of its own.
///
/// Root gets a sentence of its own because it is not a misconfiguration to
/// go and fix: the distribution's `pulseaudio.socket` carries
/// `ConditionUser=!root`, so systemd declines to start a sound server for
/// uid 0 and there is nothing for any RDP server to capture. Naming the
/// condition saves the reader from concluding the audio code is broken.
fn no_daemon(target: &crate::session::gate::AudioTarget) -> String {
    let socket = target.socket();
    if target.is_root() {
        format!(
            "this session has no sound server: nothing is listening at {}, and systemd will not \
             start one for root — pulseaudio.socket carries ConditionUser=!root. A desktop running \
             as root has no audio to capture; log in as an ordinary account instead.",
            socket.display()
        )
    } else {
        format!(
            "this session has no sound server yet: nothing is listening at {}",
            socket.display()
        )
    }
}

/// Stream one attachment: connect, make sure the daemon has what we need,
/// then pump the monitor until the gate moves or the handler stops.
fn stream_from(
    target: Option<&crate::session::gate::AudioTarget>,
    tx: &UnboundedSender<Vec<u8>>,
    stop: &Shared<bool>,
    generation: u64,
) -> anyhow::Result<()> {
    use pulse::stream::FlagSet as StreamFlags;

    let mut mainloop = PaMainloop::new().ok_or_else(|| anyhow::anyhow!("pulse mainloop"))?;
    let mut context = PaContext::new(&mainloop, "linrdp-capture").ok_or_else(|| anyhow::anyhow!("pulse context"))?;

    // The server is passed explicitly rather than left to the environment.
    // That is the whole point of the change: an explicit server string
    // outranks `PULSE_SERVER`, so a unit that still exports one cannot
    // redirect a session's audio to another account's daemon. The cookie has
    // no such argument and comes from `PULSE_COOKIE`, which the gate set when
    // it bound this session.
    // Look at the socket first. libpulse answers a *missing* socket with
    // `Access denied` — the same words it uses for a rejected cookie — and an
    // explicit server string suppresses autospawn, so a session with no sound
    // server of its own can never grow one while we wait. Saying which of the
    // two it is turns a long investigation into one log line.
    if let Some(target) = target
        && !target.socket().exists()
    {
        anyhow::bail!("{}", no_daemon(target));
    }

    let server = target.map(|t| t.server.as_str());
    context
        .connect(server, pulse::context::FlagSet::NOFLAGS, None)
        .map_err(|e| anyhow::anyhow!("connect to {}: {e}", server.unwrap_or("the default daemon")))?;
    context.set_state_callback(Some(Box::new(|| {})));

    let deadline = Instant::now() + ATTACH_TIMEOUT;
    loop {
        match context.get_state() {
            pulse::context::State::Ready => break,
            pulse::context::State::Failed | pulse::context::State::Terminated => {
                anyhow::bail!(
                    "{} refused the connection — is the cookie at {} readable?",
                    server.unwrap_or("the default daemon"),
                    target.map_or_else(|| "$PULSE_COOKIE".to_owned(), |t| t.cookie.display().to_string())
                );
            }
            _ => {}
        }
        if stop.lock().map(|g| *g).unwrap_or(true) || crate::session::gate::generation() != generation {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("{} did not answer within {ATTACH_TIMEOUT:?}", server.unwrap_or("the default daemon"));
        }
        iterate(&mut mainloop, "connecting")?;
    }

    // A session's own FIFO, or — with nothing bound — whatever the gate makes
    // of the ambient environment. Both answers come from the same place the
    // microphone writer asks, so the module we load and the file it is fed
    // through can never disagree.
    let fifo = target
        .map(|t| t.mic_fifo())
        .or_else(crate::session::gate::mic_fifo);
    ensure_objects(&mut mainloop, &mut context, fifo.as_deref())?;

    let mut map = pulse::channelmap::Map::default();
    map.init_stereo();
    let spec = pulse::sample::Spec {
        format: pulse::sample::Format::S16le,
        channels: CHANNELS as u8,
        rate: SAMPLE_RATE,
    };
    if !spec.is_valid() {
        anyhow::bail!("invalid sample spec");
    }

    let mut stream = pulse::stream::Stream::new(&mut context, "linrdp-capture", &spec, Some(&map))
        .ok_or_else(|| anyhow::anyhow!("pulse stream"))?;
    // Low-latency record: default monitor buffering is huge (seconds). Ask for
    // fragsize = one 40 ms chunk so peek() delivers promptly; ADJUST_LATENCY
    // makes PA honor it.
    let buffer_attr = pulse::def::BufferAttr {
        maxlength: u32::MAX,
        tlength: u32::MAX,
        prebuf: u32::MAX,
        minreq: u32::MAX,
        fragsize: CHUNK_BYTES as u32,
    };
    let monitor = format!("{SINK}.monitor");
    stream
        .connect_record(
            Some(&monitor),
            Some(&buffer_attr),
            StreamFlags::START_UNMUTED | StreamFlags::ADJUST_LATENCY,
        )
        .map_err(|e| anyhow::anyhow!("record from {monitor}: {e}"))?;
    stream.set_read_callback(Some(Box::new(|_bytes: usize| {})));
    stream.set_state_callback(Some(Box::new(|| {})));

    let deadline = Instant::now() + ATTACH_TIMEOUT;
    loop {
        match stream.get_state() {
            pulse::stream::State::Ready => break,
            pulse::stream::State::Failed | pulse::stream::State::Terminated => {
                anyhow::bail!("{monitor} would not open");
            }
            _ => {}
        }
        if stop.lock().map(|g| *g).unwrap_or(true) || crate::session::gate::generation() != generation {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("{monitor} was not ready within {ATTACH_TIMEOUT:?}");
        }
        iterate(&mut mainloop, "opening the monitor")?;
    }

    tracing::info!(
        source = %monitor,
        daemon = server.unwrap_or("the default daemon"),
        "[audio-capture] stream ready — continuous capture started"
    );
    let mut backlog: VecDeque<u8> = VecDeque::new();

    // CONTINUOUS capture: iterate mainloop → peek data → send to client.
    let mut logged = false;
    let mut iteration: u64 = 0;
    let mut last_send = Instant::now();
    loop {
        iteration += 1;
        // A liveness line at debug rate would be thousands per minute
        // (this loop spins fast when PulseAudio returns immediately);
        // once a minute is enough to prove the loop is running.
        if iteration <= 10 || iteration % 10_000_000 == 0 {
            tracing::debug!(iteration, "capture loop alive");
        }
        if stop.lock().map(|g| *g).unwrap_or(false) {
            tracing::info!(iteration, "capture loop: stop requested");
            break;
        }
        // The gate moved: this daemon belongs to a session this worker is no
        // longer serving. Tear down and let the outer loop attach to the new
        // one. Without this check a worker that started on the logon screen
        // would keep capturing whatever it first attached to.
        if crate::session::gate::generation() != generation {
            tracing::info!("[audio-capture] the bound session moved — reattaching");
            break;
        }
        mainloop.iterate(false); // non-blocking; we control the pace

        // Peek real audio from the monitor into the backlog buffer.
        if let Ok(pulse::stream::PeekResult::Data(data)) = stream.peek() {
            if !data.is_empty() {
                backlog.extend(data.iter().copied());
            }
            let _ = stream.discard();
        } else if matches!(stream.peek(), Ok(pulse::stream::PeekResult::Hole(_))) {
            let _ = stream.discard();
        }

        // Hard cap on buffered audio: if we consumed slower than the monitor
        // produced (network stall, scheduling), drop the oldest data instead
        // of letting latency grow without bound.
        let cap = MAX_QUEUE * CHUNK_BYTES;
        if backlog.len() > cap {
            let excess = backlog.len() - CHUNK_BYTES;
            backlog.drain(..excess);
            tracing::debug!(dropped = excess, "audio backlog capped");
        }

        // Extract exactly CHUNK_BYTES (if available) for consistent timing.
        let has_real_audio = backlog.len() >= CHUNK_BYTES;
        let chunk: Vec<u8> = if has_real_audio {
            backlog.drain(..CHUNK_BYTES).collect()
        } else {
            Vec::new()
        };

        // Pace: wait until 40ms has passed since last send.
        let elapsed = last_send.elapsed();
        if elapsed < Duration::from_millis(CHUNK_MS) {
            std::thread::sleep(Duration::from_millis(CHUNK_MS) - elapsed);
        }

        if chunk.is_empty() {
            continue;
        }
        last_send = Instant::now();

        if !logged {
            logged = true;
            tracing::info!("[audio-capture] streaming audio to client");
        }
        let _ = tx.send(chunk);
    }

    stream.disconnect().ok();
    context.disconnect();
    tracing::info!("[audio-capture] detached from {}", server.unwrap_or("the default daemon"));
    Ok(())
}

/// Give the session's daemon the objects this session's audio needs.
///
/// Idempotent, and done in-process through libpulse rather than by shelling
/// out to `pactl`: this file promises no external binaries, and it replaces a
/// hand-installed setup script that could only ever configure one account's
/// daemon — which is how every session came to be recording uid 1000's.
///
/// The sink is created rather than borrowed because the monitor of a sink we
/// own is the one thing certain to carry exactly this desktop's audio, at the
/// rate we capture at. Recording "the default source" instead would capture
/// [`MIC_SOURCE`] the moment it is made default: an echo loop by
/// construction.
fn ensure_objects(mainloop: &mut PaMainloop, context: &mut PaContext, fifo: Option<&Path>) -> anyhow::Result<()> {
    if !has_object(mainloop, context, Object::Sink, SINK)? {
        load_module(mainloop, context, "module-null-sink", &null_sink_args())?;
        tracing::info!(sink = SINK, "[audio-capture] created this session's sink");
    }
    set_default(mainloop, context, Object::Sink, SINK)?;

    // No FIFO means no microphone for this attachment, which is a complete
    // answer: the output direction does not depend on it.
    let Some(fifo) = fifo else {
        return Ok(());
    };
    if !has_object(mainloop, context, Object::Source, MIC_SOURCE)? {
        load_module(mainloop, context, "module-pipe-source", &pipe_source_args(fifo))?;
        tracing::info!(source = MIC_SOURCE, fifo = %fifo.display(), "[audio-capture] created this session's microphone");
    }
    set_default(mainloop, context, Object::Source, MIC_SOURCE)?;
    Ok(())
}

/// Arguments for the null sink this session's desktop plays into.
///
/// At [`SAMPLE_RATE`] deliberately: the sink runs at the rate the capture
/// spec asks for, so nothing in the daemon resamples on the way to us.
fn null_sink_args() -> String {
    format!("sink_name={SINK} rate={SAMPLE_RATE} channels={CHANNELS} sink_properties=device.description=LinRDP_Audio")
}

/// Arguments for the pipe source the client's microphone is written into.
///
/// The module creates the FIFO itself, under the session's own runtime dir —
/// which the keeper has already made and handed to the session owner, so the
/// daemon can create a file there while the worker can write to it.
fn pipe_source_args(fifo: &Path) -> String {
    format!(
        "source_name={MIC_SOURCE} file={} format=s16le rate={SAMPLE_RATE} channels={CHANNELS}",
        fifo.display()
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Object {
    Sink,
    Source,
}

/// Whether the daemon already has this object, by name.
fn has_object(mainloop: &mut PaMainloop, context: &PaContext, kind: Object, name: &str) -> anyhow::Result<bool> {
    let found = Rc::new(RefCell::new(false));
    let wanted = name.to_owned();
    let slot = Rc::clone(&found);
    let record = move |seen: Option<&str>| {
        if seen == Some(wanted.as_str()) {
            *slot.borrow_mut() = true;
        }
    };

    let introspect = context.introspect();
    match kind {
        Object::Sink => {
            let op = introspect.get_sink_info_list(move |result| {
                if let pulse::callbacks::ListResult::Item(info) = result {
                    record(info.name.as_deref());
                }
            });
            pump(mainloop, &op, "list the sinks")?;
        }
        Object::Source => {
            let op = introspect.get_source_info_list(move |result| {
                if let pulse::callbacks::ListResult::Item(info) = result {
                    record(info.name.as_deref());
                }
            });
            pump(mainloop, &op, "list the sources")?;
        }
    }
    Ok(*found.borrow())
}

/// Load a module, and fail loudly if the daemon would not have it.
fn load_module(mainloop: &mut PaMainloop, context: &PaContext, module: &str, args: &str) -> anyhow::Result<()> {
    let index = Rc::new(RefCell::new(pulse::def::INVALID_INDEX));
    let slot = Rc::clone(&index);
    let mut introspect = context.introspect();
    let op = introspect.load_module(module, args, move |idx| *slot.borrow_mut() = idx);
    pump(mainloop, &op, module)?;
    if *index.borrow() == pulse::def::INVALID_INDEX {
        anyhow::bail!("the daemon refused {module} ({args})");
    }
    Ok(())
}

/// Make this object the daemon's default, so the desktop's applications use
/// it without being told to.
fn set_default(mainloop: &mut PaMainloop, context: &mut PaContext, kind: Object, name: &str) -> anyhow::Result<()> {
    let ok = Rc::new(RefCell::new(false));
    let slot = Rc::clone(&ok);
    let op = match kind {
        Object::Sink => context.set_default_sink(name, move |done| *slot.borrow_mut() = done),
        Object::Source => context.set_default_source(name, move |done| *slot.borrow_mut() = done),
    };
    pump(mainloop, &op, "set the default device")?;
    if !*ok.borrow() {
        anyhow::bail!("the daemon would not make {name} its default {kind:?}");
    }
    Ok(())
}

/// Drive the mainloop until `op` finishes.
///
/// The standard mainloop is synchronous: an operation submitted to it makes no
/// progress at all unless someone iterates, so every introspection call has to
/// be pumped like this.
fn pump<T: ?Sized>(
    mainloop: &mut PaMainloop,
    op: &pulse::operation::Operation<T>,
    what: &str,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + ATTACH_TIMEOUT;
    loop {
        match op.get_state() {
            pulse::operation::State::Done => return Ok(()),
            pulse::operation::State::Cancelled => anyhow::bail!("{what}: the daemon cancelled the request"),
            pulse::operation::State::Running => {}
        }
        if Instant::now() >= deadline {
            anyhow::bail!("{what}: no answer within {ATTACH_TIMEOUT:?}");
        }
        iterate(mainloop, what)?;
    }
}

/// One mainloop turn, with the two failure results treated as failures.
///
/// Idle turns sleep for a millisecond. The streaming loop below deliberately
/// does not use this — it is paced by its own 40 ms chunk clock — but the
/// attach path would otherwise spin a core while waiting on the daemon.
fn iterate(mainloop: &mut PaMainloop, what: &str) -> anyhow::Result<()> {
    match mainloop.iterate(false) {
        pulse::mainloop::standard::IterateResult::Success(dispatched) => {
            if dispatched == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        }
        pulse::mainloop::standard::IterateResult::Quit(retval) => {
            anyhow::bail!("{what}: the mainloop quit ({retval:?})")
        }
        pulse::mainloop::standard::IterateResult::Err(e) => anyhow::bail!("{what}: mainloop error: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sink is created at the rate the capture spec asks for, so the
    /// daemon has nothing to resample between the desktop and the wire.
    #[test]
    fn the_sink_is_created_at_the_capture_rate() {
        let args = null_sink_args();

        assert!(args.contains("sink_name=linrdp_audio"), "got {args}");
        assert!(args.contains(&format!("rate={SAMPLE_RATE}")), "got {args}");
    }

    /// The microphone FIFO comes from the session that is being served. The
    /// path used to be the literal `/run/user/1000/linrdp/mic.fifo` for every
    /// session on the host, so this is the regression guard for that bug.
    #[test]
    fn the_microphone_reads_the_sessions_own_fifo() {
        let args = pipe_source_args(Path::new("/run/user/1002/linrdp/mic.fifo"));

        assert!(args.contains("file=/run/user/1002/linrdp/mic.fifo"), "got {args}");
        assert!(
            !args.contains("/run/user/1000"),
            "a session's microphone must never read another user's FIFO: {args}"
        );
    }

    /// Two sessions describe two different FIFOs, from nothing but their own
    /// runtime dirs.
    #[test]
    fn two_sessions_describe_two_microphones() {
        let one = pipe_source_args(Path::new("/run/user/1002/linrdp/mic.fifo"));
        let two = pipe_source_args(Path::new("/run/user/1003/linrdp/mic.fifo"));

        assert_ne!(one, two);
    }

    /// A session with no sound server is told so by name. libpulse calls a
    /// missing socket `Access denied` — the same words as a rejected cookie —
    /// and that single misleading word cost a long investigation.
    #[test]
    fn a_session_without_a_daemon_is_told_which_socket_is_missing() {
        let target = crate::session::gate::AudioTarget::for_test("/run/user/1002", "/home/rdptest");

        let message = no_daemon(&target);
        assert!(message.contains("/run/user/1002/pulse/native"), "got {message}");
        assert!(!message.contains("ConditionUser"), "only root gets that: {message}");
    }

    /// A root desktop has no audio to capture and never will: systemd's
    /// `pulseaudio.socket` declines to start for uid 0. That is worth saying
    /// outright, so nobody reads it as a fault in this code.
    #[test]
    fn a_root_session_is_told_why_it_will_never_have_audio() {
        let target = crate::session::gate::AudioTarget::for_test("/run/user/0", "/root");

        let message = no_daemon(&target);
        assert!(message.contains("ConditionUser=!root"), "got {message}");
        assert!(message.contains("ordinary account"), "got {message}");
    }

    /// An unarmed worker keeps the ambient daemon, which is what
    /// single-session and console-mode deployments have always used.
    #[test]
    fn an_unarmed_worker_attaches_to_the_ambient_daemon() {
        assert!(!crate::session::gate::is_armed(), "default state is unarmed");
        assert!(matches!(attach_point(), Attach::Ambient));
    }
}

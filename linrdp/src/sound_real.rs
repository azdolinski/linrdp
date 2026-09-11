//! Real audio output: captures Linux session audio via PulseAudio (monitor
//! of `linrdp_sink`) and streams Wave PDUs to the RDP client through
//! MS-RDPSND — the same role a Windows session server plays (MS-RDPSND
//! server captures the session mixer and sends Wave PDUs).
//!
//! Uses `libpulse-binding` — safe Rust binding to the libpulse shared
//! library already present on the system. No external binaries.

use core::time::Duration;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicIsize, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ironrdp_rdpsnd::pdu::{AudioFormat, WaveFormat};
use ironrdp_rdpsnd::server::{NegotiatedFormat, RdpsndError};
use ironrdp_server::{RdpsndServerHandler, RdpsndServerMessage, ServerEvent, ServerEventSender, SoundServerFactory};
use tokio::sync::mpsc::UnboundedSender;

const SAMPLE_RATE: u32 = 48000;
const CHANNELS: u16 = 2;
const CHUNK_MS: u64 = 40;
const CHUNK_BYTES: usize = SAMPLE_RATE as usize / 1000 * CHUNK_MS as usize * 4; // 40ms stereo s16le
// ~320 ms of audio; drop backlog beyond that so latency can never grow
// unbounded between the PA monitor and the sender
const MAX_QUEUE: usize = 8;
// Opus frame of 40 ms @ 48 kHz stereo = 1920 samples/frame
const OPUS_FRAME_SAMPLES: usize = SAMPLE_RATE as usize / 1000 * CHUNK_MS as usize;
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
        std::thread::spawn(move || {
            let _ = capture_thread(tx, Arc::clone(&stop));
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

fn capture_thread(tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>, stop: Shared<bool>) -> anyhow::Result<()> {
    use libpulse_binding as pulse;
    use pulse::context::Context;
    use pulse::context::FlagSet;
    use pulse::mainloop::standard::Mainloop;
    use pulse::sample::Format;
    use pulse::stream::{self, FlagSet as StreamFlags};
    use std::sync::atomic::Ordering;

    let mut mainloop = Mainloop::new().ok_or_else(|| anyhow::anyhow!("pulse mainloop"))?;
    let mut context = Context::new(&mainloop, "linrdp-capture")
        .ok_or_else(|| anyhow::anyhow!("pulse context"))?;
    context
        .connect(None, FlagSet::NOFLAGS, None)
        .map_err(|e| anyhow::anyhow!("pulse context connect: {e}"))?;
    context.set_state_callback(Some(Box::new(|| {})));

    loop {
        match context.get_state() {
            pulse::context::State::Ready => break,
            pulse::context::State::Failed | pulse::context::State::Terminated => {
                anyhow::bail!("pulse context failed");
            }
            _ => {}
        }
        if stop.lock().map(|g| *g).unwrap_or(true) {
            return Ok(());
        }
        mainloop.iterate(false);
    }

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
    stream
        .connect_record(
            Some("linrdp_sink.monitor"),
            Some(&buffer_attr),
            StreamFlags::START_UNMUTED | StreamFlags::ADJUST_LATENCY,
        )
        .map_err(|e| anyhow::anyhow!("connect record: {e}"))?;
    stream.set_read_callback(Some(Box::new(|_bytes: usize| {})));
    stream.set_state_callback(Some(Box::new(|| {})));

    loop {
        match stream.get_state() {
            pulse::stream::State::Ready => break,
            pulse::stream::State::Failed | pulse::stream::State::Terminated => {
                anyhow::bail!("pulse stream failed");
            }
            _ => {}
        }
        if stop.lock().map(|g| *g).unwrap_or(true) {
            return Ok(());
        }
        mainloop.iterate(false);
    }

    tracing::info!("[audio-capture] stream ready — continuous capture started");
    let mut backlog: VecDeque<u8> = VecDeque::new();

    // CONTINUOUS capture: iterate mainloop → peek data → send to client.
    // If PA returns silence (no app playing), also send a test tone so the
    // user can confirm the RDPSND → client audio path works.
    let mut logged = false;
    let mut iteration: u64 = 0;
    let mut phase: f32 = 0.0;
    let mut last_send = std::time::Instant::now();
    loop {
        iteration += 1;
        if iteration <= 10 || iteration % 100 == 0 {
            tracing::debug!(iteration, "capture loop alive");
        }
        let stop_requested = stop.lock().map(|g| *g).unwrap_or(false);
        if stop_requested {
            tracing::info!(iteration, "capture loop: stop requested");
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

        // Test tone removed — production mode captures real audio only.
        // The 880 Hz beep was for initial channel verification.
        let _ = phase;

        // Pace: wait until 40ms has passed since last send.
        let elapsed = last_send.elapsed();
        if elapsed < Duration::from_millis(CHUNK_MS) {
            std::thread::sleep(Duration::from_millis(CHUNK_MS) - elapsed);
        }

        if chunk.is_empty() {
            continue;
        }
        last_send = std::time::Instant::now();

        if !logged {
            logged = true;
            tracing::info!("[audio-capture] streaming audio to client");
        }
        let _ = tx.send(chunk);
    }

    stream.disconnect().ok();
    context.disconnect();
    tracing::info!("[audio-capture] capture thread finished");
    Ok(())
}

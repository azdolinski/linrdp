//! EGFX-driven display backend (MS-RDPEGFX, the modern Windows RDP graphics
//! pipeline).
//!
//! While the client has the graphics dynamic virtual channel negotiated, this
//! backend consumes every screen grab itself and sends frames over EGFX:
//!
//! - first paint / after a resize: a full-surface **ClearCodec** frame — a
//!   mandatory-lossless EGFX codec, exactly the "crisp text" path Windows
//!   uses for static content;
//! - small damage (typing, cursor, UI): a lossless ClearCodec rectangle;
//! - large damage (video, scrolling): a full-frame **H.264 AVC420** encode
//!   (OpenH264 in `ScreenContentRealTime` mode, quality rate control).
//!
//! If the channel is not negotiated (older clients, macOS Microsoft Remote
//! Desktop), or it goes down mid-session, the loop transparently falls back
//! to yielding legacy bitmap updates, which the server encodes with
//! RemoteFX/NSCodec as before.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ironrdp_egfx::pdu::{Avc420Region, PixelFormat};
use ironrdp_egfx::server::GraphicsPipelineServer;
use ironrdp_graphics::clearcodec::ClearCodecEncoder;
use ironrdp_pdu::geometry::ExclusiveRectangle;
use ironrdp_server::{
    DesktopSize, DisplayUpdate, LargePointer, RdpServerDisplay, RdpServerDisplayUpdates,
    RGBAPointer, ServerResult,
};
use openh264::encoder::{
    BitRate, Encoder as OpenH264, EncoderConfig, FrameRate, RateControlMode, UsageType, VuiConfig,
};

use crate::capture::{CursorImage, Grab, ScreenGrabber, X11Display, POLL_INTERVAL, RESIZE_SETTLE};
use crate::gfx::GfxSession;

type GfxHandle = Arc<Mutex<GraphicsPipelineServer>>;

/// Damage covering more than this fraction of the screen counts as motion
/// and goes through H.264 instead of lossless ClearCodec.
const MOTION_DENOM: usize = 4;

/// Minimum spacing between H.264 encodes (~30 fps); the encoder is by far
/// the most expensive step, and more than 30 fps of 4:2:0 video is wasted on
/// an RDP link anyway.
const H264_MIN_INTERVAL: Duration = Duration::from_millis(33);

/// Hard ceiling for one X11 grab (screen read + tile diff). A frozen X
/// server never errors — it just never replies — so silence past this means
/// the connection is dead weight: the grab task is abandoned and a fresh
/// connection replaces it.
const GRAB_TIMEOUT: Duration = Duration::from_secs(3);

/// Hard ceiling for connecting a replacement grabber, same rationale as
/// [`GRAB_TIMEOUT`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Hard ceiling for processing one grab (encode + queue + drain). Whatever
/// wedges inside — encoder deadlock, a lock held across a stuck writer — the
/// loop resets its codec state and keeps running instead of freezing the
/// display forever (seen as a "static screenshot" session, followed by a
/// black-screen session once a new client connects and gets no frames).
const FRAME_PROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// After a client caps re-advertise (mstsc decoder reset), hold frames this
/// long before the full repaint: the client is tearing down and rebuilding
/// its whole EGFX pipeline and cannot consume frames until it settles.
const CAPS_SETTLE: Duration = Duration::from_millis(250);

/// How long to wait for a graphics-capable client to open its EGFX channel
/// before concluding the client cannot do EGFX at all and starting legacy
/// bitmap updates. Graphics clients negotiate well inside this window;
/// sending bitmap updates earlier mixes update streams during mstsc's
/// pipeline negotiation and costs the first session of every process
/// lifetime its composition (the "first connection is black" bug).
const LEGACY_GRACE: Duration = Duration::from_millis(1500);

/// H.264 encoder ceiling. The adaptive target below stays at or under the
/// resolution anchor (7.5 Mbit/s at 4K); this only bounds pathological frames.
/// (Kept as an absolute last-resort clamp for the rate controller.)
const H264_BITRATE_CEILING_BPS: u32 = 12_000_000;

/// Re-evaluate the adaptive encoder quality at most this often (KRdp:
/// `QualityUpdateInterval`). Each evaluation loads two atomics and at most
/// rebuilds the encoder, so the throttle also bounds encoder churn.
const QUALITY_UPDATE_INTERVAL: Duration = Duration::from_millis(1500);

/// Adaptive-quality bounds and step sizes (KRdp: MinAdaptiveQuality,
/// QualityStepUp, QualityStepDown). Quality moves down faster than up, so a
/// degrading link sheds bitrate quickly and re-gains it cautiously.
const MIN_ADAPTIVE_QUALITY: i32 = 10;
const QUALITY_STEP_UP: i32 = 5;
const QUALITY_STEP_DOWN: i32 = 10;

/// "Quality 100" H.264 bitrate targets by resolution — KRdp's
/// `FullQualityBitrateAnchors` (RustDesk's `base_bitrate`): kilobits per
/// second for a given pixel count, linearly scaled between the nearest
/// anchors. The adaptive encoder target is this anchor scaled by the
/// measured-goodput quality ratio, so a fast LAN converges to the anchor and
/// a slow link steps down instead of filling client queues.
const BITRATE_ANCHORS: [(f64, f64); 4] = [
    (921_600.0, 1_500.0),   // 1280x720
    (2_073_600.0, 3_110.0), // 1920x1080
    (3_686_400.0, 4_500.0), // 2560x1440
    (8_294_400.0, 7_500.0), // 3840x2160
];

/// Full-quality bitrate anchor (kbit/s) for a screen of `pixels` pixels.
fn full_quality_kbit(pixels: f64) -> f64 {
    let (anchor_px, anchor_kbit) = BITRATE_ANCHORS
        .iter()
        .copied()
        .min_by(|a, b| (a.0 - pixels).abs().total_cmp(&(b.0 - pixels).abs()))
        .expect("anchor table is non-empty");
    anchor_kbit * (pixels / anchor_px)
}

/// ClearCodec rectangles above this pixel count go through H.264 instead —
/// encoding a huge lossless rect costs more than it is worth.
const CLEAR_MAX_PIXELS: usize = 2_500_000;

/// After the last motion frame, keep the display in "motion mode" this
/// long: while active, small lossless ClearCodec updates are suppressed so
/// static UI does not flip-flop between the lossless and the (inherently
/// lossy 4:2:0) H.264 looks — the visible "pulsing". When the window
/// lapses, one full lossless repaint snaps the whole screen crisp again,
/// mirroring how Windows RDP presents video regions.
const MOTION_LINGER: Duration = Duration::from_millis(250);

/// Cursor shape poll interval (XFixes GetCursorImage). Shape changes are
/// rare; position is not tracked at all (clients draw their own pointer).
const CURSOR_POLL_INTERVAL: Duration = Duration::from_millis(128);

/// How often the in-flight window is recomputed from the latest RTT and
/// producer rate. Both inputs move slower than frame rate; re-locking the
/// pipeline mutex on every frame is wasted work.
const WINDOW_UPDATE_INTERVAL: Duration = Duration::from_millis(500);

/// In-flight window floor — also the bootstrap value before any RTT
/// measurement lands (matches the EGFX server's own default).
const MIN_IN_FLIGHT: u32 = 3;

/// The window spans this many round trips of produced frames
/// (bandwidth-delay product gain).
const IN_FLIGHT_GAIN: f64 = 1.0;

/// Never buffer more than this many seconds of video, however large the
/// bandwidth-delay product is (upper bound: ceil(fps × budget)).
const LATENCY_BUDGET_SEC: f64 = 1.0;

/// Floor for the producer-rate estimate feeding window sizing — below this
/// the estimate degenerates toward stop-and-wait.
const MIN_PRODUCER_FPS: f64 = 5.0;

/// Ceiling for the producer-rate estimate (the capture loop polls at ~60 Hz).
const MAX_PRODUCER_FPS: f64 = 60.0;

/// EWMA smoothing factors, mirroring KRdp's VideoStream: the producer rate
/// is smoothed at 0.25, the (already windowed) RTT a second time at 0.125 so
/// transient spikes do not immediately inflate the submission window.
const PRODUCER_FPS_ALPHA: f64 = 0.25;
const RTT_ALPHA: f64 = 0.125;

/// RTT samples outside this range are ignored as implausible (probe noise,
/// u32::MAX sentinel) rather than corrupting the window size.
const MIN_VALID_RTT_MS: f64 = 5.0;
const MAX_VALID_RTT_MS: f64 = 60_000.0;

/// CPU-heavy encoders, moved in and out of `spawn_blocking` per frame.
struct Encoders {
    h264: Option<OpenH264>,
    clear: ClearCodecEncoder,
}

/// Active EGFX surface state.
#[derive(Clone, Copy)]
struct SurfaceState {
    id: u16,
    width: u16,
    height: u16,
    pad_width: u16,
    pad_height: u16,
}

/// One per-session frame producer (X11 grabber, PipeWire stream, ...).
///
/// `poll_and_cursor` runs inside `spawn_blocking`; a source Box that is lost
/// with an abandoned blocking task is simply rebuilt by the factory
/// (`try_attach` / [`DisplaySourceFactory::updates_source`]).
pub(crate) trait FrameSource: Send + 'static {    /// Poll for a frame (plus the cursor sprite when `cursor_due`).
    /// `None` = nothing this tick — the caller retries.
    fn poll_and_cursor(&mut self, cursor_due: bool) -> Option<(Grab, Option<CursorImage>)>;
    /// Best-effort (re)attach attempt when detached; throttled by the caller.
    fn try_attach(&mut self) {}
    /// Whether a poll can currently produce frames.
    fn is_attached(&self) -> bool {
        true
    }
    /// Log-friendly source identifier (display name, stream node, ...).
    fn name(&self) -> &str;
    /// While in the future: the source just changed geometry and frames
    /// should be held until it settles (WM re-layout after a RandR resize,
    /// a PipeWire format change).
    fn settle_until(&self) -> Instant {
        Instant::now()
    }
}

/// Process-wide frame-source factory: answers display-size negotiation for
/// new connections and mints per-session [`FrameSource`]s.
pub(crate) trait DisplaySourceFactory: Send + Sync + 'static {
    fn size(&self) -> DesktopSize;
    fn request_initial_size(&self, client_size: DesktopSize) -> DesktopSize;
    fn request_layout(&self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout);
    fn updates_source(&self) -> Box<dyn FrameSource>;
}

/// Display backend that routes frames over EGFX when available.
pub(crate) struct EgfxDisplay {
    factory: Arc<dyn DisplaySourceFactory>,
    session: Arc<GfxSession>,
    suppressed: Arc<AtomicBool>,
    /// Latest auto-detect RTT (ms) and session-minimum RTT (ms), shared with
    /// the server's probe loop — feeds the in-flight window sizing.
    rtt: Arc<AtomicU32>,
    rtt_baseline: Arc<AtomicU32>,
    /// Latest auto-detect bandwidth (kbit/s; `u32::MAX` = not yet measured),
    /// shared with the server's Bandwidth Measure loop — feeds the adaptive
    /// encoder quality.
    bw_kbps: Arc<AtomicU32>,
    /// Client's negotiated `pointerCacheSize` — bounds the cursor LRU.
    pointer_cache: Arc<AtomicU16>,
}

impl EgfxDisplay {
    pub(crate) fn new(
        factory: Arc<dyn DisplaySourceFactory>,
        session: Arc<GfxSession>,
        suppressed: Arc<AtomicBool>,
        rtt: Arc<AtomicU32>,
        rtt_baseline: Arc<AtomicU32>,
        bw_kbps: Arc<AtomicU32>,
        pointer_cache: Arc<AtomicU16>,
    ) -> Self {
        Self {
            factory,
            session,
            suppressed,
            rtt,
            rtt_baseline,
            bw_kbps,
            pointer_cache,
        }
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for EgfxDisplay {
    async fn size(&mut self) -> DesktopSize {
        self.factory.size()
    }

    async fn request_initial_size(&mut self, client_size: DesktopSize) -> DesktopSize {
        self.factory.request_initial_size(client_size)
    }

    fn request_layout(&mut self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
        self.factory.request_layout(layout)
    }

    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        let source = self.factory.updates_source();
        let settle_until = source.settle_until();
        Ok(Box::new(EgfxUpdates {
            factory: Arc::clone(&self.factory),
            source: Some(source),
            pending_grab: None,
            session: Arc::clone(&self.session),
            suppressed: Arc::clone(&self.suppressed),
            encoders: None,
            surface: None,
            generation: None,
            last_h264: Instant::now() - H264_MIN_INTERVAL,
            pending_full: true,
            in_motion: false,
            motion_until: Instant::now(),
            caps_reset_until: Instant::now(),
            egfx_latched: false,
            legacy_grace_until: Instant::now() + LEGACY_GRACE,
            settle_until,
            last_attach_attempt: Instant::now() - Duration::from_secs(1),
            hb_polls: 0,
            hb_damaged: 0,
            hb_last: Instant::now(),
            avc_disabled: false,
            started: Instant::now(),
            stat_frames: 0,
            stat_h264: 0,
            stat_clear: 0,
            stat_bytes: 0,
            stat_last: Instant::now(),
            rtt: Arc::clone(&self.rtt),
            rtt_baseline: Arc::clone(&self.rtt_baseline),
            bw_kbps: Arc::clone(&self.bw_kbps),
            pointer_cache: Arc::clone(&self.pointer_cache),
            cursor_cache: HashMap::new(),
            cursor_next_index: 0,
            cursor_last_hash: None,
            cursor_last_poll: Instant::now(),
            pending_cursor: None,
            producer_frames: 0,
            producer_mark: None,
            producer_fps: MIN_PRODUCER_FPS,
            rtt_ewma: None,
            window_applied: None,
            window_last_check: Instant::now(),
            quality: 100,
            // First evaluation can run as soon as the first measurement lands.
            last_quality_update: Instant::now() - QUALITY_UPDATE_INTERVAL,
            enc_bitrate_bps: None,
        }))
    }
}

struct EgfxUpdates {
    factory: Arc<dyn DisplaySourceFactory>,
    /// The per-session frame source; `None` while a source lost with an
    /// abandoned blocking task is awaited (rebuilt from the factory,
    /// throttled by `last_attach_attempt`) or while a prefetched grab runs
    /// (the source travels inside that task, see [`PendingGrab`]).
    source: Option<Box<dyn FrameSource>>,
    /// The in-flight prefetch grab, if any. At most one poll runs at a time;
    /// it is started before the previous frame is processed so capture
    /// overlaps encoding instead of serializing behind it.
    pending_grab: Option<PendingGrab>,
    session: Arc<GfxSession>,
    suppressed: Arc<AtomicBool>,
    /// Taken out per frame for `spawn_blocking`; re-created if a blocking
    /// task ever fails to join (codec state is then simply rebuilt).
    encoders: Option<Encoders>,
    surface: Option<SurfaceState>,
    /// The connection generation the surface belongs to; a pointer change
    /// means a new client attached and the surface must be re-created.
    generation: Option<GfxHandle>,
    last_h264: Instant,
    /// A full-surface send is owed (first paint, resize, skipped frame) —
    /// partial lossless updates are blocked until it is cleared, or pixels
    /// from the skipped frame could stay stale forever.
    pending_full: bool,
    /// Motion-mode state: H.264 frames were sent recently. While active,
    /// lossless partials are suppressed (they make static UI alternate
    /// between exact and 4:2:0-lossy colors — the user-visible pulse).
    in_motion: bool,
    motion_until: Instant,
    /// While set, the client just re-advertised caps (pipeline reset) and
    /// frames are held until it settles.
    caps_reset_until: Instant,
    /// While set, the X screen was just resized and the desktop (WM
    /// re-layout, wallpaper) is still churning — frames are held until it
    /// settles, then one full lossless repaint goes out. Resolution-
    /// independent: taken from the display after request_initial_size.
    settle_until: Instant,
    /// Once a session has used EGFX, never fall back to legacy bitmap
    /// updates (a client decoder reset briefly clears `ready`).
    egfx_latched: bool,
    /// Legacy bitmap updates are allowed only after this much session time
    /// with no graphics channel ever opened — see the comment at the
    /// handle check in `next_update`.
    legacy_grace_until: Instant,
    /// Throttle for (re)attaching a missing source.
    last_attach_attempt: Instant,
    /// Heartbeat counters: make a stalled loop (no damage, wedged grab,
    /// stuck suppress) visible in the logs instead of silent.
    hb_polls: u64,
    hb_damaged: u64,
    hb_last: Instant,
    /// Client negotiated EGFX without AVC (AVC_DISABLED), or the H.264
    /// encoder failed to initialize — lossless ClearCodec only.
    avc_disabled: bool,
    started: Instant,
    stat_frames: u64,
    stat_h264: u64,
    stat_clear: u64,
    stat_bytes: u64,
    stat_last: Instant,
    /// Latest auto-detect RTT (ms, `u32::MAX` sentinel = not yet measured)
    /// and the session-minimum RTT, shared with the server's probe loop.
    rtt: Arc<AtomicU32>,
    rtt_baseline: Arc<AtomicU32>,
    /// Latest auto-detect bandwidth in kbit/s (`u32::MAX` = not yet measured),
    /// shared with the server's Bandwidth Measure loop.
    bw_kbps: Arc<AtomicU32>,
    /// Client's negotiated `pointerCacheSize` — bounds the cursor LRU. Zero
    /// means the client cannot receive New Pointer updates at all.
    pointer_cache: Arc<AtomicU16>,
    /// Adaptive encoder quality, 10..=100 (KRdp semantics): the H.264 target
    /// bitrate is the resolution anchor scaled by this. Starts at 100 so the
    /// first frames go out at full anchor bitrate before any measurement.
    quality: u8,
    last_quality_update: Instant,
    /// Bitrate the running H.264 encoder was built with; `None` until the
    /// first motion frame creates one. Drives rebuild-on-change hysteresis.
    enc_bitrate_bps: Option<u32>,
    /// Cursor shape cache: shape hash → cache slot. Bounded by the client's
    /// negotiated pointer cache size; LRU eviction frees a slot on overflow.
    cursor_cache: HashMap<u64, CursorCacheEntry>,
    cursor_next_index: u16,
    /// Hash of the cursor shape currently shown to the client (skip
    /// re-sending the same sprite every poll).
    cursor_last_hash: Option<u64>,
    cursor_last_poll: Instant,
    /// A cursor update waiting to be yielded to the server encoder. Cursor
    /// changes are independent of screen damage and must not swallow a
    /// damaged grab, so they are stashed and returned on a tick without
    /// pending frame work.
    pending_cursor: Option<DisplayUpdate>,
    /// Frames delivered into the EGFX pipeline — the producer-rate signal
    /// for in-flight window sizing. Measured upstream of the window so the
    /// estimate cannot feed back into itself.
    producer_frames: u64,
    /// `(when, producer_frames)` at the last rate evaluation.
    producer_mark: Option<(Instant, u64)>,
    /// EWMA of the frame production rate (fps), clamped to
    /// [`MIN_PRODUCER_FPS`, [`MAX_PRODUCER_FPS`]].
    producer_fps: f64,
    /// Second-stage EWMA of the windowed RTT (the auto-detect handle already
    /// smooths per-sample); `None` until the first valid sample.
    rtt_ewma: Option<f64>,
    /// Last window value actually applied to the pipeline server.
    window_applied: Option<u32>,
    window_last_check: Instant,
}

/// One cached cursor shape (MS-RDPBCGR pointer cache slot).
struct CursorCacheEntry {
    cache_index: u16,
    last_used: Instant,
}

/// A grab poll in flight — the one-frame prefetch that pipelines capture
/// against encoding: the next X11/PipeWire poll runs in a blocking task while
/// the previous grab is being converted and encoded. The frame source lives
/// inside the task until the poll completes, so `EgfxUpdates::source` is
/// `None` for the duration (`try_consume_grab` puts it back).
struct PendingGrab {
    handle: tokio::task::JoinHandle<(Box<dyn FrameSource>, Option<(Grab, Option<CursorImage>)>)>,
    started: Instant,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for EgfxUpdates {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;

            // Client minimized (Suppress Output): skip emission entirely.
            if self.suppressed.load(Ordering::Relaxed) {
                continue;
            }

            let cursor_due = self.cursor_last_poll.elapsed() >= CURSOR_POLL_INTERVAL;
            if cursor_due {
                self.cursor_last_poll = Instant::now();
            }

            // Producer backpressure (KRdp pauses its encoder; our poll loop
            // IS the producer): while the EGFX pipeline reports the client
            // behind, skip the expensive part — the YUV conversion and encode
            // — not just the send. No new grab is started either; whatever
            // landed already updated the damage baseline, so `pending_full`
            // makes a later full repaint deliver those pixels.
            if let Some(handle) = self.session.handle() {
                if self.session.ready()
                    && Self::lock_handle(&handle).should_backpressure()
                {
                    self.pending_full = true;
                    continue;
                }
            }

            // Start the next capture before consuming the previous grab: the
            // poll (GetImage + tile diff) runs concurrently with the previous
            // frame's YUV conversion + encode instead of serializing behind
            // it. Per-frame cost drops from grab+encode to ~max(encode, grab).
            self.maybe_start_grab(cursor_due);

            let Some((grab, cursor)) = self.try_consume_grab().await else {
                // Prefetch still running — a stashed cursor update can go out now.
                if let Some(update) = self.pending_cursor.take() {
                    return Ok(Some(update));
                }
                continue;
            };

            if let Some(cursor) = cursor {
                if let Some(update) = self.cursor_update(cursor) {
                    self.pending_cursor = Some(update);
                }
            }

            // First-session hole: a graphics-capable client opens its EGFX
            // channel a few hundred milliseconds into the session, and the
            // process-global GfxSession still holds NO handle until then (on
            // every later session the previous handle is already present).
            // Emitting legacy bitmap updates into that window mixes update
            // streams while mstsc negotiates the graphics pipeline — it stops
            // composing (black screen) although every EGFX frame decodes
            // fine. Hold everything for a short grace; if no channel ever
            // opens, the client genuinely cannot do EGFX and legacy starts.
            let legacy_allowed = self.session.handle().is_none()
                && Instant::now() >= self.legacy_grace_until;

            let Some(handle) = self.session.handle() else {
                // Grace passed and still no graphics channel: legacy path.
                debug_assert!(legacy_allowed);
                if let Some(update) = grab.legacy_display_update() {
                    return Ok(Some(update));
                }
                if let Some(update) = self.pending_cursor.take() {
                    return Ok(Some(update));
                }
                continue;
            };

            let egfx_active = {
                let server = Self::lock_handle(&handle);
                self.session.ready() && server.is_ready()
            };
            if egfx_active {
                // This session is on the graphics pipeline. Latch it: when
                // the client re-opens the graphics channel (decoder reset),
                // the factory briefly clears `ready` and swaps the handle —
                // falling back to legacy bitmap updates in that window mixes
                // two update streams in one session, which mstsc rejects
                // outright (protocol error). The EGFX path rides out the
                // swap via the generation check instead.
                self.egfx_latched = true;
            } else if self.egfx_latched {
                if let Some(update) = self.pending_cursor.take() {
                    return Ok(Some(update));
                }
                continue;
            } else {
                // The graphics channel exists but caps have not landed yet:
                // this client IS graphics-capable, so never send legacy
                // bitmap updates — hold until negotiation completes (the
                // same stream-mixing hazard as above, in the first session's
                // pre-ready window).
                if let Some(update) = self.pending_cursor.take() {
                    return Ok(Some(update));
                }
                continue;
            }

            // Bounded processing: a wedged encoder or a lock held across a
            // stuck writer must not freeze the whole display pipeline — the
            // session would show one last static frame forever, and every
            // later client would connect to a dead loop (black screen).
            // Dropping the future abandons whatever blocked; codec state is
            // rebuilt next frame.
            let frame_done = tokio::time::timeout(FRAME_PROCESS_TIMEOUT, self.egfx_frame(&handle, grab))
                .await
                .is_ok();
            if !frame_done {
                tracing::error!(
                    process_timeout = ?FRAME_PROCESS_TIMEOUT,
                    "EGFX frame processing stalled — resetting encoders and motion state"
                );
                self.encoders = None;
                self.in_motion = false;
                self.pending_full = true;
            }

            // Size the in-flight window from the bandwidth-delay product:
            // enough produced frames to fill one round trip, so high-RTT
            // links keep flowing instead of collapsing to stop-and-wait.
            self.update_in_flight_window(&handle);

            // Steer the H.264 encoder from the measured goodput (KRdp's
            // updateAdaptiveQuality): internally throttled to its own interval.
            self.update_adaptive_quality();

            // A processed tick that did not produce a returnable display
            // update is the natural moment to hand a stashed cursor update
            // to the encoder.
            if let Some(update) = self.pending_cursor.take() {
                return Ok(Some(update));
            }
        }
    }
}

impl EgfxUpdates {
    /// Kick off the next capture poll unless one is already in flight.
    ///
    /// The poll runs in a blocking task and its result is picked up by
    /// [`Self::try_consume_grab`] on a later tick — that split is what lets
    /// the next GetImage + tile diff overlap the previous frame's conversion
    /// and encode. A poll that exceeds [`GRAB_TIMEOUT`] is abandoned with the
    /// task (the source inside it is lost; the factory rebuilds one, and the
    /// dropped baseline forces a full repaint once frames flow again).
    fn maybe_start_grab(&mut self, cursor_due: bool) {
        match &mut self.pending_grab {
            Some(pending) => {
                if !pending.handle.is_finished() && pending.started.elapsed() > GRAB_TIMEOUT {
                    tracing::warn!(timeout = ?GRAB_TIMEOUT, "frame source poll timed out — abandoning it");
                    // A blocking task cannot be interrupted; dropping the
                    // handle detaches it and the result is discarded.
                    self.pending_grab = None;
                }
                // In flight (or just abandoned this tick — the source rebuild
                // is throttled by `maybe_attach_source` below, next tick).
                return;
            }
            None => {
                if self
                    .source
                    .as_ref()
                    .is_some_and(|s| s.is_attached())
                {
                    // Fast path: poll the live source.
                } else {
                    self.maybe_attach_source();
                    return;
                }
            }
        }
        let mut source = self.source.take().expect("source checked above");
        self.hb_polls += 1;
        let handle = tokio::task::spawn_blocking(move || {
            let polled = source.poll_and_cursor(cursor_due);
            (source, polled)
        });
        self.pending_grab = Some(PendingGrab {
            handle,
            started: Instant::now(),
        });
    }

    /// Consume the prefetched grab once its blocking poll has finished.
    /// `None` = still running (or being rebuilt after a timeout) — retry next
    /// tick; the frame source stays inside the task meanwhile.
    async fn try_consume_grab(&mut self) -> Option<(Grab, Option<CursorImage>)> {
        let pending = self.pending_grab.take()?;
        if !pending.handle.is_finished() {
            self.pending_grab = Some(pending);
            return None;
        }
        match pending.handle.await {
            Ok((source, polled)) => {
                self.hb_damaged += u64::from(polled.as_ref().is_some_and(|(g, _)| g.damage.is_some()));
                let name = source.name().to_owned();
                self.source = Some(source);
                self.heartbeat(&name);
                polled
            }
            Err(join_err) => {
                // The poll panicked: the source was lost with the task, the
                // factory rebuilds one next tick. (A panic in an async task
                // would otherwise kill the display loop silently.)
                tracing::warn!(error = %join_err, "frame source poll panicked — rebuilding source");
                None
            }
        }
    }

    /// Throttled rebuild/reattach of a missing source. One attempt per
    /// second keeps a dead source from turning into a factory storm.
    fn maybe_attach_source(&mut self) {
        if self.last_attach_attempt.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_attach_attempt = Instant::now();
        match self.source.as_mut() {
            Some(source) => source.try_attach(),
            None => {
                let source = self.factory.updates_source();
                tracing::info!(source = source.name(), "frame source rebuilt");
                self.source = Some(source);
            }
        }
    }

    /// Lock the pipeline server, surviving a poisoned mutex: a panic on
    /// another thread must not take the display loop down with it.
    fn lock_handle<'a>(handle: &'a GfxHandle) -> std::sync::MutexGuard<'a, GraphicsPipelineServer> {
        handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Recompute the EGFX in-flight window from the bandwidth-delay product,
    /// KRdp-style: the window holds one round trip of produced frames, so a
    /// high-RTT link keeps frames flowing instead of collapsing to
    /// stop-and-wait. The producer rate is measured upstream of the window
    /// (delivered frame count), the RTT is smoothed a second time here and
    /// floored at the session-minimum so the window never drops below the
    /// path's true BDP, and a latency budget caps it so a fat-but-laggy link
    /// cannot buffer seconds of video.
    fn update_in_flight_window(&mut self, handle: &GfxHandle) {
        if self.window_last_check.elapsed() < WINDOW_UPDATE_INTERVAL {
            return;
        }
        self.window_last_check = Instant::now();

        // Producer-rate EWMA over delivered frames.
        let now = Instant::now();
        let total = self.producer_frames;
        match self.producer_mark {
            None => self.producer_mark = Some((now, total)),
            Some((mark, mark_total)) => {
                let elapsed = now.duration_since(mark).as_secs_f64();
                if elapsed > 0.0 && total > mark_total {
                    let fps = (total - mark_total) as f64 / elapsed;
                    self.producer_fps = self.producer_fps * (1.0 - PRODUCER_FPS_ALPHA) + fps * PRODUCER_FPS_ALPHA;
                }
                // Idle: hold the last active rate rather than shrink toward
                // zero — the window must be usable the instant motion resumes.
                self.producer_mark = Some((now, total));
            }
        }
        let fps = self.producer_fps.clamp(MIN_PRODUCER_FPS, MAX_PRODUCER_FPS);

        let rtt_raw = self.rtt.load(Ordering::Relaxed);
        if rtt_raw == u32::MAX {
            return; // no measurement yet — keep the bootstrap window
        }
        let rtt_ms = f64::from(rtt_raw);
        if !(MIN_VALID_RTT_MS..=MAX_VALID_RTT_MS).contains(&rtt_ms) {
            return; // implausible sample (probe noise), keep the last window
        }

        // Second-stage smoothing + session-minimum floor (base RTT): the
        // floor is what makes high-RTT throughput survive — a window below
        // one BDP collapses to one frame per round trip.
        let smoothed = match self.rtt_ewma {
            None => rtt_ms,
            Some(prev) => prev * (1.0 - RTT_ALPHA) + rtt_ms * RTT_ALPHA,
        };
        self.rtt_ewma = Some(smoothed);
        let baseline_raw = self.rtt_baseline.load(Ordering::Relaxed);
        let baseline = if baseline_raw == u32::MAX {
            rtt_ms
        } else {
            f64::from(baseline_raw)
        };
        let effective_rtt_ms = smoothed.max(baseline);

        let bdp = (fps * effective_rtt_ms / 1000.0 * IN_FLIGHT_GAIN).ceil();
        let cap = (fps * LATENCY_BUDGET_SEC).ceil().max(f64::from(MIN_IN_FLIGHT));
        let window = bdp.clamp(f64::from(MIN_IN_FLIGHT), cap);
        // Precision guard: u32 cast is safe, values are bounded by the cap.
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "clamped small range")]
        let window = window as u32;

        if self.window_applied != Some(window) {
            Self::lock_handle(handle).set_max_frames_in_flight(window);
            tracing::debug!(
                window,
                fps,
                rtt_ms = effective_rtt_ms,
                in_flight = self.session.handle().map(|h| Self::lock_handle(&h).frames_in_flight()),
                "EGFX in-flight window resized (BDP)"
            );
            self.window_applied = Some(window);
        }
    }

    /// Turn a captured cursor sprite into a pointer `DisplayUpdate`,
    /// managing the client-side pointer cache (LRU over the negotiated
    /// `pointerCacheSize`). `None` = nothing to send (unchanged shape).
    fn cursor_update(&mut self, cursor: CursorImage) -> Option<DisplayUpdate> {
        let cache_size = self.pointer_cache.load(Ordering::Relaxed);
        if cache_size == 0 {
            // Client cannot receive New Pointer updates; the encoder would
            // drop them anyway. Report once per shape change for the log.
            tracing::debug!("cursor shape changed but client has no pointer cache — skipping");
            self.cursor_last_hash = None;
            return None;
        }

        let hash = cursor.shape_hash();
        if self.cursor_last_hash == Some(hash) {
            return None; // same sprite as on the client
        }
        self.cursor_last_hash = Some(hash);

        // Cache hit: one cheap CachedPointer PDU.
        if let Some(entry) = self.cursor_cache.get_mut(&hash) {
            entry.last_used = Instant::now();
            return Some(DisplayUpdate::CachedPointer(entry.cache_index));
        }

        // RDP cannot transport sprites above 384x384 — fall back to the
        // system default cursor for those (KRdp does the same).
        if cursor.width > 384 || cursor.height > 384 {
            return Some(DisplayUpdate::DefaultPointer);
        }

        // Evict the least recently used slot when the cache is full.
        let cache_index = if u32::from(self.cursor_next_index) < u32::from(cache_size) {
            let idx = self.cursor_next_index;
            self.cursor_next_index += 1;
            idx
        } else {
            match self.cursor_cache.iter().min_by_key(|(_, e)| e.last_used) {
                Some((_, evicted)) => evicted.cache_index,
                None => return None, // zero-size cache reported nonzero: bail
            }
        };

        let update = if cursor.width <= 96 && cursor.height <= 96 {
            DisplayUpdate::RGBAPointer(RGBAPointer {
                cache_index,
                hot_x: cursor.hot_x,
                hot_y: cursor.hot_y,
                width: cursor.width,
                height: cursor.height,
                data: cursor.xor,
            })
        } else {
            DisplayUpdate::LargePointer(LargePointer {
                cache_index,
                hot_x: cursor.hot_x,
                hot_y: cursor.hot_y,
                width: cursor.width,
                height: cursor.height,
                data: cursor.xor,
            })
        };
        self.cursor_cache.insert(
            hash,
            CursorCacheEntry {
                cache_index,
                last_used: Instant::now(),
            },
        );
        Some(update)
    }

    /// Process one grab through the graphics pipeline.
    async fn egfx_frame(&mut self, handle: &GfxHandle, grab: Grab) {
        // New connection or screen resize: re-create the surface.
        let generation_changed = !self.generation.as_ref().is_some_and(|g| Arc::ptr_eq(g, handle));
        let size_changed = !self
            .surface
            .is_some_and(|s| s.width == grab.width && s.height == grab.height);
        if generation_changed || size_changed {
            self.ensure_surface(handle, grab.width, grab.height);
            self.generation = Some(Arc::clone(handle));
            if let Some(Encoders {
                h264: Some(h264), ..
            }) = self.encoders.as_mut()
            {
                h264.force_intra_frame();
            }
            self.pending_full = true;
        }

        // mstsc re-advertises capabilities right after connecting (decoder
        // recovery): the client deletes every surface, but the connection
        // handle is unchanged, so the generation check above does not fire.
        // Frames sent to the vanished surface are dropped by the client —
        // the screen stays black/frozen while our stats look healthy. Detect
        // it by asking the pipeline server whether our surface still exists.
        if let Some(surface) = self.surface {
            let alive = handle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_surface(surface.id)
                .is_some();
            if !alive {
                tracing::warn!(
                    surface = surface.id,
                    "EGFX surface vanished (client re-advertised caps) — re-creating"
                );
                self.surface = None;
                if let Some(Encoders {
                    h264: Some(h264), ..
                }) = self.encoders.as_mut()
                {
                    h264.force_intra_frame();
                }
                self.ensure_surface(handle, grab.width, grab.height);
                self.pending_full = true;
                self.caps_reset_until = Instant::now() + CAPS_SETTLE;
                // Frames pushed during the client's reset are what trip
                // mstsc into "protocol error 0xD06" and an RST (observed: a
                // ~1.1 MB ClearCodec frame right after re-advertised caps).
                return;
            }
        }

        // Backpressure (MS-RDPEGFX 2.2.4.3): the client is behind — skip the
        // frame entirely; the full-frame send that follows covers this grab.
        if handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).should_backpressure() {
            self.pending_full = true;
            return;
        }

        // Client just reset its graphics pipeline (caps re-advertise):
        // hold frames until its decoder rebuild settles.
        if Instant::now() < self.caps_reset_until {
            return;
        }

        // The X screen was resized for this session: the desktop churns for
        // a moment (WM re-layout, wallpaper), and H.264 pushed mid-churn is
        // decoded but never composed by mstsc — the frozen first session.
        // Lossless ClearCodec is safe to send during the churn (the very
        // first paint must go out immediately or the user stares at black),
        // so the settle clamps everything to the lossless path instead of
        // holding frames.
        let settling = Instant::now() < self.settle_until;
        if settling {
            self.in_motion = false;
        }

        let Grab {
            data,
            width,
            height,
            damage,
            changed_tiles,
            total_tiles,
        } = grab;

        // Motion-mode exit: the linger window lapsed — snap the whole
        // screen back to lossless with one full repaint (even with no new
        // damage, the last H.264 frame left everything in 4:2:0 quality).
        if self.in_motion && Instant::now() >= self.motion_until {
            self.in_motion = false;
            self.pending_full = true;
        }

        let Some(damage) = damage else {
            // Nothing changed — unless a full frame is still owed (e.g. a
            // motion frame was skipped and the screen went static right
            // after), in which case paint everything now.
            if self.pending_full {
                self.send_clear(handle, data, width, height, 0, 0, width, height)
                    .await;
            }
            return;
        };

        // Repay the full-paint debt ONLY outside motion mode. Inside it, a
        // rate-limited skip flags pending_full and the next H.264 frame
        // covers the pixels — repaying mid-motion with a lossless repaint
        // alternates the whole screen between exact and 4:2:0 looks at the
        // H.264 cadence (~6.5 Hz), which is exactly the visible flicker.
        if self.pending_full && !self.in_motion {
            self.send_clear(handle, data, width, height, 0, 0, width, height)
                .await;
            return;
        }

        let (dx, dy, dw, dh) = damage;
        // Motion signal = fraction of tiles that actually changed, NOT the
        // bounding box: a blinking cursor in one corner and a clock in the
        // other span the whole screen as a bbox but are ~0.1% of the tiles —
        // bbox-based detection kept such screens in soft H.264 mode forever.
        let motion = !settling
            && (u64::from(changed_tiles) * MOTION_DENOM as u64 > u64::from(total_tiles)
                || u64::from(changed_tiles) * (64 * 64) > CLEAR_MAX_PIXELS as u64);

        if motion && !self.avc_disabled {
            if self.last_h264.elapsed() < H264_MIN_INTERVAL {
                // Skip this encode to hold ~30 fps. The next H.264 frame is
                // a FULL-frame encode, so this grab's content arrives with
                // it — block lossless partials until then.
                self.pending_full = true;
                return;
            }
            self.send_h264(handle, data, width, height).await;
            self.in_motion = true;
            self.motion_until = Instant::now() + MOTION_LINGER;
        } else if self.in_motion {
            // Small damage inside the motion window: suppress the lossless
            // partial. Sending it would flip these pixels to exact colors,
            // only for the next full-frame H.264 to re-lossy them — that
            // alternation is the visible pulse. The next motion frame (or
            // the linger-exit repaint) delivers these pixels consistently.
            self.pending_full = true;
        } else {
            self.send_clear(handle, data, width, height, dx, dy, dw, dh)
                .await;
        }
    }

    /// (Re)create the EGFX surface for the current screen geometry.
    fn ensure_surface(&mut self, handle: &GfxHandle, width: u16, height: u16) {
        let pad_width = width.div_ceil(16) * 16; // H.264 macroblock alignment
        let pad_height = height.div_ceil(16) * 16;
        let mut server = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        if self.surface.is_some() {
            // Mid-session resize: full EGFX reset sequence.
            server.resize(width, height);
        }
        server.set_output_dimensions(width, height);

        self.avc_disabled = !server.supports_avc420();
        if self.avc_disabled {
            tracing::warn!("EGFX: client has AVC disabled — using lossless ClearCodec only");
        }

        let Some(id) = server.create_surface_with_format(pad_width, pad_height, PixelFormat::XRgb) else {
            tracing::warn!("EGFX: surface creation failed — legacy path resumes next frame");
            return;
        };
        server.map_surface_to_output(id, 0, 0);
        self.surface = Some(SurfaceState {
            id,
            width,
            height,
            pad_width,
            pad_height,
        });

        tracing::info!(surface = id, width, height, pad_width, pad_height, "EGFX surface created");
        drop(server);
        self.session.drain_and_send(handle);
    }

    /// Adaptive encoder quality (KRdp's `updateAdaptiveQuality`): map the
    /// measured goodput — the client's Bandwidth Measure Results, refreshed
    /// every ~2 s — onto a target quality 10..=100 relative to a full-quality
    /// bitrate anchor for the current resolution, then step toward it. A fast
    /// link converges to the anchor; a slow link sheds bitrate instead of
    /// filling client queues. Queueing congestion (latest RTT well above the
    /// session minimum) forces quality down and blocks step-ups.
    fn update_adaptive_quality(&mut self) {
        if self.last_quality_update.elapsed() < QUALITY_UPDATE_INTERVAL {
            return;
        }
        let goodput_kbit = self.bw_kbps.load(Ordering::Relaxed);
        if goodput_kbit == 0 || goodput_kbit == u32::MAX {
            return; // no measurement yet — keep the bootstrap full-quality target
        }
        self.last_quality_update = Instant::now();

        let Some(surface) = self.surface else { return };
        let pixels = f64::from(surface.width) * f64::from(surface.height);
        if pixels <= 0.0 {
            return;
        }
        let full_kbit = full_quality_kbit(pixels);

        let mut target = ((f64::from(goodput_kbit) / full_kbit) * 100.0)
            .round()
            .clamp(f64::from(MIN_ADAPTIVE_QUALITY), 100.0) as i32;

        let avg_rtt = self.rtt.load(Ordering::Relaxed);
        let min_rtt = self.rtt_baseline.load(Ordering::Relaxed);
        let congested = min_rtt != u32::MAX
            && avg_rtt != u32::MAX
            && f64::from(avg_rtt) > f64::from(min_rtt) * 1.5;
        if congested {
            // Congested: cap the target below the current quality so the next
            // step is guaranteed to shed load (KRdp clamps the same way).
            target = target
                .min(i32::from(self.quality) - QUALITY_STEP_DOWN)
                .max(MIN_ADAPTIVE_QUALITY);
        }

        let mut next = i32::from(self.quality);
        if target < next {
            next = target.max(next - QUALITY_STEP_DOWN);
        } else if target > next && !congested {
            next = target.min(next + QUALITY_STEP_UP);
        }

        let Ok(next) = u8::try_from(next) else { return };
        if next == self.quality {
            return;
        }
        tracing::info!(
            quality = next,
            target,
            goodput_kbit,
            congested,
            "adaptive H.264 quality"
        );
        self.quality = next;
    }

    /// Current adaptive H.264 target bitrate: the full-quality anchor for the
    /// surface size scaled by the adaptive quality. Falls back to the 1080p
    /// anchor before the first surface exists (the caller returns early then).
    fn h264_bitrate_bps(&self) -> u32 {
        let pixels = self
            .surface
            .map(|s| f64::from(s.width) * f64::from(s.height))
            .unwrap_or(f64::from(1920) * f64::from(1080));
        let kbit = full_quality_kbit(pixels) * f64::from(self.quality) / 100.0;
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "bitrate clamped below")]
        let bps = (kbit * 1000.0).clamp(250_000.0, f64::from(H264_BITRATE_CEILING_BPS)) as u32;
        bps
    }

    /// Lossless ClearCodec rectangle for small damage (or the full surface,
    /// used for first paint / recovery).
    async fn send_clear(
        &mut self,
        handle: &GfxHandle,
        data: Vec<u8>,
        frame_w: u16,
        frame_h: u16,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
    ) {
        let Some(surface) = self.surface else { return };
        let Some(mut encoders) = self.take_encoders() else { return };
        let ts = self.timestamp_ms();
        let full = x == 0 && y == 0 && w == frame_w && h == frame_h;

        let joined = tokio::task::spawn_blocking(move || {
            let bgra = if full {
                // Whole frame: just force the alpha byte opaque in place.
                let mut bgra = data;
                for px in bgra.chunks_exact_mut(4) {
                    px[3] = 0xFF;
                }
                bgra
            } else {
                crop_bgra(&data, frame_w, x, y, w, h)
            };
            let stream = encoders.clear.encode(&bgra, w, h);
            (encoders, stream)
        })
        .await;

        let Ok((encoders, stream)) = joined else {
            // Join failure: the encoders were lost with the task — rebuilt
            // on the next take_encoders() call.
            return;
        };
        self.encoders = Some(encoders);

        let dest = ExclusiveRectangle {
            left: x,
            top: y,
            right: x + w,
            bottom: y + h,
        };
        let mut server = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let sent = server.send_clearcodec_frame(surface.id, dest, stream, ts);
        drop(server);

        if sent.is_some() {
            self.stat_clear += 1;
            self.producer_frames += 1;
            if full {
                // A delivered full-surface paint clears the debt; a delivered
                // partial rect does not (older debt may still be outstanding).
                self.pending_full = false;
            }
        } else {
            // Dropped (backpressure): this grab's pixels are already consumed
            // from the damage tracker, so only a later full paint can deliver
            // them — keep the debt flagged.
            self.pending_full = true;
        }
        self.record_drained(self.session.drain_and_send(handle));
    }

    /// Full-frame H.264 encode for motion.
    async fn send_h264(&mut self, handle: &GfxHandle, data: Vec<u8>, w: u16, h: u16) {
        let Some(surface) = self.surface else { return };

        if self.avc_disabled {
            self.send_clear(handle, data, w, h, 0, 0, w, h).await;
            return;
        }

        // Adaptive bitrate: (re)build the encoder whenever the target moved by
        // more than 10% from what the running one was built with. Quality
        // steps are throttled to QUALITY_UPDATE_INTERVAL, so this settles
        // quickly; the openh264 wrapper has no runtime bitrate option, and a
        // fresh encoder conveniently opens with an IDR, re-syncing the client
        // after the rate change.
        let want_bps = self.h264_bitrate_bps();
        let bitrate_stale = match self.enc_bitrate_bps {
            None => true,
            Some(built) => {
                let lo = built.min(want_bps);
                let hi = built.max(want_bps);
                hi - lo > built / 10
            }
        };
        if bitrate_stale {
            match make_h264_encoder(want_bps) {
                Ok(h264) => {
                    match self.encoders.as_mut() {
                        Some(encoders) => encoders.h264 = Some(h264),
                        None => {
                            self.encoders = Some(Encoders {
                                h264: Some(h264),
                                clear: ClearCodecEncoder::new(),
                            });
                        }
                    }
                    self.enc_bitrate_bps = Some(want_bps);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "EGFX: OpenH264 init failed — ClearCodec only");
                    self.avc_disabled = true;
                    self.send_clear(handle, data, w, h, 0, 0, w, h).await;
                    return;
                }
            }
        }
        let Some(mut encoders) = self.take_encoders() else { return };

        let (pw, ph) = (surface.pad_width, surface.pad_height);
        let ts = self.timestamp_ms();

        let joined = tokio::task::spawn_blocking(move || {
            let yuv = bgrx_to_yuv420(&data, usize::from(w), usize::from(h), usize::from(pw), usize::from(ph));
            // Materialize the bitstream inside the closure: EncodedBitStream
            // borrows the encoder's internal buffer and is not Send.
            let bitstream = encoders.h264.as_mut().map(|enc| enc.encode(&yuv).map(|bs| bs.to_vec()));
            (encoders, bitstream)
        })
        .await;

        let Ok((encoders, bitstream)) = joined else {
            return;
        };
        self.encoders = Some(encoders);

        let Some(Ok(bitstream)) = bitstream else {
            // No encoder or encoder error: recover with a lossless full paint.
            self.pending_full = true;
            return;
        };
        if bitstream.is_empty() {
            return; // encoder skipped unchanged input
        }

        let region = Avc420Region {
            left: 0,
            top: 0,
            right: w,
            bottom: h,
            quantization_parameter: 21, // low QP = high quality
            quality: 90,
        };
        let mut server = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let sent = server.send_avc420_frame(surface.id, &bitstream, &[region], ts);
        drop(server);

        if sent.is_some() {
            self.stat_h264 += 1;
            self.producer_frames += 1;
            self.last_h264 = Instant::now();
            self.pending_full = false;
        } else {
            self.pending_full = true;
        }
        self.record_drained(self.session.drain_and_send(handle));
    }

    /// Encoders for this frame, re-initializing if a previous blocking task
    /// failed to join and dropped the previous instance.
    fn take_encoders(&mut self) -> Option<Encoders> {
        if self.encoders.is_none() {
            self.encoders = Some(Encoders {
                h264: None,
                clear: ClearCodecEncoder::new(),
            });
        }
        self.encoders.take()
    }

    fn timestamp_ms(&self) -> u32 {
        u32::try_from(self.started.elapsed().as_millis()).unwrap_or(u32::MAX)
    }

    /// One INFO line every 5 s: polls vs. damaged grabs (a stall shows as
    /// polls without damage — wedged X grab or genuinely static screen),
    /// plus the suppress flag and EGFX frame pacing state.
    fn heartbeat(&mut self, source: &str) {
        if self.hb_last.elapsed() < Duration::from_secs(5) {
            return;
        }
        tracing::info!(
            source,
            polls = self.hb_polls,
            damaged = self.hb_damaged,
            suppressed = self.suppressed.load(Ordering::Relaxed),
            in_motion = self.in_motion,
            pending_full = self.pending_full,
            "EGFX display heartbeat (5s window)"
        );
        self.hb_polls = 0;
        self.hb_damaged = 0;
        self.hb_last = Instant::now();
    }

    fn record_drained(&mut self, bytes: usize) {
        self.stat_bytes += bytes as u64;
        self.stat_frames += 1;
        self.stats_line();
    }

    fn stats_line(&mut self) {
        if self.stat_last.elapsed() >= Duration::from_secs(10) {
            let in_flight = self
                .generation
                .as_ref()
                .map(|g| g.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).frames_in_flight())
                .unwrap_or(0);
            tracing::info!(
                frames = self.stat_frames,
                h264 = self.stat_h264,
                clear = self.stat_clear,
                bytes = self.stat_bytes,
                in_flight,
                "EGFX stats (10s window)"
            );
            self.stat_frames = 0;
            self.stat_h264 = 0;
            self.stat_clear = 0;
            self.stat_bytes = 0;
            self.stat_last = Instant::now();
        }
    }
}

fn make_h264_encoder(bitrate_bps: u32) -> anyhow::Result<OpenH264> {
    let api = openh264::OpenH264API::from_source();
    let config = EncoderConfig::new()
        .bitrate(BitRate::from_bps(bitrate_bps))
        .max_frame_rate(FrameRate::from_hz(30.0))
        .usage_type(UsageType::ScreenContentRealTime)
        // KRdp/RustDesk drive the encoder by target bitrate (the resolution
        // anchor scaled by measured goodput — see `update_adaptive_quality`);
        // quality mode has no dial the adaptation could turn.
        .rate_control_mode(RateControlMode::Bitrate)
        .skip_frames(false)
        // Signal the colorspace in the SPS VUI: the planes are full-range
        // BT.709 (MS-RDPEGFX §3.3.8.3.1), and without this flag a
        // spec-compliant decoder assumes limited range (Y 16..235) and
        // crushes our dark-theme desktop (luma ~20) to near-black.
        .vui(VuiConfig::bt709().full_range(true));
    OpenH264::with_api_config(api, config).map_err(|e| anyhow::anyhow!("openh264 init: {e}"))
}

/// Convert a BGRX grab into macroblock-padded I420 planes, **full-range
/// BT.709**.
///
/// MS-RDPEGFX §3.3.8.3.1 normatively mandates full-range luma (0..255, no
/// 16..235 studio swing) with the BT.709 matrix — the same conversion
/// FreeRDP's `prim_YUV` implements on the decode side and mstsc expects.
/// OpenH264's own `YUVBuffer::from_rgb_source` converter is limited-range
/// BT.601 (luma +16 offset), which decodes on the client as washed-out,
/// shifted colors — visibly pulsing when interleaved with lossless
/// ClearCodec updates (IronRDP issue #1924 documents the same trap).
///
/// The padding region is black (Y=0, Cb=Cr=128) — the destination rectangle
/// crops it away.
fn bgrx_to_yuv420(src: &[u8], w: usize, h: usize, pw: usize, ph: usize) -> openh264::formats::YUVBuffer {
    let stride = w * 4;
    let mut yuv = vec![0u8; 3 * (pw * ph) / 2];
    let (y_len, u_len) = (pw * ph, pw * ph / 4);
    let (y_plane, rest) = yuv.split_at_mut(y_len);
    let (u_plane, v_plane) = rest.split_at_mut(u_len);

    // Pixel accessor: real (R, G, B) inside the frame, black in the padding.
    let px = |x: usize, y: usize| -> (i32, i32, i32) {
        if x < w && y < h {
            let off = y * stride + x * 4;
            (i32::from(src[off + 2]), i32::from(src[off + 1]), i32::from(src[off]))
        } else {
            (0, 0, 0)
        }
    };

    for j in 0..ph / 2 {
        for i in 0..pw / 2 {
            let p00 = px(i * 2, j * 2);
            let p01 = px(i * 2, j * 2 + 1);
            let p10 = px(i * 2 + 1, j * 2);
            let p11 = px(i * 2 + 1, j * 2 + 1);

            // Chroma: average of the 2x2 block.
            let r = (p00.0 + p01.0 + p10.0 + p11.0) / 4;
            let g = (p00.1 + p01.1 + p10.1 + p11.1) / 4;
            let b = (p00.2 + p01.2 + p10.2 + p11.2) / 4;
            let cb = ((-29 * r - 99 * g + 128 * b) >> 8) + 128;
            let cr = ((128 * r - 116 * g - 12 * b) >> 8) + 128;
            u_plane[j * (pw / 2) + i] = cb.clamp(0, 255) as u8;
            v_plane[j * (pw / 2) + i] = cr.clamp(0, 255) as u8;

            // Luma per pixel (full-range BT.709: 54/183/18, sum 255).
            for (p, (dx, dy)) in [(p00, (0, 0)), (p01, (0, 1)), (p10, (1, 0)), (p11, (1, 1))] {
                let y_val = (54 * p.0 + 183 * p.1 + 18 * p.2) >> 8;
                y_plane[(j * 2 + dy) * pw + (i * 2 + dx)] = y_val.clamp(0, 255) as u8;
            }
        }
    }

    openh264::formats::YUVBuffer::from_vec(yuv, pw, ph)
}

/// Crop a rectangle out of a BGRX grab into tightly-packed BGRA (ClearCodec
/// input; the alpha byte is forced opaque).
fn crop_bgra(data: &[u8], width: u16, x: u16, y: u16, w: u16, h: u16) -> Vec<u8> {
    let stride = usize::from(width) * 4;
    let mut out = Vec::with_capacity(usize::from(w) * usize::from(h) * 4);
    for row in y..y + h {
        let start = usize::from(row) * stride + usize::from(x) * 4;
        for px in data[start..start + usize::from(w) * 4].chunks_exact(4) {
            out.extend_from_slice(&[px[0], px[1], px[2], 0xFF]);
        }
    }
    out
}

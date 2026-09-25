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
//! - large damage (video, scrolling): a full-frame **H.264** encode
//!   (OpenH264, camera-class coding tools with multi-threaded size-limited
//!   slices, bitrate-target rate control). Clients with cap version >= 10.6
//!   get **AVC444v2** — full-resolution chroma, dual-view encoding — while
//!   the rest get AVC420.
//!
//! If the channel is not negotiated (older clients, macOS Microsoft Remote
//! Desktop), or it goes down mid-session, the loop transparently falls back
//! to yielding legacy bitmap updates, which the server encodes with
//! RemoteFX/NSCodec as before.

use anyhow::Context as _;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ironrdp_egfx::pdu::{Avc420Region, Encoding, PixelFormat};
use ironrdp_egfx::server::{CLIENT_QUEUE_BACKOFF, GraphicsPipelineServer};
use ironrdp_graphics::clearcodec::ClearCodecEncoder;
use ironrdp_pdu::geometry::ExclusiveRectangle;
use ironrdp_server::{
    DesktopSize, DisplayUpdate, LargePointer, RdpServerDisplay, RdpServerDisplayUpdates,
    RGBAPointer, ServerResult,
};
use crate::capture::{CursorImage, Grab, ScreenGrabber, X11Display, POLL_INTERVAL, RESIZE_SETTLE};
use crate::x264_encoder::X264Encoder;
use openh264::formats::YUVSource;
use crate::gfx::GfxSession;

type GfxHandle = Arc<Mutex<GraphicsPipelineServer>>;

/// Damage covering at least this fraction of the screen counts as motion and
/// goes through H.264 instead of lossless ClearCodec.
const MOTION_NUM: u64 = 1;
const MOTION_DEN: u64 = 8;

/// Minimum spacing between H.264 encodes. Purely a runaway guard: the
/// multi-threaded camera-mode encoder encodes a frame in ~35 ms, so the poll
/// pacing (~16 ms) is the real cap; this only stops a pathological loop from
/// encoding faster than frames arrive. The old 33 ms value dated from the
/// screen-content encoder and silently discarded two of every three grabs
/// (each skip burned a full capture + damage pass).
const H264_MIN_INTERVAL: Duration = Duration::from_millis(12);

/// Hard ceiling for one X11 grab (screen read + tile diff). A frozen X
/// server never errors — it just never replies — so silence past this means
/// the connection is dead weight: the grab task is abandoned and a fresh
/// connection replaces it.
const GRAB_TIMEOUT: Duration = Duration::from_secs(3);

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

/// How long a client that DID advertise the graphics pipeline may keep the
/// display loop waiting for EGFX capability negotiation before the session
/// gives up and starts legacy bitmap updates.
///
/// MS-RDPEDYC 3.3.3.1.4 sets the protocol's own precedent for a deadline here
/// — ten seconds for the DVC Capabilities Response, after which the server
/// stops trying — but ten seconds of black screen reads as a hung session.
/// Three seconds is comfortably longer than a real client needs to open the
/// channel and send CapsAdvertise (measured well under one), and short enough
/// that a client which never will is not mistaken for one that is slow.
const EGFX_READY_DEADLINE: Duration = Duration::from_secs(3);

/// What the display loop should do with the frame it is holding.
///
/// Extracted from the loop so the three ways EGFX can fail to arrive — the
/// client never advertised it (MS-RDPEGFX 1.5), the client refused the channel
/// (MS-RDPEDYC 3.3.3.2), or negotiation stalled — are one table of cases
/// rather than a chain of `continue`s that cannot be tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EgfxDecision {
    /// Send this frame over the graphics pipeline.
    Egfx,
    /// Send it as a legacy bitmap update.
    Legacy,
    /// Drop it: EGFX is still expected, and mixing update streams while a
    /// graphics client negotiates makes it stop composing entirely.
    Hold,
}

/// Inputs the loop has in hand when it must route a frame.
#[derive(Debug, Clone, Copy)]
struct EgfxState {
    /// Capability negotiation completed — frames can flow.
    ready: bool,
    /// This session has already sent EGFX frames.
    latched: bool,
    /// The channel was refused or closed; no negotiation will follow.
    unavailable: bool,
    /// The client advertised `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL`.
    client_supports: bool,
    /// Elapsed since the pipeline server was published; `None` means no
    /// pipeline server exists yet for this connection.
    waited: Option<Duration>,
    /// Elapsed since the updates stream started, for the no-handle grace.
    since_start: Duration,
}

impl EgfxState {
    /// Why this session is not on the graphics pipeline, in one phrase — so an
    /// operator reading the log does not have to reconstruct it from a DVC
    /// warning three seconds earlier, which is exactly what this cost last
    /// time.
    fn legacy_reason(&self) -> &'static str {
        if !self.client_supports {
            "client did not advertise the graphics pipeline (MS-RDPEGFX 1.5)"
        } else if self.unavailable {
            "client refused or closed the graphics channel"
        } else if self.waited.is_some() {
            "EGFX capability negotiation did not complete in time"
        } else {
            "no graphics channel opened"
        }
    }
}

fn egfx_decision(state: EgfxState) -> EgfxDecision {
    if state.ready {
        return EgfxDecision::Egfx;
    }

    // A session already on the pipeline rides out a handle swap (the client
    // re-advertising after a decoder reset) rather than interleaving legacy
    // updates into it, which mstsc rejects as a protocol error. Only the
    // channel actually going away releases the latch.
    if state.latched {
        return if state.unavailable {
            EgfxDecision::Legacy
        } else {
            EgfxDecision::Hold
        };
    }

    // MS-RDPEGFX 1.5: a client implementing the graphics pipeline MUST
    // advertise it in its Client Core Data. One that did not will refuse the
    // channel, so there is nothing to wait for — not for the grace window
    // either.
    if !state.client_supports {
        return EgfxDecision::Legacy;
    }

    // MS-RDPEDYC 3.3.3.2: creation failure is terminal for the channel.
    if state.unavailable {
        return EgfxDecision::Legacy;
    }

    match state.waited {
        // The channel is open and the client is graphics-capable: hold, but
        // not forever — a client that stalls before CapsAdvertise would
        // otherwise take the whole session down with it in silence.
        Some(waited) => {
            if waited >= EGFX_READY_DEADLINE {
                EgfxDecision::Legacy
            } else {
                EgfxDecision::Hold
            }
        }
        // No pipeline server yet. A graphics client opens its channel a few
        // hundred milliseconds in; emitting legacy updates into that window
        // costs the first session of every process its composition.
        None => {
            if state.since_start >= LEGACY_GRACE {
                EgfxDecision::Legacy
            } else {
                EgfxDecision::Hold
            }
        }
    }
}

/// H.264 encoder ceiling. The adaptive target below stays at or under the
/// resolution anchor (7.5 Mbit/s at 4K); this only bounds pathological frames.
/// (Kept as an absolute last-resort clamp for the rate controller.)
const H264_BITRATE_CEILING_BPS: u32 = 50_000_000;

/// Bitrate multiplier applied when the link shows no strain (RTT flat,
/// client keeping up). The quality anchors are conservative "works over
/// WAN" targets; on an unstrained link they are the floor, not the ceiling —
/// a 1 Gbit LAN carries 10-50 Mbit without blinking, and the strain gates
/// (RTT inflation, client backpressure) are what pull the target back the
/// moment the client or path objects.
const UNSTRAINED_BITRATE_BOOST: f64 = 3.0;

/// Bounds for the rate-control frame-rate assumption fed to OpenH264. The RC
/// spreads the target bitrate across this many frames per second, so it has
/// to track the rate we actually produce: at a fixed 30 fps assumption while
/// really producing 9 fps, the encoder emits a third of its target and the
/// goodput-driven quality adaptation reads that as "slow network" (a
/// downward spiral measured in production). Clamped low so the very first
/// frames get a sane per-frame budget before the producer rate is measured.
const ENC_RC_FPS_MIN: f64 = 8.0;
const ENC_RC_FPS_MAX: f64 = 30.0;

/// Re-evaluate the adaptive encoder quality at most this often (KRdp:
/// `QualityUpdateInterval`). Each evaluation loads two atomics and at most
/// rebuilds the encoder, so the throttle also bounds encoder churn.
const QUALITY_UPDATE_INTERVAL: Duration = Duration::from_millis(1500);

/// Adaptive quality is only evaluated while sustained motion flows: at least
/// this many H.264 frames must have been sent since the previous evaluation.
/// A quiet screen sends almost no bytes, and reading that goodput as "slow
/// network" dragged the quality to the floor — video resumed after a pause
/// then started blocky and sharpened over seconds. Below the threshold the
/// quality is HELD, so a resumed video starts at the quality it left with.
const MIN_MOTION_FRAMES_PER_EVAL: u64 = 22;

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

/// After the last motion frame, keep the display in "motion mode" this
/// long: while active, small lossless ClearCodec updates are suppressed so
/// static UI does not flip-flop between the lossless and the (inherently
/// lossy 4:2:0) H.264 looks — the visible "pulsing". When the window
/// lapses, one full lossless repaint snaps the whole screen crisp again,
/// mirroring how Windows RDP presents video regions.
/// Why a lossless repaint was armed.
///
/// Diagnostic only. A full-screen ClearCodec paint costs ~1 MB at 2880x1800,
/// so a storm of them is the whole bandwidth of an idle session — but the
/// stats line only showed `clear=N`, which cannot tell one 1 MB repaint from
/// a handful of small partials, nor say which of the eleven call sites armed
/// it. The per-cause tally is what turns "something repaints constantly" into
/// a specific line of code.
#[derive(Clone, Copy)]
enum DebtCause {
    ProducerBackpressure,
    ProcessStall,
    Generation,
    SurfaceVanished,
    PreFrameBackpressure,
    LingerExit,
    H264Skip,
    MotionPartial,
    ClearSendFailed,
    NoEncoder,
    H264SendFailed,
}

impl DebtCause {
    const COUNT: usize = 11;

    fn idx(self) -> usize {
        match self {
            Self::ProducerBackpressure => 0,
            Self::ProcessStall => 1,
            Self::Generation => 2,
            Self::SurfaceVanished => 3,
            Self::PreFrameBackpressure => 4,
            Self::LingerExit => 5,
            Self::H264Skip => 6,
            Self::MotionPartial => 7,
            Self::ClearSendFailed => 8,
            Self::NoEncoder => 9,
            Self::H264SendFailed => 10,
        }
    }

    const NAMES: [&'static str; Self::COUNT] = [
        "producer_bp",
        "process_stall",
        "generation",
        "surface_vanished",
        "preframe_bp",
        "linger_exit",
        "h264_skip",
        "motion_partial",
        "clear_send_failed",
        "no_encoder",
        "h264_send_failed",
    ];
}

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
    /// The single H.264 stream.
    ///
    /// [MS-RDPEGFX 2.2.4.5/2.2.4.6]: the two AVC444 subframes "MUST be
    /// encoded using the same MPEG-4 AVC/H.264 encoder and decoded by a
    /// single MPEG-4 AVC/H.264 decoder as one stream". For a v2 frame the
    /// luma view and the chroma view are therefore two consecutive frames of
    /// THIS stream — never two streams.
    h264: Option<X264Encoder>,
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
    ///
    /// `debt_due` means the display still owes the client pixels it has never
    /// seen. A source that would otherwise report "nothing changed" MUST then
    /// hand back the current screen contents with `damage: None`: an unchanged
    /// screen is exactly the case where no later event will deliver those
    /// pixels, so a source that stays silent leaves the paint unfinished
    /// forever. It is not a fresh-frame signal — `damage` still says what
    /// actually changed.
    fn poll_and_cursor(&mut self, cursor_due: bool, debt_due: bool) -> Option<(Grab, Option<CursorImage>)>;
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

/// Build the x264 motion encoder: ABR at `target_bitrate`, superfast preset
/// with zero-latency tuning (no B-frames, no lookahead — interactive), full
/// multithreading. Annex-B output with in-band SPS/PPS at each IDR.
#[must_use]
pub(crate) fn make_h264_encoder(
    target_bitrate: u32,
    rc_fps: f32,
    pw: u16,
    ph: u16,
) -> anyhow::Result<crate::x264_encoder::X264Encoder> {
    // ONE encoder for the whole session ([MS-RDPEGFX 2.2.4.5/2.2.4.6]): both
    // AVC444 subframes must come from the same encoder because the client
    // feeds them to a single decoder. Two encoders each emit their own
    // SPS/PPS/IDR and their own frame_num sequence; interleaved into one
    // decoder the second IDR flushes the DPB and the next P-frame of the
    // other view references a picture that is gone.
    crate::x264_encoder::X264Encoder::new(target_bitrate, rc_fps, pw, ph).context("x264 encoder init")
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
    /// `features.avc444v2`: whether the operator permits the layout at all.
    /// Whether it is *used* additionally depends on what the client
    /// negotiates — see `EgfxUpdates::avc444v2_enabled`.
    avc444v2_allowed: bool,
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
        avc444v2_allowed: bool,
    ) -> Self {
        Self {
            factory,
            session,
            suppressed,
            rtt,
            rtt_baseline,
            bw_kbps,
            pointer_cache,
            avc444v2_allowed,
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
        let desktop = self.factory.size();
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
            debt_rect: None,
            in_motion: false,
            motion_until: Instant::now(),
            caps_reset_until: Instant::now(),
            egfx_latched: false,
            handle_first_seen: None,
            legacy_reason_logged: false,
            settle_until,
            legacy_size: Some((desktop.width, desktop.height)),
            last_attach_attempt: Instant::now() - Duration::from_secs(1),
            hb_polls: 0,
            hb_damaged: 0,
            hb_last: Instant::now(),
            avc_disabled: false,
            started: Instant::now(),
            avc444v2_allowed: self.avc444v2_allowed,
            avc444v2_enabled: false,
            clear_seq: 0,
            stat_frames: 0,
            stat_h264: 0,
            stat_clear: 0,
            stat_bytes: 0,
            stat_last: Instant::now(),
            stat_debt: [0; DebtCause::COUNT],
            stat_motion_grabs: 0,
            stat_damaged_grabs: 0,
            stat_tiles_peak_pct: 0,
            stat_full_paints: 0,
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
            enc_built: None,
            last_grab_start: Instant::now(),
            grab_ms: 0.0,
            process_ms: 0.0,
            motion_frames: 0,
            motion_frames_mark: 0,
            last_sent: 0,
            backpressure_events: 0,
            bitrate_boost: 1.0,
            clear_bytes_per_px: CLEARCODEC_BYTES_PER_PX,
            busy_ms: 0.0,
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
    /// A lossless send is owed (first paint, resize, skipped frame) —
    /// partial lossless updates are blocked until it is cleared, or pixels
    /// from the skipped frame could stay stale forever.
    pending_full: bool,
    /// Which region owes that lossless paint, as a union of the damage
    /// rectangles that were skipped. `None` while `pending_full` means the
    /// whole screen owes it (post-resize, surface rebuild, motion exit under
    /// 4:2:0). Repaying only the region that actually went stale is the
    /// difference between a 1.07 MB full-screen repaint and a few KB.
    debt_rect: Option<(u16, u16, u16, u16)>,
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
    /// The desktop size the client has while on the legacy path: the size the
    /// display reported when this stream started, then the size of the last
    /// resize sent.
    legacy_size: Option<(u16, u16)>,
    /// Once a session has used EGFX, never fall back to legacy bitmap
    /// updates (a client decoder reset briefly clears `ready`).
    egfx_latched: bool,
    /// When a pipeline server first appeared for this connection. Starts the
    /// clock on [`EGFX_READY_DEADLINE`]: a client that opened the graphics
    /// channel but never finished capability negotiation must not hold the
    /// display loop for the rest of the session.
    handle_first_seen: Option<Instant>,
    /// The legacy-fallback reason is logged once per session, not once per
    /// frame.
    legacy_reason_logged: bool,
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
    /// `features.avc444v2`: whether the operator permits the layout at all.
    /// Deliberately a separate field from the one below — the two differ in
    /// meaning by one word, "allowed" against "negotiated", and they used to
    /// meet on two adjacent lines with only an env var to tell them apart.
    avc444v2_allowed: bool,
    /// Client negotiated cap version >= 10.6 AND the operator allows it: the
    /// AVC444v2 chroma layout may be used for motion frames.
    avc444v2_enabled: bool,
    /// MS-RDPEGFX 2.2.4.1 ClearCodec `seqNumber` for this session: the first
    /// message is 0 and every later one is the previous plus one (wrapping at
    /// 0xFF). Owned here rather than inside `Encoders` because that struct is
    /// rebuilt mid-session; a restarted counter is a protocol violation the
    /// client answers with a pipeline reset and then a disconnect.
    clear_seq: u8,
    started: Instant,
    stat_frames: u64,
    stat_h264: u64,
    stat_clear: u64,
    stat_bytes: u64,
    stat_last: Instant,
    /// Diagnostic tallies, reset with every 10 s stats line: which call site
    /// armed the lossless debt, how many damaged grabs crossed the motion
    /// threshold, the peak changed-tile fraction, and how many lossless
    /// paints covered the entire frame.
    stat_debt: [u32; DebtCause::COUNT],
    stat_motion_grabs: u32,
    stat_damaged_grabs: u32,
    stat_tiles_peak_pct: u32,
    stat_full_paints: u32,
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
    /// Encoder config the running H.264 instance was built with:
    /// `(target bitrate bps, rate-control fps)`. `None` until the first
    /// motion frame creates one. Drives rebuild-on-change hysteresis.
    enc_built: Option<(u32, f32)>,
    /// When the last capture poll was started — paces grab starts to the
    /// poll interval in the event-driven loop.
    last_grab_start: Instant,
    /// Smoothed capture-poll duration and frame-processing duration (YUV +
    /// encode + send), for the heartbeat. EWMA, alpha 0.25.
    grab_ms: f64,
    process_ms: f64,
    /// H.264 frames sent since the last adaptive-quality evaluation — the
    /// "is motion actually flowing" gate (see MIN_MOTION_FRAMES_PER_EVAL).
    motion_frames: u64,
    motion_frames_mark: u64,
    /// Total v2 frames sent — drives the chroma-every-other-frame parity.
    last_sent: u64,
    /// Backpressure incidents (client decode queue full) observed since the
    /// last adaptive-quality evaluation — together with RTT inflation, one of
    /// the two real strain signals.
    backpressure_events: u64,
    /// Bitrate multiplier over the anchor: 3x while the link is unstrained
    /// (quality anchors are WAN-safe floors; a LAN wants best-effort quality
    /// bounded only by what the client can decode), 1x under strain.
    bitrate_boost: f64,
    /// Measured ClearCodec bytes per source pixel (EWMA), sizing the lossless
    /// band budget. Seeded from [`CLEARCODEC_BYTES_PER_PX`].
    clear_bytes_per_px: f64,
    /// Capture+process CPU-proxy time accumulated in the heartbeat window:
    /// every consumed grab's poll duration plus every frame's processing
    /// duration. Divided by the window length in the heartbeat log, this is
    /// the display loop's own load figure (does not count the X server side
    /// or the rate-limit skips that burn grabs).
    busy_ms: f64,
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
/// the previous frame is being converted and encoded. The frame source lives
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
            // Client minimized (Suppress Output): skip emission entirely.
            if self.suppressed.load(Ordering::Relaxed) {
                tokio::time::sleep(POLL_INTERVAL).await;
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
                    self.owe_everything(DebtCause::ProducerBackpressure);
                    self.backpressure_events += 1;
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            }

            // Start the next capture when the pacing interval has passed;
            // otherwise wait out the remainder. When encoding is slower than
            // the interval (motion) this never sleeps — the encoder paces the
            // loop and the capture runs concurrently with it.
            if self.pending_grab.is_none() {
                let since_last = self.last_grab_start.elapsed();
                if since_last < POLL_INTERVAL {
                    tokio::time::sleep(POLL_INTERVAL - since_last).await;
                    continue;
                }
                self.maybe_start_grab(cursor_due, self.pending_full);
                if self.pending_grab.is_none() {
                    // Could not start (source lost, rebuild throttled): idle
                    // briefly instead of spinning.
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            }

            // Event-driven consume: await the in-flight poll directly instead
            // of sleeping a fixed tick, so the per-frame period is
            // max(pacing, encode) rather than pacing + encode.
            let Some((grab, cursor)) = self.try_consume_grab().await else {
                continue;
            };

            if let Some(cursor) = cursor {
                if let Some(update) = self.cursor_update(cursor) {
                    self.pending_cursor = Some(update);
                }
            }

            // Route this frame: graphics pipeline, legacy bitmaps, or drop it
            // and keep waiting. `egfx_decision` holds the whole table (and its
            // reasoning); everything here is gathering its inputs.
            let handle = self.session.handle();
            let now = Instant::now();
            if handle.is_some() && self.handle_first_seen.is_none() {
                self.handle_first_seen = Some(now);
            }
            let ready = handle.as_ref().is_some_and(|handle| {
                let server = Self::lock_handle(handle);
                self.session.ready() && server.is_ready()
            });
            let state = EgfxState {
                ready,
                latched: self.egfx_latched,
                unavailable: self.session.unavailable(),
                client_supports: self.session.client_supports_egfx(),
                waited: self.handle_first_seen.map(|seen| now.saturating_duration_since(seen)),
                since_start: now.saturating_duration_since(self.started),
            };

            let decision = egfx_decision(state);
            // MS-RDPEDISP 1.3: without the graphics pipeline a new desktop
            // size takes a Deactivation-Reactivation Sequence, which the
            // server runs on `DisplayUpdate::Resize`. The stream that follows
            // starts over with a full repaint.
            if decision == EgfxDecision::Legacy
                && let Some(resize) = legacy_resize(&mut self.legacy_size, grab.width, grab.height)
            {
                return Ok(Some(resize));
            }
            let handle = match decision {
                EgfxDecision::Egfx => {
                    // This session is on the graphics pipeline. Latch it: when
                    // the client re-opens the graphics channel (decoder reset),
                    // the factory briefly clears `ready` and swaps the handle —
                    // falling back to legacy bitmap updates in that window mixes
                    // two update streams in one session, which mstsc rejects
                    // outright (protocol error). The EGFX path rides out the
                    // swap via the generation check instead.
                    self.egfx_latched = true;
                    handle.expect("EGFX decision implies a pipeline server")
                }
                EgfxDecision::Legacy => {
                    self.log_legacy_fallback(&state);
                    if let Some(update) = grab.legacy_display_update() {
                        return Ok(Some(update));
                    }
                    if let Some(update) = self.pending_cursor.take() {
                        return Ok(Some(update));
                    }
                    continue;
                }
                EgfxDecision::Hold => {
                    if let Some(update) = self.pending_cursor.take() {
                        return Ok(Some(update));
                    }
                    continue;
                }
            };

            // Bounded processing: a wedged encoder or a lock held across a
            // stuck writer must not freeze the whole display pipeline — the
            // session would show one last static frame forever, and every
            // later client would connect to a dead loop (black screen).
            // Dropping the future abandons whatever blocked; codec state is
            // rebuilt next frame.
            let process_started = Instant::now();
            let frame_done = tokio::time::timeout(FRAME_PROCESS_TIMEOUT, self.egfx_frame(&handle, grab))
                .await
                .is_ok();
            let process_ms = process_started.elapsed().as_secs_f64() * 1000.0;
            self.process_ms = if self.process_ms == 0.0 { process_ms } else { self.process_ms * 0.75 + process_ms * 0.25 };
            self.busy_ms += process_ms;
            if !frame_done {
                tracing::error!(
                    process_timeout = ?FRAME_PROCESS_TIMEOUT,
                    "EGFX frame processing stalled — resetting encoders and motion state"
                );
                self.encoders = None;
                self.enc_built = None;
                self.in_motion = false;
                self.owe_everything(DebtCause::ProcessStall);
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
    /// Kick off the next capture poll. The poll runs in a blocking task and
    /// [`Self::try_consume_grab`] awaits its result — that split is what lets
    /// the next GetImage + tile diff overlap the previous frame's conversion
    /// and encode.
    fn maybe_start_grab(&mut self, cursor_due: bool, debt_due: bool) {
        if self.pending_grab.is_some() {
            return; // one poll at a time
        }
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
        let mut source = self.source.take().expect("source checked above");
        self.hb_polls += 1;
        self.last_grab_start = Instant::now();
        let handle = tokio::task::spawn_blocking(move || {
            let polled = source.poll_and_cursor(cursor_due, debt_due);
            (source, polled)
        });
        self.pending_grab = Some(PendingGrab {
            handle,
            started: Instant::now(),
        });
    }

    /// Await the in-flight capture poll (event-driven: no fixed tick sleep).
    /// A poll exceeding [`GRAB_TIMEOUT`] is abandoned — the source inside the
    /// task is lost and the factory rebuilds one, with the dropped baseline
    /// forcing a full repaint once frames flow again.
    async fn try_consume_grab(&mut self) -> Option<(Grab, Option<CursorImage>)> {
        let pending = self.pending_grab.take()?;
        let remaining = GRAB_TIMEOUT.saturating_sub(pending.started.elapsed());
        match tokio::time::timeout(remaining, pending.handle).await {
            Ok(Ok((source, polled))) => {
                self.hb_damaged += u64::from(polled.as_ref().is_some_and(|(g, _)| g.damage.is_some()));
                let grab_ms = pending.started.elapsed().as_secs_f64() * 1000.0;
                self.grab_ms = if self.grab_ms == 0.0 { grab_ms } else { self.grab_ms * 0.75 + grab_ms * 0.25 };
                self.busy_ms += grab_ms;
                let name = source.name().to_owned();
                self.source = Some(source);
                self.heartbeat(&name);
                polled
            }
            Ok(Err(join_err)) => {
                // The poll panicked: the source was lost with the task, the
                // factory rebuilds one next tick. (A panic in an async task
                // would otherwise kill the display loop silently.)
                tracing::warn!(error = %join_err, "frame source poll panicked — rebuilding source");
                None
            }
            Err(_) => {
                tracing::warn!(timeout = ?GRAB_TIMEOUT, "frame source poll timed out — abandoning it");
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

    /// Say once, at the point of the decision, why this session is drawing
    /// with legacy bitmap updates instead of EGFX.
    fn log_legacy_fallback(&mut self, state: &EgfxState) {
        if self.legacy_reason_logged {
            return;
        }
        self.legacy_reason_logged = true;
        tracing::info!(reason = state.legacy_reason(), "display is using legacy bitmap updates");
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
        // A size change under an EXISTING surface means the X screen moved
        // mid-session (e.g. fixed-size enforcement re-applying a drifted
        // screen): the desktop churns (WM re-layout) and H.264 pushed
        // mid-churn is decoded but never composed (learnings #5) — hold it.
        if size_changed && self.surface.is_some() {
            self.settle_until = Instant::now() + RESIZE_SETTLE;
            tracing::info!(
                width = grab.width,
                height = grab.height,
                "screen size changed mid-session — settling before H.264 resumes"
            );
        }
        if generation_changed || size_changed {
            self.ensure_surface(handle, grab.width, grab.height);
            self.generation = Some(Arc::clone(handle));
            if let Some(Encoders { h264: Some(enc), .. }) = self.encoders.as_mut() {
                enc.force_intra();
            }
            self.owe_everything(DebtCause::Generation);
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
                // MS-RDPEGFX 3.2.5.18 resets the client to its initial state,
                // which includes the ClearCodec sequence and glyph cache: the
                // next message must be seqNumber 0 and must not reference a
                // cached glyph.
                self.clear_seq = 0;
                if let Some(encoders) = self.encoders.as_mut() {
                    encoders.clear.reset_session();
                }
                if let Some(Encoders { h264: Some(enc), .. }) = self.encoders.as_mut() {
                    enc.force_intra();
                }
                self.ensure_surface(handle, grab.width, grab.height);
                self.owe_everything(DebtCause::SurfaceVanished);
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
            self.owe_everything(DebtCause::PreFrameBackpressure);
            self.backpressure_events += 1;
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

        // Motion-mode exit: the linger window lapsed. Under 4:2:0 the last
        // H.264 frame left the whole screen with half-resolution chroma, so
        // a full lossless repaint is what makes text crisp again.
        //
        // Under AVC444v2 there is nothing to repair: the chroma is already
        // full resolution, and the stream runs at QP 5-8. Snapping back
        // anyway cost a 1.07 MB repaint of unchanged content roughly once a
        // second — measured at 14 of them per 10 s, which was the entire
        // bandwidth of an idle session.
        if self.in_motion && Instant::now() >= self.motion_until {
            self.in_motion = false;
            if !self.avc444v2_enabled {
                self.owe_everything(DebtCause::LingerExit);
            }
        }

        let Some(damage) = damage else {
            // Nothing changed — unless a full frame is still owed (e.g. a
            // motion frame was skipped and the screen went static right
            // after), in which case paint everything now.
            if self.pending_full {
                let (x, y, w, h) = self.debt_region(width, height);
                self.repay_debt(handle, data, width, height, x, y, w, h).await;
            }
            return;
        };

        // Repay the full-paint debt ONLY outside motion mode. Inside it, a
        // rate-limited skip flags pending_full and the next H.264 frame
        // covers the pixels — repaying mid-motion with a lossless repaint
        // alternates the whole screen between exact and 4:2:0 looks at the
        // H.264 cadence (~6.5 Hz), which is exactly the visible flicker.
        if self.pending_full && !self.in_motion {
            let (x, y, w, h) = self.debt_region(width, height);
            self.repay_debt(handle, data, width, height, x, y, w, h).await;
            return;
        }

        let (dx, dy, dw, dh) = damage;
        // Motion signal = fraction of the screen that actually changed, NOT
        // the bounding box and NOT an absolute pixel count: a blinking cursor
        // in one corner and a clock in the other span the whole screen as a
        // bbox but are ~0.1% of the tiles (bbox-based detection kept such
        // screens in soft H.264 mode forever), and a fixed pixel cutoff made
        // the threshold resolution-dependent — a mid-size video window on a
        // 4K desktop stayed on the lossless ClearCodec path (slow to encode,
        // huge on the wire for video noise) while the same window on 1080p
        // correctly used H.264.
        let motion = !settling
            && u64::from(changed_tiles) * MOTION_DEN > u64::from(total_tiles) * MOTION_NUM;

        // Diagnostic: the motion threshold is a fraction of the screen, so
        // "is the screen really moving?" cannot be read from `damaged` alone.
        self.stat_damaged_grabs += 1;
        if motion {
            self.stat_motion_grabs += 1;
            // The fork in the road: `changed == total` means the baseline was
            // dropped (a capture bug), anything less is a real screen change.
            tracing::debug!(changed_tiles, total_tiles, dx, dy, dw, dh, "motion frame");
        }
        #[expect(clippy::arithmetic_side_effects, reason = "total_tiles is clamped to >= 1")]
        let pct = u64::from(changed_tiles) * 100 / u64::from(total_tiles.max(1));
        self.stat_tiles_peak_pct = self.stat_tiles_peak_pct.max(u32::try_from(pct).unwrap_or(100));

        if motion && !self.avc_disabled {
            if self.last_h264.elapsed() < H264_MIN_INTERVAL {
                // Skip this encode to hold ~30 fps. The next H.264 frame is
                // a FULL-frame encode, so this grab's content arrives with
                // it — block lossless partials until then.
                self.owe_region(dx, dy, dw, dh, DebtCause::H264Skip);
                return;
            }
            // Motion mode only if the frame actually shipped: it suppresses
            // the lossless partial path below, so entering it on a dropped
            // frame strands the pixels nothing else will deliver.
            if self.send_h264(handle, data, width, height).await {
                self.in_motion = true;
                self.motion_until = Instant::now() + MOTION_LINGER;
            }
        } else if self.in_motion {
            // Small damage inside the motion window: suppress the lossless
            // partial. Sending it would flip these pixels to exact colors,
            // only for the next full-frame H.264 to re-lossy them — that
            // alternation is the visible pulse. The next motion frame (or
            // the linger-exit repaint) delivers these pixels consistently.
            self.owe_region(dx, dy, dw, dh, DebtCause::MotionPartial);
        } else {
            let _delivered = self.send_clear(handle, data, width, height, dx, dy, dw, dh).await;
        }
    }


    /// Record that `rect` owes a lossless paint, merging it with whatever is
    /// already owed. An existing whole-screen debt stays whole-screen.
    fn owe_region(&mut self, x: u16, y: u16, w: u16, h: u16, cause: DebtCause) {
        self.stat_debt[cause.idx()] += 1;
        if self.pending_full && self.debt_rect.is_none() {
            return; // already owe everything
        }
        self.debt_rect = Some(match self.debt_rect {
            None => (x, y, w, h),
            Some(cur) => union_rect(cur, (x, y, w, h)),
        });
        self.pending_full = true;
    }

    /// Record that the whole screen owes a lossless paint (resize, surface
    /// rebuild, a frame that never reached the wire).
    fn owe_everything(&mut self, cause: DebtCause) {
        self.stat_debt[cause.idx()] += 1;
        self.pending_full = true;
        self.debt_rect = None;
    }

    /// The region to repaint for the outstanding debt, clamped to the frame.
    fn debt_region(&self, width: u16, height: u16) -> (u16, u16, u16, u16) {
        match self.debt_rect {
            None => (0, 0, width, height),
            Some((x, y, w, h)) => {
                let x = x.min(width);
                let y = y.min(height);
                (x, y, w.min(width - x), h.min(height - y))
            }
        }
    }

    /// How many pixels one lossless paint may cover, from the only backpressure
    /// signal the protocol actually defines.
    ///
    /// MS-RDPEGFX 3.2.5.13: the server SHOULD throttle "if the queueDepth field
    /// is in the range 0x00000001 to 0xFFFFFFFE" — that range is the whole
    /// mandate. `queueDepth == 0` is the client reporting an empty decode queue,
    /// i.e. explicitly *not* lagging, so there is nothing to throttle and the
    /// paint goes out whole. Above zero the budget shrinks with the room left
    /// before [`CLIENT_QUEUE_BACKOFF`], where the pipeline stops sending.
    ///
    /// Two tempting inputs are deliberately NOT used:
    /// - `bw_kbps`: MS-RDPBCGR 3.2.5.14 computes it as `(byteCount * 8) /
    ///   timeDelta` over "the PDUs sent from server to client", so on a quiet
    ///   session it measures our own output. Feeding it back here made the
    ///   budget chase itself downward.
    /// - QoE timings: MS-RDPEGFX 3.2.5.21 says they "SHOULD only be used for
    ///   informational and debugging purposes".
    ///
    /// The previous formula budgeted an eighth of a second of a fixed H.264
    /// bitrate anchor so "audio never queues behind one". Measured on this
    /// path: `SharedWriter` `lock_wait_ms` was 0 across 34113 samples with a
    /// largest single write of 448 KB at `write_ms` ≤ 1 — the head-of-line cost
    /// it was guarding against was not there, while the anchor cut a 2880x1800
    /// repaint into 34-row strips that took ~30 s to walk down the screen.
    fn lossless_budget_px(&self, handle: &GfxHandle) -> u32 {
        // Bound the guard to this statement: `send_clear` locks the same mutex
        // a few lines later in the caller.
        let depth = Self::lock_handle(handle).fresh_client_queue_depth();
        let headroom_bytes = match depth {
            // No usable measurement (no ack yet, acks suspended, or the sample
            // has expired) or a client reporting zero backlog: no throttle.
            None | Some(0) => return u32::MAX,
            Some(depth) => CLIENT_QUEUE_BACKOFF.saturating_sub(depth),
        };
        let px = f64::from(headroom_bytes) / self.clear_bytes_per_px;
        let floor = f64::from(u32::from(MIN_BAND_ROWS) * 64);
        // Precision guard: clamped into [floor, u32::MAX] before the cast.
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "clamped to a u32 range"
        )]
        let px = px.clamp(floor, f64::from(u32::MAX)) as u32;
        px
    }

    /// Fold one finished ClearCodec encode into the compression-ratio estimate
    /// that sizes the next band.
    ///
    /// [`CLEARCODEC_BYTES_PER_PX`] is only a bootstrap value, and a deliberately
    /// pessimistic one. Measured on a real desktop it overstates the true cost
    /// about fivefold, which shrank every band by the same factor on top of the
    /// budget error above.
    fn record_clear_ratio(&mut self, bytes: usize, w: u16, h: u16) {
        let px = f64::from(u32::from(w) * u32::from(h));
        if px <= 0.0 {
            return;
        }
        // Precision guard: an encoded frame is far below 2^53 bytes.
        #[expect(clippy::cast_precision_loss, reason = "encoded sizes are small")]
        let ratio = bytes as f64 / px;
        self.clear_bytes_per_px =
            (self.clear_bytes_per_px * (1.0 - CLEAR_RATIO_ALPHA) + ratio * CLEAR_RATIO_ALPHA).max(MIN_CLEAR_BYTES_PER_PX);
    }

    /// Pay off the outstanding lossless debt over `rect`. The debt is only
    /// cleared once the paint actually reached the wire — a frame dropped by
    /// backpressure leaves the pixels stale, so the debt must survive it.
    #[expect(clippy::too_many_arguments, reason = "mirrors send_clear's frame + rect signature")]
    async fn repay_debt(
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
        if w == 0 || h == 0 {
            self.pending_full = false;
            self.debt_rect = None;
            return;
        }
        let (band, remainder) = split_debt_band((x, y, w, h), self.lossless_budget_px(handle));
        let (bx, by, bw, bh) = band;
        if self.send_clear(handle, data, frame_w, frame_h, bx, by, bw, bh).await {
            let (pending, rect) = settle_debt(remainder);
            self.pending_full = pending;
            self.debt_rect = rect;
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
        // AVC444v2 (4:4:4 color) needs both halves: `features.avc444v2` in the
        // configuration, and a client that negotiated cap version >= 10.6.
        self.avc444v2_enabled = server.supports_avc444v2() && self.avc444v2_allowed;

        // The surface is the REAL desktop, never the 16-aligned encoder size.
        // MS-RDPEGFX 3.3.8.3.3: "Color conversion MUST be performed for the
        // entire macroblock, after which the region mask in regionRects MUST
        // be applied" — the 16-alignment belongs to the encoder, and a region
        // is free to end at 1800. Sizing the surface to the padding instead
        // is what put an 8-row strip on screen below a 1800 px desktop,
        // flipping between black (full ClearCodec paint) and replicated edge
        // content (motion frames).
        let Some(id) = server.create_surface_with_format(width, height, PixelFormat::XRgb) else {
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

        tracing::info!(
            surface = id,
            width,
            height,
            pad_width,
            pad_height,
            avc444v2 = self.avc444v2_enabled,
            avc_disabled = self.avc_disabled,
            "EGFX surface created"
        );
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
        // Hold while motion is not sustained (see MIN_MOTION_FRAMES_PER_EVAL):
        // measured goodput on a quiet screen is what WE are sending, not what
        // the network supports. The timestamp is intentionally left fresh so
        // the cheap gate re-runs per frame until motion resumes.
        let motion_delta = self.motion_frames - self.motion_frames_mark;
        self.motion_frames_mark = self.motion_frames;
        if motion_delta < MIN_MOTION_FRAMES_PER_EVAL {
            self.last_quality_update = Instant::now();
            return;
        }
        self.last_quality_update = Instant::now();

        let Some(surface) = self.surface else { return };
        let pixels = f64::from(surface.width) * f64::from(surface.height);
        if pixels <= 0.0 {
            return;
        }
        let full_kbit = full_quality_kbit(pixels);

        let avg_rtt = self.rtt.load(Ordering::Relaxed);
        let min_rtt = self.rtt_baseline.load(Ordering::Relaxed);
        // Sub-millisecond LAN samples are whole-millisecond quantized (0/1 ms)
        // and would make `avg > min*1.5` fire on pure noise — KRdp guards the
        // same comparison with `min > 0`. Only declare congestion when the
        // session minimum is at least the plausibility floor, i.e. there is
        // enough resolution for queueing to show up at all.
        let congested = f64::from(min_rtt) >= MIN_VALID_RTT_MS
            && avg_rtt != u32::MAX
            && f64::from(avg_rtt) > f64::from(min_rtt) * 1.5;

        // Two real strain signals gate the quality target: RTT inflation
        // (queueing on the path) and client backpressure (decode queue full).
        // Measured goodput alone is NOT a strain signal — it counts what we
        // just sent (MS-RDPBCGR 3.2.5.14), so on a healthy link it is our own
        // output rather than the network's capacity. Letting it drive the
        // target created a self-referential spiral down to the quality floor
        // (measured: quality 100 -> 10 during plain text scrolling on a
        // 1 ms LAN with in_flight=1 and zero backpressure).
        let strained = congested || self.backpressure_events > 0;
        let backpressure_events = self.backpressure_events;
        self.backpressure_events = 0;
        self.bitrate_boost = if strained { 1.0 } else { UNSTRAINED_BITRATE_BOOST };

        let mut target = if strained {
            ((f64::from(goodput_kbit) / full_kbit) * 100.0)
                .round()
                .clamp(f64::from(MIN_ADAPTIVE_QUALITY), 100.0)
        } else {
            // No strain: hold the full-quality target regardless of how many
            // bytes the encoder happened to emit.
            100.0
        };
        // Precision guard: the value is clamped into 10..=100 above, so the
        // f64→i32 cast cannot truncate.
        #[expect(clippy::as_conversions, clippy::cast_possible_truncation, reason = "clamped to 10..=100")]
        let mut target = target as i32;

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
        // Precision guard: the boost only ever holds 1.0 or 3.0.
        #[expect(clippy::as_conversions, clippy::cast_sign_loss, reason = "boost is 1.0 or 3.0")]
        let bitrate_boost_u64 = self.bitrate_boost as u64;
        tracing::info!(
            quality = next,
            target,
            goodput_kbit,
            congested,
            backpressure_events,
            bitrate_boost = bitrate_boost_u64,
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
        let kbit = full_quality_kbit(pixels) * f64::from(self.quality) / 100.0 * self.bitrate_boost;
        // Precision guard: the kbit figure is clamped to a sane bitrate range.
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "clamped to 250 kbit/s..50 Mbit/s"
        )]
        let bps = (kbit * 1000.0).clamp(250_000.0, f64::from(H264_BITRATE_CEILING_BPS)) as u32;
        bps
    }

    /// Rate-control frame-rate assumption for the encoder: the measured
    /// producer rate, clamped. OpenH264 spreads the target bitrate across
    /// this many frames per second, so it has to match what we actually
    /// produce — otherwise the emitted stream undershoots the target by
    /// (assumed/actual) and the goodput-driven adaptation misreads that as a
    /// slow network.
    fn h264_rc_fps(&self) -> f32 {
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "clamped to ENC_RC_FPS_MIN..ENC_RC_FPS_MAX"
        )]
        let fps = self.producer_fps.clamp(ENC_RC_FPS_MIN, ENC_RC_FPS_MAX) as f32;
        fps
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
    ) -> bool {
        let Some(surface) = self.surface else { return false };
        let Some(mut encoders) = self.take_encoders() else { return false };
        let ts = self.timestamp_ms();
        // MS-RDPEGFX 2.2.4.1: seqNumber is a SESSION counter — "the value of
        // the seqNumber field MUST be equal to the value of the seqNumber
        // field in the previous ClearCodec message plus one". The encoder
        // object is rebuilt under us (adaptive bitrate, a lost blocking task),
        // so the counter is owned here and stamped on every encode; it is
        // committed further down only once the frame actually reaches the
        // wire, because a frame dropped by backpressure must not burn a
        // number the client will never see.
        encoders.clear.set_sequence(self.clear_seq);
        // A full paint covers the real desktop rows. The encoder's 16-aligned
        // padding is never part of the surface any more, so there is nothing
        // below `frame_h` to keep painted.
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
            return false;
        };
        self.encoders = Some(encoders);
        // Learn this content's real compression ratio before the next band is
        // sized — recorded on encode, not on delivery, because a frame the
        // pipeline rejects still tells the truth about the bytes per pixel.
        self.record_clear_ratio(stream.len(), w, h);

        let dest = ExclusiveRectangle {
            left: x,
            top: y,
            right: x + w,
            bottom: y + h,
        };
        let mut server = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let sent = server.send_clearcodec_frame(surface.id, dest, stream, ts);
        drop(server);

        // Counted on OFFER, not on delivery. `update_in_flight_window` sizes the
        // window from this rate and its own comment claims the rate is measured
        // upstream of the window "so the estimate cannot feed back into itself" —
        // which only holds if a frame the window rejected still counts as
        // produced. Counting deliveries made it a feedback loop: a starved
        // producer decayed to MIN_PRODUCER_FPS and pinned the window at
        // MIN_IN_FLIGHT, which starved it further.
        self.producer_frames += 1;
        let delivered = sent.is_some();
        if delivered {
            // The message is on the wire: the session's next ClearCodec
            // message carries this one plus one.
            tracing::debug!(
                seq = self.clear_seq,
                full,
                w,
                h,
                "EGFX ClearCodec frame sent"
            );
            self.clear_seq = self.clear_seq.wrapping_add(1);
            self.stat_clear += 1;
            if x == 0 && y == 0 && w == frame_w && h == frame_h {
                self.stat_full_paints += 1;
            }
        } else {
            // Dropped (backpressure): this grab's pixels are already consumed
            // from the damage tracker, so only a later lossless paint can
            // deliver them — the region stays owed.
            self.owe_region(x, y, w, h, DebtCause::ClearSendFailed);
            // See the matching note in send_h264: an actual rejection is the
            // strain signal the quality loop needs.
            self.backpressure_events += 1;
        }
        self.record_drained(self.session.drain_and_send(handle));
        delivered
    }

    /// Full-frame H.264 encode for motion.
    /// Returns whether the client's view is now current *via H.264*, i.e.
    /// whether the caller may enter (or stay in) motion mode.
    ///
    /// `false` covers every path that did not put this grab's pixels on the
    /// wire as an H.264 frame: no surface, AVC disabled or broken (those repay
    /// the debt losslessly instead), a failed encode, and a frame the pipeline
    /// rejected. Motion mode suppresses the lossless partial path, so claiming
    /// it after a frame that never shipped strands those pixels until some
    /// later repaint — with AVC disabled, permanently.
    async fn send_h264(&mut self, handle: &GfxHandle, data: Vec<u8>, w: u16, h: u16) -> bool {
        let Some(surface) = self.surface else { return false };

        if self.avc_disabled {
            self.repay_debt(handle, data, w, h, 0, 0, w, h).await;
            return false;
        }

        // Adaptive encoder config: (re)build whenever the target bitrate
        // drifted more than 25% or the rate-control frame-rate assumption more
        // than 25% from what the running one was built with. Quality steps are
        // throttled to QUALITY_UPDATE_INTERVAL; the wide hysteresis matters
        // because every rebuild opens with an IDR (a ~0.5-1 MB burst at these
        // bitrates) that itself spikes the measured goodput — a tight
        // threshold made the encoder rebuild every step and the IDR bursts
        // fed the quality oscillation right back.
        let target_bitrate = self.h264_bitrate_bps();
        let target_rate_fps = self.h264_rc_fps();
        // Stale means "no usable H.264 encoder at the current target": missing
        // entirely (first motion frame, post-stall reset), or built at a
        // config that drifted from the current adaptive target.
        let bitrate_stale = match (
            self.encoders.as_ref().is_some_and(|e| e.h264.is_some()),
            self.enc_built,
        ) {
            (true, Some((built_bitrate, built_rate_fps))) => {
                let lo = built_bitrate.min(target_bitrate);
                let hi = built_bitrate.max(target_bitrate);
                if hi - lo > built_bitrate / 4 {
                    true
                } else {
                    // >25% rate-control fps drift.
                    (built_rate_fps - target_rate_fps).abs() > built_rate_fps * 0.25
                }
            }
            _ => true,
        };
        if bitrate_stale {
            let encoders_clear = self.encoders.take().map(|e| e.clear);
            match make_h264_encoder(
                target_bitrate,
                target_rate_fps,
                surface.pad_width,
                surface.pad_height,
            ) {
                Ok(enc) => {
                    // Carry the ClearCodec encoder across the rebuild: its
                    // sequence counter and glyph cache belong to the session,
                    // not to the H.264 encoder's lifetime.
                    let clear = encoders_clear.unwrap_or_default();
                    self.encoders = Some(Encoders {
                        h264: Some(enc),
                        clear,
                    });
                    self.enc_built = Some((target_bitrate, target_rate_fps));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "EGFX: x264 init failed — ClearCodec only");
                    self.avc_disabled = true;
                    self.repay_debt(handle, data, w, h, 0, 0, w, h).await;
                    return false;
                }
            }
        }
        let Some(mut encoders) = self.take_encoders() else { return false };

        let (pw, ph) = (surface.pad_width, surface.pad_height);
        let ts = self.timestamp_ms();
        let avc444v2 = self.avc444v2_enabled;

        let joined = tokio::task::spawn_blocking(move || {
            // Materialize the bitstreams inside the closure: EncodedBitStream
            // borrows the encoder's internal buffer and is not Send.
            if avc444v2 {
                let (luma, chroma) = bgrx_to_yuv444v2(
                    &data,
                    usize::from(w),
                    usize::from(h),
                    usize::from(pw),
                    usize::from(ph),
                );
                // [MS-RDPEGFX 2.2.4.6]: both subframes "MUST be encoded using
                // the same MPEG-4 AVC/H.264 encoder and decoded by a single
                // MPEG-4 AVC/H.264 decoder as one stream" — so the luma view
                // and the chroma view go through THIS encoder back to back,
                // as two consecutive frames of one stream. The client's single
                // decoder sees them in the same order, so both sides agree on
                // the reference chain.
                let Some(enc) = encoders.h264.as_mut() else {
                    return (encoders, None, None);
                };
                let luma_bs = enc.encode_planes(luma.y(), luma.u(), luma.v());
                let chroma_bs = enc.encode_planes(chroma.y(), chroma.u(), chroma.v());
                (encoders, Some(luma_bs), Some(chroma_bs))
            } else {
                let yuv = bgrx_to_yuv420(&data, usize::from(w), usize::from(h), usize::from(pw), usize::from(ph));
                let luma_bs = encoders
                    .h264
                    .as_mut()
                    .map(|enc| enc.encode_planes(yuv.y(), yuv.u(), yuv.v()));
                (encoders, luma_bs, None)
            }
        })
        .await;

        let Ok((encoders, luma_bs, chroma_bs)) = joined else {
            tracing::error!("H.264 encode task failed to join — motion frame dropped");
            return false;
        };
        self.encoders = Some(encoders);

        let Some(luma_bitstream) = luma_bs else {
            // No encoder: recover with a lossless full paint.
            self.owe_everything(DebtCause::NoEncoder);
            return false;
        };
        if luma_bitstream.is_empty() {
            // The encoder skipped unchanged input: nothing went out, but the
            // client's view already matches these pixels, so motion mode is
            // still telling the truth.
            return true;
        }

        // Region rects cover the real desktop, for both v1 and v2. The
        // encoder works on the 16-aligned buffer, but MS-RDPEGFX 3.3.8.3.3
        // applies regionRects as a mask AFTER whole-macroblock conversion, so
        // a region ending on an unaligned row is exactly what the spec
        // intends — and the padding never reaches the screen.
        let (region_right, region_bottom): (u16, u16) = (w, h);
        let region = Avc420Region {
            left: 0,
            top: 0,
            right: region_right,
            bottom: region_bottom,
            quantization_parameter: 21, // low QP = high quality
            quality: 90,
        };
        let chroma_region = Avc420Region { ..region.clone() };
        let mut server = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let sent = if avc444v2 {
            let chroma_bitstream = chroma_bs.unwrap_or_default();
            // LC=1 fallback when the encoder produced nothing for the chroma
            // view (MS-RDPEGFX 2.2.4.6, LC value 0x1): the client keeps the
            // luma update and waits for the matching chroma view in a later
            // v2 frame.
            if chroma_bitstream.is_empty() {
                server.send_avc444v2_frame(
                    surface.id,
                    Encoding::LUMA,
                    &luma_bitstream,
                    &[region],
                    None,
                    None,
                    ts,
                )
            } else {
                server.send_avc444v2_frame(
                    surface.id,
                    Encoding::LUMA_AND_CHROMA,
                    &luma_bitstream,
                    &[region],
                    Some(&chroma_bitstream),
                    Some(&[chroma_region]),
                    ts,
                )
            }
        } else {
            server.send_avc420_frame(surface.id, &luma_bitstream, &[region], ts)
        };
        drop(server);

        // On offer, not on delivery — see the note in `send_clear`.
        self.producer_frames += 1;
        let delivered = sent.is_some();
        if delivered {
            self.stat_h264 += 1;
            self.motion_frames += 1;
            self.last_sent += 1;
            self.last_h264 = Instant::now();
            self.pending_full = false;
            self.debt_rect = None;
        } else {
            // A frame that never reached the wire breaks the P-frame
            // reference chain: the encoder counts it as history the client's
            // decoder never saw, and every following frame decodes as
            // progressively wrong colors (observed: the image appears,
            // decays, then nothing). The next frame must restart both
            // streams from a clean IDR.
            tracing::warn!("H.264 frame send failed — forcing an IDR on both substreams");
            if let Some(Encoders { h264: Some(enc), .. }) = self.encoders.as_mut() {
                enc.force_intra();
            }
            self.owe_everything(DebtCause::H264SendFailed);
            // A rejected send IS the strain signal. Counting only the
            // pre-encode `should_backpressure()` polls misses exactly the
            // drops that matter, so the adaptive quality loop never learns
            // about them.
            self.backpressure_events += 1;
        }
        self.record_drained(self.session.drain_and_send(handle));
        delivered
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
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "durations are non-negative milliseconds"
        )]
        let (grab_ms, process_ms, busy_ms) = (self.grab_ms as u64, self.process_ms as u64, self.busy_ms as u64);
        tracing::info!(
            source,
            polls = self.hb_polls,
            damaged = self.hb_damaged,
            suppressed = self.suppressed.load(Ordering::Relaxed),
            in_motion = self.in_motion,
            pending_full = self.pending_full,
            grab_ms,
            process_ms,
            busy_ms,
            "EGFX display heartbeat (5s window)"
        );
        self.hb_polls = 0;
        self.hb_damaged = 0;
        self.busy_ms = 0.0;
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
            let debt: String = DebtCause::NAMES
                .iter()
                .zip(self.stat_debt.iter())
                .filter(|(_, n)| **n > 0)
                .map(|(name, n)| format!("{name}={n}"))
                .collect::<Vec<_>>()
                .join(" ");
            tracing::info!(
                frames = self.stat_frames,
                h264 = self.stat_h264,
                clear = self.stat_clear,
                full_paints = self.stat_full_paints,
                bytes = self.stat_bytes,
                in_flight,
                damaged_grabs = self.stat_damaged_grabs,
                motion_grabs = self.stat_motion_grabs,
                tiles_peak_pct = self.stat_tiles_peak_pct,
                debt = %debt,
                "EGFX stats (10s window)"
            );
            self.stat_frames = 0;
            self.stat_h264 = 0;
            self.stat_clear = 0;
            self.stat_bytes = 0;
            self.stat_debt = [0; DebtCause::COUNT];
            self.stat_motion_grabs = 0;
            self.stat_damaged_grabs = 0;
            self.stat_tiles_peak_pct = 0;
            self.stat_full_paints = 0;
            self.stat_last = Instant::now();
        }
    }
}


/// Convert a BGRX grab into macroblock-padded I420 planes, **full-range
/// BT.709**, split across worker threads (single-threaded the conversion
/// costs ~20 ms at 2880x1800 — comparable to the encode itself).
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
    let mut yuv = vec![0u8; 3 * (pw * ph) / 2];
    let (y_len, u_len) = (pw * ph, pw * ph / 4);
    let (y_plane, rest) = yuv.split_at_mut(y_len);
    let (u_plane, v_plane) = rest.split_at_mut(u_len);

    let chroma_rows = ph / 2;
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 8)
        .min(chroma_rows);
    let rows_per_worker = chroma_rows.div_ceil(workers);
    let chunk_count = chroma_rows.div_ceil(rows_per_worker);
    let starts: Vec<usize> = (0..chunk_count).map(|c| c * rows_per_worker).collect();
    let ys = split_row_chunks(y_plane, rows_per_worker, 2 * pw, chunk_count);
    let us = split_row_chunks(u_plane, rows_per_worker, pw / 2, chunk_count);
    let vs = split_row_chunks(v_plane, rows_per_worker, pw / 2, chunk_count);

    std::thread::scope(|scope| {
        for (((j0, y), u), v) in starts.into_iter().zip(ys).zip(us).zip(vs) {
            let j1 = (j0 + rows_per_worker).min(chroma_rows);
            scope.spawn(move || convert_rows(src, w, h, pw, y, u, v, j0, j1));
        }
    });
    openh264::formats::YUVBuffer::from_vec(yuv, pw, ph)
}

/// Split `slice` into at most `count` consecutive chunks of
/// `rows_per_chunk * row_len` bytes (the tail chunk may be shorter).
fn split_row_chunks(slice: &mut [u8], rows_per_chunk: usize, row_len: usize, count: usize) -> Vec<&mut [u8]> {
    let mut chunks = Vec::with_capacity(count);
    let mut rest = slice;
    for _ in 0..count {
        let take = (rows_per_chunk * row_len).min(rest.len());
        let (head, tail) = rest.split_at_mut(take);
        chunks.push(head);
        rest = tail;
    }
    chunks
}

/// Convert chroma-row range `[j0, j1)` (source rows `2*j0 .. 2*j1`) into the
/// provided Y/U/V slices — full-range BT.709, padding stays black.
fn convert_rows(
    src: &[u8],
    w: usize,
    h: usize,
    pw: usize,
    y_plane: &mut [u8],
    u_plane: &mut [u8],
    v_plane: &mut [u8],
    j0: usize,
    j1: usize,
) {
    let stride = w * 4;
    // Pixel accessor: real (R, G, B) inside the frame, black in the padding.
    let px = |x: usize, y: usize| -> (i32, i32, i32) {
        if x < w && y < h {
            let off = y * stride + x * 4;
            (i32::from(src[off + 2]), i32::from(src[off + 1]), i32::from(src[off]))
        } else {
            (0, 0, 0)
        }
    };

    for j in j0..j1 {
        let j_local = j - j0;
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
            u_plane[j_local * (pw / 2) + i] = cb.clamp(0, 255) as u8;
            v_plane[j_local * (pw / 2) + i] = cr.clamp(0, 255) as u8;

            // Luma per pixel (full-range BT.709: 54/183/18, sum 255).
            for (p, (dx, dy)) in [(p00, (0usize, 0usize)), (p01, (0, 1)), (p10, (1, 0)), (p11, (1, 1))] {
                let y_val = (54 * p.0 + 183 * p.1 + 18 * p.2) >> 8;
                y_plane[(j_local * 2 + dy) * pw + (i * 2 + dx)] = y_val.clamp(0, 255) as u8;
            }
        }
    }
}

/// Convert a BGRX grab into the two YUV420 views of the AVC444v2 layout
/// (MS-RDPEGFX 3.3.8.3.3): the luma view carries full-resolution Y with
/// 2x2-subsampled U/V (identical to the AVC420 path), and the chroma view
/// carries the full-resolution chroma distributed so a compliant decoder can
/// reconstruct U/V at 4:4:4. Port of FreeRDP's
/// `general_RGBToAVC444YUVv2_BGRX` (libfreerdp/primitives/prim_YUV.c) with
/// our full-range BT.709 conversion.
///
/// The chroma view's Y plane (full resolution) holds, per source row pair:
/// even row — left half U444 at odd source columns, right half V444 at odd
/// columns; odd row — same for the odd source row. The chroma view's U plane
/// carries the even source columns of the odd row (U left, V right), and the
/// V plane the odd source columns of the odd row (U left, V right).
fn bgrx_to_yuv444v2(
    src: &[u8],
    w: usize,
    h: usize,
    pw: usize,
    ph: usize,
) -> (openh264::formats::YUVBuffer, openh264::formats::YUVBuffer) {
    let mut luma = vec![0u8; 3 * (pw * ph) / 2];
    let mut chroma = vec![0u8; 3 * (pw * ph) / 2];
    let (ly, rest) = luma.split_at_mut(pw * ph);
    let (lu, lv) = rest.split_at_mut(pw * ph / 4);
    let (cy, rest2) = chroma.split_at_mut(pw * ph);
    let (cu, cv) = rest2.split_at_mut(pw * ph / 4);

    let pairs = ph / 2;
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 8)
        .min(pairs.max(1));
    let pairs_per_worker = pairs.div_ceil(workers);
    let chunk_count = pairs.div_ceil(pairs_per_worker);
    let j0s: Vec<usize> = (0..chunk_count).map(|c| c * pairs_per_worker).collect();
    // Luma Y and chroma Y carry two rows per pair; the sub-sampled planes
    // one. Each plane is pre-split into per-worker chunks so the scoped
    // threads get disjoint regions.
    let lys = split_row_chunks(ly, 2 * pairs_per_worker, pw, chunk_count);
    let lus = split_row_chunks(lu, pairs_per_worker, half_of(pw), chunk_count);
    let lvs = split_row_chunks(lv, pairs_per_worker, half_of(pw), chunk_count);
    let cys = split_row_chunks(cy, 2 * pairs_per_worker, pw, chunk_count);
    let cus = split_row_chunks(cu, pairs_per_worker, half_of(pw), chunk_count);
    let cvs = split_row_chunks(cv, pairs_per_worker, half_of(pw), chunk_count);

    std::thread::scope(|scope| {
        for ((((j0, ly), lu), (lv, cy)), (cu, cv)) in j0s
            .into_iter()
            .zip(lys)
            .zip(lus)
            .zip(lvs.into_iter().zip(cys))
            .zip(cus.into_iter().zip(cvs))
        {
            let j1 = (j0 + pairs_per_worker).min(pairs);
            scope.spawn(move || {
                convert_rows_v2(src, w, h, pw, ly, lu, lv, cy, cu, cv, j0, j1);
            });
        }
    });

    (
        openh264::formats::YUVBuffer::from_vec(luma, pw, ph),
        openh264::formats::YUVBuffer::from_vec(chroma, pw, ph),
    )
}

/// Bootstrap ClearCodec output per source pixel, until real encodes replace it.
///
/// Measured on real desktop content a 2880x1800 full-screen paint encodes to
/// 1,069,809 bytes, i.e. ~0.21 B/px; this starts at the pessimistic end and
/// [`EgfxUpdates::record_clear_ratio`] converges it onto whatever the actual
/// content costs. It used to be the permanent value, which understated every
/// band by ~5x.
const CLEARCODEC_BYTES_PER_PX: f64 = 1.0;

/// Weight of the newest encode in the bytes-per-pixel estimate.
const CLEAR_RATIO_ALPHA: f64 = 0.25;

/// Floor for the bytes-per-pixel estimate. A few flat bands in a row can drive
/// the ratio to near zero, and dividing the byte headroom by that would hand
/// back an unbounded pixel budget just before busy content arrives.
const MIN_CLEAR_BYTES_PER_PX: f64 = 0.02;

/// Minimum band height, so a tight budget cannot degenerate into hundreds of
/// one-row PDUs whose headers cost more than their pixels.
const MIN_BAND_ROWS: u16 = 16;

/// Split `rect` into the slice that fits `budget_px` and the remainder still
/// owed, as `(paint_now, still_owed)`.
///
/// A lossless repaint of a 2880x1800 desktop is ~1 MB in a single PDU. On a
/// link that measures ~17 Mb/s that is most of a second on the wire, and
/// every small packet behind it — audio above all — waits for it: a 24-byte
/// write was measured taking 7 ms and a 5.6 KB write 25 ms, while a 2.25 MB
/// write into a fresh socket buffer took 5. Painting in bands spreads the
/// same pixels over consecutive frames and keeps the pipe available.
fn split_debt_band(rect: (u16, u16, u16, u16), budget_px: u32) -> ((u16, u16, u16, u16), Option<(u16, u16, u16, u16)>) {
    let (x, y, w, h) = rect;
    if w == 0 || h == 0 {
        return (rect, None);
    }
    let area = u32::from(w) * u32::from(h);
    if area <= budget_px {
        return (rect, None);
    }
    let rows = (budget_px / u32::from(w)).max(u32::from(MIN_BAND_ROWS));
    let Ok(rows) = u16::try_from(rows) else {
        return (rect, None); // budget wider than the rect can be split
    };
    if rows >= h {
        return (rect, None);
    }
    ((x, y, w, rows), Some((x, y + rows, w, h - rows)))
}

/// Debt bookkeeping after one band reached the wire: what the debt becomes.
///
/// `debt_rect: Some(_)` MUST imply `pending_full == true`. That pair is the
/// only representation of "part of the screen still owes a lossless paint",
/// and the repayment gates in `egfx_frame` read `pending_full` alone.
///
/// Setting the remainder without re-arming `pending_full` stranded it: the
/// x264-init-failure path calls `repay_debt` directly, with no `pending_full`
/// precondition, so a failed encoder build left almost the whole screen owing
/// a paint that nothing would ever trigger — while the producer's own
/// bookkeeping reported no debt at all. Deriving both fields from one place
/// makes that state unrepresentable regardless of who calls in.
fn settle_debt(remainder: Option<(u16, u16, u16, u16)>) -> (bool, Option<(u16, u16, u16, u16)>) {
    match remainder {
        Some(rest) => (true, Some(rest)),
        None => (false, None),
    }
}

/// A `DisplayUpdate::Resize` when a legacy frame no longer has the size of
/// the client's desktop, recorded in `known` for the frames after it.
fn legacy_resize(known: &mut Option<(u16, u16)>, width: u16, height: u16) -> Option<DisplayUpdate> {
    let previous = known.replace((width, height))?;
    if previous == (width, height) {
        return None;
    }
    tracing::info!(
        ?previous,
        width,
        height,
        "desktop size changed on the legacy path: deactivation-reactivation"
    );
    Some(DisplayUpdate::Resize(DesktopSize { width, height }))
}

#[cfg(test)]
mod legacy_resize_tests {
    use super::*;

    fn resized_to(update: Option<DisplayUpdate>) -> Option<(u16, u16)> {
        match update {
            Some(DisplayUpdate::Resize(size)) => Some((size.width, size.height)),
            None => None,
            Some(other) => panic!("expected a resize, got {other:?}"),
        }
    }

    /// MS-RDPEDISP 1.3: without the graphics pipeline, a new desktop size
    /// takes a Deactivation-Reactivation Sequence.
    ///
    /// Regression: the legacy path sent bitmaps of the new size into the
    /// client's old desktop.
    #[test]
    fn a_legacy_frame_of_another_size_resizes_the_desktop_once() {
        let mut known = Some((1920, 1080));

        assert_eq!(resized_to(legacy_resize(&mut known, 1920, 1080)), None);
        assert_eq!(resized_to(legacy_resize(&mut known, 1600, 900)), Some((1600, 900)));
        assert_eq!(resized_to(legacy_resize(&mut known, 1600, 900)), None, "only once");
    }

    #[test]
    fn an_unknown_size_is_adopted_without_a_resize() {
        let mut known = None;

        assert_eq!(resized_to(legacy_resize(&mut known, 1600, 900)), None);
        assert_eq!(known, Some((1600, 900)));
    }
}

/// Smallest rectangle containing both inputs, as (x, y, w, h).
fn union_rect(a: (u16, u16, u16, u16), b: (u16, u16, u16, u16)) -> (u16, u16, u16, u16) {
    let left = a.0.min(b.0);
    let top = a.1.min(b.1);
    let right = (a.0 + a.2).max(b.0 + b.2);
    let bottom = (a.1 + a.3).max(b.1 + b.3);
    (left, top, right - left, bottom - top)
}

fn half_of(pw: usize) -> usize {
    pw / 2
}

/// Mean of four i32 component samples, saturated to u8 (always in 0..=1020/4).
fn v8_mean(sum: i32) -> u8 {
    u8::try_from(sum / 4).unwrap_or(u8::MAX)
}

/// Convert row-pair range `[j0, j1)` (source rows `2*j0 .. 2*j1`) into the
/// provided AVC444v2 view planes: luma Y (2 rows per pair) + sub-sampled
/// U/V (1 row per pair), and the chroma view's Y (2 rows) + U/V (1 row).
#[expect(clippy::too_many_arguments, reason = "worker signature over the six plane chunks of one row-pair range")]
fn convert_rows_v2(
    src: &[u8],
    w: usize,
    h: usize,
    pw: usize,
    luma_y: &mut [u8],
    luma_u: &mut [u8],
    luma_v: &mut [u8],
    chroma_y: &mut [u8],
    chroma_u: &mut [u8],
    chroma_v: &mut [u8],
    j0: usize,
    j1: usize,
) {
    let stride = w * 4;
    // Full-range BT.709 per component. Coordinates outside the real frame
    // (the 16-macroblock padding) replicate the nearest real pixel: mstsc
    // composites the padded bottom strip (v2 regions must cover the whole
    // surface), and any constant fill shows up as a colored band.
    let yuv_at = |x: usize, y: usize| -> (u8, u8, u8) {
        let x = x.min(w - 1);
        let y = y.min(h - 1);
        let off = y * stride + x * 4;
        let b = i32::from(src[off]);
        let g = i32::from(src[off + 1]);
        let r = i32::from(src[off + 2]);
        // Precision guard: each formula is clamped to 0..=255, so the casts
        // cannot truncate or wrap.
        #[expect(
            clippy::as_conversions,
            clippy::cast_sign_loss,
            reason = "clamped to 0..=255"
        )]
        let (yv, uv, vv) = (
            ((54 * r + 183 * g + 18 * b) >> 8).clamp(0, 255) as u8,
            (((-29 * r - 99 * g + 128 * b) >> 8) + 128).clamp(0, 255) as u8,
            (((128 * r - 116 * g - 12 * b) >> 8) + 128).clamp(0, 255) as u8,
        );
        (yv, uv, vv)
    };

    // Plane geometry: `half` is the chroma-view Y plane's left/right half
    // width, `quarter` the chroma U/V plane's left/right half width. All
    // destination indices are CHUNK-LOCAL (the planes arrive split per
    // worker); only the source sampling uses global coordinates.
    let half = pw / 2;
    let quarter = half / 2;
    for j in j0..j1 {
        let j_local = j - j0;
        let ye_global = 2 * j;
        let yo_global = yo_of(j);
        let ye = 2 * j_local;
        let yo = ye + 1;

        for x2 in 0..half {
            let xe_src = 2 * x2;
            let xo_src = xe_src + 1;
            let ye_src = ye_global;
            let yo_src = yo_global;

            let (y00, u00, v00) = yuv_at(xe_src, ye_src);
            let (y01, u01, v01) = yuv_at(xo_src, ye_src);
            let (y10, u10, v10) = yuv_at(xe_src, yo_src);
            let (y11, u11, v11) = yuv_at(xo_src, yo_src);

            // Luma view: full-resolution Y, 2x2-averaged chroma [B1, B2, B3].
            // Odd rows past the real height replicate the last real row —
            // skipped writes would leave zeros, which decode as purple.
            luma_y[ye * pw + 2 * x2] = y00;
            luma_y[ye * pw + 2 * x2 + 1] = y01;
            luma_y[yo * pw + 2 * x2] = y10;
            luma_y[yo * pw + 2 * x2 + 1] = y11;
            // The mean of four u8 samples always fits in u8. The sum is
            // computed in i32: u8 arithmetic would overflow for bright
            // pixels (4 x 255).
            let u_sum = i32::from(u00) + i32::from(u01) + i32::from(u10) + i32::from(u11);
            let v_sum = i32::from(v00) + i32::from(v01) + i32::from(v10) + i32::from(v11);
            luma_u[j_local * half + x2] = u8::try_from(u_sum / 4).unwrap_or(u8::MAX);
            luma_v[j_local * half + x2] = v8_mean(v_sum);

            // Chroma view Y, even source row [B4, B5]: odd source columns.
            chroma_y[ye * pw + x2] = u01;
            chroma_y[ye * pw + x2 + half] = v01;
            // Chroma view Y, odd source row [B6-left, B5-odd-right]: odd
            // source columns of the odd row (replicated past the real
            // height — see the luma odd-row note).
            chroma_y[yo * pw + x2] = u11;
            chroma_y[yo * pw + x2 + half] = v11;

            // Chroma view U/V planes [B6/B7, B8/B9]: the even source column
            // of the odd row, split left/right per 4-column group.
            if x2 % 2 == 0 {
                chroma_u[j_local * half + x2 / 2] = u10;
                chroma_u[j_local * half + quarter + x2 / 2] = v10;
            } else {
                chroma_v[j_local * half + x2 / 2] = u10;
                chroma_v[j_local * half + quarter + x2 / 2] = v10;
            }
        }
    }
}

/// The odd source row of the row-pair `j`.
fn yo_of(j: usize) -> usize {
    2 * j + 1
}

#[cfg(test)]
mod debt_region_tests {
    use super::{MIN_BAND_ROWS, settle_debt, split_debt_band, union_rect};

    /// The lossless debt is repaid over the union of the regions that
    /// actually went stale, not the whole screen.
    ///
    /// Regression: every debt was repaid with a full-surface ClearCodec
    /// paint. On a 2880x1800 desktop that is 1.07 MB, and an idle AVC444v2
    /// session emitted 14 of them per 10 s — identical bytes each time,
    /// because the screen was not changing at all.
    #[test]
    fn debt_regions_merge_into_their_bounding_box() {
        // Two small, far-apart rects (a blinking caret and a clock) must not
        // become the whole screen unless they really span it.
        let caret = (100, 200, 8, 16);
        let clock = (2700, 40, 120, 24);

        let merged = union_rect(caret, clock);
        assert_eq!(merged, (100, 40, 2720, 176));

        // Merging is idempotent and order-independent.
        assert_eq!(union_rect(clock, caret), merged);
        assert_eq!(union_rect(merged, caret), merged);
        assert_eq!(union_rect(merged, clock), merged);

        // And still far smaller than a full-screen repaint.
        let full_px = 2880u32 * 1800;
        let merged_px = u32::from(merged.2) * u32::from(merged.3);
        assert!(merged_px * 3 < full_px, "merged {merged_px} px vs full {full_px} px");
    }

    /// A rect fully inside another leaves it unchanged.
    #[test]
    fn a_contained_rect_does_not_grow_the_debt() {
        let outer = (10, 10, 500, 400);
        assert_eq!(union_rect(outer, (20, 20, 100, 100)), outer);
        assert_eq!(union_rect(outer, outer), outer);
    }

    /// `debt_rect: Some(_)` must always imply `pending_full == true`.
    ///
    /// Regression: `repay_debt` set only `debt_rect` when a band left a
    /// remainder, relying on its caller having already armed `pending_full`.
    /// Two call sites in `send_h264` do not — so a failed x264 build painted
    /// one band and stranded the rest of the screen forever, with the
    /// producer reporting no debt owed.
    #[test]
    fn a_remaining_band_keeps_the_debt_armed() {
        let (pending, rect) = settle_debt(Some((0, 128, 2880, 1672)));
        assert!(pending, "a remainder that does not re-arm pending_full is never painted");
        assert_eq!(rect, Some((0, 128, 2880, 1672)));
    }

    #[test]
    fn the_last_band_clears_the_debt() {
        let (pending, rect) = settle_debt(None);
        assert!(!pending);
        assert_eq!(rect, None);
    }

    /// A repaint that fits the per-frame budget goes out whole.
    #[test]
    fn a_small_debt_is_painted_in_one_go() {
        let rect = (0, 0, 400, 300);
        let (band, rest) = split_debt_band(rect, 1_000_000);
        assert_eq!(band, rect);
        assert_eq!(rest, None);
    }

    /// A full-screen repaint is spread over consecutive frames instead of
    /// going out as one multi-megabyte write that audio has to queue behind.
    #[test]
    fn a_full_screen_debt_is_painted_in_bands_covering_every_row() {
        let full = (0u16, 0u16, 2880u16, 1800u16);
        let budget = 265_000; // ~1/8 s of a 17 Mb/s link

        let mut rect = Some(full);
        let mut painted_rows = 0u32;
        let mut bands = 0;
        let mut next_y = 0u16;

        while let Some(current) = rect {
            let (band, rest) = split_debt_band(current, budget);
            assert_eq!(band.0, 0, "bands keep the region's x");
            assert_eq!(band.2, full.2, "bands span the region's width");
            assert_eq!(band.1, next_y, "bands are contiguous, no gaps");
            assert!(
                u32::from(band.2) * u32::from(band.3) <= budget.max(u32::from(band.2) * u32::from(MIN_BAND_ROWS)),
                "a band must fit the budget (or be the minimum height), got {band:?}"
            );
            painted_rows += u32::from(band.3);
            next_y = band.1 + band.3;
            bands += 1;
            assert!(bands < 200, "banding must terminate");
            rect = rest;
        }

        assert_eq!(painted_rows, u32::from(full.3), "every row must be repainted exactly once");
        assert!(bands > 1, "a full screen must not go out as a single write");
    }

    /// An unthrottled client gets the whole repaint at once.
    ///
    /// Regression: the budget came from a fixed H.264 bitrate anchor rather
    /// than from the client, so a 2880x1800 first paint was cut into 53 strips
    /// of 34 rows. Each strip needed its own damage event to go out, which on
    /// an idle desktop arrive ~1.6/s — the screen filled top to bottom over
    /// ~30 s on a 1 Gbit link. MS-RDPEGFX 3.2.5.13 only asks for throttling
    /// while `queueDepth` is in 1..=0xFFFFFFFE; `lossless_budget_px` answers
    /// `u32::MAX` outside that range, and that must mean one band.
    #[test]
    fn an_unthrottled_budget_paints_the_whole_screen_in_one_band() {
        let full = (0u16, 0u16, 2880u16, 1800u16);
        let (band, rest) = split_debt_band(full, u32::MAX);
        assert_eq!(band, full, "no throttle must paint the entire region at once");
        assert_eq!(rest, None, "nothing may be left owed");
    }
}

#[cfg(test)]
mod avc444v2_tests {
    use super::bgrx_to_yuv444v2;

    /// A constant-color frame converted across many worker chunks (j0 > 0 for
    /// most of them) must come out uniformly: every luma Y is the color's Y,
    /// every chroma-view Y is its U (odd columns, clamped at the edge), and
    /// the chroma U/V planes hold the odd-row samples per the B6-B9 split.
    /// Regression for the global-vs-local row indexing panic.
    #[test]
    fn avc444v2_conversion_is_chunk_safe() {
        let (w, h) = (112usize, 80usize);
        let pw = w.div_ceil(16) * 16;
        let ph = h.div_ceil(16) * 16;
        let mut src = vec![0u8; w * h * 4];
        for px in src.chunks_exact_mut(4) {
            px[0] = 30; // B
            px[1] = 160; // G
            px[2] = 240; // R
            px[3] = 0xFF;
        }

        let (luma, chroma) = bgrx_to_yuv444v2(&src, w, h, pw, ph);

        let (b, g, r) = (i32::from(30), i32::from(160), i32::from(240));
        let y_c = ((54 * r + 183 * g + 18 * b) >> 8).clamp(0, 255) as u8;
        let u_c = (((-29 * r - 99 * g + 128 * b) >> 8) + 128).clamp(0, 255) as u8;
        let v_c = (((128 * r - 116 * g - 12 * b) >> 8) + 128).clamp(0, 255) as u8;

        use openh264::formats::YUVSource as _;
        assert!(luma.y().iter().all(|&v| v == y_c), "luma Y must be uniform");
        assert!(luma.u().iter().all(|&v| v == u_c), "luma U must be uniform");
        assert!(luma.v().iter().all(|&v| v == v_c), "luma V must be uniform");

        // Chroma view Y plane: left half carries U of odd source columns,
        // right half V of odd source columns.
        let half = pw / 2;
        let quarter = half / 2;
        for row in 0..ph {
            let row_data = &chroma.y()[row * pw..(row + 1) * pw];
            assert!(
                row_data[..half].iter().all(|&v| v == u_c)
                    && row_data[half..].iter().all(|&v| v == v_c),
                "chroma Y row {row}: left must be U, right V"
            );
        }
        // Chroma U and V planes: each row is [U block | V block] — the left
        // quarter of the plane holds U of the odd row's even source columns,
        // the right quarter holds V of the odd row's odd source columns
        // (even pairs fill the U plane, odd pairs the V plane).
        for row in 0..ph / 2 {
            let u_row = &chroma.u()[row * half..(row + 1) * half];
            let v_row = &chroma.v()[row * half..(row + 1) * half];
            assert!(
                u_row[..quarter].iter().all(|&v| v == u_c)
                    && u_row[quarter..].iter().all(|&v| v == v_c),
                "chroma U row {row}: left must be U, right V"
            );
            assert!(
                v_row[..quarter].iter().all(|&v| v == u_c)
                    && v_row[quarter..].iter().all(|&v| v == v_c),
                "chroma V row {row}: left must be U, right V"
            );
        }
    }
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

#[cfg(test)]
mod egfx_routing_tests {
    use super::{EGFX_READY_DEADLINE, EgfxDecision, EgfxState, LEGACY_GRACE, egfx_decision};

    /// The default: nothing has happened yet, no handle, client silent.
    fn state() -> EgfxState {
        EgfxState {
            ready: false,
            latched: false,
            unavailable: false,
            client_supports: false,
            waited: None,
            since_start: std::time::Duration::ZERO,
        }
    }

    /// MS-RDPEGFX 1.5: a client that did not advertise the graphics pipeline
    /// will refuse the channel, so there is nothing to wait for — not even
    /// through the grace window. This is the case that hung every IronRDP
    /// session: handle published, readiness impossible, frames held forever.
    #[test]
    fn a_client_that_never_advertised_egfx_goes_straight_to_legacy() {
        let s = EgfxState {
            client_supports: false,
            waited: Some(std::time::Duration::ZERO),
            ..state()
        };
        assert_eq!(egfx_decision(s), EgfxDecision::Legacy);

        // Not even before a pipeline server exists, where the grace window
        // would otherwise hold the frame.
        assert_eq!(egfx_decision(EgfxState { waited: None, ..s }), EgfxDecision::Legacy);
    }

    /// MS-RDPEDYC 3.3.3.2: creation failure is terminal — no retry, no
    /// renegotiation. Even a client that advertised support gets legacy once
    /// it has refused.
    #[test]
    fn a_refused_channel_releases_the_hold() {
        let s = EgfxState {
            client_supports: true,
            waited: Some(std::time::Duration::ZERO),
            ..state()
        };
        assert_eq!(egfx_decision(s), EgfxDecision::Hold);
        assert_eq!(
            egfx_decision(EgfxState { unavailable: true, ..s }),
            EgfxDecision::Legacy
        );
    }

    /// A graphics-capable client gets its negotiation window — but a bounded
    /// one. Past the deadline a stalled client no longer takes the session
    /// down in silence.
    #[test]
    fn waiting_for_capability_negotiation_expires() {
        let s = EgfxState {
            client_supports: true,
            waited: Some(EGFX_READY_DEADLINE - std::time::Duration::from_millis(1)),
            ..state()
        };
        assert_eq!(egfx_decision(s), EgfxDecision::Hold);
        assert_eq!(
            egfx_decision(EgfxState {
                waited: Some(EGFX_READY_DEADLINE),
                ..s
            }),
            EgfxDecision::Legacy
        );
    }

    /// The pre-handle grace has to actually gate something. It used to be
    /// computed into a `debug_assert!` and nothing else, so the window existed
    /// only in the comment.
    #[test]
    fn the_pre_handle_grace_holds_then_releases() {
        let s = EgfxState {
            client_supports: true,
            since_start: std::time::Duration::ZERO,
            ..state()
        };
        assert_eq!(egfx_decision(s), EgfxDecision::Hold);
        assert_eq!(
            egfx_decision(EgfxState {
                since_start: LEGACY_GRACE,
                ..s
            }),
            EgfxDecision::Legacy
        );
    }

    /// Regression: a session already on the pipeline must not interleave
    /// legacy updates while the client re-advertises after a decoder reset.
    /// mstsc treats a mixed stream as a protocol error.
    #[test]
    fn a_latched_session_rides_out_a_handle_swap() {
        let s = EgfxState {
            latched: true,
            client_supports: true,
            waited: Some(EGFX_READY_DEADLINE * 10),
            ..state()
        };
        assert_eq!(egfx_decision(s), EgfxDecision::Hold);

        // But a latched session whose channel actually went away must still
        // fall back rather than hold for the rest of its life.
        assert_eq!(
            egfx_decision(EgfxState { unavailable: true, ..s }),
            EgfxDecision::Legacy
        );
    }

    /// Readiness wins over everything, including a lapsed deadline.
    #[test]
    fn readiness_routes_to_the_pipeline() {
        assert_eq!(
            egfx_decision(EgfxState {
                ready: true,
                client_supports: true,
                waited: Some(EGFX_READY_DEADLINE * 10),
                ..state()
            }),
            EgfxDecision::Egfx
        );
    }
}

#[cfg(test)]
mod tests {
    use super::bgrx_to_yuv420;

    /// The row-parallel YUV conversion must produce byte-identical planes to
    /// a straightforward sequential reference (same BT.709 full-range math),
    /// including the black 16-px padding, at a size that is not a multiple of
    /// the macroblock grid and splits unevenly across worker threads.
    #[test]
    fn parallel_yuv_matches_sequential_reference() {
        let (w, h) = (100usize, 73usize);
        let mut src = vec![0u8; w * h * 4];
        let mut seed = 0x1234_5678_9abc_def0u64;
        for px in src.chunks_exact_mut(4) {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            px[0] = (seed >> 24) as u8;
            px[1] = (seed >> 32) as u8;
            px[2] = (seed >> 40) as u8;
            px[3] = 0xFF;
        }

        let pw = w.div_ceil(16) * 16;
        let ph = h.div_ceil(16) * 16;
        let got = bgrx_to_yuv420(&src, w, h, pw, ph);

        // Sequential reference, same math as convert_rows (see its docs).
        let stride = w * 4;
        let px = |x: usize, y: usize| -> (i32, i32, i32) {
            if x < w && y < h {
                let off = y * stride + x * 4;
                (i32::from(src[off + 2]), i32::from(src[off + 1]), i32::from(src[off]))
            } else {
                (0, 0, 0)
            }
        };
        let mut exp_y = vec![0u8; pw * ph];
        let mut exp_u = vec![128u8; pw * ph / 4];
        let mut exp_v = vec![128u8; pw * ph / 4];
        for j in 0..ph / 2 {
            for i in 0..pw / 2 {
                let p00 = px(i * 2, j * 2);
                let p01 = px(i * 2, j * 2 + 1);
                let p10 = px(i * 2 + 1, j * 2);
                let p11 = px(i * 2 + 1, j * 2 + 1);
                let r = (p00.0 + p01.0 + p10.0 + p11.0) / 4;
                let g = (p00.1 + p01.1 + p10.1 + p11.1) / 4;
                let b = (p00.2 + p01.2 + p10.2 + p11.2) / 4;
                exp_u[j * (pw / 2) + i] = (((-29 * r - 99 * g + 128 * b) >> 8) + 128).clamp(0, 255) as u8;
                exp_v[j * (pw / 2) + i] = (((128 * r - 116 * g - 12 * b) >> 8) + 128).clamp(0, 255) as u8;
                for (p, (dx, dy)) in [(p00, (0usize, 0usize)), (p01, (0, 1)), (p10, (1, 0)), (p11, (1, 1))] {
                    let val = (54 * p.0 + 183 * p.1 + 18 * p.2) >> 8;
                    exp_y[(j * 2 + dy) * pw + (i * 2 + dx)] = val.clamp(0, 255) as u8;
                }
            }
        }

        use openh264::formats::YUVSource as _;
        assert_eq!(got.y(), exp_y.as_slice(), "Y planes differ");
        assert_eq!(got.u(), exp_u.as_slice(), "U planes differ");
        assert_eq!(got.v(), exp_v.as_slice(), "V planes differ");
    }
}

#[cfg(test)]
mod v2_roundtrip_tests {
    use super::{bgrx_to_yuv444v2, make_h264_encoder};
    use openh264::formats::YUVSource as _;

    /// End-to-end wire-format round trip: source BGRX -> ONE H.264 stream
    /// carrying both views -> Annex-B on disk, for the ffmpeg-decode +
    /// FreeRDP-algorithm recombine check (scripts/v2_roundtrip_check.sh).
    ///
    /// Mirrors the live path exactly: per MS-RDPEGFX 2.2.4.6 both subframes
    /// come from the same encoder, so the stream is luma, chroma, luma,
    /// chroma, … and decodes as one sequence.
    #[test]
    fn v2_roundtrip_writes_artifacts() {
        let (w, h) = (640usize, 480usize);
        let (pw, ph) = (640usize, 480usize);
        let stride = w * 4;

        let mut src = vec![0u8; pw * ph * 4];
        for y in 0..h {
            for x in 0..w {
                let o = y * stride + x * 4;
                let (b, g, r);
                if (y / 24) % 2 == 0 && (x / 8 + y / 3) % 7 < 3 {
                    (b, g, r) = (235u8, 235u8, 235u8);
                } else if x > w * 3 / 4 && y > h * 3 / 4 {
                    (b, g, r) = (240, 60, 30);
                } else if x < w / 8 && y < h / 8 {
                    (b, g, r) = (40, 50, 230);
                } else {
                    (b, g, r) = ((20 + x / 24) as u8, (18 + y / 24) as u8, 22u8);
                }
                src[o] = b;
                src[o + 1] = g;
                src[o + 2] = r;
                src[o + 3] = 0xFF;
            }
        }

        let mut enc = make_h264_encoder(12_000_000, 30.0, pw as u16, ph as u16).expect("encoder");

        // One stream, both views: luma, chroma, luma, chroma, …
        let mut stream: Vec<u8> = Vec::new();
        for i in 0..8 {
            let mut f = src.clone();
            if i % 2 == 1 {
                for px in f.chunks_exact_mut(4).step_by(97) {
                    px[0] = px[0].wrapping_add(7);
                }
            }
            let (luma, chroma) = bgrx_to_yuv444v2(&f, w, h, pw, ph);
            stream.extend_from_slice(&enc.encode_planes(luma.y(), luma.u(), luma.v()));
            stream.extend_from_slice(&enc.encode_planes(chroma.y(), chroma.u(), chroma.v()));
        }
        std::fs::write("/tmp/v2_stream.h264", &stream).unwrap();

        let mut ref_planes = Vec::with_capacity(3 * pw * ph);
        for y in 0..h {
            for x in 0..w {
                let o = y * stride + x * 4;
                let (b, g, r) = (i32::from(src[o]), i32::from(src[o + 1]), i32::from(src[o + 2]));
                ref_planes.push(((54 * r + 183 * g + 18 * b) >> 8).clamp(0, 255) as u8);
            }
        }
        for off in [1usize, 2] {
            for y in 0..h {
                for x in 0..w {
                    let o = y * stride + x * 4;
                    let (b, g, r) = (i32::from(src[o]), i32::from(src[o + 1]), i32::from(src[o + 2]));
                    let v = match off {
                        1 => ((-29 * r - 99 * g + 128 * b) >> 8) + 128,
                        _ => ((128 * r - 116 * g - 12 * b) >> 8) + 128,
                    };
                    ref_planes.push(v.clamp(0, 255) as u8);
                }
            }
        }
        std::fs::write("/tmp/v2_ref.y444", ref_planes).unwrap();
        assert!(!stream.is_empty());
    }
}

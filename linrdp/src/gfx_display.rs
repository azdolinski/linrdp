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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ironrdp_egfx::pdu::{Avc420Region, PixelFormat};
use ironrdp_egfx::server::GraphicsPipelineServer;
use ironrdp_graphics::clearcodec::ClearCodecEncoder;
use ironrdp_pdu::geometry::ExclusiveRectangle;
use ironrdp_server::{
    DesktopSize, DisplayUpdate, RdpServerDisplay, RdpServerDisplayUpdates, ServerResult,
};
use openh264::encoder::{
    BitRate, Encoder as OpenH264, EncoderConfig, FrameRate, RateControlMode, UsageType, VuiConfig,
};

use crate::capture::{Grab, ScreenGrabber, X11Display, POLL_INTERVAL};
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

/// H.264 target bitrate. Rate control runs in quality mode, so this is a
/// ceiling that keeps pathological frames (noise, fast scroll) bounded.
const H264_BITRATE_BPS: u32 = 12_000_000;

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

/// Display backend that routes frames over EGFX when available.
pub(crate) struct EgfxDisplay {
    x11: X11Display,
    session: Arc<GfxSession>,
    suppressed: Arc<AtomicBool>,
}

impl EgfxDisplay {
    pub(crate) fn new(x11: X11Display, session: Arc<GfxSession>, suppressed: Arc<AtomicBool>) -> Self {
        Self {
            x11,
            session,
            suppressed,
        }
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for EgfxDisplay {
    async fn size(&mut self) -> DesktopSize {
        self.x11.size().await
    }

    async fn request_initial_size(&mut self, client_size: DesktopSize) -> DesktopSize {
        self.x11.request_initial_size(client_size).await
    }

    fn request_layout(&mut self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
        self.x11.request_layout(layout)
    }

    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(EgfxUpdates {
            grabber: Some(self.x11.grabber()),
            display_name: self.x11.display_name().to_owned(),
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
            last_grabber_connect: Instant::now() - Duration::from_secs(1),
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
        }))
    }
}

struct EgfxUpdates {
    grabber: Option<ScreenGrabber>,
    display_name: String,
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
    /// Once a session has used EGFX, never fall back to legacy bitmap
    /// updates (a client decoder reset briefly clears `ready`).
    egfx_latched: bool,
    /// Throttle for (re)connecting the X grabber when none is present.
    last_grabber_connect: Instant,
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

            let Some(grab) = self.grabbed().await else {
                continue;
            };

            let Some(handle) = self.session.handle() else {
                // No EGFX connection — legacy bitmap path.
                if let Some(update) = grab.legacy_display_update() {
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
                continue;
            } else if let Some(update) = grab.legacy_display_update() {
                return Ok(Some(update));
            } else {
                continue;
            }

            // Bounded processing: a wedged encoder or a lock held across a
            // stuck writer must not freeze the whole display pipeline — the
            // session would show one last static frame forever, and every
            // later client would connect to a dead loop (black screen).
            // Dropping the future abandons whatever blocked; codec state is
            // rebuilt next frame.
            if tokio::time::timeout(FRAME_PROCESS_TIMEOUT, self.egfx_frame(&handle, grab))
                .await
                .is_err()
            {
                tracing::error!(
                    process_timeout = ?FRAME_PROCESS_TIMEOUT,
                    "EGFX frame processing stalled — resetting encoders and motion state"
                );
                self.encoders = None;
                self.in_motion = false;
                self.pending_full = true;
            }
        }
    }
}

impl EgfxUpdates {
    /// Grab one frame with a hard timeout, (re)connecting to the X server as
    /// needed. `None` means "nothing this tick" — the caller retries.
    async fn grabbed(&mut self) -> Option<Grab> {
        let Some(mut grabber) = self.grabber.take() else {
            self.maybe_reconnect_grabber().await;
            return None;
        };
        self.hb_polls += 1;
        let joined = tokio::time::timeout(
            GRAB_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                let grab = grabber.poll();
                (grabber, grab)
            }),
        )
        .await;
        match joined {
            Ok(Ok((grabber, grab))) => {
                self.grabber = Some(grabber);
                self.hb_damaged += u64::from(grab.as_ref().is_some_and(|g| g.damage.is_some()));
                self.heartbeat(true);
                grab
            }
            Ok(Err(join_err)) => {
                // The poll panicked: the grabber was lost with the task, the
                // loop rebuilds one next tick. (A panic in an async task
                // would otherwise kill the display loop silently.)
                tracing::warn!(error = %join_err, "X grab task panicked — rebuilding grabber");
                None
            }
            Err(_) => {
                // Frozen X server: the socket is alive but replies never
                // come. The task (and the grabber inside it) is abandoned;
                // a fresh connection replaces it, and the dropped
                // prev_frame forces a full repaint once X responds again.
                tracing::warn!(
                    display = %self.display_name,
                    timeout = ?GRAB_TIMEOUT,
                    "X grab timed out — X server frozen? abandoning its connection"
                );
                None
            }
        }
    }

    /// Throttled reconnect for a missing/abandoned grabber.
    async fn maybe_reconnect_grabber(&mut self) {
        if self.last_grabber_connect.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_grabber_connect = Instant::now();
        let display_name = self.display_name.clone();
        let joined = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::task::spawn_blocking(move || ScreenGrabber::connect_new(&display_name)),
        )
        .await;
        match joined {
            Ok(Ok(Some(grabber))) => {
                tracing::info!(display = %self.display_name, "X grabber (re)connected");
                self.grabber = Some(grabber);
            }
            Ok(Ok(None)) => {
                tracing::warn!(display = %self.display_name, "X connect failed — screen unavailable, retrying");
            }
            Ok(Err(join_err)) => {
                tracing::warn!(error = %join_err, "X connect task panicked — retrying");
            }
            Err(_) => {
                tracing::warn!(display = %self.display_name, "X connect timed out — X server frozen? retrying");
            }
        }
    }

    /// Lock the pipeline server, surviving a poisoned mutex: a panic on
    /// another thread must not take the display loop down with it.
    /// Lock the pipeline server, surviving a poisoned mutex: a panic on
    /// another thread must not take the display loop down with it.
    fn lock_handle<'a>(handle: &'a GfxHandle) -> std::sync::MutexGuard<'a, GraphicsPipelineServer> {
        handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
        let motion = u64::from(changed_tiles) * MOTION_DENOM as u64 > u64::from(total_tiles)
            || u64::from(changed_tiles) * (64 * 64) > CLEAR_MAX_PIXELS as u64;

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

        // Lazy encoder creation (only once motion is actually needed).
        if self.encoders.as_ref().is_some_and(|e| e.h264.is_none()) {
            match make_h264_encoder() {
                Ok(h264) => {
                    if let Some(enc) = self.encoders.as_mut() {
                        enc.h264 = Some(h264);
                    }
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
    fn heartbeat(&mut self, _grabbed: bool) {
        if self.hb_last.elapsed() < Duration::from_secs(5) {
            return;
        }
        tracing::info!(
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

fn make_h264_encoder() -> anyhow::Result<OpenH264> {
    let api = openh264::OpenH264API::from_source();
    let config = EncoderConfig::new()
        .bitrate(BitRate::from_bps(H264_BITRATE_BPS))
        .max_frame_rate(FrameRate::from_hz(30.0))
        .usage_type(UsageType::ScreenContentRealTime)
        .rate_control_mode(RateControlMode::Quality)
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

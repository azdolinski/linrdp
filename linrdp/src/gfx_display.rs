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
use openh264::encoder::{BitRate, Encoder as OpenH264, EncoderConfig, FrameRate, RateControlMode, UsageType};

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

/// H.264 target bitrate. Rate control runs in quality mode, so this is a
/// ceiling that keeps pathological frames (noise, fast scroll) bounded.
const H264_BITRATE_BPS: u32 = 12_000_000;

/// ClearCodec rectangles above this pixel count go through H.264 instead —
/// encoding a huge lossless rect costs more than it is worth.
const CLEAR_MAX_PIXELS: usize = 2_500_000;

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
            grabber: self.x11.grabber(),
            session: Arc::clone(&self.session),
            suppressed: Arc::clone(&self.suppressed),
            encoders: None,
            surface: None,
            generation: None,
            last_h264: Instant::now() - H264_MIN_INTERVAL,
            pending_full: true,
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
    grabber: ScreenGrabber,
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

            let Some(grab) = self.grabber.poll() else {
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
                let server = handle.lock().expect("GfxServerHandle mutex poisoned");
                self.session.ready() && server.is_ready()
            };
            if !egfx_active {
                if let Some(update) = grab.legacy_display_update() {
                    return Ok(Some(update));
                }
                continue;
            }

            self.egfx_frame(&handle, grab).await;
            // EGFX mode never yields a legacy update; keep polling.
        }
    }
}

impl EgfxUpdates {
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

        // Backpressure (MS-RDPEGFX 2.2.4.3): the client is behind — skip the
        // frame entirely; the full-frame send that follows covers this grab.
        if handle.lock().expect("GfxServerHandle mutex poisoned").should_backpressure() {
            self.pending_full = true;
            return;
        }

        let Grab {
            data,
            width,
            height,
            damage,
        } = grab;

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

        if self.pending_full {
            self.send_clear(handle, data, width, height, 0, 0, width, height)
                .await;
            return;
        }

        let (dx, dy, dw, dh) = damage;
        let area = usize::from(dw) * usize::from(dh);
        let screen = usize::from(width) * usize::from(height);
        let motion = area * MOTION_DENOM > screen || area > CLEAR_MAX_PIXELS;

        if motion && !self.avc_disabled {
            if self.last_h264.elapsed() < H264_MIN_INTERVAL {
                // Skip this encode to hold ~30 fps. The next H.264 frame is
                // a FULL-frame encode, so this grab's content arrives with
                // it — block lossless partials until then.
                self.pending_full = true;
                return;
            }
            self.send_h264(handle, data, width, height).await;
        } else {
            self.send_clear(handle, data, width, height, dx, dy, dw, dh)
                .await;
        }
    }

    /// (Re)create the EGFX surface for the current screen geometry.
    fn ensure_surface(&mut self, handle: &GfxHandle, width: u16, height: u16) {
        let pad_width = width.div_ceil(16) * 16; // H.264 macroblock alignment
        let pad_height = height.div_ceil(16) * 16;
        let mut server = handle.lock().expect("GfxServerHandle mutex poisoned");

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
        let mut server = handle.lock().expect("GfxServerHandle mutex poisoned");
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
            let rgba = bgrx_to_rgba_padded(&data, w, h, pw, ph);
            let yuv = openh264::formats::YUVBuffer::from_rgb_source(openh264::formats::RgbaSliceU8::new(
                &rgba,
                (usize::from(pw), usize::from(ph)),
            ));
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
        let mut server = handle.lock().expect("GfxServerHandle mutex poisoned");
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
                .map(|g| g.lock().expect("GfxServerHandle mutex poisoned").frames_in_flight())
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
        .skip_frames(false);
    OpenH264::with_api_config(api, config).map_err(|e| anyhow::anyhow!("openh264 init: {e}"))
}

/// Convert a BGRX grab into a macroblock-padded RGBA buffer (OpenH264's
/// `from_rgb_source` conversion expects RGBA). The padding region is left
/// black — the destination rectangle crops it away.
fn bgrx_to_rgba_padded(src: &[u8], w: u16, h: u16, pw: u16, ph: u16) -> Vec<u8> {
    let stride = usize::from(w) * 4;
    let pstride = usize::from(pw) * 4;
    let mut out = vec![0u8; pstride * usize::from(ph)];
    for row in 0..usize::from(h) {
        let s = &src[row * stride..row * stride + stride];
        let d = &mut out[row * pstride..row * pstride + stride];
        for (sp, dp) in s.chunks_exact(4).zip(d.chunks_exact_mut(4)) {
            dp[0] = sp[2]; // R
            dp[1] = sp[1]; // G
            dp[2] = sp[0]; // B
            dp[3] = 0xFF;
        }
    }
    out
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

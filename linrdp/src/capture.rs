//! Real X11 screen capture via x11rb (pure Rust, no external binaries).
//! Polls the root window with GetImage and serves the frame when it changes.
//!
//! Grabs prefer the MIT-SHM extension: the X server writes the frame straight
//! into a SysV shared-memory segment we mapped, skipping the full-frame
//! socket round trip of a core-protocol `GetImage` reply — the dominant
//! per-grab cost at high resolutions. Everything falls back to the core
//! protocol when MIT-SHM is unavailable (remote X, restricted SysV limits).
//!
//! Grabs are also gated on the DAMAGE extension: a damage object on the root
//! window (level NonEmpty, subtracted after every grab) tells us whether
//! anything changed since the previous frame, so a static desktop costs no
//! GetImage traffic at all. Root damage catches child-window redraws on
//! Xvfb (verified empirically, `examples/damage_probe.rs`); when the
//! extension is unusable the grabber falls back to blind polling.

use std::sync::Arc;
use std::time::Instant;

use core::num::{NonZeroU16, NonZeroUsize};
use core::time::Duration;

use anyhow::Context as _;
use x11rb::connection::Connection as _;
use x11rb::protocol::damage::{self, ConnectionExt as _};
use x11rb::protocol::shm;
use x11rb::protocol::xfixes::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat};

use ironrdp_connector::DesktopSize;
use ironrdp_server::{
    BitmapUpdate, DisplayUpdate, PixelFormat, RdpServerDisplay, RdpServerDisplayUpdates, ServerResult,
};

pub(crate) struct X11Display {
    conn: Arc<x11rb::rust_connection::RustConnection>,
    root: u32,
    width: u16,
    height: u16,
    display_name: String,
    xauthority: String,
    /// Fixed desktop size (`--fixed-size`): the X screen is resized once at
    /// startup and never per-connection again. Windows RDP works this way —
    /// the server desktop has one size and clients scale locally — and it
    /// avoids the post-resize window where a freshly re-layouting desktop
    /// pushes heavy H.264 immediately after the first paint, which mstsc
    /// decodes (frame acks flow) but never composes, freezing the picture
    /// until the client reconnects (when X is already at the right size and
    /// the session starts settled).
    fixed_size: Option<(u16, u16)>,
    /// Frames are held until this instant after any RandR resize: the
    /// desktop (WM layout, wallpaper) churns for a second or two after a
    /// size change, and video pushed during that window is what mstsc
    /// decodes but never composes (the frozen-session failure). Works for
    /// any client resolution — the settle follows every actual resize.
    settle_until: Instant,
}

impl X11Display {
    /// Connect to `$DISPLAY` (or `:99`) and take the root window geometry.
    pub(crate) fn connect(fixed_size: Option<(u16, u16)>) -> anyhow::Result<Self> {
        let display_name = std::env::var("DISPLAY").unwrap_or_else(|_| ":99".to_owned());
        let (conn, screen_num) = x11rb::rust_connection::RustConnection::connect(Some(display_name.as_str()))
            .with_context(|| format!("connect to X display {display_name}"))?;
        let screen = conn.setup().roots.get(screen_num).context("no X screen")?;
        let (width, height) = (screen.width_in_pixels, screen.height_in_pixels);
        let root = screen.root;
        tracing::info!(display = %display_name, width, height, "X11 capture ready");
        let mut display = Self {
            conn: Arc::new(conn),
            root,
            width,
            height,
            display_name,
            xauthority: std::env::var("XAUTHORITY").unwrap_or_default(),
            fixed_size,
            settle_until: Instant::now(),
        };
        // Apply the fixed size once, before any client can connect: the
        // desktop must be settled (layout done, no churn) by the time a
        // session's first frames go out.
        if let Some((w, h)) = fixed_size {
            if w != width || h != height {
                display.resize_screen(w, h)?;
                tracing::info!(w, h, "X screen pre-resized to the fixed desktop size");
            }
        }
        Ok(display)
    }

    /// Record that the X screen just changed size: the desktop will churn
    /// (WM re-layout, wallpaper) for a short while, and the display loop
    /// must hold frames until it settles (see `settle_until`).
    fn note_resize(&mut self) {
        self.settle_until = Instant::now() + RESIZE_SETTLE;
    }

    /// Current root-window geometry.
    fn query_root_geometry(&self) -> anyhow::Result<(u16, u16)> {
        let g = self.conn.get_geometry(self.root)?.reply().context("geometry reply")?;
        Ok((g.width, g.height))
    }

    /// Resize the X screen to `width`×`height` via RandR (Xvfb exposes a
    /// single output whose mode list includes the maximum virtual size).
    /// Per MS-RDPBCGR the server resizes its desktop to the negotiated
    /// session size — exactly what this performs on the X server.
    fn resize_screen(&mut self, width: u16, height: u16) -> anyhow::Result<()> {
        xrandr_resize(&self.display_name, &self.xauthority, width, height)?;

        let (w, h) = self.query_root_geometry()?;
        if w != width || h != height {
            anyhow::bail!("root geometry {w}x{h} != requested {width}x{height}");
        }
        self.width = w;
        self.height = h;
        self.note_resize();
        tracing::info!(width = w, height = h, "X screen resized via xrandr");
        Ok(())
    }

    /// Frames are held while the desktop settles after a resize; callers
    /// hold off encoding until this instant passes, then repaint in full.
    pub(crate) fn settle_until(&self) -> Instant {
        self.settle_until
    }

    /// A fresh damage-tracking poller over this display's root window.
    pub(crate) fn grabber(&self) -> ScreenGrabber {
        let mut grabber = ScreenGrabber::new(
            Arc::clone(&self.conn),
            self.root,
            self.width,
            self.height,
            self.display_name.clone(),
        );
        grabber.set_fixed_size(self.fixed_size);
        grabber
    }

    /// The X display this server captures (for reconnects).
    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Current screen geometry (see [`Self::display_name`] for the factory
    /// that consumes this).
    pub(crate) fn width(&self) -> u16 {
        self.width
    }

    pub(crate) fn height(&self) -> u16 {
        self.height
    }

    /// Synchronous core of `request_initial_size` (the RdpServerDisplay
    /// method delegates here so the source factory can call it directly).
    pub(crate) fn request_initial_size_sync(&mut self, client_size: DesktopSize) -> DesktopSize {
        tracing::info!(?client_size, "request_initial_size called");
        if let Some((w, h)) = self.fixed_size {
            // Fixed desktop: never adopt a client size, but DO re-assert the
            // fixed geometry when the X screen drifted (observed spontaneous
            // 2880x1800 → 2880x1680). A surface built from a drifted grab
            // contradicts the negotiated session size and mstsc resets the
            // connection on the next EGFX pipeline re-init. The resize also
            // arms the settle hold, so the first frames go out post-churn.
            match self.query_root_geometry() {
                Ok((cw, ch)) if (cw, ch) == (w, h) => {}
                Ok((cw, ch)) => {
                    tracing::warn!(
                        current = format!("{cw}x{ch}"),
                        fixed = format!("{w}x{h}"),
                        "X screen drifted from the fixed size — re-applying before the session"
                    );
                    if let Err(e) = self.resize_screen(w, h) {
                        tracing::warn!(error = format!("{e:#}"), "fixed-size re-apply failed");
                    }
                }
                Err(e) => tracing::warn!(error = format!("{e:#}"), "root geometry query failed"),
            }
            tracing::info!(w, h, client_w = client_size.width, client_h = client_size.height,
                           "fixed desktop size — client scales locally");
            return DesktopSize { width: w, height: h };
        }
        // MS-RDPBCGR: the server adopts the negotiated session size. Resize
        // the X screen to the client's exact size (RandR) so the remote
        // desktop fills the client window edge-to-edge.
        if let Err(e) = self.resize_screen(client_size.width, client_size.height) {
            // Fallback: keep the current X screen size when the requested
            // size has no RandR mode (e.g. larger than the virtual maximum).
            tracing::warn!(error = format!("{e:#}"), requested = ?client_size, "RandR resize failed; keeping current size");
            if let Ok((w, h)) = self.query_root_geometry() {
                self.width = w;
                self.height = h;
            }
        }
        tracing::info!(client_w = client_size.width, client_h = client_size.height,
                       w = self.width, h = self.height, "negotiating initial desktop size");
        DesktopSize {
            width: self.width,
            height: self.height,
        }
    }

    /// Synchronous core of `request_layout` (see
    /// [`Self::request_initial_size_sync`]).
    pub(crate) fn request_layout_sync(&mut self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
        tracing::info!(?layout, "client requested layout change");
        if self.fixed_size.is_some() {
            tracing::debug!("fixed desktop size — ignoring client layout change");
            return;
        }
        let Some(monitor) = layout.monitors().first() else {
            return;
        };
        let (w, h) = (monitor.width() as u16, monitor.height() as u16);
        if w == 0 || h == 0 {
            return;
        }
        if let Err(e) = self.resize_screen(w, h) {
            tracing::warn!(error = format!("{e:#}"), requested = ?(w, h), "layout resize failed");
            return;
        }
        if let Ok((gw, gh)) = self.query_root_geometry() {
            self.width = gw;
            self.height = gh;
        }
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for X11Display {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize {
            width: self.width,
            height: self.height,
        }
    }

    /// Adopt the client's requested desktop size (target.md #4: "match size of
    /// screen — same experience as Windows RDP"). The X11 root is captured at
    /// whatever geometry it has; we intersect the request with the physical
    /// screen so the RDP framebuffer matches what the client can show.
    async fn request_initial_size(&mut self, client_size: DesktopSize) -> DesktopSize {
        self.request_initial_size_sync(client_size)
    }

    /// Client-driven resize (mstsc "Smart resize", MS-RDPBCGR 2.2.11.3
    /// Display Control Monitor Layout): resize the X screen to the first
    /// requested monitor geometry so the desktop fills the client window.
    fn request_layout(&mut self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
        self.request_layout_sync(layout)
    }

    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(Updates {
            grabber: self.grabber(),
            first: true,
        }))
    }
}

// NOTE: the grabber reads the CURRENT root geometry on every grab (query via
// get_geometry) so a DisplayControl resize mid-session is picked up without
// reconnecting.

/// A full-screen grab plus the damage computed against the previous grab.
///
/// The data is bottom-up BGRX (X11 ZPixmap at depth 24), `width * 4` stride.
pub(crate) struct Grab {
    pub(crate) data: Vec<u8>,
    pub(crate) width: u16,
    pub(crate) height: u16,
    /// Changed bounding box `(x, y, w, h)` versus the previous grab; `None`
    /// when nothing changed. A geometry change forces full-screen damage.
    pub(crate) damage: Option<(u16, u16, u16, u16)>,
    /// How many 64x64 tiles actually changed (vs. how many the bounding box
    /// spans). A blinking cursor in one corner plus a clock in the other
    /// produces a full-screen bounding box with ~zero changed tiles — the
    /// bbox alone is a terrible motion signal.
    pub(crate) changed_tiles: u32,
    /// Total tile count covering the screen.
    pub(crate) total_tiles: u32,
}

/// Cursor sprite captured via XFixes `GetCursorImage`, already in the RDP
/// 32-bpp xor-mask layout: `R,G,B,x` bytes per pixel, bottom-up rows.
pub(crate) struct CursorImage {
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) hot_x: u16,
    pub(crate) hot_y: u16,
    pub(crate) xor: Vec<u8>,
}

/// Convert an XFixes cursor sprite (native-endian CARD32 ARGB, top-down,
/// premultiplied alpha) into the RDP 32-bpp pointer xor mask: bytes `R,G,B,A`
/// per pixel in bottom-up rows, straight alpha.
///
/// Byte 3 is not a filler: for New/Large Pointer Updates it is the ONLY
/// transparency source (we send no AND mask — mstsc composites 32-bpp
/// pointers src-over with this alpha). Forcing it opaque renders the cursor
/// as a solid black box around the arrow, and passing premultiplied RGB
/// through makes soft edges darker than intended.
fn argb_to_rdp_xor(src: &[u32], width: u16, height: u16) -> Vec<u8> {
    let stride = usize::from(width) * 4;
    let mut xor = vec![0u8; stride * usize::from(height)];
    for row in 0..usize::from(height) {
        let src_row = &src[row * usize::from(width)..(row + 1) * usize::from(width)];
        // Destination row is the vertically mirrored one (pointer masks
        // travel bottom-up like bitmaps).
        let dst_row = usize::from(height) - 1 - row;
        let dst = &mut xor[dst_row * stride..(dst_row + 1) * stride];
        for (s, d) in src_row.iter().zip(dst.chunks_exact_mut(4)) {
            let argb = *s;
            let a = ((argb >> 24) & 0xFF) as u32;
            let (r, g, b) = (
                ((argb >> 16) & 0xFF) as u32,
                ((argb >> 8) & 0xFF) as u32,
                (argb & 0xFF) as u32,
            );
            match a {
                0 => {
                    // Fully transparent pixels can carry garbage RGB; zero
                    // them so premultiplied == straight at this extreme.
                    d[..4].copy_from_slice(&[0, 0, 0, 0]);
                }
                255 => {
                    d[..4].copy_from_slice(&[r as u8, g as u8, b as u8, 255]);
                }
                _ => {
                    // Un-premultiply (Windows cursor resources are straight
                    // ARGB; XFixes hands us premultiplied).
                    d[..4].copy_from_slice(&[
                        (r * 255 / a).min(255) as u8,
                        (g * 255 / a).min(255) as u8,
                        (b * 255 / a).min(255) as u8,
                        a as u8,
                    ]);
                }
            }
        }
    }
    xor
}

impl CursorImage {
    /// Cheap identity of the shape (size + hotspot + pixels) for cache
    /// lookups — recomputed per call, callers memoize the result.
    pub(crate) fn shape_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a
        let mut mix = |h: &mut u64, b: u8| {
            *h ^= u64::from(b);
            *h = h.wrapping_mul(0x1000_0000_01b3);
        };
        for b in &self.xor {
            mix(&mut h, *b);
        }
        for v in [self.width, self.height, self.hot_x, self.hot_y] {
            for b in v.to_le_bytes() {
                mix(&mut h, b);
            }
        }
        h
    }
}

impl Grab {
    /// Crop the damage rectangle into a legacy-path `DisplayUpdate`.
    pub(crate) fn legacy_display_update(&self) -> Option<DisplayUpdate> {
        let (x, y, w, h) = self.damage?;
        let stride = usize::from(self.width) * 4;
        let mut region = Vec::with_capacity(usize::from(w) * usize::from(h) * 4);
        for row in y..y + h {
            let start = usize::from(row) * stride + usize::from(x) * 4;
            region.extend_from_slice(&self.data[start..start + usize::from(w) * 4]);
        }
        Some(DisplayUpdate::Bitmap(BitmapUpdate {
            x,
            y,
            width: NonZeroU16::new(w).expect("non-zero width"),
            height: NonZeroU16::new(h).expect("non-zero height"),
            format: PixelFormat::BgrX32,
            data: region.into(),
            stride: NonZeroUsize::new(usize::from(w) * 4).expect("non-zero stride"),
        }))
    }
}

/// Consecutive failed grabs after which the X server connection is presumed
/// dead and a reconnect is attempted (~0.5 s at the 17 ms poll interval).
/// The X server (Xvfb) is a separate systemd unit that can crash and be
/// restarted at any moment; without a reconnect every later session would
/// grab from the stale connection forever and paint nothing but black.
const GRAB_FAILURES_BEFORE_RECONNECT: u32 = 30;

/// While the X server stays unreachable, retry the reconnect this often.
const GRAB_RECONNECT_RETRY_EVERY: u32 = 60;

/// Consecutive MIT-SHM grab failures tolerated before falling back to
/// core-protocol GetImage permanently. A stray failure is usually a transient
/// geometry race (BadMatch on resize); a systematically broken SHM setup
/// (missing extension, non-local display, tight `shmmax`) shows up as a run.
const SHM_MAX_FAILURES: u32 = 5;

/// A MIT-SHM segment attached to the grabber's X connection: the server
/// writes `ShmGetImage` results straight into this memory instead of
/// streaming the whole frame back over the socket.
struct ShmCapture {
    conn: Arc<x11rb::rust_connection::RustConnection>,
    /// X resource id of the segment on `conn`.
    seg: u32,
    /// Our mapping of the segment, `size` bytes of ZPixmap data.
    addr: *mut u8,
    size: usize,
}

// SAFETY: the raw mapping is only ever dereferenced by `read`, on the thread
// that owns the grabber; ownership moves with ScreenGrabber into its blocking
// poll task, so no two threads can touch `addr` at the same time.
unsafe impl Send for ShmCapture {}

impl ShmCapture {
    /// Allocate a SysV segment for one `width`×`height` 32-bpp frame and
    /// attach it to the X server. `None` = MIT-SHM unusable right now.
    ///
    /// The segment mode matters: linrdp usually runs as root while the X
    /// server runs as the desktop user, and a root-owned 0600 segment is
    /// un-attachable by that server — `ShmAttach` fails with `BadAccess`, SHM
    /// is written off, and every grab falls back to a core-protocol GetImage
    /// of the whole screen (~20 MB at 2880x1800, ~50x a second). That flood
    /// wedges the X connection every few seconds, and each recovery forces a
    /// full lossless repaint. So: try the strict mode first and only widen it
    /// when the server actually refuses.
    fn create(conn: &Arc<x11rb::rust_connection::RustConnection>, width: u16, height: u16) -> Option<Self> {
        let size = usize::from(width) * usize::from(height) * 4;
        // Extension present at all? (Missing MIT-SHM makes every request fail.)
        shm::query_version(conn).ok()?.reply().ok()?;

        // 0600 keeps the framebuffer private when the X server shares our uid.
        // 0666 is the fallback for a cross-uid server; the window in which it
        // is world-attachable is closed immediately below by IPC_RMID, which
        // makes the segment unreachable to any process not already attached.
        for mode in [0o600, 0o666] {
            if let Some(capture) = Self::try_attach(conn, size, mode) {
                return Some(capture);
            }
        }
        None
    }

    /// One shmget/shmat/ShmAttach attempt at `mode`. Cleans up fully on any
    /// failure so the caller can retry with different permissions.
    fn try_attach(conn: &Arc<x11rb::rust_connection::RustConnection>, size: usize, mode: i32) -> Option<Self> {
        // SAFETY: plain SysV shmget with a private key; no invariants beyond
        // the size, and failures are reported by the negative return value.
        let shmid = unsafe { libc::shmget(libc::IPC_PRIVATE, size, mode | libc::IPC_CREAT) };
        if shmid < 0 {
            return None;
        }
        // SAFETY: attaching the segment we just created; the only failure
        // mode is MAP_FAILED.
        let addr = unsafe { libc::shmat(shmid, core::ptr::null(), 0) };
        if addr == libc::MAP_FAILED {
            // SAFETY: marking the unusable segment for destruction; the id is
            // valid (shmget succeeded above) and we never attached it.
            unsafe { libc::shmctl(shmid, libc::IPC_RMID, core::ptr::null_mut()) };
            return None;
        }

        let failure = |shmid: i32, addr: *mut core::ffi::c_void| {
            // SAFETY: `addr` is the mapping from shmat above, detached exactly
            // once here.
            unsafe { libc::shmdt(addr) };
            // SAFETY: `shmid` is valid and, with both mappings now gone (we
            // never let the server attach on these paths), destroyed by RMID.
            unsafe { libc::shmctl(shmid, libc::IPC_RMID, core::ptr::null_mut()) };
        };

        let seg = match conn.generate_id() {
            Ok(seg) => seg,
            Err(_) => {
                failure(shmid, addr);
                return None;
            }
        };
        match shm::attach(conn, seg, u32::try_from(shmid).ok()?, false) {
            // check() waits for the server to process the attach — required
            // before RMID below, because the X server performs its own shmat
            // while handling the request.
            Ok(cookie) => {
                if cookie.check().is_err() {
                    failure(shmid, addr);
                    let _ = shm::detach(conn, seg);
                    return None;
                }
            }
            Err(_) => {
                failure(shmid, addr);
                return None;
            }
        }

        // Both sides are attached: destroy the name now (the standard MIT-SHM
        // contract). The memory lives until the last attachment drops, but no
        // further process can reach it, and a crash can no longer leak the
        // segment — a reconnect always builds a fresh one anyway.
        // SAFETY: `shmid` is valid and attached by us and by the X server.
        unsafe { libc::shmctl(shmid, libc::IPC_RMID, core::ptr::null_mut()) };

        Some(Self {
            conn: Arc::clone(conn),
            seg,
            addr: addr.cast(),
            size,
        })
    }

    /// Copy the last-written frame out of the segment.
    fn read(&self) -> Vec<u8> {
        // SAFETY: the server wrote `size` bytes after our successful
        // ShmGetImage; we hold our own valid SysV mapping for the lifetime.
        unsafe { core::slice::from_raw_parts(self.addr, self.size) }.to_vec()
    }
}

impl Drop for ShmCapture {
    fn drop(&mut self) {
        // SAFETY: `addr` came from shmat and is detached exactly once here.
        unsafe { libc::shmdt(self.addr.cast()) };
        // No IPC_RMID here: `try_attach` already destroyed the name once both
        // sides were attached. Dropping our mapping and the server's
        // attachment is what actually frees the memory.
        let _ = shm::detach(&*self.conn, self.seg);
    }
}

/// What one poll of the screen produced.
///
/// The distinction between `Idle` and `Failed` is the whole point of this
/// type: a static desktop and a dead X server both used to collapse into a
/// bare `None`, so ~0.5 s of an unchanging screen was indistinguishable from
/// the connection dying — see [`GrabFailures`].
enum PollOutcome {
    /// The damage gate reported no change; no grab was attempted.
    Idle,
    /// A frame (its `damage` field says whether any tile actually changed).
    Frame(Box<Grab>),
    /// The grab itself failed — the X connection may be gone.
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PollKind {
    Idle,
    Frame,
    Failed,
}

impl PollOutcome {
    fn kind(&self) -> PollKind {
        match self {
            Self::Idle => PollKind::Idle,
            Self::Frame(_) => PollKind::Frame,
            Self::Failed => PollKind::Failed,
        }
    }
}

/// Consecutive-grab-failure accounting for the poll loop.
///
/// An idle poll must leave the counter alone: it proves neither that the
/// connection works nor that it is broken. Counting idle polls as failures
/// made a static screen trip the reconnect after ~0.5 s, and every spurious
/// reconnect dropped the diff baseline and forced a full-screen lossless
/// repaint (~1.2 MB at 2880x1800, once or twice a second on a quiet desktop).
#[derive(Default)]
struct GrabFailures {
    consecutive: u32,
}

impl GrabFailures {
    /// Record one poll. Returns the failure count when a reconnect is due.
    fn record(&mut self, kind: PollKind) -> Option<u32> {
        match kind {
            PollKind::Idle => None,
            PollKind::Frame => {
                self.consecutive = 0;
                None
            }
            PollKind::Failed => {
                self.consecutive = self.consecutive.saturating_add(1);
                let n = self.consecutive;
                let due = n == GRAB_FAILURES_BEFORE_RECONNECT
                    || (n > GRAB_FAILURES_BEFORE_RECONNECT
                        && (n - GRAB_FAILURES_BEFORE_RECONNECT) % GRAB_RECONNECT_RETRY_EVERY == 0);
                due.then_some(n)
            }
        }
    }
}

/// Reusable screen poller: grabs the X11 root and computes tile-level damage
/// against the previous grab. Shared by the legacy bitmap path (`Updates`)
/// and the EGFX display backend.
pub(crate) struct ScreenGrabber {
    conn: Arc<x11rb::rust_connection::RustConnection>,
    root: u32,
    width: u16,
    height: u16,
    prev_frame: Option<Vec<u8>>,
    display_name: String,
    failures: GrabFailures,
    /// Whether XFixes QueryVersion has been exchanged on this connection
    /// (reset by reconnect — a fresh connection must renegotiate).
    xfixes_negotiated: bool,
    /// Active MIT-SHM segment, sized for the current geometry. `None` until
    /// first use, after a geometry change, or when broken (see below).
    shm: Option<ShmCapture>,
    /// Consecutive SHM grab failures; past [`SHM_MAX_FAILURES`] the core
    /// GetImage path is used permanently.
    shm_failures: u32,
    /// Set once MIT-SHM has been judged unusable — no further attempts.
    shm_broken: bool,
    /// Root-window damage object gating grabs (`None` until first use).
    damage: Option<damage::Damage>,
    /// Set once DAMAGE has been judged unusable — grab every poll, as before.
    damage_ok: bool,
    /// The next poll grabs unconditionally (first grab, reconnect, resize).
    force_grab: bool,
    /// Fixed desktop size (`--fixed-size`): when set, the grabber re-asserts
    /// this geometry if the X screen drifts (see [`Self::grab`]).
    fixed_size: Option<(u16, u16)>,
    /// Xauthority for the `xrandr` re-apply spawned by the fixed-size
    /// enforcement.
    xauthority: String,
    /// Next instant the fixed-size enforcement may query the root geometry.
    next_size_check: Instant,
}

impl ScreenGrabber {
    pub(crate) fn new(
        conn: Arc<x11rb::rust_connection::RustConnection>,
        root: u32,
        width: u16,
        height: u16,
        display_name: String,
    ) -> Self {
        Self {
            conn,
            root,
            width,
            height,
            prev_frame: None,
            display_name,
            failures: GrabFailures::default(),
            xfixes_negotiated: false,
            shm: None,
            shm_failures: 0,
            shm_broken: false,
            damage: None,
            damage_ok: false,
            force_grab: true,
            fixed_size: None,
            xauthority: std::env::var("XAUTHORITY").unwrap_or_default(),
            next_size_check: Instant::now(),
        }
    }

    /// Pin the grabber to a fixed desktop size: the X screen is re-asserted
    /// whenever it drifts (throttled — see [`Self::grab`]).
    pub(crate) fn set_fixed_size(&mut self, fixed_size: Option<(u16, u16)>) {
        self.fixed_size = fixed_size;
    }

    /// Connect a fresh grabber to `display_name` (blocking). Used at session
    /// start and after an X server crash or freeze — the X server unit can
    /// die and be restarted at any moment, and the startup connection must
    /// never be assumed alive forever.
    pub(crate) fn connect_new(display_name: &str) -> Option<Self> {
        let (conn, screen_num) =
            x11rb::rust_connection::RustConnection::connect(Some(display_name)).ok()?;
        let setup = conn.setup();
        let screen = setup.roots.get(screen_num)?;
        let (root, width, height) = (screen.root, screen.width_in_pixels, screen.height_in_pixels);
        Some(Self::new(
            Arc::new(conn),
            root,
            width,
            height,
            display_name.to_owned(),
        ))
    }

    /// Establish a fresh connection to the X display, adopting the new root
    /// window and geometry. Dropping `prev_frame` makes the next successful
    /// grab report full-screen damage, which unconditionally repaints every
    /// connected client.
    fn reconnect(&mut self) -> bool {
        let connected = x11rb::rust_connection::RustConnection::connect(Some(self.display_name.as_str()));
        match connected {
            Ok((conn, screen_num)) => {
                let Some(screen) = conn.setup().roots.get(screen_num) else {
                    return false;
                };
                self.root = screen.root;
                self.width = screen.width_in_pixels;
                self.height = screen.height_in_pixels;
                self.conn = Arc::new(conn);
                self.prev_frame = None;
                self.xfixes_negotiated = false;
                // The old segment is bound to the dead connection; a fresh one
                // is created lazily on the next grab (SHM itself is retried —
                // whatever broke may have been the connection, not SHM).
                self.shm = None;
                self.shm_failures = 0;
                self.shm_broken = false;
                // Same for the damage object (connection-scoped resource).
                self.damage = None;
                self.damage_ok = false;
                self.force_grab = true;
                true
            }
            Err(_) => false,
        }
    }

    fn current_geometry(&self) -> (u16, u16) {
        self.conn
            .get_geometry(self.root)
            .ok()
            .and_then(|c| c.reply().ok())
            .map(|g| (g.width, g.height))
            .unwrap_or((self.width, self.height))
    }

    /// Grab the current root-window contents, preferring the MIT-SHM path
    /// (server writes into our shared segment; no full-frame socket transfer).
    /// Falls back to core GetImage while SHM is failing (bounded) and
    /// permanently once it is judged unusable. `None` on transient X11
    /// failure (retry next tick).
    fn grab(&mut self) -> Option<(Vec<u8>, u16, u16)> {
        // Fixed-size enforcement: nothing in linrdp moves the X screen once
        // the fixed size is applied, yet the screen demonstrably drifts
        // (observed 2880x1800 → 2880x1680 with no client asking for it). A
        // surface built from a drifted grab contradicts the negotiated
        // session size, and mstsc resets the connection on the next EGFX
        // pipeline re-init — so re-assert the size here (throttled) before
        // the grab bakes the wrong geometry into a frame.
        if let Some((fw, fh)) = self.fixed_size {
            if Instant::now() >= self.next_size_check {
                self.next_size_check = Instant::now() + FIXED_SIZE_CHECK_INTERVAL;
                let (cw, ch) = self.current_geometry();
                if (cw, ch) != (fw, fh) {
                    tracing::warn!(
                        current = format!("{cw}x{ch}"),
                        fixed = format!("{fw}x{fh}"),
                        "X screen drifted from the fixed size — re-applying"
                    );
                    if xrandr_resize(&self.display_name, &self.xauthority, fw, fh).is_ok() {
                        self.width = fw;
                        self.height = fh;
                    }
                }
            }
        }

        let (w, h) = self.current_geometry();
        let want = usize::from(w) * usize::from(h) * 4;

        // Geometry changed since the segment was sized: rebuild at the new
        // size (drops the old segment via Drop).
        if self.shm.as_ref().is_some_and(|capture| capture.size != want) {
            self.shm = None;
        }
        if self.shm.is_none() && !self.shm_broken && want > 0 {
            match ShmCapture::create(&self.conn, w, h) {
                Some(capture) => self.shm = Some(capture),
                None => {
                    // No MIT-SHM (extension missing, /proc/sys/kernel/shmmax
                    // too small, remote X server): core GetImage still works.
                    self.shm_broken = true;
                    tracing::info!("MIT-SHM unavailable — using core-protocol GetImage");
                }
            }
        }

        if let Some(capture) = self.shm.as_ref() {
            let grabbed = shm::get_image(&*capture.conn, self.root, 0, 0, w, h, !0, u8::from(ImageFormat::Z_PIXMAP), capture.seg, 0)
                .ok()
                .and_then(|cookie| cookie.reply().ok())
                .map(|_| capture.read());
            match grabbed {
                Some(data) => {
                    self.shm_failures = 0;
                    return Some((data, w, h));
                }
                None => {
                    // One failure can be a transient resize race (BadMatch);
                    // fall through to the core path THIS grab so the frame is
                    // not lost, and only give up on SHM after a run of them.
                    self.shm_failures += 1;
                    self.shm = None;
                    if self.shm_failures >= SHM_MAX_FAILURES {
                        self.shm_broken = true;
                        tracing::warn!(failures = self.shm_failures, "MIT-SHM keeps failing — using core-protocol GetImage");
                    }
                }
            }
        }

        self.conn
            .get_image(
                ImageFormat::Z_PIXMAP,
                self.root,
                0,
                0,
                w,
                h,
                !0,
            )
            .ok()?
            .reply()
            .ok()
            .map(|r| (r.data, w, h))
    }

    /// Grab the current screen contents and diff them against the previous
    /// grab. Returns `None` on a transient X11 failure (retry next tick).
    pub(crate) fn poll(&mut self) -> Option<Grab> {
        let outcome = self.poll_inner();
        if let Some(failures) = self.failures.record(outcome.kind()) {
            if self.reconnect() {
                tracing::warn!(
                    display = %self.display_name,
                    failures,
                    "X server connection was dead — reconnected (next grab repaints in full)"
                );
            } else {
                tracing::warn!(
                    display = %self.display_name,
                    failures,
                    "X server unreachable — screen cannot be captured; retrying"
                );
            }
        }
        match outcome {
            PollOutcome::Frame(grab) => Some(*grab),
            PollOutcome::Idle | PollOutcome::Failed => None,
        }
    }

    /// One screen grab plus, when `cursor_due`, a fresh cursor image.
    ///
    /// The cursor is not part of the root-window pixels `GetImage` returns
    /// (X draws it as an overlay), so without this the remote user never sees
    /// the real session cursor shape — only their client's default arrow.
    /// XFixes `GetCursorImage` returns the current sprite as ARGB, which the
    /// display backend ships to the client as RDP pointer updates.
    pub(crate) fn poll_and_cursor(&mut self, cursor_due: bool) -> (Option<Grab>, Option<CursorImage>) {
        let cursor = if cursor_due { self.cursor_image() } else { None };
        (self.poll(), cursor)
    }

    /// Current cursor sprite via XFixes, converted to the RDP xor-mask byte
    /// order (R,G,B,x per pixel) in bottom-up rows.
    fn cursor_image(&mut self) -> Option<CursorImage> {
        if !self.xfixes_negotiated {
            // GetCursorImage needs the XFixes extension announced first.
            self.conn.xfixes_query_version(4, 0).ok()?.reply().ok()?;
            self.xfixes_negotiated = true;
        }
        let cur = self.conn.xfixes_get_cursor_image().ok()?.reply().ok()?;
        let width = u16::try_from(cur.width).ok()?;
        let height = u16::try_from(cur.height).ok()?;
        if width == 0 || height == 0 {
            return None;
        }
        let hot_x = u16::try_from(cur.xhot).ok()?;
        let hot_y = u16::try_from(cur.yhot).ok()?;

        let src_len = usize::from(width) * usize::from(height);
        if cur.cursor_image.len() < src_len {
            return None;
        }
        let xor = argb_to_rdp_xor(&cur.cursor_image[..src_len], width, height);

        Some(CursorImage {
            width,
            height,
            hot_x: hot_x.min(width.saturating_sub(1)),
            hot_y: hot_y.min(height.saturating_sub(1)),
            xor,
        })
    }

    fn poll_inner(&mut self) -> PollOutcome {
        // Damage gate: skip the whole GetImage + diff when the root window has
        // not changed since the previous grab. The first grab (and the first
        // after a reconnect) is forced so the diff baseline exists.
        let force = std::mem::take(&mut self.force_grab);
        if !force && !self.damage_pending() {
            return PollOutcome::Idle; // static screen: healthy, not a failure
        }
        // Re-arm BEFORE taking the image: any change that happens after the
        // subtraction re-arms the damage, so it can never be silently
        // swallowed by a grab that already contains it.
        self.rearm_damage();

        let Some((data, width, height)) = tokio::task::block_in_place(|| self.grab()) else {
            return PollOutcome::Failed;
        };
        let stride = usize::from(width) * 4;
        if data.len() != stride * usize::from(height) {
            return PollOutcome::Failed; // geometry changed mid-grab; retry next tick
        }

        if self.width != width || self.height != height {
            // Session was resized (DisplayControl/RandR): repaint everything
            // at the new size so no stale/partial content remains.
            tracing::info!(width, height, "session size changed — full repaint");
            self.width = width;
            self.height = height;
            self.prev_frame = None;
        }

        let (damage, changed_tiles, total_tiles) = compute_tile_damage(self.prev_frame.as_deref(), &data, width, height);

        // Keep the frame as the diff baseline only when something changed —
        // an unchanged grab is byte-identical to the stored baseline already,
        // so skipping the (large) copy keeps idle polling cheap.
        if damage.is_some() {
            self.prev_frame = Some(data.clone());
        }
        PollOutcome::Frame(Box::new(Grab {
            data,
            width,
            height,
            damage,
            changed_tiles,
            total_tiles,
        }))
    }

    /// Whether the root window changed since the last grab, per the DAMAGE
    /// extension. Lazily creates the damage object; if the extension is
    /// unusable this always reports "changed" (blind polling, the previous
    /// behavior). Pending events are drained; anything that is not a damage
    /// notification is discarded.
    fn damage_pending(&mut self) -> bool {
        if !self.damage_ok && self.damage.is_none() {
            self.damage_ok = self.setup_damage();
            if !self.damage_ok {
                tracing::warn!("X DAMAGE unavailable — capturing with blind polling");
                return true;
            }
        }
        if !self.damage_ok {
            return true;
        }

        let mut pending = false;
        loop {
            match self.conn.poll_for_event() {
                Ok(Some(event)) => {
                    if matches!(event, x11rb::protocol::Event::DamageNotify(_)) {
                        pending = true;
                    }
                }
                Ok(None) => return pending,
                Err(_) => {
                    // Connection is in trouble; grab anyway so the failure
                    // surfaces through the usual reconnect path.
                    return true;
                }
            }
        }
    }

    /// Create the root-window damage object (level NonEmpty: one notification
    /// per change batch, re-armed by subtracting — minimal event traffic).
    fn setup_damage(&mut self) -> bool {
        if damage::query_version(&*self.conn, 1, 1)
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .is_none()
        {
            return false;
        }
        let Some(dmg) = self.conn.generate_id().ok() else {
            return false;
        };
        match damage::create(&*self.conn, dmg, self.root, damage::ReportLevel::NON_EMPTY) {
            Ok(cookie) => {
                if cookie.check().is_err() {
                    return false;
                }
                self.damage = Some(dmg);
                true
            }
            Err(_) => false,
        }
    }

    /// Clear the damage state so the next change re-arms the notification.
    /// Called after deciding to grab, before taking the image.
    fn rearm_damage(&mut self) {
        if let Some(dmg) = self.damage {
            let _ = damage::subtract(&*self.conn, dmg, xfixes::RegionEnum::NONE, xfixes::RegionEnum::NONE);
        }
    }
}

/// Tile edge length for change detection (MS-RDPBCGR-style dirty-region
/// granularity; the server encoder re-diffs the delivered region against its
/// own framebuffer, so only actually-changed sub-rectangles are encoded).
const TILE: u16 = 64;

/// Screen polling interval: ~60 Hz capture, each grab delivered as one
/// bitmap update — the encoder wraps it in a single Frame Marker group
/// (MS-RDPBCGR 2.2.9.2.3) so the client presents it atomically.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(16);

/// How long the display loop holds frames after a RandR resize: the desktop
/// (WM re-layout, wallpaper redraw) churns in this window and video pushed
/// mid-churn is decoded but never composed by mstsc — the frozen-session
/// failure. Resolution-independent: it follows every actual resize.
pub(crate) const RESIZE_SETTLE: Duration = Duration::from_millis(1500);

/// How often the fixed-size grabber re-checks the root geometry.
const FIXED_SIZE_CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// Resize the X screen to `width`×`height` via the standard `xrandr`
/// utility. Sequence: create CVT mode (if missing) → add to output → apply.
/// This is the exact sequence of `xrandr --newmode/--addmode/--output`.
/// Shared by the per-connection resize and the fixed-size enforcement.
fn xrandr_resize(display_name: &str, xauthority: &str, width: u16, height: u16) -> anyhow::Result<()> {
    let mode_name = format!("{width}x{height}_60.00");

    let run = |args: &[&str]| -> anyhow::Result<()> {
        let status = std::process::Command::new("xrandr")
            .args(args)
            .env("DISPLAY", display_name)
            .env("XAUTHORITY", xauthority)
            .status()
            .context("spawn xrandr")?;
        if !status.success() {
            anyhow::bail!("xrandr {args:?} failed: {status}");
        }
        Ok(())
    };

    // Fast path: switch straight to the mode if one with this exact name
    // already exists. Modes persist in the X server across linrdp
    // restarts, so reconnects usually land here.
    let switched = run(&["--output", "screen", "--mode", &mode_name]);
    if switched.is_err() {
        // Create a standard CVT timing for width×height @60Hz.
        let output = std::process::Command::new("cvt")
            .args([width.to_string().as_str(), height.to_string().as_str(), "60"])
            .env("DISPLAY", display_name)
            .env("XAUTHORITY", xauthority)
            .output()
            .context("spawn cvt")?;
        let cvt_out = String::from_utf8_lossy(&output.stdout).to_string();
        // cvt prints: Modeline "2880x1800_60.00" 442.00 2880 3104 3416 3952 ...
        let modeline = cvt_out
            .lines()
            .find(|l| l.contains("Modeline"))
            .context("cvt produced no modeline")?;
        let params: Vec<&str> = modeline.split_whitespace().skip(1).collect();
        // The name comes back wrapped in quotes — strip them, or the mode
        // gets created under a name that includes the `"` characters and
        // can never be selected by the clean name used above.
        let name = params
            .first()
            .copied()
            .context("no mode name")
            .map(|n| n.trim_matches('"').to_owned())?;
        let nums: Vec<&str> = params[1..].to_vec();
        let mut a: Vec<&str> = vec!["--newmode", &name];
        a.extend(nums);
        // newmode/addmode failures are fine when the mode is already
        // registered (e.g. added to the output in a previous run) — the
        // definitive check is whether the final mode switch applies.
        let _ = run(&a);
        let _ = run(&["--addmode", "screen", &name]);
        run(&["--output", "screen", "--mode", &mode_name])?;
    }
    Ok(())
}

struct Updates {
    grabber: ScreenGrabber,
    first: bool,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        // Returning `None` terminates the session, so poll until something
        // actually changes instead of reporting an empty poll.
        loop {
            let interval = if self.first { Duration::ZERO } else { POLL_INTERVAL };
            tokio::time::sleep(interval).await;

            if let Some(grab) = self.grabber.poll() {
                if self.first && grab.damage.is_some() {
                    tracing::info!(w = grab.width, h = grab.height, "first real frame captured");
                }
                self.first = false;
                if let Some(update) = grab.legacy_display_update() {
                    return Ok(Some(update));
                }
            }
        }
    }
}

/// Compare a tile against the same region of a previous full frame.
fn tile_eq_same_pos(prev_frame: &[u8], tile: &[u8], stride: usize, x: u16, y: u16, w: u16, h: u16) -> bool {
    for row in 0..h {
        let start = usize::from(y + row) * stride + usize::from(x) * 4;
        let t_start = usize::from(row) * usize::from(w) * 4;
        if prev_frame[start..start + usize::from(w) * 4] != tile[t_start..t_start + usize::from(w) * 4] {
            return false;
        }
    }
    true
}

/// Bounding box AND changed-tile count of `cur` vs `prev` (both tightly
/// packed BGRX, `width * 4` stride). `prev == None` means full damage — the
/// first grab after (re)connect or resize.
///
/// One grab is delivered as ONE update: the consumer either wraps it in a
/// single Frame Marker BEGIN/END group (legacy path) or one EGFX frame, so
/// the client presents the whole grab atomically — no mixed-age tiles during
/// video playback. Shared by the X11 grabber and the Wayland/PipeWire source.
pub(crate) fn compute_tile_damage(
    prev: Option<&[u8]>,
    cur: &[u8],
    width: u16,
    height: u16,
) -> (Option<(u16, u16, u16, u16)>, u32, u32) {
    let stride = usize::from(width) * 4;
    let total_tiles = u32::from((width + TILE - 1) / TILE) * u32::from((height + TILE - 1) / TILE);
    match prev {
        None => (Some((0u16, 0u16, width, height)), total_tiles, total_tiles),
        Some(prev) => {
            let mut min_x = u16::MAX;
            let mut min_y = u16::MAX;
            let mut max_x = 0u16; // exclusive
            let mut max_y = 0u16; // exclusive
            let mut changed = 0u32;
            let mut y = 0u16;
            while y < height {
                let mut x = 0u16;
                while x < width {
                    let w = TILE.min(width - x);
                    let h = TILE.min(height - y);
                    if !tile_eq_same_pos(prev, cur, stride, x, y, w, h) {
                        changed += 1;
                        min_x = min_x.min(x);
                        min_y = min_y.min(y);
                        max_x = max_x.max(x + w);
                        max_y = max_y.max(y + h);
                    }
                    x += TILE;
                }
                y += TILE;
            }
            (
                (min_x != u16::MAX).then(|| (min_x, min_y, max_x - min_x, max_y - min_y)),
                changed,
                total_tiles,
            )
        }
    }
}

/// X11 adapter over [`X11Display`] implementing the source traits the EGFX
/// display loop drives (see `gfx_display::FrameSource`). The grabber and its
/// crash/freeze self-healing stay in [`ScreenGrabber`]; this only feeds the
/// generic display machinery.
pub(crate) struct X11DisplayFactory {
    display: std::sync::Mutex<X11Display>,
}

impl X11DisplayFactory {
    pub(crate) fn new(display: X11Display) -> Self {
        Self {
            display: std::sync::Mutex::new(display),
        }
    }
}

impl crate::gfx_display::DisplaySourceFactory for X11DisplayFactory {
    fn size(&self) -> ironrdp_connector::DesktopSize {
        let display = self.display.lock().expect("display lock poisoned");
        let (width, height) = (display.width(), display.height());
        ironrdp_connector::DesktopSize { width, height }
    }

    fn request_initial_size(&self, client_size: ironrdp_connector::DesktopSize) -> ironrdp_connector::DesktopSize {
        let mut display = self.display.lock().expect("display lock poisoned");
        display.request_initial_size_sync(client_size)
    }

    fn request_layout(&self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
        let mut display = self.display.lock().expect("display lock poisoned");
        display.request_layout_sync(layout);
    }

    fn updates_source(&self) -> Box<dyn crate::gfx_display::FrameSource> {
        let display = self.display.lock().expect("display lock poisoned");
        Box::new(X11Source {
            grabber: Some(display.grabber()),
            display_name: display.display_name().to_owned(),
            fixed_size: display.fixed_size,
        })
    }
}

/// Per-session X11 frame source: one grabber over the factory's connection.
struct X11Source {
    grabber: Option<ScreenGrabber>,
    display_name: String,
    fixed_size: Option<(u16, u16)>,
}

impl crate::gfx_display::FrameSource for X11Source {
    fn poll_and_cursor(&mut self, cursor_due: bool) -> Option<(Grab, Option<CursorImage>)> {
        let Some(grabber) = self.grabber.as_mut() else {
            return None;
        };
        let (grab, cursor) = grabber.poll_and_cursor(cursor_due);
        grab.map(|g| (g, cursor))
    }

    fn try_attach(&mut self) {
        if self.grabber.is_none() {
            tracing::warn!(display = %self.display_name, "X grabber lost — reconnecting");
            self.grabber = ScreenGrabber::connect_new(&self.display_name);
            if let Some(grabber) = self.grabber.as_mut() {
                grabber.set_fixed_size(self.fixed_size);
            }
        }
    }

    fn is_attached(&self) -> bool {
        self.grabber.is_some()
    }

    fn name(&self) -> &str {
        &self.display_name
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GRAB_FAILURES_BEFORE_RECONNECT, GRAB_RECONNECT_RETRY_EVERY, GrabFailures, PollKind, argb_to_rdp_xor,
    };

    #[test]
    fn cursor_conversion_preserves_alpha_and_flips_rows() {
        // 1x2 sprite: top = opaque white arrow pixel, bottom = transparent
        // (with garbage RGB, as themes leave in fully transparent pixels).
        let top = 0xFFFF_FFFFu32; // a=255 r=255 g=255 b=255
        let bottom = 0x0056_3412u32; // a=0, garbage rgb
        let xor = argb_to_rdp_xor(&[top, bottom], 1, 2);
        // Rows are bottom-up: first stored row = source bottom row, RGB
        // zeroed and alpha 0 so the client composites nothing there.
        assert_eq!(&xor[0..4], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&xor[4..8], &[0xFF, 0xFF, 0xFF, 0xFF]); // opaque white
    }

    #[test]
    fn cursor_conversion_unpremultiplies_soft_edges() {
        // Premultiplied 50% white: a=128, rgb=128/255*128 -> un-premult to ~255.
        let px = (128u32 << 24) | (128 << 16) | (128 << 8) | 128;
        let xor = argb_to_rdp_xor(&[px], 1, 1);
        assert_eq!(xor[3], 128); // alpha passes through
        assert_eq!(&xor[0..3], &[255, 255, 255]); // straight 50% white
    }

    #[test]
    fn cursor_conversion_opaque_keeps_rgb() {
        let px = 0xFF00_FF80u32; // a=255 r=0 g=255 b=128
        let xor = argb_to_rdp_xor(&[px], 1, 1);
        assert_eq!(&xor[0..4], &[0x00, 0xFF, 0x80, 0xFF]);
    }

    /// A static desktop must never look like a dead X server.
    ///
    /// Regression: `poll_inner` returned a bare `None` both for "the damage
    /// gate saw no change" and for "the grab failed", and `poll` counted
    /// every `None` as a failure. ~0.5 s of an unchanging screen therefore
    /// tripped the reconnect, which drops the diff baseline and forces a
    /// full-screen lossless repaint — measured live at 37 repaints of 1.2 MB
    /// in one quiet session, ~1.7 MB/s for a desktop that was barely moving.
    #[test]
    fn idle_polls_never_trigger_a_reconnect() {
        let mut failures = GrabFailures::default();

        for _ in 0..(GRAB_FAILURES_BEFORE_RECONNECT * 10) {
            assert_eq!(failures.record(PollKind::Idle), None, "an idle poll is not a failure");
        }
    }

    /// Idle polls must not mask a genuinely dead connection either: a run of
    /// real failures still reconnects, whatever idle polls sit between them.
    #[test]
    fn real_failures_still_reconnect_across_idle_polls() {
        let mut failures = GrabFailures::default();

        for _ in 0..(GRAB_FAILURES_BEFORE_RECONNECT - 1) {
            assert_eq!(failures.record(PollKind::Failed), None);
            assert_eq!(failures.record(PollKind::Idle), None, "idle must not reset the run");
        }

        assert_eq!(
            failures.record(PollKind::Failed),
            Some(GRAB_FAILURES_BEFORE_RECONNECT),
            "the 30th consecutive failure reconnects"
        );
    }

    /// A successful grab clears the run, and the retry cadence after the
    /// first reconnect is every GRAB_RECONNECT_RETRY_EVERY failures.
    #[test]
    fn a_frame_resets_the_run_and_retries_are_paced() {
        let mut failures = GrabFailures::default();

        for _ in 0..(GRAB_FAILURES_BEFORE_RECONNECT - 1) {
            assert_eq!(failures.record(PollKind::Failed), None);
        }
        assert_eq!(failures.record(PollKind::Frame), None, "a frame clears the run");
        assert_eq!(failures.record(PollKind::Failed), None, "the run restarts from one");

        let mut failures = GrabFailures::default();
        let mut reconnects = 0;
        for _ in 0..(GRAB_FAILURES_BEFORE_RECONNECT + GRAB_RECONNECT_RETRY_EVERY * 2) {
            if failures.record(PollKind::Failed).is_some() {
                reconnects += 1;
            }
        }
        assert_eq!(reconnects, 3, "first at 30, then every 60");
    }
}

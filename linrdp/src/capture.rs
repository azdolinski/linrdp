//! Real X11 screen capture via x11rb (pure Rust, no external binaries).
//! Polls the root window with GetImage and serves the frame when it changes.

use std::sync::Arc;
use std::time::Instant;

use core::num::{NonZeroU16, NonZeroUsize};
use core::time::Duration;

use anyhow::Context as _;
use x11rb::connection::Connection as _;
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xproto::ConnectionExt as _;

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
        // X11 resize via the standard `xrandr` utility (part of the X11
        // server stack this server requires — same as Xvfb itself).
        // Sequence: create CVT mode (if missing) → add to output → apply.
        // This is the exact sequence of `xrandr --newmode/--addmode/--output`.
        let mode_name = format!("{width}x{height}_60.00");

        let run = |args: &[&str]| -> anyhow::Result<()> {
            let status = std::process::Command::new("xrandr")
                .args(args)
                .env("DISPLAY", self.display_name.as_str())
                .env("XAUTHORITY", self.xauthority.as_str())
                .status()
                .context("spawn xrandr")?;
            if !status.success() {
                anyhow::bail!("xrandr {:?} failed: {status}", args);
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
                .env("DISPLAY", self.display_name.as_str())
                .env("XAUTHORITY", self.xauthority.as_str())
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
        ScreenGrabber::new(
            Arc::clone(&self.conn),
            self.root,
            self.width,
            self.height,
            self.display_name.clone(),
        )
    }

    /// The X display this server captures (for reconnects).
    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
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
        tracing::info!(?client_size, "request_initial_size called");
        if let Some((w, h)) = self.fixed_size {
            // Fixed desktop: never touch the X screen per-connection. The
            // client scales the fixed framebuffer locally, exactly like a
            // Windows RDP session to a monitor of a different resolution.
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

    /// Client-driven resize (mstsc "Smart resize", MS-RDPBCGR 2.2.11.3
    /// Display Control Monitor Layout): resize the X screen to the first
    /// requested monitor geometry so the desktop fills the client window.
    fn request_layout(&mut self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
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
    consecutive_failures: u32,
    /// Whether XFixes QueryVersion has been exchanged on this connection
    /// (reset by reconnect — a fresh connection must renegotiate).
    xfixes_negotiated: bool,
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
            consecutive_failures: 0,
            xfixes_negotiated: false,
        }
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

    fn grab(&self) -> Option<(Vec<u8>, u16, u16)> {
        let (w, h) = self.current_geometry();
        self.conn
            .get_image(
                x11rb::protocol::xproto::ImageFormat::Z_PIXMAP,
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
        let grab = self.poll_inner();
        if grab.is_some() {
            self.consecutive_failures = 0;
            return grab;
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let failures = self.consecutive_failures;
        let due = failures == GRAB_FAILURES_BEFORE_RECONNECT
            || (failures > GRAB_FAILURES_BEFORE_RECONNECT
                && (failures - GRAB_FAILURES_BEFORE_RECONNECT) % GRAB_RECONNECT_RETRY_EVERY == 0);
        if due {
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
        grab
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

        // XFixes pixels are native-endian CARD32 ARGB (a<<24|r<<16|g<<8|b);
        // the RDP 32-bpp xor mask wants 0x00BBGGRR u32s (bytes R,G,B,x) in
        // bottom-up rows — reorder channels and flip vertically in one pass.
        let src = cur.cursor_image;
        let src_len = usize::from(width) * usize::from(height);
        if src.len() < src_len {
            return None;
        }
        let stride = usize::from(width) * 4;
        let mut xor = vec![0u8; src_len * 4];
        for row in 0..usize::from(height) {
            let src_row = &src[row * usize::from(width)..(row + 1) * usize::from(width)];
            // Destination row is the vertically mirrored one.
            let dst_row = usize::from(height) - 1 - row;
            let dst = &mut xor[dst_row * stride..(dst_row + 1) * stride];
            for (s, d) in src_row.iter().zip(dst.chunks_exact_mut(4)) {
                let argb = *s;
                d[0] = ((argb >> 16) & 0xFF) as u8; // R
                d[1] = ((argb >> 8) & 0xFF) as u8; // G
                d[2] = (argb & 0xFF) as u8; // B
                d[3] = 0xFF; // ignored byte; keep opaque for good measure
            }
        }

        Some(CursorImage {
            width,
            height,
            hot_x: hot_x.min(width.saturating_sub(1)),
            hot_y: hot_y.min(height.saturating_sub(1)),
            xor,
        })
    }

    fn poll_inner(&mut self) -> Option<Grab> {
        let (data, width, height) = tokio::task::block_in_place(|| self.grab())?;
        let stride = usize::from(width) * 4;
        if data.len() != stride * usize::from(height) {
            return None; // geometry changed mid-grab; retry next tick
        }

        if self.width != width || self.height != height {
            // Session was resized (DisplayControl/RandR): repaint everything
            // at the new size so no stale/partial content remains.
            tracing::info!(width, height, "session size changed — full repaint");
            self.width = width;
            self.height = height;
            self.prev_frame = None;
        }

        // Bounding box AND changed-tile count vs the previous grab. One grab
        // is delivered as ONE update: the consumer either wraps it in a
        // single Frame Marker BEGIN/END group (legacy path) or one EGFX
        // frame, so the client presents the whole grab atomically — no
        // mixed-age tiles during video playback.
        let total_tiles = u32::from((width + TILE - 1) / TILE) * u32::from((height + TILE - 1) / TILE);
        let (damage, changed_tiles) = match &self.prev_frame {
            None => (Some((0u16, 0u16, width, height)), total_tiles),
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
                        if !tile_eq_same_pos(prev, &data, stride, x, y, w, h) {
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
                )
            }
        };

        // Keep the frame as the diff baseline only when something changed —
        // an unchanged grab is byte-identical to the stored baseline already,
        // so skipping the (large) copy keeps idle polling cheap.
        if damage.is_some() {
            self.prev_frame = Some(data.clone());
        }
        Some(Grab {
            data,
            width,
            height,
            damage,
            changed_tiles,
            total_tiles,
        })
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

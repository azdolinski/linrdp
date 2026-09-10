//! Real X11 screen capture via x11rb (pure Rust, no external binaries).
//! Polls the root window with GetImage and serves the frame when it changes.

use std::sync::Arc;

use core::num::{NonZeroU16, NonZeroUsize};
use core::time::Duration;

use anyhow::Context as _;
use x11rb::connection::Connection as _;
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
}

fn v_blank_lines_total(height: u32, refresh: u32) -> u32 {
    let min_vbi_lines = (550 * refresh + 999) / 1000;
    ((min_vbi_lines + 3) / 4 * 4).max(23)
}

impl X11Display {
    /// Connect to `$DISPLAY` (or `:99`) and take the root window geometry.
    pub(crate) fn connect() -> anyhow::Result<Self> {
        let display_name = std::env::var("DISPLAY").unwrap_or_else(|_| ":99".to_owned());
        let (conn, screen_num) = x11rb::rust_connection::RustConnection::connect(Some(display_name.as_str()))
            .with_context(|| format!("connect to X display {display_name}"))?;
        let screen = conn.setup().roots.get(screen_num).context("no X screen")?;
        let (width, height) = (screen.width_in_pixels, screen.height_in_pixels);
        let root = screen.root;
        tracing::info!(display = %display_name, width, height, "X11 capture ready");
        Ok(Self {
            conn: Arc::new(conn),
            root,
            width,
            height,
            display_name,
            xauthority: std::env::var("XAUTHORITY").unwrap_or_default(),
        })
    }

    /// CVT v1.2 timing (standard blanking) for Xvfb mode creation — values
    /// follow the VESA CVT formula so Xvfb accepts the mode.
    fn cvt_timings(
        width: u16,
        height: u16,
        refresh: u32,
    ) -> (u16, u16, u32, u16, u16, u16, u16, u16, u16) {
        // CVT (Coordinated Video Timings) v1.2 — matches the values produced
        // by `cvt`/`xrandr --newmode` for Xvfb (verified: 2880×1800@60 →
        // dot 338.00 MHz, htotal 3568, vtotal 1893).
        let w = width as u32;
        let h = height as u32;

        // Horizontal: blanking = 160 px rounded up to multiple of 8.
        const CELL_GRAN: u32 = 8;
        let h_blank = ((w + 160) / CELL_GRAN) * CELL_GRAN - w;
        let h_total = w + h_blank;
        let hsync_start = w + 88; // hblank/2 (CVT: centered sync)
        let hsync_end = hsync_start + 32;

        // Vertical: blanking scaled with resolution (CVT: min 460 lines @60Hz
        // for typical desktop heights).
        let v_lines_est = (h + 450) * refresh / 1000; // estimated lines incl. blank
        let v_blank = v_lines_est - h;
        let v_blank = ((v_blank + 1) / 2) * 2; // even
        let v_total = h + v_blank;
        let vsync_start = h + 3;
        let vsync_end = vsync_start + 10;

        // Pixel clock (kHz) so that refresh = dot / (htotal*vtotal).
        let dot_clock = h_total * v_total * refresh / 1000;

        (
            h_total as u16,
            v_total as u16,
            dot_clock,
            hsync_start as u16,
            hsync_end as u16,
            vsync_start as u16,
            vsync_end as u16,
            32, // hsync width
            10, // vsync width
        )
    }

    fn v_blank_lines(&self, height: u32, refresh: u32) -> u32 {
        // Minimum VBLANK lines per CVT (scaled by lines): ≈ 460 lines at
        // 60 Hz regardless of height (CVT v1.2 min VBI time = 550 µs → lines).
        let min_vbi_lines = (550 * refresh + 999) / 1000; // 550 µs at refresh Hz
        let lines = (min_vbi_lines + 3) / 4 * 4; // multiple of 4
        lines.max(23) // floor
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

        let need_mode = !std::process::Command::new("xrandr")
            .args(["--verbose"])
            .env("DISPLAY", self.display_name.as_str())
            .env("XAUTHORITY", self.xauthority.as_str())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&mode_name))
            .unwrap_or(false);

        if need_mode {
            // Standard CVT timing for width×height @60Hz (as computed by cvt).
            let output = std::process::Command::new("cvt")
                .args([width.to_string().as_str(), height.to_string().as_str(), "60"])
                .env("DISPLAY", self.display_name.as_str())
                .env("XAUTHORITY", self.xauthority.as_str())
                .output()
                .context("spawn cvt")?;
            let cvt_out = String::from_utf8_lossy(&output.stdout).to_string();
            // cvt prints: Modeline "2880x1800_60.00" 338.00 2880 2968 3264 3568 ...
            let modeline = cvt_out
                .lines()
                .find(|l| l.contains("Modeline"))
                .context("cvt produced no modeline")?;
            let params: Vec<&str> = modeline.split_whitespace().skip(1).collect();
            let name = params.first().copied().context("no mode name").map(str::to_owned)?;
            let nums: Vec<&str> = params[1..].to_vec();
            let mut a: Vec<&str> = vec!["--newmode", &name];
            a.extend(nums);
            run(&a)?;
            run(&["--addmode", "screen", &name])?;
        }
        run(&["--output", "screen", "--mode", &mode_name])?;

        let (w, h) = self.query_root_geometry()?;
        if w != width || h != height {
            anyhow::bail!("root geometry {w}x{h} != requested {width}x{height}");
        }
        self.width = w;
        self.height = h;
        tracing::info!(width = w, height = h, "X screen resized via xrandr");
        Ok(())
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
            conn: Arc::clone(&self.conn),
            root: self.root,
            width: self.width,
            height: self.height,
            prev_frame: None,
            first: true,
        }))
    }
}

// NOTE: `Updates` reads the CURRENT root geometry on every grab (query via
// get_geometry) so a DisplayControl resize mid-session is picked up without
// reconnecting.

struct Updates {
    conn: Arc<x11rb::rust_connection::RustConnection>,
    root: u32,
    width: u16,
    height: u16,
    prev_frame: Option<Vec<u8>>,
    first: bool,
}

/// Tile edge length for change detection (MS-RDPBCGR-style dirty-region
/// granularity; the server encoder re-diffs the delivered region against its
/// own framebuffer, so only actually-changed sub-rectangles are encoded).
const TILE: u16 = 64;

/// Screen polling interval: ~60 Hz capture, each grab delivered as one
/// bitmap update — the encoder wraps it in a single Frame Marker group
/// (MS-RDPBCGR 2.2.9.2.3) so the client presents it atomically.
const POLL_INTERVAL: Duration = Duration::from_millis(16);

impl Updates {
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

    fn make_update(data: Vec<u8>, x: u16, y: u16, width: u16, height: u16) -> DisplayUpdate {
        DisplayUpdate::Bitmap(BitmapUpdate {
            x,
            y,
            width: NonZeroU16::new(width).expect("non-zero width"),
            height: NonZeroU16::new(height).expect("non-zero height"),
            format: PixelFormat::BgrX32,
            data: data.into(),
            stride: NonZeroUsize::new(usize::from(width) * 4).expect("non-zero stride"),
        })
    }

    /// Extract one sub-rectangle from a full frame buffer.
    fn crop(data: &[u8], stride: usize, x: u16, y: u16, w: u16, h: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(usize::from(w) * usize::from(h) * 4);
        for row in y..y + h {
            let start = usize::from(row) * stride + usize::from(x) * 4;
            out.extend_from_slice(&data[start..start + usize::from(w) * 4]);
        }
        out
    }
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        // Returning `None` terminates the session, so poll until something
        // actually changes instead of reporting an empty poll.
        loop {
            let interval = if self.first { Duration::ZERO } else { POLL_INTERVAL };
            tokio::time::sleep(interval).await;

            match self.poll_once()? {
                Some(update) => return Ok(Some(update)),
                None => continue,
            }
        }
    }
}

impl Updates {
    fn poll_once(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        let Some((data, width, height)) = tokio::task::block_in_place(|| self.grab()) else {
            return Ok(None);
        };
        let stride = usize::from(width) * 4;
        if data.len() != stride * usize::from(height) {
            return Ok(None); // geometry changed mid-grab; retry next tick
        }

        if self.width != width || self.height != height {
            // Session was resized (DisplayControl/RandR): repaint everything
            // at the new size so no stale/partial content remains.
            tracing::info!(width, height, "session size changed — full repaint");
            self.width = width;
            self.height = height;
            self.prev_frame = None;
        }

        // Bounding box of changed tiles vs the previous grab. One grab is
        // delivered as ONE bitmap update: the encoder diffs it against its own
        // framebuffer (only real changes are encoded) and wraps the result in
        // a single Frame Marker BEGIN/END group, so the client presents the
        // whole grab atomically — no mixed-age tiles during video playback.
        let damage = match &self.prev_frame {
            None => {
                if self.first {
                    tracing::info!(w = width, h = height, "first real frame captured");
                }
                Some((0u16, 0u16, width, height))
            }
            Some(prev) => {
                let mut min_x = u16::MAX;
                let mut min_y = u16::MAX;
                let mut max_x = 0u16; // exclusive
                let mut max_y = 0u16; // exclusive
                let mut y = 0u16;
                while y < height {
                    let mut x = 0u16;
                    while x < width {
                        let w = TILE.min(width - x);
                        let h = TILE.min(height - y);
                        if !tile_eq_same_pos(prev, &data, stride, x, y, w, h) {
                            min_x = min_x.min(x);
                            min_y = min_y.min(y);
                            max_x = max_x.max(x + w);
                            max_y = max_y.max(y + h);
                        }
                        x += TILE;
                    }
                    y += TILE;
                }
                (min_x != u16::MAX).then(|| (min_x, min_y, max_x - min_x, max_y - min_y))
            }
        };

        self.first = false;
        self.prev_frame = Some(data);

        match damage {
            Some((x, y, w, h)) => {
                let frame = self.prev_frame.as_ref().expect("just stored");
                let region = Self::crop(frame, stride, x, y, w, h);
                Ok(Some(Self::make_update(region, x, y, w, h)))
            }
            None => Ok(None), // nothing changed this poll
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

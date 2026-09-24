//! A desktop this worker serves through its compositor rather than through
//! an X display.
//!
//! A worker is built before anyone has authenticated, so it cannot know yet
//! which desktop it will serve: the router decides that after the login, per
//! account (see `session::backends`). The X11 paths reach their display
//! through the session gate. Every other desktop — GNOME through Mutter
//! today — is attached here, once, and the display, input, clipboard and
//! disconnect paths follow it from then on. None of them names a
//! compositor: serving another one (KWin, a wlroots compositor) means
//! implementing [`CompositorDesktop`], not touching them.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use ironrdp_server::{DesktopSize, RdpServerInputHandler};

use crate::gfx_display::{DisplaySourceFactory, FrameSource};

/// One attached desktop, as the worker's subsystems see it.
pub(crate) trait CompositorDesktop: Send + Sync {
    /// The account whose desktop this is.
    fn user(&self) -> &str;

    /// A name for the log and for noticing a handover, e.g. `gnome:alice`.
    fn label(&self) -> String;

    /// Where its frames come from, at the size the desktop has now.
    fn frames(&self) -> Arc<dyn DisplaySourceFactory>;

    /// The client's desktop is now `width`x`height`.
    fn resize(&self, width: u32, height: u32);

    /// Input for one connection to this desktop. Each handler keeps its own
    /// state (the keys the client holds down), so a new connection starts
    /// clean.
    fn input(self: Arc<Self>) -> Box<dyn RdpServerInputHandler>;

    /// Moves each time something in the session copies. `None` when the
    /// compositor cannot say so, and the clipboard is polled instead.
    fn clipboard_generation(&self) -> Option<u64>;

    /// The MIME types the session's clipboard holds.
    fn clipboard_mimes(&self) -> Vec<String>;

    /// The session's clipboard in `mime`, if it holds that. Blocking, for at
    /// most a few seconds — the app that copied has to write it out.
    fn read_clipboard(&self, mime: &str) -> Option<Vec<u8>>;

    /// Offer `targets` (MIME type, bytes) as the session's clipboard.
    fn publish_clipboard(&self, targets: Vec<(String, Vec<u8>)>);

    /// Put the desktop back behind its lock screen, if serving it took the
    /// lock down. Runs on the disconnect path, so it must not hang on a
    /// compositor that stopped answering.
    fn relock(&self);
}

/// The desktop this worker serves, once it serves one. A worker serves exactly
/// one connection, so it is set at most once — the same rule the session gate
/// enforces for X displays.
static ACTIVE: OnceLock<Arc<dyn CompositorDesktop>> = OnceLock::new();

pub(crate) fn active() -> Option<Arc<dyn CompositorDesktop>> {
    ACTIVE.get().cloned()
}

/// Serve `desktop` for the rest of this worker's life.
pub(crate) fn set_active(desktop: Arc<dyn CompositorDesktop>) -> anyhow::Result<()> {
    let label = desktop.label();
    ACTIVE.set(desktop).map_err(|_| {
        anyhow::anyhow!("this worker already serves a desktop through its compositor; refusing to attach {label} too")
    })
}

/// The display factory a worker is built with before it knows whose desktop
/// it serves: X11 until a desktop is attached here, that desktop's frames after.
pub(crate) struct SessionDisplayFactory {
    x11: Arc<dyn DisplaySourceFactory>,
}

impl SessionDisplayFactory {
    pub(crate) fn new(x11: Arc<dyn DisplaySourceFactory>) -> Self {
        Self { x11 }
    }
}

impl DisplaySourceFactory for SessionDisplayFactory {
    fn size(&self) -> DesktopSize {
        match active() {
            Some(desktop) => desktop.frames().size(),
            None => self.x11.size(),
        }
    }

    fn request_initial_size(&self, client_size: DesktopSize) -> DesktopSize {
        match active() {
            Some(desktop) => desktop.frames().request_initial_size(client_size),
            // Not attached yet — which is the normal case: the size is
            // negotiated before the client has authenticated. The client's own
            // size is the honest answer; the stream's real size arrives with
            // its first frame and the surface is rebuilt to it.
            None => self.x11.request_initial_size(client_size),
        }
    }

    fn request_layout(&self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
        match active() {
            Some(desktop) => match layout.monitors().first() {
                Some(monitor) => desktop.resize(monitor.width(), monitor.height()),
                None => desktop.frames().request_layout(layout),
            },
            None => self.x11.request_layout(layout),
        }
    }

    fn updates_source(&self) -> Box<dyn FrameSource> {
        match active() {
            Some(desktop) => desktop.frames().updates_source(),
            None => Box::new(SwitchingSource {
                inner: self.x11.updates_source(),
                attached: false,
            }),
        }
    }
}

/// A frame source minted before authentication, which follows the worker to
/// the attached desktop's stream once there is one.
///
/// The display loop keeps the source it has and only asks it to reattach, so
/// the switch has to happen inside the source: an X11 source that simply
/// stayed detached would keep the client on a black screen forever.
struct SwitchingSource {
    inner: Box<dyn FrameSource>,
    attached: bool,
}

impl SwitchingSource {
    fn follow(&mut self) {
        if self.attached {
            return;
        }
        if let Some(desktop) = active() {
            tracing::info!(desktop = desktop.label(), "frame source moved to the attached desktop");
            self.inner = desktop.frames().updates_source();
            self.attached = true;
        }
    }
}

impl FrameSource for SwitchingSource {
    fn poll_and_cursor(
        &mut self,
        cursor_due: bool,
        debt_due: bool,
    ) -> Option<(crate::capture::Grab, Option<crate::capture::CursorImage>)> {
        self.follow();
        self.inner.poll_and_cursor(cursor_due, debt_due)
    }

    fn try_attach(&mut self) {
        self.follow();
        if !self.attached {
            self.inner.try_attach();
        }
    }

    fn is_attached(&self) -> bool {
        // Detached as far as the loop can tell until it has moved, so the loop
        // calls `try_attach` — which is where the move happens.
        if !self.attached && active().is_some() {
            return false;
        }
        self.inner.is_attached()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn settle_until(&self) -> Instant {
        self.inner.settle_until()
    }
}

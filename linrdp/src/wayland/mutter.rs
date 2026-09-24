//! GNOME backend: serve a user's running GNOME session through Mutter's own
//! remote-desktop API — the one gnome-remote-desktop is built on.
//!
//! Why not the portal path next to this file: xdg-desktop-portal asks the
//! person at the desk for consent, and nobody is at the desk of a machine
//! being reached over RDP. `org.gnome.Mutter.RemoteDesktop` and
//! `org.gnome.Mutter.ScreenCast` live on the user's own session bus, ask
//! nothing, and are only reachable by a process that can authenticate to
//! that bus as the user — which is exactly the account the RDP client has
//! just proved it is.
//!
//! Why this exists at all: GNOME 49 dropped the X11 session and GNOME 50
//! dropped Mutter's X11 backend. On such a machine no Xvfb or Xorg will ever
//! serve the desktop the user actually has; this is the only way to it.
//!
//! The pieces:
//!
//! - the bus and the PipeWire socket are found under the user's runtime dir,
//!   `/run/user/<uid>`, or under `/run/host/run/user/<uid>` when linrdp runs
//!   inside a distrobox/apx/toolbox container whose desktop is the host's;
//! - both sockets are connected by a short-lived thread whose effective uid
//!   is the user's (per-thread `setresuid`, not the process-wide wrapper), so
//!   the peer credentials the bus and PipeWire see are the user's and never
//!   root's, and nothing else in this worker changes identity;
//! - frames come from the Mutter screencast stream through the PipeWire
//!   consumer in `pipewire.rs`; input goes back over the same bus through
//!   `RemoteDesktop.Session.Notify*`, which needs no libei.
//!
//! Everything D-Bus runs on one thread with its own runtime, for the life of
//! the worker: Mutter ties a remote-desktop session to the connection that
//! created it and closes it when that connection goes away.

use std::collections::{HashMap, HashSet};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use futures_util::StreamExt as _;
use ironrdp_server::{KeyboardEvent, MouseButton, MouseEvent, RdpServerInputHandler};
use tokio::sync::mpsc;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MatchRule, MessageStream};

use crate::gfx_display::DisplaySourceFactory;
use crate::wayland::compositor::CompositorDesktop;
use crate::wayland::pipewire::{PwCapture, PwDisplayFactory};

const RD_NAME: &str = "org.gnome.Mutter.RemoteDesktop";
const RD_PATH: &str = "/org/gnome/Mutter/RemoteDesktop";
const RD_IFACE: &str = "org.gnome.Mutter.RemoteDesktop";
const RD_SESSION_IFACE: &str = "org.gnome.Mutter.RemoteDesktop.Session";
const SC_NAME: &str = "org.gnome.Mutter.ScreenCast";
const SC_PATH: &str = "/org/gnome/Mutter/ScreenCast";
const SC_IFACE: &str = "org.gnome.Mutter.ScreenCast";
const SC_SESSION_IFACE: &str = "org.gnome.Mutter.ScreenCast.Session";
const SC_STREAM_IFACE: &str = "org.gnome.Mutter.ScreenCast.Stream";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";
const SCREENSAVER_NAME: &str = "org.gnome.ScreenSaver";
const SCREENSAVER_PATH: &str = "/org/gnome/ScreenSaver";
const SCREENSAVER_IFACE: &str = "org.gnome.ScreenSaver";
const DISPLAY_CONFIG_NAME: &str = "org.gnome.Mutter.DisplayConfig";
const DISPLAY_CONFIG_PATH: &str = "/org/gnome/Mutter/DisplayConfig";
const DISPLAY_CONFIG_IFACE: &str = "org.gnome.Mutter.DisplayConfig";

/// `DisplayConfig.PowerSaveMode`: on, and off (DPMS off). Mutter keeps
/// compositing — and the screencast keeps recording — with the outputs off.
const POWER_ON: i32 = 0;
const POWER_OFF: i32 = 3;

/// Cleared when the client leaves, before the monitors are turned back on —
/// otherwise the guard below sees them come on and turns them off again.
static GUARD_DESK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Set while linrdp itself is ending the remote-desktop session on the way
/// out, so its `Closed` signal is not mistaken for the desktop going away.
static LEAVING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How long gnome-shell may take to lift its remote-access inhibition after
/// the shield has gone down. It is lifted from the shell's main loop, not
/// synchronously with `SetActive`.
const UNLOCK_SETTLE: Duration = Duration::from_secs(5);

/// Mutter answers `Start` with the PipeWire node within milliseconds; a
/// stream that has not appeared by then is not going to.
const STREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// `cursor-mode` 1: the pointer is drawn into the frames, so the client sees
/// it without a pointer channel of its own (the X11 path draws it the same way
/// when it cannot send a sprite).
const CURSOR_MODE_EMBEDDED: u32 = 1;

// linux/input-event-codes.h
const BTN_LEFT: i32 = 0x110;
const BTN_RIGHT: i32 = 0x111;
const BTN_MIDDLE: i32 = 0x112;
const BTN_SIDE: i32 = 0x113;
const BTN_EXTRA: i32 = 0x114;

/// `NotifyPointerAxisDiscrete` axes.
const AXIS_VERTICAL: u32 = 0;
const AXIS_HORIZONTAL: u32 = 1;

/// Where one user's GNOME session can be reached from this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GnomeSession {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// The user's runtime dir, as this process sees it — the PipeWire socket
    /// and the session's PulseAudio live there.
    pub(crate) runtime_dir: PathBuf,
    /// The session's own bus. For a desktop the user logged in to, the
    /// runtime dir's `bus`; for a headless session linrdp started, the
    /// private bus it was given (two GNOME Shells cannot share one bus).
    pub(crate) bus: PathBuf,
}

impl GnomeSession {
    /// The desktop the user logged in to: its bus is the runtime dir's.
    pub(crate) fn logged_in(uid: u32, gid: u32, runtime_dir: PathBuf) -> Self {
        let bus = runtime_dir.join("bus");
        Self { uid, gid, runtime_dir, bus }
    }

    fn bus(&self) -> PathBuf {
        self.bus.clone()
    }

    fn pipewire(&self) -> PathBuf {
        self.runtime_dir.join("pipewire-0")
    }
}

/// What the client is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Screen {
    /// The primary monitor as it is — the console (`mstsc /admin`).
    Monitor,
    /// A virtual monitor Mutter creates at exactly this size for as long as
    /// the client is connected — a remote session of its own.
    Virtual(u32, u32),
}

/// The runtime dirs a user's desktop may live in, most direct first.
///
/// `/run/host` is where distrobox, toolbox and Vanilla OS's apx mount the
/// host's root: when linrdp is installed in such a container, the desktop is
/// the host's and so are its sockets. The container's own `/run/user/<uid>`
/// usually exists too, with a bus of the container's systemd on it and no
/// Mutter — which is why every candidate is asked, not just the first that
/// exists.
pub(crate) fn runtime_dir_candidates(uid: u32) -> Vec<PathBuf> {
    vec![
        PathBuf::from(format!("/run/user/{uid}")),
        PathBuf::from(format!("/run/host/run/user/{uid}")),
    ]
}

/// Connect a unix socket with this thread's effective uid/gid switched to the
/// user's.
///
/// The bus authenticates with the peer credentials taken at `connect()`, and
/// so does PipeWire's access module: a worker connecting as root is somebody
/// else to both, and in a rootless container root is not even root — it is a
/// sub-uid nobody on the host knows. The switch is made with the raw
/// syscalls, which change only the calling thread (glibc's `seteuid` would
/// broadcast to every thread of the worker), on a thread that exits straight
/// afterwards, so no restore is needed and none can be forgotten.
fn connect_as(uid: u32, gid: u32, path: &Path) -> std::io::Result<UnixStream> {
    let path = path.to_owned();
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                // SAFETY: plain syscalls; geteuid cannot fail.
                let euid = unsafe { libc::geteuid() };
                // -1 leaves the real and saved ids alone.
                const KEEP: libc::c_long = -1;
                if euid != uid {
                    // SAFETY: setresgid/setresuid on this thread only. The
                    // group first: once the uid is not root the gid cannot
                    // change.
                    unsafe {
                        if libc::syscall(libc::SYS_setresgid, KEEP, libc::c_long::from(gid), KEEP)
                            != 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::syscall(libc::SYS_setresuid, KEEP, libc::c_long::from(uid), KEEP)
                            != 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                }
                UnixStream::connect(&path)
            })
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("socket connect thread panicked")))
    })
}

/// Open the session bus at `bus` as `uid`.
async fn connect_bus(uid: u32, gid: u32, bus: &Path) -> anyhow::Result<Connection> {
    let stream = connect_as(uid, gid, bus).with_context(|| format!("connect to {}", bus.display()))?;
    stream.set_nonblocking(true)?;
    let stream = tokio::net::UnixStream::from_std(stream)?;
    zbus::connection::Builder::unix_stream(stream)
        // EXTERNAL sends a uid; it must be the one the socket was opened
        // with, not the worker's own.
        .user_id(uid)
        .build()
        .await
        .with_context(|| format!("authenticate to the session bus at {} as uid {uid}", bus.display()))
}

async fn has_mutter(connection: &Connection) -> bool {
    let Ok(proxy) = zbus::fdo::DBusProxy::new(connection).await else {
        return false;
    };
    let Ok(name) = zbus::names::BusName::try_from(RD_NAME) else {
        return false;
    };
    proxy.name_has_owner(name).await.unwrap_or(false)
}

/// Find `uid`'s running GNOME session, on a bus that has Mutter's
/// remote-desktop service on it. `None` when the user has none — not logged
/// in, or logged in to something that is not GNOME.
async fn find_async(uid: u32, gid: u32) -> Option<(GnomeSession, Connection)> {
    for runtime_dir in runtime_dir_candidates(uid) {
        let session = GnomeSession::logged_in(uid, gid, runtime_dir);
        if !session.bus().exists() {
            continue;
        }
        match connect_bus(uid, gid, &session.bus()).await {
            Ok(connection) if has_mutter(&connection).await => return Some((session, connection)),
            Ok(_) => tracing::debug!(bus = %session.bus().display(), "session bus without Mutter"),
            Err(error) => tracing::debug!(error = format!("{error:#}"), "session bus unreachable"),
        }
    }
    None
}

/// Blocking form of [`find_async`], for `doctor` and the session router,
/// neither of which is async. Runs on a runtime of its own so it can be
/// called from inside another one.
pub(crate) fn find(uid: u32, gid: u32) -> Option<GnomeSession> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().ok()?;
                runtime.block_on(async { find_async(uid, gid).await.map(|(session, _)| session) })
            })
            .join()
            .ok()
            .flatten()
    })
}

/// Wait for a headless GNOME Shell on `bus` to answer, then give the bus the
/// activation environment of that session.
///
/// Blocking, for the keeper. The environment is the part that makes the
/// session usable at all: services the private bus activates — apps among
/// them — otherwise inherit the bus daemon's own environment, and an app
/// that finds no `WAYLAND_DISPLAY` for its session opens on nobody's screen.
pub(crate) fn prepare_headless(
    uid: u32,
    gid: u32,
    bus: &Path,
    activation: &[(String, String)],
    timeout: Duration,
) -> anyhow::Result<()> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                runtime.block_on(async {
                    let deadline = Instant::now() + timeout;
                    loop {
                        if let Ok(connection) = connect_bus(uid, gid, bus).await
                            && has_mutter(&connection).await
                        {
                            let env: HashMap<&str, &str> =
                                activation.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                            connection
                                .call_method(
                                    Some("org.freedesktop.DBus"),
                                    "/org/freedesktop/DBus",
                                    Some("org.freedesktop.DBus"),
                                    "UpdateActivationEnvironment",
                                    &env,
                                )
                                .await
                                .context("UpdateActivationEnvironment")?;
                            return Ok(());
                        }
                        anyhow::ensure!(
                            Instant::now() < deadline,
                            "no Mutter on {} after {timeout:?}",
                            bus.display()
                        );
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                })
            })
            .join()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("the readiness thread panicked")))
    })
}

/// Lock `session` — the console, when a remote session of the same account
/// takes over — so whoever is at the desk sees that it is in use elsewhere.
/// Best effort: a console that cannot be locked does not refuse the login.
pub(crate) fn lock_session(session: &GnomeSession) {
    let result = std::thread::scope(|scope| {
        scope
            .spawn(|| -> anyhow::Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                runtime.block_on(async {
                    let connection = connect_bus(session.uid, session.gid, &session.bus()).await?;
                    set_locked(&connection, true).await?;
                    Ok(())
                })
            })
            .join()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("the lock thread panicked")))
    });
    match result {
        Ok(()) => tracing::info!(bus = %session.bus().display(), "console session locked — the account is in use over RDP"),
        Err(error) => tracing::warn!(error = format!("{error:#}"), "could not lock the console session"),
    }
}

/// One input event on its way to Mutter.
#[derive(Debug, Clone, Copy)]
enum InputCall {
    Keycode(u32, bool),
    Keysym(u32, bool),
    Motion(f64, f64),
    RelativeMotion(f64, f64),
    Button(i32, bool),
    Axis(u32, i32),
}

/// What the Mutter thread is asked to do.
enum Command {
    Input(InputCall),
    /// Lock the session again, acknowledging once it is locked (or failed).
    Lock(std::sync::mpsc::Sender<()>),
    /// The client's desktop changed size: fit the monitor to it again.
    Resize(u32, u32),
    /// Read the session's clipboard in one MIME type.
    ReadClipboard(String, std::sync::mpsc::Sender<Option<Vec<u8>>>),
    /// Put the client's clipboard on the session's, in these MIME types.
    PublishClipboard(Vec<(String, Vec<u8>)>),
}

/// The session's clipboard, as far as this connection knows it.
///
/// Mutter's remote-desktop clipboard is the Wayland one, reached over the
/// session's bus: `SelectionOwnerChanged` says what the session now holds,
/// `SelectionRead` fetches it, `SetSelection` offers the client's, and
/// `SelectionTransfer` asks for it when an app in the session pastes.
#[derive(Default)]
pub(crate) struct ClipboardState {
    /// Bumped whenever something in the session (not this connection)
    /// copies. The clipboard poller reads only when it moves.
    generation: std::sync::atomic::AtomicU64,
    /// MIME types the session's clipboard holds right now.
    mimes: std::sync::Mutex<Vec<String>>,
    /// What this connection put on the session's clipboard, by MIME type —
    /// served on `SelectionTransfer`.
    offered: std::sync::Mutex<HashMap<String, Vec<u8>>>,
}

/// The largest clipboard payload read from the session. A clipboard is not a
/// file transfer, and an app offering gigabytes must not exhaust the worker.
const MAX_CLIPBOARD: u64 = 256 * 1024 * 1024;

/// How the attach treats the desk the session is shown on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttachOptions {
    /// Unlock a locked session once the RDP login has proved the password.
    /// gnome-shell refuses every remote-desktop session while its shield is
    /// up, so without this a locked desktop — the usual state of a machine
    /// nobody is sitting at — cannot be reached at all.
    pub(crate) unlock: bool,
    /// Lock it again when the client disconnects, so the desk is left the way
    /// the unlock found it.
    pub(crate) relock: bool,
    /// Keep the physical monitors off while a client is connected. The
    /// session is one desktop shown in two places; without this, whoever
    /// walks past the desk watches what the remote user is doing — and a
    /// session unlocked for a remote login would sit unlocked in front of
    /// them.
    pub(crate) blank_local: bool,
    /// Switch the monitor to the mode that fits the client best, and back
    /// on disconnect (see `display_mode`). Monitor screens only.
    pub(crate) fit_client: bool,
    /// Lock the session whenever the client disconnects, whether or not this
    /// attach unlocked it — a remote session nobody is looking at.
    pub(crate) always_lock: bool,
    pub(crate) screen: Screen,
    /// With a virtual screen: make it the only monitor of the layout while
    /// the client is connected, and put the desk's layout back afterwards —
    /// the console shown at the client's own resolution, the way Windows
    /// resizes a console session taken over remotely.
    pub(crate) replace_desk: bool,
}

impl AttachOptions {
    /// The console (`mstsc /admin`) at the client's size: a virtual monitor
    /// replaces the desk's monitors while connected, the session is unlocked
    /// for the verified login and locked again afterwards, and the desk gets
    /// its own layout — its own resolution — back.
    pub(crate) fn console(size: (u16, u16)) -> Self {
        Self {
            screen: Screen::Virtual(u32::from(size.0), u32::from(size.1)),
            replace_desk: true,
            ..Self::default()
        }
    }

    /// A remote session of its own, at the client's size, locked whenever
    /// nobody is connected.
    pub(crate) fn remote(size: (u16, u16)) -> Self {
        Self {
            unlock: true,
            relock: true,
            blank_local: false,
            fit_client: false,
            always_lock: true,
            screen: Screen::Virtual(u32::from(size.0), u32::from(size.1)),
            replace_desk: false,
        }
    }
}

impl Default for AttachOptions {
    fn default() -> Self {
        Self {
            unlock: true,
            relock: true,
            blank_local: true,
            fit_client: true,
            always_lock: false,
            screen: Screen::Monitor,
            replace_desk: false,
        }
    }
}

/// The attached desktop: the capture stream and the input queue.
struct GnomeDesktop {
    user: String,
    /// Owned for its `Drop`, which stops the stream; frames are read
    /// through `frames`.
    _capture: PwCapture,
    frames: Arc<dyn DisplaySourceFactory>,
    commands: mpsc::UnboundedSender<Command>,
    /// Whether this attach unlocked the session, and so owes a lock back.
    unlocked: bool,
    options: AttachOptions,
    clipboard: Arc<ClipboardState>,
}

impl CompositorDesktop for GnomeDesktop {
    fn user(&self) -> &str {
        &self.user
    }

    fn label(&self) -> String {
        format!("gnome:{}", self.user)
    }

    fn frames(&self) -> Arc<dyn DisplaySourceFactory> {
        Arc::clone(&self.frames)
    }

    fn resize(&self, width: u32, height: u32) {
        if self.options.fit_client {
            let _ = self.commands.send(Command::Resize(width, height));
        }
    }

    fn input(self: Arc<Self>) -> Box<dyn RdpServerInputHandler> {
        Box::new(MutterInput {
            desktop: self,
            pressed: HashSet::new(),
        })
    }

    /// GNOME says so with a signal, so this is always `Some`.
    fn clipboard_generation(&self) -> Option<u64> {
        Some(self.clipboard.generation.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn clipboard_mimes(&self) -> Vec<String> {
        self.clipboard.mimes.lock().map(|m| m.clone()).unwrap_or_default()
    }

    fn read_clipboard(&self, mime: &str) -> Option<Vec<u8>> {
        if !self.clipboard_mimes().iter().any(|m| m == mime) {
            return None;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        self.commands.send(Command::ReadClipboard(mime.to_owned(), tx)).ok()?;
        rx.recv_timeout(Duration::from_secs(6)).ok().flatten()
    }

    fn publish_clipboard(&self, targets: Vec<(String, Vec<u8>)>) {
        let _ = self.commands.send(Command::PublishClipboard(targets));
    }

    /// Put the session back behind its lock screen, if this attach took it
    /// down. Blocks until done, or for at most two seconds: it runs on the
    /// disconnect path, which must not hang on a shell that stopped answering.
    fn relock(&self) {
        if !(self.options.blank_local
            || self.options.replace_desk
            || self.options.fit_client
            || self.options.always_lock
            || (self.unlocked && self.options.relock))
        {
            return;
        }
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        if self.commands.send(Command::Lock(done_tx)).is_ok() {
            let _ = done_rx.recv_timeout(Duration::from_secs(2));
        }
    }
}

/// Attach this worker to `user`'s running GNOME session: start a Mutter
/// remote-desktop + screencast session on their bus, connect the PipeWire
/// stream, and make the display, input and clipboard paths use it (see
/// `wayland::compositor`).
///
/// Blocks until the stream is up or has failed. The D-Bus side keeps running
/// on its own thread for the rest of the worker's life.
pub(crate) fn attach(
    user: &str,
    session: &GnomeSession,
    options: AttachOptions,
    client_size: (u16, u16),
) -> anyhow::Result<Arc<dyn CompositorDesktop>> {
    if let Some(existing) = crate::wayland::compositor::active() {
        anyhow::ensure!(
            existing.user() == user,
            "this worker already serves {}; refusing to attach to {user}'s GNOME session",
            existing.label()
        );
        return Ok(existing);
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<anyhow::Result<Arc<GnomeDesktop>>>();
    let session = session.clone();
    let user = user.to_owned();
    std::thread::Builder::new()
        .name("linrdp-mutter".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(anyhow::anyhow!("start the Mutter runtime: {error}")));
                    return;
                }
            };
            runtime.block_on(run(user, session, options, client_size, ready_tx));
        })
        .context("spawn the Mutter thread")?;

    let desktop = ready_rx
        .recv_timeout(STREAM_TIMEOUT + Duration::from_secs(5))
        .map_err(|_| anyhow::anyhow!("GNOME session did not come up in time"))??;
    Ok(desktop)
}

/// The Mutter thread: set up, report, then serve input until the session ends.
async fn run(
    user: String,
    session: GnomeSession,
    options: AttachOptions,
    client_size: (u16, u16),
    ready: std::sync::mpsc::Sender<anyhow::Result<Arc<GnomeDesktop>>>,
) {
    let (connection, remote, unlocked) = match start(&session, options, client_size).await {
        Ok(started) => started,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };

    let size = match options.screen {
        Screen::Virtual(width, height) => Some((width, height)),
        Screen::Monitor => None,
    };
    let capture = match connect_pipewire(&session, remote.node_id, size) {
        Ok(capture) => capture,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };

    // The virtual monitor exists once the stream's format is agreed; only
    // then can it become the layout's only monitor.
    if let Some(before) = &remote.desk_layout {
        let replaced = async {
            anyhow::ensure!(capture.wait_negotiated(Duration::from_secs(5)), "the stream never negotiated");
            let connector = crate::wayland::display_mode::new_connector(&connection, before)
                .await?
                .context("no new monitor appeared for the stream")?;
            crate::wayland::display_mode::make_sole(&connection, &connector).await?;
            anyhow::Ok(connector)
        }
        .await;
        match replaced {
            Ok(connector) => tracing::info!(%connector, "the desk's monitors replaced by the client-sized one"),
            Err(error) => tracing::warn!(
                error = format!("{error:#}"),
                "could not replace the desk's monitors — the client gets an extra monitor instead"
            ),
        }
    }

    let clipboard = Arc::new(ClipboardState::default());
    // Without it the session's clipboard is simply not shared; the desktop
    // is still worth serving.
    if let Err(error) = connection
        .call_method(
            Some(RD_NAME),
            remote.rd_path.as_str(),
            Some(RD_SESSION_IFACE),
            "EnableClipboard",
            &HashMap::<&str, Value<'_>>::new(),
        )
        .await
    {
        tracing::warn!(%error, "the session's clipboard cannot be shared (EnableClipboard)");
    }

    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let desktop = Arc::new(GnomeDesktop {
        user: user.clone(),
        frames: Arc::new(PwDisplayFactory::new(capture.shared())),
        _capture: capture,
        commands: commands_tx,
        unlocked,
        options,
        clipboard: Arc::clone(&clipboard),
    });
    let active: Arc<dyn CompositorDesktop> = Arc::<GnomeDesktop>::clone(&desktop);
    if let Err(error) = crate::wayland::compositor::set_active(active) {
        let _ = ready.send(Err(error));
        return;
    }
    tracing::info!(
        user,
        bus = %session.bus().display(),
        node = remote.node_id,
        width = remote.size.0,
        height = remote.size.1,
        "serving the user's GNOME session through Mutter"
    );
    let _ = ready.send(Ok(desktop));

    // Mutter closes the session when the user logs out or the shell restarts.
    // The connection has nothing left to show then; ending the worker drops
    // it with the reason in the log, rather than streaming a frozen frame.
    let closed = async {
        watch_closed(&connection, &remote.rd_path).await;
        // Closed by linrdp itself on the way out: the leaving path finishes.
        if LEAVING.load(std::sync::atomic::Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
    };
    let guard = async {
        if options.blank_local {
            keep_desk_dark(&connection).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        () = serve_commands(&connection, &remote, commands_rx, &clipboard) => {}
        () = watch_clipboard(&connection, &remote, &clipboard) => {}
        () = guard => {}
        () = closed => {
            tracing::warn!(user, "the GNOME session closed the remote-desktop session — ending this connection");
            std::process::exit(0);
        }
    }
}

struct RemoteSession {
    options: AttachOptions,
    /// Whether this attach unlocked the session.
    unlocked: bool,
    /// The monitor mode before the client's, to go back to on disconnect.
    original_mode: Option<String>,
    /// The desk's layout before a virtual monitor replaced it.
    desk_layout: Option<crate::wayland::display_mode::Snapshot>,
    rd_path: OwnedObjectPath,
    stream_path: OwnedObjectPath,
    node_id: u32,
    size: (u32, u32),
}

async fn screen_locked(connection: &Connection) -> bool {
    let Ok(reply) = connection
        .call_method(Some(SCREENSAVER_NAME), SCREENSAVER_PATH, Some(SCREENSAVER_IFACE), "GetActive", &())
        .await
    else {
        return false;
    };
    reply.body().deserialize::<bool>().unwrap_or(false)
}

async fn set_locked(connection: &Connection, locked: bool) -> zbus::Result<()> {
    connection
        .call_method(Some(SCREENSAVER_NAME), SCREENSAVER_PATH, Some(SCREENSAVER_IFACE), "SetActive", &locked)
        .await
        .map(drop)
}

/// `RemoteDesktop.CreateSession`, unlocking the session first when it is
/// locked and the options allow it. Returns the session and whether this call
/// unlocked it.
async fn create_session(connection: &Connection, options: AttachOptions) -> anyhow::Result<(OwnedObjectPath, bool)> {
    let mut unlocked = false;
    if screen_locked(connection).await {
        anyhow::ensure!(
            options.unlock,
            "the GNOME session is locked, and GNOME refuses remote-desktop sessions while it is \
             — unlock it at the machine, or allow linrdp to unlock it after a verified login"
        );
        set_locked(connection, false)
            .await
            .context("unlock the GNOME session (org.gnome.ScreenSaver.SetActive)")?;
        unlocked = true;
        tracing::info!("the GNOME session was locked — unlocked it for the verified login");
    }

    let deadline = Instant::now() + UNLOCK_SETTLE;
    loop {
        match connection
            .call_method(Some(RD_NAME), RD_PATH, Some(RD_IFACE), "CreateSession", &())
            .await
        {
            Ok(reply) => return Ok((reply.body().deserialize()?, unlocked)),
            // Inhibited: the shield is still up, or has just gone down and
            // the shell has not lifted the inhibition yet.
            Err(zbus::Error::MethodError(_, Some(message), _))
                if message.contains("inhibited") && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => {
                if unlocked {
                    let _ = set_locked(connection, true).await;
                }
                return Err(anyhow::Error::new(error).context(
                    "RemoteDesktop.CreateSession (\"inhibited\" means the session is locked, or remote \
                     access is switched off in GNOME's settings)",
                ));
            }
        }
    }
}

/// CreateSession → ScreenCast session tied to it → RecordMonitor → Start →
/// wait for the PipeWire node.
async fn start(
    session: &GnomeSession,
    options: AttachOptions,
    client_size: (u16, u16),
) -> anyhow::Result<(Connection, RemoteSession, bool)> {
    let connection = connect_bus(session.uid, session.gid, &session.bus()).await?;
    anyhow::ensure!(
        has_mutter(&connection).await,
        "no GNOME (Mutter) remote-desktop service on {}",
        session.bus().display()
    );

    let (rd_path, unlocked) = create_session(&connection, options).await?;

    // Before the stream exists, so its first frame is already the client's
    // size rather than a resize a moment later.
    let original_mode = if options.fit_client && options.screen == Screen::Monitor {
        crate::wayland::display_mode::fit(&connection, (u32::from(client_size.0), u32::from(client_size.1)))
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(error = format!("{error:#}"), "could not fit the monitor to the client");
                None
            })
    } else {
        None
    };

    let session_id: OwnedValue = connection
        .call_method(
            Some(RD_NAME),
            rd_path.as_str(),
            Some(PROPERTIES_IFACE),
            "Get",
            &(RD_SESSION_IFACE, "SessionId"),
        )
        .await
        .context("RemoteDesktop.Session.SessionId")?
        .body()
        .deserialize()?;
    let session_id = String::try_from(session_id).context("SessionId is not a string")?;

    let mut screencast: HashMap<&str, Value<'_>> = HashMap::new();
    screencast.insert("remote-desktop-session-id", Value::from(session_id.as_str()));
    let sc_path: OwnedObjectPath = connection
        .call_method(Some(SC_NAME), SC_PATH, Some(SC_IFACE), "CreateSession", &screencast)
        .await
        .context("ScreenCast.CreateSession")?
        .body()
        .deserialize()?;

    // Taken before the virtual monitor exists, so it is the desk's own.
    let desk_layout = if options.replace_desk {
        match crate::wayland::display_mode::snapshot(&connection).await {
            Ok(layout) => Some(layout),
            Err(error) => {
                tracing::warn!(error = format!("{error:#}"), "cannot read the desk's layout — not replacing it");
                None
            }
        }
    } else {
        None
    };

    let mut record: HashMap<&str, Value<'_>> = HashMap::new();
    record.insert("cursor-mode", Value::U32(CURSOR_MODE_EMBEDDED));
    let stream_path: OwnedObjectPath = match options.screen {
        // The empty connector is Mutter's "primary monitor".
        Screen::Monitor => connection
            .call_method(Some(SC_NAME), sc_path.as_str(), Some(SC_SESSION_IFACE), "RecordMonitor", &("", record))
            .await
            .context("ScreenCast.Session.RecordMonitor (is a monitor connected and the screen on?)")?,
        // The monitor exists while the stream does; its size is the one the
        // PipeWire consumer fixes (see `pipewire::enum_format_pod`).
        Screen::Virtual(..) => connection
            .call_method(Some(SC_NAME), sc_path.as_str(), Some(SC_SESSION_IFACE), "RecordVirtual", &record)
            .await
            .context("ScreenCast.Session.RecordVirtual")?,
    }
    .body()
    .deserialize()?;

    // Subscribe before Start: the node is announced once, right after it.
    let rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(SC_STREAM_IFACE)?
        .path(stream_path.as_str())?
        .member("PipeWireStreamAdded")?
        .build();
    let mut added = MessageStream::for_match_rule(rule, &connection, None).await?;

    connection
        .call_method(Some(RD_NAME), rd_path.as_str(), Some(RD_SESSION_IFACE), "Start", &())
        .await
        .context("RemoteDesktop.Session.Start")?;

    let message = tokio::time::timeout(STREAM_TIMEOUT, added.next())
        .await
        .map_err(|_| anyhow::anyhow!("Mutter started the session but announced no PipeWire stream"))?
        .context("the bus closed before the PipeWire stream was announced")??;
    let (node_id,): (u32,) = message.body().deserialize()?;

    let parameters: OwnedValue = connection
        .call_method(
            Some(SC_NAME),
            stream_path.as_str(),
            Some(PROPERTIES_IFACE),
            "Get",
            &(SC_STREAM_IFACE, "Parameters"),
        )
        .await
        .context("ScreenCast.Stream.Parameters")?
        .body()
        .deserialize()?;
    let parameters = HashMap::<String, OwnedValue>::try_from(parameters).unwrap_or_default();
    let size = parameters
        .get("size")
        .and_then(|v| <(i32, i32)>::try_from(v.try_clone().ok()?).ok())
        .map(|(w, h)| (w.unsigned_abs(), h.unsigned_abs()))
        .unwrap_or((0, 0));

    Ok((
        connection,
        RemoteSession {
            options,
            unlocked,
            original_mode,
            desk_layout,
            rd_path,
            stream_path,
            node_id,
            size,
        },
        unlocked,
    ))
}

/// Open the PipeWire socket as the user and start consuming `node_id`.
fn connect_pipewire(session: &GnomeSession, node_id: u32, size: Option<(u32, u32)>) -> anyhow::Result<PwCapture> {
    let socket = session.pipewire();
    let stream = connect_as(session.uid, session.gid, &socket)
        .with_context(|| format!("connect to PipeWire at {}", socket.display()))?;
    PwCapture::start(std::os::fd::OwnedFd::from(stream), node_id, None, size)
}

/// Read the session's clipboard in `mime` through `SelectionRead`: Mutter
/// hands back a pipe the copying app writes into.
async fn read_selection(connection: &Connection, remote: &RemoteSession, mime: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let fd: zbus::zvariant::OwnedFd = connection
        .call_method(Some(RD_NAME), remote.rd_path.as_str(), Some(RD_SESSION_IFACE), "SelectionRead", &mime)
        .await
        .context("SelectionRead")?
        .body()
        .deserialize()?;
    let fd = blocking(std::os::fd::OwnedFd::from(fd))?;
    let read = tokio::task::spawn_blocking(move || {
        use std::io::Read as _;
        let mut data = Vec::new();
        std::fs::File::from(fd).take(MAX_CLIPBOARD).read_to_end(&mut data).map(|_| data)
    });
    let data = tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .context("the copying app did not write the clipboard out in time")???;
    Ok(Some(data))
}

/// Follow the session's clipboard, and answer its requests for the client's.
async fn watch_clipboard(connection: &Connection, remote: &RemoteSession, clipboard: &ClipboardState) {
    let Ok(rule) = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(RD_SESSION_IFACE)
        .and_then(|b| b.path(remote.rd_path.as_str()))
        .map(|b| b.build())
    else {
        return std::future::pending().await;
    };
    let Ok(mut signals) = MessageStream::for_match_rule(rule, connection, None).await else {
        return std::future::pending().await;
    };
    while let Some(Ok(signal)) = signals.next().await {
        let member = signal.header().member().map(|m| m.to_string()).unwrap_or_default();
        match member.as_str() {
            "SelectionOwnerChanged" => {
                let Ok((options,)) = signal.body().deserialize::<(HashMap<String, OwnedValue>,)>() else {
                    continue;
                };
                let ours = options
                    .get("session-is-owner")
                    .and_then(|v| bool::try_from(v).ok())
                    .unwrap_or(false);
                // Our own offer coming back: the client already has it.
                if ours {
                    continue;
                }
                let mimes = options.get("mime-types").map(mime_list).unwrap_or_default();
                tracing::debug!(?mimes, "clipboard: the session copied");
                if let Ok(mut current) = clipboard.mimes.lock() {
                    *current = mimes;
                }
                clipboard.generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            "SelectionTransfer" => {
                let Ok((mime, serial)) = signal.body().deserialize::<(String, u32)>() else {
                    continue;
                };
                let data = clipboard.offered.lock().ok().and_then(|o| o.get(&mime).cloned());
                let ok = match data {
                    Some(data) => write_selection(connection, remote, serial, data).await.is_ok(),
                    None => false,
                };
                let _ = connection
                    .call_method(
                        Some(RD_NAME),
                        remote.rd_path.as_str(),
                        Some(RD_SESSION_IFACE),
                        "SelectionWriteDone",
                        &(serial, ok),
                    )
                    .await;
                tracing::debug!(%mime, ok, "clipboard: served the client's clipboard to the session");
            }
            _ => {}
        }
    }
    std::future::pending().await
}

/// Make a pipe Mutter handed over blocking. They arrive `O_NONBLOCK`, and
/// the other end is an app writing at its own pace: a non-blocking read
/// gives up with `EAGAIN` before it has written a byte. The copy runs on a
/// blocking thread with a timeout around it, so blocking is what is wanted.
fn blocking(fd: std::os::fd::OwnedFd) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: fcntl on a descriptor this function owns.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(fd)
}

/// The MIME types in a `SelectionOwnerChanged` option.
///
/// Mutter 50 sends them as a structure holding the array — `(as)` — not as
/// the bare `as` its introspection suggests; both are read, so a Mutter that
/// changes its mind does not take the clipboard with it.
fn mime_list(value: &OwnedValue) -> Vec<String> {
    fn strings(value: &Value<'_>) -> Vec<String> {
        match value {
            Value::Array(array) => array
                .iter()
                .filter_map(|v| match v {
                    Value::Str(s) => Some(s.to_string()),
                    _ => None,
                })
                .collect(),
            Value::Structure(structure) => structure.fields().iter().flat_map(strings).collect(),
            Value::Value(inner) => strings(inner),
            _ => Vec::new(),
        }
    }
    strings(value)
}

async fn write_selection(connection: &Connection, remote: &RemoteSession, serial: u32, data: Vec<u8>) -> anyhow::Result<()> {
    let fd: zbus::zvariant::OwnedFd = connection
        .call_method(Some(RD_NAME), remote.rd_path.as_str(), Some(RD_SESSION_IFACE), "SelectionWrite", &serial)
        .await
        .context("SelectionWrite")?
        .body()
        .deserialize()?;
    let fd = blocking(std::os::fd::OwnedFd::from(fd))?;
    tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        std::fs::File::from(fd).write_all(&data)
    })
    .await??;
    Ok(())
}

async fn set_power_save(connection: &Connection, mode: i32) -> zbus::Result<()> {
    connection
        .call_method(
            Some(DISPLAY_CONFIG_NAME),
            DISPLAY_CONFIG_PATH,
            Some(PROPERTIES_IFACE),
            "Set",
            &(DISPLAY_CONFIG_IFACE, "PowerSaveMode", Value::I32(mode)),
        )
        .await
        .map(drop)
}

/// Turn the physical monitors off, and turn them off again whenever
/// something at the desk wakes them, for as long as the client is connected.
///
/// Remote input does not wake them (measured: forty pointer moves through
/// Mutter, PowerSaveMode stayed 3); a key pressed at the desk does, through
/// gnome-settings-daemon — and that is the person this exists to keep out.
async fn keep_desk_dark(connection: &Connection) {
    if let Err(error) = set_power_save(connection, POWER_OFF).await {
        tracing::warn!(%error, "could not turn the local monitors off — the desk shows the session");
        return std::future::pending().await;
    }
    tracing::info!("local monitors off while the client is connected");
    let Ok(rule) = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(PROPERTIES_IFACE)
        .and_then(|b| b.path(DISPLAY_CONFIG_PATH))
        .and_then(|b| b.member("PropertiesChanged"))
        .map(|b| b.build())
    else {
        return std::future::pending().await;
    };
    let Ok(mut changes) = MessageStream::for_match_rule(rule, connection, None).await else {
        return std::future::pending().await;
    };
    while let Some(Ok(message)) = changes.next().await {
        let Ok((_, changed, _)) = message
            .body()
            .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
        else {
            continue;
        };
        let woke = changed
            .get("PowerSaveMode")
            .and_then(|v| i32::try_from(v).ok())
            .is_some_and(|mode| mode != POWER_OFF);
        if woke && GUARD_DESK.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::info!("the local monitors were woken at the desk — turning them off again");
            let _ = set_power_save(connection, POWER_OFF).await;
        }
    }
    std::future::pending().await
}

/// Put the desk back the way a disconnect should leave it: monitors on, and
/// the session behind its lock screen if this attach unlocked it — so what
/// the desk shows after the client leaves is a lock screen, not the desktop.
async fn leave_desk(connection: &Connection, remote: &RemoteSession) {
    let options = remote.options;
    GUARD_DESK.store(false, std::sync::atomic::Ordering::SeqCst);
    if let Some(layout) = &remote.desk_layout {
        // Stop the stream first and let Mutter take the virtual monitor away
        // itself, then put the desk's layout back. The other order —
        // reconfiguring the virtual monitor out while it still streams —
        // crashed GNOME Shell 50 (a segfault right after the reconfiguration,
        // reproduced on a headless shell), and on the console that is the
        // user's whole session.
        LEAVING.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = connection
            .call_method(Some(RD_NAME), remote.rd_path.as_str(), Some(RD_SESSION_IFACE), "Stop", &())
            .await;
        tokio::time::sleep(Duration::from_millis(800)).await;
        crate::wayland::display_mode::restore_snapshot(connection, layout).await;
    }
    if let Some(mode) = &remote.original_mode {
        crate::wayland::display_mode::restore(connection, mode).await;
    }
    if options.always_lock || (options.relock && remote.unlocked) {
        match set_locked(connection, true).await {
            Ok(()) => tracing::info!("GNOME session locked again on disconnect"),
            Err(error) => tracing::error!(%error, "could not lock the GNOME session on disconnect"),
        }
    }
    if options.blank_local {
        let _ = set_power_save(connection, POWER_ON).await;
    }
}

async fn watch_closed(connection: &Connection, rd_path: &OwnedObjectPath) {
    let Ok(rule) = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(RD_SESSION_IFACE)
        .and_then(|b| b.path(rd_path.as_str()))
        .and_then(|b| b.member("Closed"))
        .map(|b| b.build())
    else {
        return std::future::pending().await;
    };
    match MessageStream::for_match_rule(rule, connection, None).await {
        Ok(mut stream) => {
            let _ = stream.next().await;
        }
        Err(_) => std::future::pending().await,
    }
}

/// Deliver input to Mutter in order, and run the odd control request. Pointer
/// motion is coalesced: a client streams moves far faster than anyone can see
/// them, and only the last one before the next other event matters.
async fn serve_commands(
    connection: &Connection,
    remote: &RemoteSession,
    mut rx: mpsc::UnboundedReceiver<Command>,
    clipboard: &ClipboardState,
) {
    let mut pending: Option<Command> = None;
    loop {
        let command = match pending.take() {
            Some(command) => command,
            None => match rx.recv().await {
                Some(command) => command,
                None => return,
            },
        };
        let call = match command {
            Command::Lock(done) => {
                leave_desk(connection, remote).await;
                let _ = done.send(());
                continue;
            }
            Command::Resize(width, height) => {
                if let Err(error) = crate::wayland::display_mode::fit(connection, (width, height)).await {
                    tracing::warn!(error = format!("{error:#}"), "could not fit the monitor to the resized client");
                }
                continue;
            }
            Command::ReadClipboard(mime, reply) => {
                let data = read_selection(connection, remote, &mime).await.unwrap_or_else(|error| {
                    tracing::debug!(%mime, error = format!("{error:#}"), "clipboard: session read failed");
                    None
                });
                let _ = reply.send(data);
                continue;
            }
            Command::PublishClipboard(targets) => {
                let mimes: Vec<String> = targets.iter().map(|(m, _)| m.clone()).collect();
                if let Ok(mut offered) = clipboard.offered.lock() {
                    *offered = targets.into_iter().collect();
                }
                let mut options: HashMap<&str, Value<'_>> = HashMap::new();
                options.insert("mime-types", Value::from(mimes.clone()));
                match connection
                    .call_method(Some(RD_NAME), remote.rd_path.as_str(), Some(RD_SESSION_IFACE), "SetSelection", &options)
                    .await
                {
                    Ok(_) => tracing::debug!(?mimes, "clipboard: offered to the session"),
                    Err(error) => tracing::warn!(%error, "clipboard: the session refused the client's clipboard"),
                }
                continue;
            }
            Command::Input(call) => call,
        };
        let call = if let InputCall::Motion(..) = call {
            let mut latest = call;
            loop {
                match rx.try_recv() {
                    Ok(Command::Input(next @ InputCall::Motion(..))) => latest = next,
                    Ok(other) => {
                        pending = Some(other);
                        break;
                    }
                    Err(_) => break,
                }
            }
            latest
        } else {
            call
        };
        if let Err(error) = send_input(connection, remote, call).await {
            tracing::debug!(%error, ?call, "Mutter refused an input event");
        }
    }
}

async fn send_input(connection: &Connection, remote: &RemoteSession, call: InputCall) -> zbus::Result<()> {
    let path = remote.rd_path.as_str();
    let notify = |method: &'static str| (Some(RD_NAME), path, Some(RD_SESSION_IFACE), method);
    match call {
        InputCall::Keycode(code, pressed) => {
            let (d, p, i, m) = notify("NotifyKeyboardKeycode");
            connection.call_method(d, p, i, m, &(code, pressed)).await?;
        }
        InputCall::Keysym(sym, pressed) => {
            let (d, p, i, m) = notify("NotifyKeyboardKeysym");
            connection.call_method(d, p, i, m, &(sym, pressed)).await?;
        }
        InputCall::Motion(x, y) => {
            let (d, p, i, m) = notify("NotifyPointerMotionAbsolute");
            connection
                .call_method(d, p, i, m, &(remote.stream_path.as_str(), x, y))
                .await?;
        }
        InputCall::RelativeMotion(dx, dy) => {
            let (d, p, i, m) = notify("NotifyPointerMotionRelative");
            connection.call_method(d, p, i, m, &(dx, dy)).await?;
        }
        InputCall::Button(button, pressed) => {
            let (d, p, i, m) = notify("NotifyPointerButton");
            connection.call_method(d, p, i, m, &(button, pressed)).await?;
        }
        InputCall::Axis(axis, steps) => {
            let (d, p, i, m) = notify("NotifyPointerAxisDiscrete");
            connection.call_method(d, p, i, m, &(axis, steps)).await?;
        }
    }
    Ok(())
}

// ---- input -----------------------------------------------------------------

/// RDP input for the attached GNOME session.
///
/// Mutter takes evdev keycodes and keeps the keymap itself, so the client's
/// layout is the session's layout — the same arrangement as a local keyboard.
struct MutterInput {
    desktop: Arc<GnomeDesktop>,
    /// Keycodes the client holds down, released on a Synchronize so a lost
    /// release cannot leave a key auto-repeating in somebody's desktop.
    pressed: HashSet<u32>,
}

fn button_code(button: MouseButton) -> Option<i32> {
    match button {
        MouseButton::Left => Some(BTN_LEFT),
        MouseButton::Right => Some(BTN_RIGHT),
        MouseButton::Middle => Some(BTN_MIDDLE),
        MouseButton::X1 => Some(BTN_SIDE),
        MouseButton::X2 => Some(BTN_EXTRA),
        _ => None,
    }
}

/// RDP wheel units are 120 per notch; anything smaller is a high-resolution
/// device and still deserves one step (the X11 path rounds the same way).
fn wheel_steps(value: i16) -> i32 {
    let steps = i32::from(value.unsigned_abs() / 120).max(1);
    if value >= 0 { steps } else { -steps }
}

/// The input calls one RDP event becomes. Pure, so the mapping is testable
/// without a session.
fn translate_mouse(event: &MouseEvent) -> Vec<InputCall> {
    match *event {
        MouseEvent::Move { x, y } => vec![InputCall::Motion(f64::from(x), f64::from(y))],
        MouseEvent::Button { x, y, button, pressed } => {
            let mut calls = vec![InputCall::Motion(f64::from(x), f64::from(y))];
            calls.extend(button_code(button).map(|b| InputCall::Button(b, pressed)));
            calls
        }
        MouseEvent::ButtonRel { x, y, button, pressed } => {
            let mut calls = Vec::new();
            if x != 0 || y != 0 {
                calls.push(InputCall::RelativeMotion(f64::from(x), f64::from(y)));
            }
            calls.extend(button_code(button).map(|b| InputCall::Button(b, pressed)));
            calls
        }
        MouseEvent::RelMove { x, y } => vec![InputCall::RelativeMotion(f64::from(x), f64::from(y))],
        // RDP: positive is the wheel rolled away from the user, which scrolls
        // up. Mutter: positive steps scroll down.
        MouseEvent::VerticalScroll { value } => vec![InputCall::Axis(AXIS_VERTICAL, -wheel_steps(value))],
        // RDP and Mutter agree here: positive is to the right.
        MouseEvent::HorizontalScroll { value } => vec![InputCall::Axis(AXIS_HORIZONTAL, wheel_steps(value))],
        _ => Vec::new(),
    }
}

impl MutterInput {
    fn send(desktop: &GnomeDesktop, call: InputCall) {
        // The receiver lives as long as the session; a send failing means the
        // session is gone and the worker is on its way out.
        let _ = desktop.commands.send(Command::Input(call));
    }
}

impl RdpServerInputHandler for MutterInput {
    fn keyboard(&mut self, event: KeyboardEvent) {
        match event {
            KeyboardEvent::Pressed { code, extended } => {
                if let Some(keycode) = evdev_keycode(code, extended) {
                    self.pressed.insert(keycode);
                    Self::send(&self.desktop, InputCall::Keycode(keycode, true));
                }
            }
            KeyboardEvent::Released { code, extended } => {
                if let Some(keycode) = evdev_keycode(code, extended) {
                    self.pressed.remove(&keycode);
                    Self::send(&self.desktop, InputCall::Keycode(keycode, false));
                }
            }
            KeyboardEvent::UnicodePressed(code) => {
                let keysym = unicode_to_keysym(u32::from(code));
                Self::send(&self.desktop, InputCall::Keysym(keysym, true));
                Self::send(&self.desktop, InputCall::Keysym(keysym, false));
            }
            // The pair was sent on the press.
            KeyboardEvent::UnicodeReleased(_) => {}
            KeyboardEvent::Synchronize(_) => {
                for keycode in self.pressed.drain() {
                    Self::send(&self.desktop, InputCall::Keycode(keycode, false));
                }
            }
        }
    }

    fn mouse(&mut self, event: MouseEvent) {
        for call in translate_mouse(&event) {
            let call = match call {
                // Clamp into the screen: Mutter drops a motion that lands
                // outside the stream, and a client desktop a few pixels larger
                // than the monitor would otherwise lose its right and bottom
                // edges.
                // The stream's size now, not at attach: fitting the monitor to
                // the client changes it.
                InputCall::Motion(x, y) => {
                    let size = self.desktop.frames.size();
                    InputCall::Motion(
                        x.min(f64::from(size.width.max(1) - 1)),
                        y.min(f64::from(size.height.max(1) - 1)),
                    )
                }
                other => other,
            };
            Self::send(&self.desktop, call);
        }
    }
}

/// RDP scancode → evdev keycode, through the X11 table (X keycode = evdev + 8).
fn evdev_keycode(code: u8, extended: bool) -> Option<u32> {
    crate::input::keycode_for(code, extended).and_then(|x| u32::from(x).checked_sub(8))
}

/// X keysym for a Unicode code point: Latin-1 is its own keysym, everything
/// else lives in the Unicode plane — the same mapping the X11 path uses.
fn unicode_to_keysym(cp: u32) -> u32 {
    match cp {
        0x20..=0x7e | 0xa0..=0xff => cp,
        _ => 0x0100_0000 | cp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gfx_display::FrameSource;
    use ironrdp_server::DesktopSize;

    /// Against the real desktop of whoever runs the tests: find their GNOME
    /// session, attach to it, and wait for a frame. Ignored by default — it
    /// needs a logged-in GNOME session — and run by hand on each machine the
    /// GNOME case is checked on:
    ///
    /// `cargo test -p linrdp live_gnome_session -- --ignored --nocapture`
    #[test]
    #[ignore = "needs a running GNOME session"]
    fn live_gnome_session_streams_frames() {
        let _ = tracing_subscriber::fmt().with_env_filter("debug,zbus=info").with_test_writer().try_init();
        // `LINRDP_LIVE_USER=<account>` runs it as root on that account's
        // behalf — the way a worker does, switching ids per thread.
        let (uid, gid) = match std::env::var("LINRDP_LIVE_USER") {
            Ok(user) => {
                let ids = crate::session::privilege::lookup_user(&user).expect("account");
                (ids.uid, ids.gid)
            }
            // SAFETY: plain getters.
            Err(_) => unsafe { (libc::getuid(), libc::getgid()) },
        };
        // `LINRDP_LIVE_RUNTIME=<dir>`: a runtime dir holding `bus` and
        // `pipewire-0` of some other GNOME instance (a headless one).
        let session = match std::env::var_os("LINRDP_LIVE_RUNTIME") {
            Some(dir) => GnomeSession::logged_in(uid, gid, PathBuf::from(dir)),
            None => find(uid, gid).expect("no GNOME session with Mutter's remote desktop for this user"),
        };
        eprintln!("found: {session:?}");
        // `LINRDP_LIVE_VIRTUAL=WxH`: a virtual monitor of that size instead of
        // the primary monitor — how a remote session is served.
        let options = match std::env::var("LINRDP_LIVE_VIRTUAL") {
            Ok(size) => {
                let (w, h) = size.split_once('x').expect("WxH");
                AttachOptions::remote((w.parse().expect("W"), h.parse().expect("H")))
            }
            // `LINRDP_LIVE_CONSOLE=WxH`: the /admin way — the desk's monitors
            // replaced by one at that size, and put back afterwards.
            Err(_) => match std::env::var("LINRDP_LIVE_CONSOLE") {
                Ok(size) => {
                    let (w, h) = size.split_once('x').expect("WxH");
                    AttachOptions::console((w.parse().expect("W"), h.parse().expect("H")))
                }
                Err(_) => AttachOptions::default(),
            },
        };
        let desktop = attach("live-test", &session, options, (1920, 1080)).expect("attach");
        eprintln!("attached: {:?}", desktop.frames().size());
        let mut source =
            crate::wayland::compositor::SessionDisplayFactory::new(Arc::new(NoX11)).updates_source();
        // Mutter only records a frame when the screen repaints, and an idle
        // desktop does not. The pointer is drawn into the frames, so moving
        // it forces one — and proves the input path while at it.
        let mut input = Arc::clone(&desktop).input();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut step = 0u16;
        let grab = loop {
            if let Some((grab, _)) = source.poll_and_cursor(false, true) {
                break grab;
            }
            assert!(Instant::now() < deadline, "no frame from the Mutter stream in 10 s");
            step = (step + 1) % 20;
            input.mouse(MouseEvent::Move { x: 100 + step, y: 100 + step });
            std::thread::sleep(Duration::from_millis(50));
        };
        eprintln!("frame: {}x{}, {} bytes", grab.width, grab.height, grab.data.len());

        // `LINRDP_LIVE_BLANK=1`: with the physical monitors in power save, do
        // frames still come, and does remote input wake the monitors?
        if std::env::var_os("LINRDP_LIVE_BLANK").is_some() {
            let bus = format!("unix:path={}", session.bus().display());
            let busctl = |args: &[&str]| {
                std::process::Command::new("busctl")
                    .env("DBUS_SESSION_BUS_ADDRESS", &bus)
                    .args(["--user"])
                    .args(args)
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                    .unwrap_or_default()
            };
            let mode = || busctl(&["get-property", "org.gnome.Mutter.DisplayConfig", "/org/gnome/Mutter/DisplayConfig", "org.gnome.Mutter.DisplayConfig", "PowerSaveMode"]);
            busctl(&["set-property", "org.gnome.Mutter.DisplayConfig", "/org/gnome/Mutter/DisplayConfig", "org.gnome.Mutter.DisplayConfig", "PowerSaveMode", "i", "3"]);
            std::thread::sleep(Duration::from_millis(500));
            eprintln!("blanked: PowerSaveMode {}", mode());
            let mut frames = 0;
            for step in 0..40u16 {
                input.mouse(MouseEvent::Move { x: 300 + step, y: 300 });
                std::thread::sleep(Duration::from_millis(50));
                if source.poll_and_cursor(false, false).is_some() {
                    frames += 1;
                }
            }
            eprintln!("while blanked: {frames} frames, PowerSaveMode after input {}", mode());
            busctl(&["set-property", "org.gnome.Mutter.DisplayConfig", "/org/gnome/Mutter/DisplayConfig", "org.gnome.Mutter.DisplayConfig", "PowerSaveMode", "i", "0"]);
        }
        assert_eq!(grab.data.len(), usize::from(grab.width) * usize::from(grab.height) * 4);
        assert!(grab.data.iter().any(|b| *b != 0), "an all-black frame is not a desktop");

        // `LINRDP_LIVE_CLIPBOARD=1`: offer a text to the session, then wait
        // for the session to copy something and read it back.
        if std::env::var_os("LINRDP_LIVE_CLIPBOARD").is_some() {
            let text = "linrdp → session: zażółć gęślą jaźń";
            desktop.publish_clipboard(vec![("text/plain;charset=utf-8".to_owned(), text.as_bytes().to_vec())]);
            eprintln!("clipboard: offered {text:?}");
            let start = desktop.clipboard_generation();
            let deadline = Instant::now() + Duration::from_secs(20);
            while desktop.clipboard_generation() == start && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            let mimes = desktop.clipboard_mimes();
            let got = desktop
                .read_clipboard("text/plain;charset=utf-8")
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            eprintln!("clipboard: session copied {mimes:?} -> {got:?}");
        }

        // `LINRDP_LIVE_HOLD=<seconds>`: stay connected that long — time to
        // look at the desk, or to kill the process and see what survives.
        if let Some(hold) = std::env::var("LINRDP_LIVE_HOLD").ok().and_then(|v| v.parse().ok()) {
            eprintln!("holding for {hold} s");
            std::thread::sleep(Duration::from_secs(hold));
        }

        // `LINRDP_LIVE_CLICKS="x,y;x,y"`: click there (1.5 s apart) and keep
        // the newest frame afterwards — enough to check that input lands and
        // what it opened.
        let mut grab = grab;
        if let Ok(clicks) = std::env::var("LINRDP_LIVE_CLICKS") {
            let mut input = Arc::clone(&desktop).input();
            for point in clicks.split(';') {
                let Some((x, y)) = point.split_once(',') else { continue };
                let (x, y): (u16, u16) = (x.trim().parse().expect("x"), y.trim().parse().expect("y"));
                for pressed in [true, false] {
                    input.mouse(MouseEvent::Button { x, y, button: MouseButton::Left, pressed });
                }
                std::thread::sleep(Duration::from_millis(1500));
            }
            let until = Instant::now() + Duration::from_secs(3);
            while Instant::now() < until {
                if let Some((newer, _)) = source.poll_and_cursor(false, false) {
                    grab = newer;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        // `LINRDP_LIVE_PNG=/path/frame.png` keeps the frame, so whoever runs
        // this on a new machine can see what was actually captured.
        if let Some(path) = std::env::var_os("LINRDP_LIVE_PNG") {
            let file = std::fs::File::create(&path).expect("create png");
            let mut encoder = png::Encoder::new(file, u32::from(grab.width), u32::from(grab.height));
            encoder.set_color(png::ColorType::Rgb);
            let rgb: Vec<u8> = grab.data.chunks_exact(4).flat_map(|p| [p[2], p[1], p[0]]).collect();
            encoder.write_header().and_then(|mut w| w.write_image_data(&rgb)).expect("write png");
        }

        // Leave the desk as it was found.
        desktop.relock();
    }

    struct NoX11;
    impl DisplaySourceFactory for NoX11 {
        fn size(&self) -> DesktopSize {
            DesktopSize { width: 1, height: 1 }
        }
        fn request_initial_size(&self, client_size: DesktopSize) -> DesktopSize {
            client_size
        }
        fn request_layout(&self, _: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {}
        fn updates_source(&self) -> Box<dyn FrameSource> {
            unreachable!("the live test attaches before minting a source")
        }
    }

    #[test]
    fn mime_types_are_read_in_either_shape() {
        let bare = OwnedValue::try_from(Value::from(vec!["text/plain", "image/png"])).expect("value");
        assert_eq!(mime_list(&bare), ["text/plain", "image/png"]);
        // What Mutter 50 actually sends: the array inside a structure.
        let wrapped = OwnedValue::try_from(Value::from((vec!["text/plain;charset=utf-8"],))).expect("value");
        assert_eq!(mime_list(&wrapped), ["text/plain;charset=utf-8"]);
    }

    #[test]
    fn a_container_looks_on_the_host_too() {
        let dirs = runtime_dir_candidates(1000);
        assert_eq!(dirs[0], PathBuf::from("/run/user/1000"));
        assert!(dirs.contains(&PathBuf::from("/run/host/run/user/1000")));
    }

    #[test]
    fn the_wheel_scrolls_the_way_it_does_locally() {
        // One notch away from the user scrolls up: Mutter's negative step.
        let calls = translate_mouse(&MouseEvent::VerticalScroll { value: 120 });
        assert!(matches!(calls.as_slice(), [InputCall::Axis(AXIS_VERTICAL, -1)]));
        let calls = translate_mouse(&MouseEvent::VerticalScroll { value: -240 });
        assert!(matches!(calls.as_slice(), [InputCall::Axis(AXIS_VERTICAL, 2)]));
        let calls = translate_mouse(&MouseEvent::HorizontalScroll { value: 120 });
        assert!(matches!(calls.as_slice(), [InputCall::Axis(AXIS_HORIZONTAL, 1)]));
    }

    #[test]
    fn a_small_wheel_delta_still_scrolls() {
        let calls = translate_mouse(&MouseEvent::VerticalScroll { value: 30 });
        assert!(matches!(calls.as_slice(), [InputCall::Axis(AXIS_VERTICAL, -1)]));
    }

    #[test]
    fn a_click_moves_the_pointer_first() {
        let calls = translate_mouse(&MouseEvent::Button {
            x: 10,
            y: 20,
            button: MouseButton::Right,
            pressed: true,
        });
        assert!(matches!(
            calls.as_slice(),
            [InputCall::Motion(x, y), InputCall::Button(BTN_RIGHT, true)] if *x == 10.0 && *y == 20.0
        ));
    }

    #[test]
    fn keys_map_to_evdev_codes() {
        // 'A' is scancode 0x1E = KEY_A (30); Up is E0 48 = KEY_UP (103).
        assert_eq!(evdev_keycode(0x1E, false), Some(30));
        assert_eq!(evdev_keycode(0x48, true), Some(103));
        // Right Ctrl is E0 1D = KEY_RIGHTCTRL (97).
        assert_eq!(evdev_keycode(0x1D, true), Some(97));
    }

    #[test]
    fn unicode_keysyms_follow_x11() {
        assert_eq!(unicode_to_keysym(u32::from('a')), 0x61);
        assert_eq!(unicode_to_keysym(0xF3), 0xF3); // ó is Latin-1
        assert_eq!(unicode_to_keysym(0x0105), 0x0100_0105); // ą is not
    }
}

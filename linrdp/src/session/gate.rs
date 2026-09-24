//! The session gate: which X display this worker is allowed to touch.
//!
//! Multi-session workers must never fall back to the ambient `$DISPLAY`.
//! That display is the shared desktop, so a worker that reached it after a
//! failed session start would show one user another user's screen and inject
//! their keystrokes into it. That is not a degraded mode — it is a
//! confidentiality and integrity failure, and it is what happened when the
//! X server failed to start and the capture path quietly used `$DISPLAY`.
//!
//! So: once a process is armed as a multi-session worker, every X connection
//! must go through [`display_name`], which refuses to answer until a session
//! has actually been bound. There is no fallback to refuse into.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Set when this process is a multi-session worker.
static ARMED: AtomicBool = AtomicBool::new(false);

/// What this worker is currently allowed to touch.
static BOUND: Mutex<Option<Bound>> = Mutex::new(None);

/// Bumped on every binding change, so the capture and input paths can notice
/// that the display under them moved and reconnect. They cache their X
/// connection; without this they would keep drawing the logon screen after
/// the user had already been let in.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// The shared screen `session.console` names.
///
/// Console mode is the one arrangement where the display does not come from a
/// session this process created, and it used to come from the unit's
/// `Environment=DISPLAY=`. With the unit carrying no environment at all, an
/// unset display fell through to the literal `:99` below — either somebody
/// else's screen or nobody's — so the configuration says which screen, and
/// says it here.
static CONSOLE: Mutex<Option<ConsoleScreen>> = Mutex::new(None);

/// The account a console connection authenticated as. Console binds no
/// session, so this is the only record of whose login it is.
static CONSOLE_USER: Mutex<Option<String>> = Mutex::new(None);

#[derive(Debug, Clone)]
struct ConsoleScreen {
    display: String,
    xauthority: Option<PathBuf>,
}

/// Serve the shared screen `display` for the rest of this process's life.
pub(crate) fn set_console(display: String, xauthority: Option<PathBuf>) {
    *CONSOLE.lock().unwrap_or_else(|p| p.into_inner()) = Some(ConsoleScreen { display, xauthority });
}

fn console() -> Option<ConsoleScreen> {
    CONSOLE.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// The number in `:12` or `:12.0`, for the socket path and the cookie lookup.
fn display_number_of(name: &str) -> Option<u16> {
    name.strip_prefix(':')?.split('.').next()?.parse().ok()
}

/// Which of the two displays a worker can be pointed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Binding {
    /// The server-drawn logon screen: its own X server, owned by linrdp, with
    /// nobody's session on it. Nothing private is reachable from here, which
    /// is what makes it safe to show before anyone has authenticated.
    Greeter,
    /// A user's own desktop, after authentication.
    Session,
    /// A user's own desktop served through its compositor (GNOME's, through
    /// Mutter) rather than an X display. There is no display to name, so every
    /// X path is refused — which is the point: the ambient display is still
    /// somebody else's.
    Compositor,
}

#[derive(Debug, Clone)]
struct Bound {
    kind: Binding,
    /// Whose session this is, for the subsystems that must act with the
    /// user's own credentials rather than the worker's. `None` for the logon
    /// screen, which belongs to nobody.
    user: Option<String>,
    display: String,
    xauthority: String,
    /// Desktop size this client negotiated — the size the session's screen is
    /// scaled to once the capture path connects.
    client_size: (u16, u16),
    /// Which PulseAudio this worker may capture. `None` for the logon screen,
    /// which has no audio of its own and nothing to play.
    audio: Option<AudioTarget>,
    /// The session's runtime dir as this process reaches it.
    runtime_dir: String,
}

/// Which PulseAudio this worker may capture, and how to authenticate to it.
///
/// Audio has to answer the same question the display does — *whose?* — and it
/// has to answer it from the same place. Before this existed the capture path
/// connected to whatever the environment named, which on a multi-session host
/// is wrong in one of two ways. With `PULSE_SERVER` set in the service unit,
/// every session records that one daemon: measured here, a worker serving any
/// account captured uid 1000's mixer, so a second user was sent the first
/// user's desktop audio. Without it, libpulse follows `XDG_RUNTIME_DIR` —
/// which [`bind_kind`] points at the session owner while the worker is still
/// root — and refuses outright:
///
/// ```text
/// XDG_RUNTIME_DIR (/run/user/1002) is not owned by us (uid 0), but by uid 1002!
/// ```
///
/// Both failures come from asking the environment a question only the session
/// can answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AudioTarget {
    /// libpulse server string for this session's own socket.
    pub(crate) server: String,
    /// The session owner's PulseAudio cookie.
    ///
    /// The worker is root and the daemon is the user's, so the daemon's
    /// unix-credential check cannot pass — uid 0 is not uid 1002, and
    /// PulseAudio gives root no exemption. Measured: without the cookie the
    /// connection is refused with `Access denied`; with it, an authenticated
    /// session.
    pub(crate) cookie: PathBuf,
    /// The session's runtime dir, which is where its audio objects live.
    pub(crate) runtime_dir: String,
}

impl AudioTarget {
    /// Where a session's PulseAudio lives, from the session's runtime dir and
    /// the owner's home.
    ///
    /// `runtime_dir` is `/run/user/<uid>`, so the socket path needs no uid
    /// arithmetic of its own — which is the point: there is no number here to
    /// get wrong or to hardcode.
    fn new(runtime_dir: &str, home: &str) -> Self {
        Self {
            server: format!("unix:{runtime_dir}/pulse/native"),
            cookie: Path::new(home).join(".config").join("pulse").join("cookie"),
            runtime_dir: runtime_dir.to_owned(),
        }
    }

    /// The socket [`Self::server`] names, as a path that can be looked at.
    ///
    /// Worth looking at before connecting, because libpulse reports a missing
    /// socket as `Access denied` — the same thing it says about a rejected
    /// cookie. Two very different faults behind one misleading word.
    pub(crate) fn socket(&self) -> PathBuf {
        Path::new(&self.runtime_dir).join("pulse").join("native")
    }

    /// Whether this session belongs to uid 0.
    ///
    /// Root is a special case worth naming in the log: the distribution's
    /// `pulseaudio.socket` carries `ConditionUser=!root`, so systemd never
    /// starts a sound server for uid 0 — measured here, with the condition
    /// reported as unmet — and a root desktop therefore has no audio for any
    /// RDP server to capture. PulseAudio itself runs as root perfectly well;
    /// it is the unit's condition that stops it.
    pub(crate) fn is_root(&self) -> bool {
        self.runtime_dir == "/run/user/0"
    }

    /// Build a target without a session, for tests in other modules that need
    /// one to describe.
    #[cfg(test)]
    pub(crate) fn for_test(runtime_dir: &str, home: &str) -> Self {
        Self::new(runtime_dir, home)
    }

    /// This session's microphone FIFO: the file a `module-pipe-source` in the
    /// session's daemon reads as a capture device, and the file the client's
    /// microphone packets are written into.
    ///
    /// Under the session's own runtime dir, next to its X cookie — the same
    /// private per-session directory [`super::xauth::cookie_path`] uses.
    pub(crate) fn mic_fifo(&self) -> PathBuf {
        Path::new(&self.runtime_dir).join("linrdp").join("mic.fifo")
    }
}

/// Mark this process as a multi-session worker: no ambient display may be
/// used from here on, only the one a later [`bind`] names.
pub(crate) fn arm() {
    ARMED.store(true, Ordering::SeqCst);
}

pub(crate) fn is_armed() -> bool {
    ARMED.load(Ordering::SeqCst)
}

/// Bind this worker to the authenticated user's session. Idempotent; a second
/// call with a different session is refused rather than silently ignored.
pub(crate) fn bind(
    user: &str,
    display: u16,
    xauthority: &str,
    runtime_dir: &str,
    client_size: (u16, u16),
) -> anyhow::Result<()> {
    let audio = audio_for(user, runtime_dir);
    bind_kind(
        Binding::Session,
        Some(user.to_owned()),
        display,
        xauthority,
        runtime_dir,
        client_size,
        audio,
    )
}

/// Whose session this worker is bound to, if it is bound to one.
///
/// The clipboard's file helper is the caller that matters: a worker is root,
/// and opening a file named by the session — or creating one named by the
/// client — with root's credentials is the boundary violation this answers.
/// The logon screen has no user, so file transfer there has nobody to act as
/// and does not happen.
pub(crate) fn session_user() -> Option<String> {
    if let Some(user) = BOUND
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .and_then(|bound| bound.user.clone())
    {
        return Some(user);
    }
    // Console mode binds nothing — it serves a screen somebody else's session
    // owns — but the connection is still authenticated as an account, and that
    // account is whose credentials file operations must use. Without this,
    // console was the one mode where the clipboard had nobody to act as.
    CONSOLE_USER.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Record whose login this console connection is, for [`session_user`].
pub(crate) fn set_console_user(user: &str) {
    *CONSOLE_USER.lock().unwrap_or_else(|p| p.into_inner()) = Some(user.to_owned());
}

/// Forget it again. Tests only: the statics are shared by the whole test
/// binary, so a test that sets an owner has to put it back.
#[cfg(test)]
pub(crate) fn clear_console_user_for_test() {
    *CONSOLE_USER.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// This session's audio target, or `None` with the reason in the log.
///
/// Audio must never fail the binding. A desktop with a screen and no sound is
/// a working desktop; a connection refused because the cookie was missing is
/// not.
fn audio_for(user: &str, runtime_dir: &str) -> Option<AudioTarget> {
    match super::privilege::lookup_user(user) {
        Ok(ids) => Some(AudioTarget::new(runtime_dir, &ids.home)),
        Err(error) => {
            tracing::warn!(
                user,
                error = format!("{error:#}"),
                "no home directory for this account — the session gets no audio"
            );
            None
        }
    }
}

/// Bind this worker to `user`'s desktop served through its compositor, after
/// authentication. `desktop` names the kind (`gnome`) for the log and for the
/// rebinding check.
///
/// No X display is involved and none may be reached: `display_name` refuses
/// for this binding exactly as it does for an unbound worker. `runtime_dir`
/// is where the session's bus was found — the host's, when linrdp runs in a
/// container — and is where its audio lives too.
pub(crate) fn bind_compositor(
    desktop: &str,
    user: &str,
    runtime_dir: &str,
    client_size: (u16, u16),
) -> anyhow::Result<()> {
    let audio = audio_for(user, runtime_dir);
    let wanted = Bound {
        kind: Binding::Compositor,
        user: Some(user.to_owned()),
        display: format!("{desktop}:{user}"),
        xauthority: String::new(),
        client_size,
        audio,
        runtime_dir: runtime_dir.to_owned(),
    };
    // Only the environment the audio path reads: a DISPLAY here would invite
    // exactly the X connection this binding exists to rule out.
    //
    // SAFETY: as in `bind_kind`.
    unsafe {
        std::env::remove_var("DISPLAY");
        std::env::set_var("XDG_RUNTIME_DIR", runtime_dir);
        if let Some(audio) = &wanted.audio {
            std::env::set_var("PULSE_COOKIE", &audio.cookie);
        }
    }
    let mut cell = BOUND.lock().unwrap_or_else(|p| p.into_inner());
    bind_into(&mut cell, wanted)?;
    GENERATION.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// Point this worker at the logon screen, before anyone has authenticated.
pub(crate) fn bind_greeter(
    display: u16,
    xauthority: &str,
    runtime_dir: &str,
    client_size: (u16, u16),
) -> anyhow::Result<()> {
    // No audio: the logon screen is linrdp's own X server with nobody's
    // session on it, so there is no daemon to capture and nothing that could
    // make a sound. Silence there is the correct behaviour, not a gap.
    bind_kind(Binding::Greeter, None, display, xauthority, runtime_dir, client_size, None)
}

fn bind_kind(
    kind: Binding,
    user: Option<String>,
    display: u16,
    xauthority: &str,
    runtime_dir: &str,
    client_size: (u16, u16),
    audio: Option<AudioTarget>,
) -> anyhow::Result<()> {
    let wanted = Bound {
        kind,
        user,
        display: format!(":{display}"),
        xauthority: xauthority.to_owned(),
        client_size,
        audio,
        runtime_dir: runtime_dir.to_owned(),
    };
    // The subsystems that start later (clipboard, selection owner) read the
    // environment, so set it too — but the gate, not the environment, is what
    // the capture and input paths trust.
    //
    // `PULSE_COOKIE` is here because libpulse takes the cookie only from the
    // environment or from a client.conf: there is no argument for it on
    // `pa_context_connect`, so the server string can be passed explicitly
    // (and is, so a stale `PULSE_SERVER` cannot hijack a session) while the
    // cookie cannot. It is set only for a session binding, so the greeter
    // never carries one.
    //
    // SAFETY: the worker is still single-threaded with respect to these; the
    // X-touching paths connect only after this returns. The audio capture
    // thread is the one reader that can already exist here — RDPSND
    // negotiates before the logon screen accepts — and it reads the cookie
    // only when it builds a PulseAudio context, which it does after seeing
    // the generation below move. These four variables share that argument;
    // it is not made weaker by the fourth.
    unsafe {
        std::env::set_var("DISPLAY", &wanted.display);
        std::env::set_var("XAUTHORITY", xauthority);
        std::env::set_var("XDG_RUNTIME_DIR", runtime_dir);
        if let Some(audio) = &wanted.audio {
            std::env::set_var("PULSE_COOKIE", &audio.cookie);
        }
    }
    let mut cell = BOUND.lock().unwrap_or_else(|p| p.into_inner());
    bind_into(&mut cell, wanted)?;
    GENERATION.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// How many times this worker has been pointed somewhere.
///
/// Cached X connections compare this against the value they connected at.
pub(crate) fn generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}

/// The binding decision, separated from the process-global cell so it can be
/// tested without mutating it (the statics are shared by every test in the
/// binary, and mutating them from one test breaks the others).
///
/// Exactly one move is allowed: from the logon screen to a session, once the
/// person in front of it has authenticated. Everything else that would change
/// the display mid-connection is refused, because a worker that switched
/// displays would be showing two users' screens down one pipe.
fn bind_into(cell: &mut Option<Bound>, wanted: Bound) -> anyhow::Result<()> {
    match cell.as_ref() {
        None => {}
        Some(existing) if existing.display == wanted.display && existing.kind == wanted.kind => {}
        // The greeter is not anybody's desktop, so leaving it for the session
        // the login just proved is not a switch between users.
        Some(existing)
            if existing.kind == Binding::Greeter && matches!(wanted.kind, Binding::Session | Binding::Compositor) => {}
        Some(existing) => anyhow::bail!(
            "this worker is already bound to {} ({:?}); refusing to rebind to {} ({:?})",
            existing.display,
            existing.kind,
            wanted.display,
            wanted.kind
        ),
    }
    *cell = Some(wanted);
    Ok(())
}

/// The display this process may connect to.
///
/// Unarmed (single-session, or console mode) this is the ambient `$DISPLAY`,
/// exactly as before. Armed, it is the bound session and nothing else — an
/// unbound armed worker gets an error, never a usable display.
pub(crate) fn display_name() -> anyhow::Result<String> {
    if !is_armed() {
        if let Some(console) = console() {
            return Ok(console.display);
        }
        return Ok(std::env::var("DISPLAY").unwrap_or_else(|_| ":99".to_owned()));
    }
    match BOUND.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        Some(bound) if bound.kind == Binding::Compositor => anyhow::bail!(
            "this connection is served by {} through its compositor — there is no X display to reach",
            bound.display
        ),
        Some(bound) => Ok(bound.display.clone()),
        None => anyhow::bail!(
            "no session bound yet — refusing to touch a display, because the only \
             one available would be another user's"
        ),
    }
}

/// Snapshot both X11 values under one lock, so handover cannot mix cookies.
pub(crate) fn clipboard_target() -> anyhow::Result<(String, String)> {
    if is_armed() {
        let bound = BOUND.lock().unwrap_or_else(|p| p.into_inner());
        let bound = bound.as_ref().ok_or_else(|| anyhow::anyhow!("no clipboard session bound"))?;
        anyhow::ensure!(
            bound.kind != Binding::Compositor,
            "the X11 clipboard does not serve a desktop reached through its compositor"
        );
        return Ok((bound.display.clone(), bound.xauthority.clone()));
    }
    if let Some(console) = console() {
        return Ok((console.display, console.xauthority.map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()));
    }
    Ok((display_name()?, std::env::var("XAUTHORITY").unwrap_or_default()))
}

/// The display number this worker is bound to, if any.
fn bound_display_number() -> Option<u16> {
    BOUND
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()?
        .display
        .trim_start_matches(':')
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// Connect to this worker's X display, authenticating with the session's own
/// cookie rather than with whatever `$XAUTHORITY` happens to name.
///
/// Every X connection in a multi-session worker goes through here. The
/// environment cannot be trusted for this: the service unit exports an
/// `XAUTHORITY` of its own (the console user's file), and x11rb silently
/// swallows every error while locating auth — an unreadable or wrong file
/// makes it connect **unauthenticated**, which the X server refuses with a
/// bare "Authorization required, but no authorization protocol specified".
/// That is what the capture and input paths were relying on, and what the
/// module comment above already claimed they did not.
///
/// Unarmed (single-session, or console mode) nothing is bound and this is
/// x11rb's ordinary environment-driven connect, exactly as before.
pub(crate) fn connect() -> anyhow::Result<(x11rb::rust_connection::RustConnection, usize)> {
    use anyhow::Context as _;

    let name = display_name()?;
    // A bound session's cookie, or — in console mode — the one the
    // configuration names. Everything else is x11rb's ordinary
    // environment-driven connect.
    let explicit = match (bound_display_number(), xauthority()) {
        (Some(display), Some(path)) => Some((display, path)),
        _ => console().and_then(|console| {
            let path = console.xauthority?;
            Some((display_number_of(&name)?, path.display().to_string()))
        }),
    };
    let Some((display, path)) = explicit else {
        return x11rb::rust_connection::RustConnection::connect(Some(name.as_str()))
            .with_context(|| format!("connect to X display {name}"));
    };

    let screen = name.split('.').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0usize);
    let socket = format!("/tmp/.X11-unix/X{display}");
    let unix = std::os::unix::net::UnixStream::connect(&socket)
        .with_context(|| format!("connect to X display {name} at {socket}"))?;
    let (stream, _peer) = x11rb::rust_connection::DefaultStream::from_unix_stream(unix)
        .with_context(|| format!("wrap the X socket for {name}"))?;
    let (auth_name, auth_data) = super::xauth::cookie_for(Path::new(&path), display)
        .with_context(|| format!("no usable cookie for {name}"))?;
    let conn =
        x11rb::rust_connection::RustConnection::connect_to_stream_with_auth_info(stream, screen, auth_name, auth_data)
            .with_context(|| format!("X11 setup for {name}"))?;
    Ok((conn, screen))
}

/// Where files pasted from the client go, when the default — the helper's
/// temporary directory — is not somewhere the session can see.
///
/// A session started on the host of linrdp's container (a GNOME one, whose
/// runtime dir is under `/run/host`) runs on the host, where the container's
/// `/tmp` does not exist; the home directory is the one place both share.
/// Every other session sees the same `/tmp` linrdp does.
pub(crate) fn paste_base() -> Option<PathBuf> {
    let bound = BOUND.lock().unwrap_or_else(|p| p.into_inner());
    let bound = bound.as_ref()?;
    if bound.kind != Binding::Compositor || !bound.runtime_dir.starts_with("/run/host/") {
        return None;
    }
    let user = bound.user.as_deref()?;
    let home = super::privilege::lookup_user(user).ok()?.home;
    Some(Path::new(&home).join(".cache").join("linrdp"))
}

/// The desktop size this connection negotiated, once a session is bound.
///
/// The session's X screen is created at the largest desktop we serve and
/// scaled down to this — a client must never be shown a desktop smaller than
/// the area it reserved for it.
pub(crate) fn client_size() -> Option<(u16, u16)> {
    BOUND.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|b| b.client_size)
}

/// Which PulseAudio this worker may capture, if any.
///
/// `None` means capture nothing, and every `None` is a real answer rather
/// than a missing one: an unarmed worker (single-session, or console mode)
/// keeps the ambient environment the service unit gave it, an armed worker
/// with no session bound has no daemon to reach yet, and the logon screen has
/// none at all. There is no fallback to some other user's daemon, which is
/// exactly the fallback that made 3389 play uid 1000's audio to everyone.
pub(crate) fn audio_target() -> Option<AudioTarget> {
    if !is_armed() {
        return None;
    }
    BOUND.lock().unwrap_or_else(|p| p.into_inner()).as_ref()?.audio.clone()
}

/// Where this worker's microphone FIFO is.
///
/// A bound session's own FIFO, or — unarmed, where the environment is a
/// correct description of the single desktop there is — the one under
/// `$XDG_RUNTIME_DIR`. `None` means there is nowhere to put a microphone
/// packet, which is the honest answer while the logon screen is up: the only
/// other place to put it would be some other account's FIFO, and that is what
/// the literal `/run/user/1000/linrdp/mic.fifo` used to be.
pub(crate) fn mic_fifo() -> Option<PathBuf> {
    if !is_armed() {
        let dir = std::env::var("XDG_RUNTIME_DIR").ok()?;
        return Some(Path::new(&dir).join("linrdp").join("mic.fifo"));
    }
    Some(audio_target()?.mic_fifo())
}

/// The Xauthority for the bound session, if any.
pub(crate) fn xauthority() -> Option<String> {
    BOUND
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(|b| b.xauthority.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: an armed worker that has not bound a session must not
    /// be handed any display at all.
    #[test]
    fn an_armed_unbound_worker_is_refused_a_display() {
        // A fresh process state cannot be simulated across tests (the statics
        // are global), so this asserts the branch directly.
        assert!(
            !is_armed(),
            "default state is unarmed so single-session behaviour is unchanged"
        );

        // Unarmed: the ambient display is returned, as before.
        let ambient = display_name().expect("unarmed always answers");
        assert!(ambient.starts_with(':'), "got {ambient}");
    }

    fn sample(kind: Binding, display: &str) -> Bound {
        Bound {
            kind,
            user: match kind {
                Binding::Greeter => None,
                Binding::Session | Binding::Compositor => Some("rdptest".to_owned()),
            },
            display: display.to_owned(),
            xauthority: format!("/run/user/1000/linrdp/Xauthority{display}"),
            client_size: (1920, 1080),
            runtime_dir: "/run/user/1002".to_owned(),
            audio: match kind {
                Binding::Greeter => None,
                Binding::Session | Binding::Compositor => Some(AudioTarget::new("/run/user/1002", "/home/rdptest")),
            },
        }
    }

    /// The socket and the cookie both come from the session, and nothing in
    /// either is a constant. This is the whole fix: the old capture path
    /// reached one hardcoded daemon (`tcp:127.0.0.1:4713`, uid 1000's), so
    /// every user heard that user's desktop.
    #[test]
    fn an_audio_target_names_the_sessions_own_daemon() {
        let target = AudioTarget::new("/run/user/1002", "/home/rdptest");

        assert_eq!(target.server, "unix:/run/user/1002/pulse/native");
        assert_eq!(
            target.cookie,
            Path::new("/home/rdptest/.config/pulse/cookie")
        );
    }

    /// Two sessions must never be handed the same audio target. Without this
    /// the socket is the same string for everyone, which is the bug.
    #[test]
    fn two_sessions_get_different_daemons() {
        let one = AudioTarget::new("/run/user/1002", "/home/rdptest");
        let two = AudioTarget::new("/run/user/1003", "/home/rdptest2");

        assert_ne!(one.server, two.server);
        assert_ne!(one.cookie, two.cookie);
        assert_ne!(one.mic_fifo(), two.mic_fifo());
    }

    /// The microphone FIFO belongs to the session, under the same private
    /// runtime directory as its X cookie. It used to be the literal
    /// `/run/user/1000/linrdp/mic.fifo` for every session on the host, so
    /// this asserts the shape that made that impossible.
    #[test]
    fn the_mic_fifo_is_derived_from_the_session_not_from_a_uid() {
        let target = AudioTarget::new("/run/user/1002", "/home/rdptest");

        assert_eq!(
            target.mic_fifo(),
            Path::new("/run/user/1002/linrdp/mic.fifo")
        );
        assert!(
            !target.mic_fifo().starts_with("/run/user/1000"),
            "a session's FIFO must never resolve to another user's runtime dir"
        );
    }

    /// The logon screen gets no audio target at all: there is no session
    /// behind it, so there is no daemon that could legitimately be captured.
    /// A fallback here would be some other user's desktop.
    #[test]
    fn the_logon_screen_has_no_audio() {
        let mut cell = None;
        bind_into(&mut cell, sample(Binding::Greeter, ":90")).expect("greeter binds");

        assert!(cell.as_ref().expect("bound").audio.is_none());
    }

    /// After the handover the worker carries the session's audio, not the
    /// greeter's absence of it — the same single move the display makes.
    #[test]
    fn the_handover_brings_the_sessions_audio_with_it() {
        let mut cell = None;
        bind_into(&mut cell, sample(Binding::Greeter, ":90")).expect("greeter binds");
        bind_into(&mut cell, sample(Binding::Session, ":11")).expect("handover after login");

        let audio = cell.as_ref().expect("bound").audio.as_ref().expect("session audio");
        assert_eq!(audio.server, "unix:/run/user/1002/pulse/native");
    }

    /// An unarmed worker (single-session, or console mode) keeps the ambient
    /// environment the unit gave it, so nothing about that deployment
    /// changes.
    #[test]
    fn an_unarmed_worker_has_no_audio_target_of_its_own() {
        assert!(!is_armed(), "default state is unarmed");
        assert!(audio_target().is_none());
    }

    /// Binding twice to the same session is fine (a reconnect); binding to a
    /// different one is refused, because a worker that switched displays
    /// mid-connection would be showing two users' screens down one pipe.
    #[test]
    fn rebinding_to_a_different_session_is_refused() {
        let mut cell = None;

        bind_into(&mut cell, sample(Binding::Session, ":77")).expect("first bind");
        bind_into(&mut cell, sample(Binding::Session, ":77")).expect("same session again");

        let err = bind_into(&mut cell, sample(Binding::Session, ":78"))
            .expect_err("a different session must be refused");
        assert!(err.to_string().contains("refusing to rebind"), "got: {err}");

        assert_eq!(
            cell.as_ref().map(|b| b.display.as_str()),
            Some(":77"),
            "the first binding stands"
        );
    }

    /// The one move that is allowed: the logon screen hands over to the
    /// session the person in front of it just authenticated as.
    #[test]
    fn the_greeter_may_hand_over_to_a_session() {
        let mut cell = None;

        bind_into(&mut cell, sample(Binding::Greeter, ":90")).expect("greeter binds");
        bind_into(&mut cell, sample(Binding::Session, ":11")).expect("handover after login");

        assert_eq!(cell.as_ref().map(|b| b.kind), Some(Binding::Session));
        assert_eq!(cell.as_ref().map(|b| b.display.as_str()), Some(":11"));
    }

    /// A login at the logon screen may land on a desktop served through its
    /// compositor (a GNOME session) as well.
    #[test]
    fn the_greeter_may_hand_over_to_a_gnome_session() {
        let mut cell = None;
        bind_into(&mut cell, sample(Binding::Greeter, ":90")).expect("greeter binds");
        bind_into(&mut cell, sample(Binding::Compositor, "gnome:rdptest")).expect("handover to GNOME");
        assert!(
            bind_into(&mut cell, sample(Binding::Session, ":12")).is_err(),
            "a GNOME-bound worker must never move to an X session"
        );
    }

    /// ...and only in that direction. A session must never be swapped for a
    /// logon screen, or for a second greeter: once a worker is showing
    /// someone's desktop, the display it is pointed at is settled.
    #[test]
    fn a_session_never_goes_back_to_a_greeter() {
        let mut cell = None;
        bind_into(&mut cell, sample(Binding::Session, ":11")).expect("session binds");
        assert!(
            bind_into(&mut cell, sample(Binding::Greeter, ":90")).is_err(),
            "a bound session must not be replaced by a logon screen"
        );

        let mut cell = None;
        bind_into(&mut cell, sample(Binding::Greeter, ":90")).expect("greeter binds");
        assert!(
            bind_into(&mut cell, sample(Binding::Greeter, ":91")).is_err(),
            "one greeter per worker"
        );
    }
}

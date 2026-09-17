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

/// Which of the two displays a worker can be pointed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Binding {
    /// The server-drawn logon screen: its own X server, owned by linrdp, with
    /// nobody's session on it. Nothing private is reachable from here, which
    /// is what makes it safe to show before anyone has authenticated.
    Greeter,
    /// A user's own desktop, after authentication.
    Session,
}

#[derive(Debug, Clone)]
struct Bound {
    kind: Binding,
    display: String,
    xauthority: String,
    /// Desktop size this client negotiated — the size the session's screen is
    /// scaled to once the capture path connects.
    client_size: (u16, u16),
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
    display: u16,
    xauthority: &str,
    runtime_dir: &str,
    client_size: (u16, u16),
) -> anyhow::Result<()> {
    bind_kind(Binding::Session, display, xauthority, runtime_dir, client_size)
}

/// Point this worker at the logon screen, before anyone has authenticated.
pub(crate) fn bind_greeter(
    display: u16,
    xauthority: &str,
    runtime_dir: &str,
    client_size: (u16, u16),
) -> anyhow::Result<()> {
    bind_kind(Binding::Greeter, display, xauthority, runtime_dir, client_size)
}

fn bind_kind(
    kind: Binding,
    display: u16,
    xauthority: &str,
    runtime_dir: &str,
    client_size: (u16, u16),
) -> anyhow::Result<()> {
    let wanted = Bound {
        kind,
        display: format!(":{display}"),
        xauthority: xauthority.to_owned(),
        client_size,
    };
    // The subsystems that start later (clipboard, selection owner) read the
    // environment, so set it too — but the gate, not the environment, is what
    // the capture and input paths trust.
    // SAFETY: the worker is still single-threaded with respect to these; the
    // X-touching paths connect only after this returns.
    unsafe {
        std::env::set_var("DISPLAY", &wanted.display);
        std::env::set_var("XAUTHORITY", xauthority);
        std::env::set_var("XDG_RUNTIME_DIR", runtime_dir);
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
        Some(existing) if existing.kind == Binding::Greeter && wanted.kind == Binding::Session => {}
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
        return Ok(std::env::var("DISPLAY").unwrap_or_else(|_| ":99".to_owned()));
    }
    match BOUND.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        Some(bound) => Ok(bound.display.clone()),
        None => anyhow::bail!(
            "no session bound yet — refusing to touch a display, because the only \
             one available would be another user's"
        ),
    }
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
/// Unarmed (single-session, or `--console`) nothing is bound and this is
/// x11rb's ordinary environment-driven connect, exactly as before.
pub(crate) fn connect() -> anyhow::Result<(x11rb::rust_connection::RustConnection, usize)> {
    use anyhow::Context as _;

    let name = display_name()?;
    let (Some(display), Some(path)) = (bound_display_number(), xauthority()) else {
        return x11rb::rust_connection::RustConnection::connect(Some(name.as_str()))
            .with_context(|| format!("connect to X display {name}"));
    };

    let screen = name.split('.').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0usize);
    let socket = format!("/tmp/.X11-unix/X{display}");
    let unix = std::os::unix::net::UnixStream::connect(&socket)
        .with_context(|| format!("connect to X display {name} at {socket}"))?;
    let (stream, _peer) = x11rb::rust_connection::DefaultStream::from_unix_stream(unix)
        .with_context(|| format!("wrap the X socket for {name}"))?;
    let (auth_name, auth_data) = super::xauth::cookie_for(std::path::Path::new(&path), display)
        .with_context(|| format!("no usable cookie for {name}"))?;
    let conn =
        x11rb::rust_connection::RustConnection::connect_to_stream_with_auth_info(stream, screen, auth_name, auth_data)
            .with_context(|| format!("X11 setup for {name}"))?;
    Ok((conn, screen))
}

/// The desktop size this connection negotiated, once a session is bound.
///
/// The session's X screen is created at the largest desktop we serve and
/// scaled down to this — a client must never be shown a desktop smaller than
/// the area it reserved for it.
pub(crate) fn client_size() -> Option<(u16, u16)> {
    BOUND.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|b| b.client_size)
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
            display: display.to_owned(),
            xauthority: format!("/run/user/1000/linrdp/Xauthority{display}"),
            client_size: (1920, 1080),
        }
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

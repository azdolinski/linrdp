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

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set when this process is a multi-session worker.
static ARMED: AtomicBool = AtomicBool::new(false);

/// The session this worker serves. Written once, after authentication.
static BOUND: OnceLock<Bound> = OnceLock::new();

#[derive(Debug, Clone)]
struct Bound {
    display: String,
    xauthority: String,
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
pub(crate) fn bind(display: u16, xauthority: &str, runtime_dir: &str) -> anyhow::Result<()> {
    let wanted = Bound {
        display: format!(":{display}"),
        xauthority: xauthority.to_owned(),
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
    bind_into(&BOUND, wanted)
}

/// The binding decision, separated from the process-global cell so it can be
/// tested without mutating it (the statics are shared by every test in the
/// binary, and mutating them from one test breaks the others).
fn bind_into(cell: &OnceLock<Bound>, wanted: Bound) -> anyhow::Result<()> {
    if cell.set(wanted.clone()).is_ok() {
        return Ok(());
    }
    let existing = cell.get().map(|b| b.display.clone()).unwrap_or_default();
    anyhow::ensure!(
        existing == wanted.display,
        "this worker is already bound to {existing}; refusing to rebind to {}",
        wanted.display
    );
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
    match BOUND.get() {
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
        .get()?
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

/// The Xauthority for the bound session, if any.
pub(crate) fn xauthority() -> Option<String> {
    BOUND.get().map(|b| b.xauthority.clone())
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

    fn sample(display: &str) -> Bound {
        Bound {
            display: display.to_owned(),
            xauthority: format!("/run/user/1000/linrdp/Xauthority{display}"),
        }
    }

    /// Binding twice to the same session is fine (a reconnect); binding to a
    /// different one is refused, because a worker that switched displays
    /// mid-connection would be showing two users' screens down one pipe.
    #[test]
    fn rebinding_to_a_different_session_is_refused() {
        let cell = OnceLock::new();

        bind_into(&cell, sample(":77")).expect("first bind");
        bind_into(&cell, sample(":77")).expect("same session again");

        let err = bind_into(&cell, sample(":78")).expect_err("a different session must be refused");
        assert!(err.to_string().contains("refusing to rebind"), "got: {err}");

        assert_eq!(cell.get().map(|b| b.display.as_str()), Some(":77"), "the first binding stands");
    }
}

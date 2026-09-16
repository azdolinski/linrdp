//! Multi-session support: per-user desktops with Windows RDP semantics.
//!
//! See `docs/superpowers/specs/2026-09-16-multi-session-design.md`.

pub(crate) mod detect;
pub(crate) mod display_alloc;
pub(crate) mod gate;
pub(crate) mod keeper;
pub(crate) mod keeper_main;
pub(crate) mod pam_session;
pub(crate) mod privilege;
pub(crate) mod registry;
pub(crate) mod router;
pub(crate) mod xauth;
pub(crate) mod runtime_dir;

use std::ops::RangeInclusive;
use std::path::Path;

use anyhow::Context as _;

/// The user's session, if one is recorded.
pub(crate) fn attach_existing(
    base: &Path,
    user: &str,
    range: RangeInclusive<u16>,
) -> Option<registry::SessionRecord> {
    registry::find(base, user, range)
}

/// Whether the record for `display` is backed by a live keeper.
///
/// A free `flock` is proof the keeper is gone: the kernel drops the lock when
/// the holding process dies, so this survives crashes and a supervisor restart
/// without any bookkeeping of our own.
pub(crate) fn is_stale(base: &Path, display: u16) -> bool {
    display_alloc::allocate(base, display..=display).is_ok()
}

/// Drop the record for a dead session so the number can be reused.
pub(crate) fn forget(base: &Path, display: u16) -> anyhow::Result<()> {
    let path = registry::record_path(base, display);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("remove {}", path.display()))),
    }
}

/// The user's session, but only if a keeper is still holding it.
pub(crate) fn attach_live(
    base: &Path,
    user: &str,
    range: RangeInclusive<u16>,
) -> Option<registry::SessionRecord> {
    let rec = attach_existing(base, user, range)?;
    if is_stale(base, rec.display) {
        // The desktop died; clear the record so the next create() starts clean.
        let _ = forget(base, rec.display);
        return None;
    }
    Some(rec)
}

/// Which display this connection serves.
///
/// `console` is the `mstsc /admin` equivalent: attach to the ambient
/// `$DISPLAY` (the shared screen) instead of a per-user session.
pub(crate) fn resolve_display(
    base: &Path,
    user: &str,
    range: RangeInclusive<u16>,
    console: bool,
    ambient: &str,
) -> String {
    if console {
        return ambient.to_owned();
    }
    match attach_live(base, user, range) {
        Some(rec) => format!(":{}", rec.display),
        // No ambient fallback: a user whose session is gone must be refused,
        // not quietly shown the shared desktop.
        None => String::new(),
    }
}


/// Start a session for `user` by handing it to a keeper process.
///
/// The keeper, not this function, owns the session: it holds the PAM handle
/// and the display lock for as long as the desktop runs. Doing that here
/// would tie both to the connection, which is how a dead X server first came
/// to look like a healthy session.
///
/// The password goes to the keeper on a pipe, never on argv or in the
/// environment, where any local user could read it out of /proc.
pub(crate) fn create(
    base: &Path,
    user: &str,
    password: &str,
    range: RangeInclusive<u16>,
    size: (u16, u16),
) -> anyhow::Result<registry::SessionRecord> {
    // Pick a free number without keeping the claim: the keeper takes its own
    // lock, and holding one here would make the keeper's claim fail.
    let display = {
        let probe = display_alloc::allocate(base, range)?;
        probe.number
    };

    let caps = detect::probe();
    let session_exec = detect::choose_session(&caps.sessions, None)
        .map(|s| s.exec.clone())
        .unwrap_or_default();
    if session_exec.is_empty() {
        tracing::warn!(
            "no runnable desktop session found — the user will get a bare X server. \
             Run `linrdp doctor` to see why."
        );
    }

    spawn_keeper(base, user, password, display, size, &session_exec)
        .with_context(|| format!("start the session keeper for {user}"))?;

    keeper_main::wait_for_record(base, display, core::time::Duration::from_secs(20))
        .with_context(|| format!("session for {user} on :{display}"))
}

/// Fork a detached `linrdp --keeper` and feed it the password on stdin.
fn spawn_keeper(
    base: &Path,
    user: &str,
    password: &str,
    display: u16,
    size: (u16, u16),
    session_exec: &str,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().context("locate the linrdp binary")?;
    let mut child = Command::new(exe)
        .arg("--keeper")
        .arg("--keeper-user")
        .arg(user)
        .arg("--keeper-display")
        .arg(display.to_string())
        .arg("--keeper-state-dir")
        .arg(base)
        .arg("--keeper-size")
        .arg(format!("{}x{}", size.0, size.1))
        .arg("--keeper-exec")
        .arg(session_exec)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn the session keeper")?;

    child
        .stdin
        .take()
        .context("keeper stdin")?
        .write_all(password.as_bytes())
        .context("hand the password to the keeper")?;

    // The keeper detaches itself; this direct child exits immediately, so
    // reap it rather than leaving a zombie.
    let _ = child.wait();
    Ok(())
}

/// The user's session, creating one if they have none.
pub(crate) fn attach_or_create(
    base: &Path,
    user: &str,
    password: &str,
    range: RangeInclusive<u16>,
    size: (u16, u16),
) -> anyhow::Result<registry::SessionRecord> {
    if let Some(existing) = attach_live(base, user, range.clone()) {
        tracing::info!(user, display = existing.display, "attached to the existing session");
        return Ok(existing);
    }
    create(base, user, password, range, size)
}


/// Lock a session: record it, and ask logind to tell the desktop.
///
/// The record is the part linrdp enforces. The logind signal is what a screen
/// locker in the session listens for — without one installed the lock is
/// bookkeeping only, which `linrdp doctor` warns about rather than letting
/// anyone believe the desktop is protected.
pub(crate) fn lock(base: &Path, display: u16) -> anyhow::Result<()> {
    registry::set_locked(base, display, true)?;
    signal_logind_lock(true);
    Ok(())
}

/// Release the lock after the user has authenticated for this session.
pub(crate) fn unlock(base: &Path, rec: &registry::SessionRecord) -> anyhow::Result<()> {
    registry::set_locked(base, rec.display, false)?;
    signal_logind_lock(false);
    Ok(())
}

/// Best-effort `loginctl lock-session` / `unlock-session` for this process's
/// own logind session.
///
/// Best-effort on purpose: the lock that matters for access control is the
/// recorded one, which linrdp enforces itself. This only drives whatever
/// locker the desktop happens to run, and desktops without one are common.
fn signal_logind_lock(lock: bool) {
    let verb = if lock { "lock-session" } else { "unlock-session" };
    match std::process::Command::new("loginctl")
        .arg(verb)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => tracing::debug!(%verb, ?status, "loginctl did not accept the lock signal"),
        Err(error) => tracing::debug!(%verb, %error, "loginctl unavailable — lock is recorded only"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_base(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("linrdp-attach-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        runtime_dir::ensure_state_dir(&base).expect("state dir");
        base
    }

    fn seed(base: &Path, user: &str, display: u16) {
        registry::write_record(
            base,
            &registry::SessionRecord {
                user: user.to_owned(),
                display,
                runtime_dir: "/run/user/1001".to_owned(),
                xauthority: "/run/user/1001/linrdp/Xauthority".to_owned(),
                locked: false,
            },
        )
        .expect("seed");
    }

    /// Reconnecting must land on the existing desktop, not a second one.
    #[test]
    fn a_second_attach_returns_the_same_display() {
        let base = temp_base("same");
        seed(&base, "alice", 11);
        let found = attach_existing(&base, "alice", 10..=20).expect("attaches");
        assert_eq!(found.display, 11, "a reconnect must not create a second desktop");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_user_without_a_session_gets_none() {
        let base = temp_base("none");
        assert!(attach_existing(&base, "bob", 10..=20).is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A record whose display lock is free belongs to a dead keeper.
    #[test]
    fn a_record_without_a_live_lock_is_stale() {
        let base = temp_base("stale");
        seed(&base, "alice", 11);
        assert!(is_stale(&base, 11), "nobody holds the lock, so the keeper is gone");

        let _held = display_alloc::allocate(&base, 11..=11).expect("hold the lock");
        assert!(!is_stale(&base, 11), "a held lock means a live session");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn forgetting_a_session_frees_the_display() {
        let base = temp_base("forget");
        seed(&base, "alice", 11);
        forget(&base, 11).expect("forget");
        assert!(attach_existing(&base, "alice", 10..=20).is_none(), "the record is gone");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A stale record must not send a reconnecting user to a dead desktop.
    #[test]
    fn attach_live_skips_a_stale_record() {
        let base = temp_base("skipstale");
        seed(&base, "alice", 11);
        assert!(
            attach_live(&base, "alice", 10..=20).is_none(),
            "a record with no live keeper must not be attached to"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// --console must bypass session resolution entirely.
    #[test]
    fn console_mode_uses_the_ambient_display() {
        let base = temp_base("console");
        seed(&base, "alice", 11);
        let _held = display_alloc::allocate(&base, 11..=11).expect("keep the session live");

        assert_eq!(
            resolve_display(&base, "alice", 10..=20, true, ":99"),
            ":99",
            "console mode must not route to a per-user session"
        );
        assert_eq!(
            resolve_display(&base, "alice", 10..=20, false, ":99"),
            ":11",
            "without console mode the user's own session wins"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

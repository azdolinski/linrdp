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

/// The largest desktop linrdp serves, and therefore the geometry every
/// session's X server is created at.
///
/// Xvfb's `-screen` size is also its RandR maximum: a screen can be scaled
/// down from it but never past it. Creating every session here means any
/// client up to this size gets a desktop that exactly fills its window, and
/// the same session can be reattached from a different monitor. It matches
/// the maximum the acceptor advertises with `honor_client_desktop_size`.
pub(crate) const SESSION_SCREEN_MAX: (u16, u16) = (3840, 2160);

/// The descriptor a keeper finds its display claim on.
///
/// 0, 1 and 2 are the password pipe and the two null streams; 3 is where the
/// supervisor puts an accepted socket for a worker, and a keeper is spawned
/// by a worker, so 4 is the first number nothing else has a claim on.
pub(crate) const KEEPER_LOCK_FD: std::os::fd::RawFd = 4;

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
    // Claim a number and KEEP the claim, then hand the descriptor holding it
    // to the keeper. The claim is never released in between, so the number
    // cannot be handed to a second login the way it could when this probed
    // and let go: two connections then chose the same display, and the one
    // whose keeper lost the lock still read — and bound to — the winner's
    // session.
    let lease = display_alloc::allocate(base, range)?;
    let display = lease.number;

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

    // From here the keeper owns the claim. On failure the lease is dropped
    // below, which releases it and frees the number again.
    let lock_fd = lease.into_handoff_fd();
    let spawned = spawn_keeper(base, user, password, display, size, &session_exec, lock_fd)
        .with_context(|| format!("start the session keeper for {user}"));
    // This process's copy of the descriptor has done its job: `flock` belongs
    // to the open file description, which the keeper inherited, so closing
    // this copy does not release anything the keeper is holding.
    //
    // SAFETY: a descriptor this function opened, used by nothing else here.
    unsafe { libc::close(lock_fd) };
    if let Err(error) = spawned {
        // Nobody inherited the claim, so put the number back rather than
        // leaving it locked by a descriptor that is already closed.
        return Err(error);
    }

    keeper_main::wait_for_record(base, display, user, core::time::Duration::from_secs(20))
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
    lock_fd: std::os::fd::RawFd,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().context("locate the linrdp binary")?;
    let mut command = Command::new(exe);
    // A keeper started from a worker that was pointed at a different
    // configuration has to be pointed at the same one, or the session's log
    // goes somewhere nobody is looking.
    if !crate::config::path_is_default() {
        command.arg("--config").arg(crate::config::path());
    }
    let mut child = unsafe { command
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
        .arg("--keeper-lock-fd")
        .arg(KEEPER_LOCK_FD.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Place the display claim on a fixed descriptor and clear
        // close-on-exec, so the keeper inherits the very open file
        // description whose `flock` is the claim.
        //
        // SAFETY: the closure runs between fork and exec and calls only
        // async-signal-safe functions — no allocation, no locks.
        .pre_exec(move || {
            // SAFETY: runs in the forked child between fork and exec; dup2
            // and fcntl are async-signal-safe.
            unsafe {
                if libc::dup2(lock_fd, KEEPER_LOCK_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // dup2 clears FD_CLOEXEC on the copy — except when the two
                // numbers are equal, where POSIX says it does nothing at all.
                if libc::fcntl(KEEPER_LOCK_FD, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        })
        .spawn() }
        .context("spawn the session keeper")?;

    child
        .stdin
        .take()
        .context("keeper stdin")?
        .write_all(password.as_bytes())
        .context("hand the password to the keeper")?;

    // The keeper forks and its parent exits at once, so this returns
    // immediately; the real keeper is re-parented to init. Reaping here keeps
    // the short-lived parent from lingering as a zombie.
    let status = child.wait().context("wait for the keeper to detach")?;
    anyhow::ensure!(status.success(), "the session keeper failed to start ({status})");
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


/// Lock a session: record it, and ask logind to tell that desktop.
///
/// The record is the part linrdp enforces. The logind signal is what a screen
/// locker in the session listens for — without one installed the lock is
/// bookkeeping only, which `linrdp doctor` warns about rather than letting
/// anyone believe the desktop is protected.
pub(crate) fn lock(base: &Path, display: u16, logind_id: Option<&str>) -> anyhow::Result<()> {
    registry::set_locked(base, display, true)?;
    signal_logind_lock(true, logind_id);
    Ok(())
}

/// Release the lock after the user has authenticated for this session.
pub(crate) fn unlock(base: &Path, rec: &registry::SessionRecord) -> anyhow::Result<()> {
    registry::set_locked(base, rec.display, false)?;
    signal_logind_lock(false, rec.logind_id.as_deref());
    Ok(())
}

/// Best-effort `loginctl lock-session <id>` / `unlock-session <id>`.
///
/// The session id is not optional in practice, only in the type. `loginctl
/// lock-session` with no argument acts on the *calling* process's logind
/// session, and the caller here is a worker — a forked RDP connection that
/// has no logind session of its own. So the argument-less form either failed
/// or, worse, signalled whatever session the supervisor happened to be in;
/// either way the desktop that was actually being locked was never told. With
/// no recorded id there is nothing to signal, and saying so is more honest
/// than a call that appears to succeed.
///
/// Best-effort on purpose beyond that: the lock that matters for access
/// control is the recorded one, which linrdp enforces itself. This only
/// drives whatever locker the desktop happens to run, and desktops without
/// one are common.
fn signal_logind_lock(lock: bool, logind_id: Option<&str>) {
    let verb = if lock { "lock-session" } else { "unlock-session" };
    let Some(id) = logind_id.filter(|id| !id.is_empty()) else {
        tracing::debug!(
            %verb,
            "no logind session id recorded — the lock is enforced by linrdp, but no screen \
             locker in the desktop can be told about it"
        );
        return;
    };
    match std::process::Command::new("loginctl")
        .arg(verb)
        .arg(id)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => tracing::debug!(%verb, %id, "logind signalled"),
        Ok(status) => tracing::debug!(%verb, %id, ?status, "loginctl did not accept the lock signal"),
        Err(error) => tracing::debug!(%verb, %id, %error, "loginctl unavailable — lock is recorded only"),
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
                logind_id: None,
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

    /// Console mode must bypass session resolution entirely.
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

//! The keeper: one process that owns a session for its whole life.
//!
//! Why a separate process at all. The desktop must outlive every connection
//! to it, so something must hold the session's PAM handle and its display
//! lock for that whole time. Doing it in the worker does not work: the worker
//! dies with the connection, taking the lock with it while the desktop lives
//! on — and the first implementation did exactly that, which is why a dead
//! Xvfb could still look like a live session and a reconnect attached to a
//! display with nothing behind it.
//!
//! So the keeper: it authenticates, opens the PAM session, then hands over to
//! the case that runs this kind of session (`DesktopBackend::serve_session`),
//! which starts the desktop, publishes the session record, and waits. When
//! the desktop ends the session is over — the record is removed, PAM is
//! closed and the lock is released by the process exiting.
//!
//! The password arrives on stdin, never on argv or in the environment, where
//! any local user could read it out of /proc.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use super::backends::DesktopBackend;
use super::{display_alloc, privilege, registry};

/// Everything the keeper is told to do.
pub(crate) struct KeeperArgs {
    pub(crate) account_fd: std::os::fd::RawFd,
    pub(crate) user: String,
    pub(crate) display: u16,
    pub(crate) state_dir: PathBuf,
    pub(crate) size: (u16, u16),
    /// The case that runs this session.
    pub(crate) backend: &'static dyn DesktopBackend,
    /// What that case needs to start it, as the worker decided it: the
    /// desktop's `Exec=` line for an X session (empty means "X server only" —
    /// useful for bringing a session up on a machine with no desktop
    /// installed, which `doctor` reports as a blocker), the launcher for a
    /// GNOME one.
    pub(crate) start: String,
    /// The inherited descriptor already holding this display's `flock`.
    ///
    /// The worker claims the number and hands the claim over rather than
    /// letting go of it, so the number is never momentarily free — see
    /// [`display_alloc::DisplayLease::into_handoff_fd`].
    pub(crate) lock_fd: std::os::fd::RawFd,
}

/// A keeper whose PAM session is open, handed to the case that runs the
/// session in it.
pub(crate) struct Keeper<'a> {
    pub(crate) args: &'a KeeperArgs,
    pub(crate) ids: privilege::UserIds,
    /// `XDG_RUNTIME_DIR`, as PAM gave it.
    pub(crate) runtime_dir: String,
    /// The logind session PAM registered (`XDG_SESSION_ID`), if it did.
    pub(crate) logind_id: Option<String>,
    pub(crate) pam: crate::pam::LibPamSession,
    /// The claim on this session's slot; the kernel releases it when this
    /// process dies, so the claim and the session end together.
    pub(crate) lease: display_alloc::DisplayLease,
    /// The account's claim: dropped once the record is published, so a
    /// reconnect can find the session.
    pub(crate) account: super::AccountLock,
}

/// Run as the session keeper. Returns only when the session is over.
pub(crate) fn run(args: &KeeperArgs) -> anyhow::Result<()> {
    // Retain the account claim even if the worker times out or dies.
    // Close-on-exec prevents desktop children from prolonging it.
    let account = super::AccountLock::adopt(args.account_fd)?;
    let mut password = String::new();
    std::io::stdin()
        .read_to_string(&mut password)
        .context("read the session password from stdin")?;
    let password = password.trim_end_matches(['\n', '\r']).to_owned();

    tracing::info!(user = %args.user, display = args.display, backend = args.backend.id(), "keeper starting");
    let ids = privilege::lookup_user(&args.user)?;

    // Adopt the claim the worker already holds, rather than taking a fresh
    // one. Re-claiming meant the number was free for an instant in between,
    // and two logins racing through that instant both picked it: the loser's
    // keeper then failed here, while the loser's *worker* went on to read the
    // winner's session record and bind to a desktop that was not its user's.
    //
    // The kernel still releases the flock when this process dies, so the
    // claim and the session end together — which is the invariant the worker
    // could not provide on its own.
    let lease = display_alloc::DisplayLease::adopt(&args.state_dir, args.display, args.lock_fd)
        .with_context(|| format!("take over the claim on display :{}", args.display))?;

    tracing::debug!(display = args.display, "display claimed; opening the PAM session");
    let (pam, env) = crate::pam::LibPamSession::open(&args.user, &password)
        .map_err(|e| anyhow::anyhow!("open a PAM session for {}: {e}", args.user))?;
    drop(password);

    let from_pam = |key: &str| env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    let runtime_dir = from_pam("XDG_RUNTIME_DIR")
        .context("PAM gave no XDG_RUNTIME_DIR — is pam_systemd.so in /etc/pam.d/linrdp?")?;
    // The keeper is the only process that ever learns this, and only while
    // its PAM session is open — so it is recorded now or never. Without it a
    // worker's `loginctl lock-session` had no session to name.
    let logind_id = from_pam("XDG_SESSION_ID").filter(|id| !id.is_empty());
    if logind_id.is_none() {
        tracing::warn!(
            "PAM registered no XDG_SESSION_ID — linrdp will still enforce the session lock, \
             but no screen locker in the desktop can be told about it"
        );
    }

    args.backend.serve_session(Keeper {
        args,
        ids,
        runtime_dir,
        logind_id,
        pam,
        lease,
        account,
    })
}

/// Stop a session process: ask, then insist.
///
/// `SIGTERM` lets the X server clean up its socket and lock file; the
/// `SIGKILL` a moment later is for the case where it does not.
pub(crate) fn end_session(pid: i32) {
    // SAFETY: signalling our own child; an already-dead pid fails harmlessly
    // because it has not been reaped yet, so the number is still ours.
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    for _ in 0..20 {
        std::thread::sleep(core::time::Duration::from_millis(50));
        // SAFETY: signal 0 only tests whether the pid is still signalable.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return;
        }
        let mut status = 0;
        // SAFETY: reaping our own child, without blocking.
        if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
            return;
        }
    }
    // SAFETY: as above.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

/// Where the keeper's own state directory lives, for argument parsing.
pub(crate) fn state_dir_from(arg: Option<String>) -> PathBuf {
    arg.map_or_else(|| PathBuf::from(super::runtime_dir::STATE_DIR), PathBuf::from)
}

/// Wait for the keeper this worker started to publish its session record.
///
/// `user` is not decoration. A record is just a file named after a display
/// number, and waiting on the number alone meant taking whatever appeared
/// there — which, when two logins had raced for the same number, was the
/// other account's session. The number is now reserved for this request
/// before the keeper starts, so a record naming somebody else can only mean
/// something went wrong; it is refused rather than returned.
pub(crate) fn wait_for_record(
    base: &Path,
    display: u16,
    user: &str,
    timeout: core::time::Duration,
) -> anyhow::Result<registry::SessionRecord> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(rec) = registry::read_one(base, display) {
            anyhow::ensure!(
                rec.user == user,
                "the session that appeared on :{display} belongs to {}, not to {user}",
                rec.user
            );
            return Ok(rec);
        }
        std::thread::sleep(core::time::Duration::from_millis(50));
    }
    anyhow::bail!("the session keeper for :{display} did not become ready within {timeout:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record that names somebody else is never this login's session.
    ///
    /// Regression: `wait_for_record` matched on the display number alone. Two
    /// logins that raced for the same number both ended up reading the
    /// winner's record, and the loser's worker then bound to an account it
    /// had not authenticated — somebody else's desktop.
    #[test]
    fn a_record_for_another_account_is_refused() {
        let base = std::env::temp_dir().join(format!("linrdp-waitrec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        super::super::runtime_dir::ensure_state_dir(&base).expect("state dir");
        registry::write_record(
            &base,
            &registry::SessionRecord {
                user: "bob".to_owned(),
                display: 11,
                runtime_dir: "/run/user/1002".to_owned(),
                xauthority: "/run/user/1002/linrdp/Xauthority".to_owned(),
                locked: false,
                logind_id: None,
                bus: None,
                backend: crate::session::backends::x11::ID.to_owned(),
            },
        )
        .expect("seed bob");

        let error = wait_for_record(&base, 11, "alice", core::time::Duration::from_millis(50))
            .expect_err("alice must not be handed bob's session");
        assert!(
            format!("{error:#}").contains("bob"),
            "the refusal has to name whose session it actually was, got: {error:#}"
        );

        wait_for_record(&base, 11, "bob", core::time::Duration::from_millis(50))
            .expect("bob's own session is still returned");
        let _ = std::fs::remove_dir_all(&base);
    }
}

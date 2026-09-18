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
//! So the keeper: it authenticates, opens the PAM session, starts the X
//! server and the desktop, publishes the session record, and then waits. When
//! the X server exits the session is over — the record is removed, PAM is
//! closed and the lock is released by the process exiting.
//!
//! The password arrives on stdin, never on argv or in the environment, where
//! any local user could read it out of /proc.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use super::{display_alloc, keeper, privilege, registry, xauth};

/// Everything the keeper is told to do.
pub(crate) struct KeeperArgs {
    pub(crate) user: String,
    pub(crate) display: u16,
    pub(crate) state_dir: PathBuf,
    pub(crate) size: (u16, u16),
    /// The desktop command from session detection, e.g. `startxfce4`.
    /// Empty means "X server only" — useful for bringing a session up on a
    /// machine with no desktop installed, which `doctor` reports as a blocker.
    pub(crate) session_exec: String,
    /// The inherited descriptor already holding this display's `flock`.
    ///
    /// The worker claims the number and hands the claim over rather than
    /// letting go of it, so the number is never momentarily free — see
    /// [`display_alloc::DisplayLease::into_handoff_fd`].
    pub(crate) lock_fd: std::os::fd::RawFd,
}

/// Run as the session keeper. Returns only when the session is over.
pub(crate) fn run(args: &KeeperArgs) -> anyhow::Result<()> {
    let mut password = String::new();
    std::io::stdin()
        .read_to_string(&mut password)
        .context("read the session password from stdin")?;
    let password = password.trim_end_matches(['\n', '\r']).to_owned();

    tracing::info!(user = %args.user, display = args.display, "keeper starting");
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
    let (mut pam, env) = crate::pam::LibPamSession::open(&args.user, &password)
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

    tracing::debug!(runtime_dir = %runtime_dir, "PAM session open; writing the X cookie");
    let xauthority = xauth::write_cookie(&runtime_dir, args.display, &ids)?;
    let rec = registry::SessionRecord {
        user: args.user.clone(),
        display: args.display,
        runtime_dir,
        xauthority: xauthority.to_string_lossy().into_owned(),
        // The user is authenticating right now; they are about to look at it.
        locked: false,
        logind_id,
    };

    let x_log = args.state_dir.join(format!("display-{}.log", args.display));
    let x_cmd = keeper::xvfb_command(args.display, &rec.xauthority, args.size);
    let env_pairs = keeper::session_env(&rec, &ids);
    tracing::debug!(display = args.display, log = %x_log.display(), "starting the X server");
    keeper::clear_stale_display(args.display);
    let x_pid = keeper::spawn_child(&x_cmd, &env_pairs, &ids, &x_log)
        .with_context(|| format!("start the X server for {} on :{}", args.user, args.display))?;

    // Only now is the display real. Publishing the record earlier is what let
    // a failed start masquerade as a healthy session.
    keeper::wait_for_display(args.display, core::time::Duration::from_secs(10)).inspect_err(|_| {
        tracing::error!(
            display = args.display,
            log = %x_log.display(),
            "the X server never published its socket — its own output is in that log"
        );
        // SAFETY: a pid this process created and has not reaped.
        unsafe { libc::kill(x_pid, libc::SIGTERM) };
    })?;

    let mut desktop_pid = None;
    if !args.session_exec.is_empty() {
        let desktop_log = args.state_dir.join(format!("display-{}.desktop.log", args.display));
        let desktop = split_exec(&args.session_exec);
        match keeper::spawn_child(&desktop, &env_pairs, &ids, &desktop_log) {
            Ok(pid) => {
                desktop_pid = Some(pid);
                tracing::info!(
                    user = %args.user,
                    display = args.display,
                    exec = %args.session_exec,
                    pid,
                    "desktop session started"
                );
            }
            // An X server with no desktop on it is a black screen, which is
            // indistinguishable to the user from a broken server. Fail the
            // session instead, so the error reaches the log and the next
            // connection starts a fresh one.
            Err(error) => {
                tracing::error!(
                    user = %args.user,
                    display = args.display,
                    %error,
                    "desktop session failed to start — ending the session rather than \
                     serving an empty screen"
                );
                end_session(x_pid);
                let _ = registry::forget_record(&args.state_dir, args.display);
                let _ = pam.close();
                drop(lease);
                return Err(error);
            }
        }
    }

    lease.record_owner(&args.user)?;
    registry::write_record(&args.state_dir, &rec)?;
    tracing::info!(user = %args.user, display = args.display, "session ready");

    // The session lasts as long as BOTH its X server and its desktop.
    //
    // Watching only the X server is what turned "log out" into a black
    // screen: XFCE's logout ends `xfce4-session`, Xvfb keeps running, and the
    // record goes on advertising a session whose desktop is gone — so the next
    // login attached to a live X server with no clients on it. Reproduced
    // deterministically: terminate `xfce4-session` and the X server, the
    // record and a few orphaned panels all stay behind.
    let ended_by = wait_for_either(x_pid, desktop_pid);
    tracing::info!(
        user = %args.user,
        display = args.display,
        ended_by,
        "session over — tearing it down"
    );
    // Whichever half died, the other must not outlive it: an X server with no
    // desktop is the black screen above, and a desktop with no X server has
    // nothing to draw on.
    end_session(x_pid);
    if let Some(pid) = desktop_pid {
        end_session(pid);
    }

    let _ = registry::forget_record(&args.state_dir, args.display);
    let _ = pam.close();
    // The lease drops with this function, releasing the flock.
    drop(lease);
    Ok(())
}

/// Split a `.desktop` `Exec=` line into a command.
///
/// Field codes like %U are placeholders for files a launcher would pass; a
/// session has none, and leaving them in would hand the desktop a literal

/// Wait until either the X server or the desktop exits, and say which.
///
/// Both are direct children, so a single `waitpid(-1)` loop covers them; any
/// other child reaped here (a desktop that forked and left one behind) is not
/// the end of the session and the loop continues.
fn wait_for_either(x_pid: i32, desktop_pid: Option<i32>) -> &'static str {
    loop {
        let mut status = 0;
        // SAFETY: waiting on our own children; -1 means "any of them".
        let dead = unsafe { libc::waitpid(-1, &mut status, 0) };
        match classify_exit(dead, x_pid, desktop_pid) {
            Some(what) => return what,
            None if dead == -1 => return "no children left",
            None => continue,
        }
    }
}

/// Which half of the session just died, if this pid was one of them.
///
/// Split out from the wait loop so the decision can be tested without
/// forking: the loop is three lines of libc, this is the part with a rule in
/// it.
fn classify_exit(dead: i32, x_pid: i32, desktop_pid: Option<i32>) -> Option<&'static str> {
    if dead == x_pid {
        return Some("the X server exited");
    }
    if desktop_pid.is_some_and(|pid| pid == dead) {
        return Some("the desktop session exited (logout)");
    }
    None
}

/// Stop a session process: ask, then insist.
///
/// `SIGTERM` lets the X server clean up its socket and lock file; the
/// `SIGKILL` a moment later is for the case where it does not.
fn end_session(pid: i32) {
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

/// "%U" as an argument.
fn split_exec(exec: &str) -> keeper::DesktopCommand {
    let mut parts = exec
        .split_whitespace()
        .filter(|part| !(part.starts_with('%') && part.len() == 2));
    let program = parts.next().unwrap_or_default().to_owned();
    keeper::DesktopCommand {
        program,
        args: parts.map(str::to_owned).collect(),
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

    /// A session ends when EITHER half dies.
    ///
    /// Regression: the keeper waited only on the X server, so XFCE's "Log Out"
    /// — which ends `xfce4-session` and leaves Xvfb running — left a session
    /// record advertising a desktop that no longer existed. The next login
    /// attached to a live X server with no clients on it: a black screen that
    /// never recovered, because nothing was watching the half that had died.
    #[test]
    fn either_half_dying_ends_the_session() {
        assert_eq!(
            classify_exit(100, 100, Some(200)),
            Some("the X server exited"),
            "the X server dying has always ended the session"
        );
        assert_eq!(
            classify_exit(200, 100, Some(200)),
            Some("the desktop session exited (logout)"),
            "a logout must end the session too, or it leaves an empty screen behind"
        );
    }

    /// Grandchildren the desktop left behind are reaped without ending
    /// anything: only the two processes the keeper started are the session.
    #[test]
    fn an_unrelated_child_does_not_end_the_session() {
        assert_eq!(classify_exit(999, 100, Some(200)), None);
        assert_eq!(classify_exit(-1, 100, Some(200)), None, "waitpid failure is not a death");
    }

    /// With no desktop configured the X server alone is the session.
    #[test]
    fn without_a_desktop_only_the_x_server_ends_it() {
        assert_eq!(classify_exit(100, 100, None), Some("the X server exited"));
        assert_eq!(classify_exit(200, 100, None), None);
    }


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

    #[test]
    fn exec_field_codes_are_dropped() {
        let cmd = split_exec("startxfce4 --session %U");
        assert_eq!(cmd.program, "startxfce4");
        assert_eq!(cmd.args, vec!["--session".to_owned()], "%U is a launcher placeholder, not an argument");
    }

    #[test]
    fn a_plain_exec_survives_intact() {
        let cmd = split_exec("startxfce4");
        assert_eq!(cmd.program, "startxfce4");
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn arguments_are_preserved() {
        let cmd = split_exec("startxfce4 --wayland");
        assert_eq!(cmd.program, "startxfce4");
        assert_eq!(cmd.args, vec!["--wayland".to_owned()]);
    }
}

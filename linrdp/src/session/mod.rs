//! Multi-session support: per-user desktops with Windows RDP semantics.
//!
//! See `docs/superpowers/specs/2026-09-16-multi-session-design.md`.

pub(crate) mod backends;
pub(crate) mod detect;
pub(crate) mod fileagent;
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


/// What a case that starts sessions of its own asks the keeper for.
pub(crate) struct KeeperSpec<'a> {
    /// The case (`DesktopBackend::id`): the keeper runs its `serve_session`.
    pub(crate) backend: &'static str,
    /// How long the session may take to come up before the login gives up
    /// on it.
    pub(crate) ready_within: core::time::Duration,
    /// What the case's keeper side needs to start the session, in its own
    /// terms. Asked only when a session is actually created, never when one
    /// is reattached.
    pub(crate) start: &'a dyn Fn() -> String,
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
fn create(
    base: &Path,
    user: &str,
    password: &str,
    range: RangeInclusive<u16>,
    size: (u16, u16),
    spec: &KeeperSpec<'_>,
    account: &AccountLock,
) -> anyhow::Result<registry::SessionRecord> {
    // Claim a number and KEEP the claim, then hand the descriptor holding it
    // to the keeper. The claim is never released in between, so the number
    // cannot be handed to a second login the way it could when this probed
    // and let go: two connections then chose the same display, and the one
    // whose keeper lost the lock still read — and bound to — the winner's
    // session.
    let lease = display_alloc::allocate(base, range)?;
    let display = lease.number;
    let start = (spec.start)();

    // From here the keeper owns the claim. On failure the lease is dropped
    // below, which releases it and frees the number again.
    let lock_fd = lease.into_handoff_fd();
    let spawned = spawn_keeper(base, user, password, display, size, spec.backend, &start, lock_fd, account)
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

    keeper_main::wait_for_record(base, display, user, spec.ready_within)
        .with_context(|| format!("session for {user} on :{display}"))
}

/// Fork a detached `linrdp --keeper` and feed it the password on stdin.
fn spawn_keeper(
    base: &Path,
    user: &str,
    password: &str,
    display: u16,
    size: (u16, u16),
    backend: &str,
    start: &str,
    lock_fd: std::os::fd::RawFd,
    account: &AccountLock,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    // Keep the source away from destinations 4/5: dup2(display, 4) must
    // not overwrite the source account lock before it is copied to fd 5.
    let account_fd = unsafe { libc::fcntl(account._file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    anyhow::ensure!(account_fd >= 0, "duplicate account lock: {}", std::io::Error::last_os_error());
    let account_copy = unsafe { std::fs::File::from_raw_fd(account_fd) };
    let exe = std::env::current_exe().context("locate the linrdp binary")?;
    let mut command = Command::new(exe);
    // A keeper started from a worker that was pointed at a different
    // configuration has to be pointed at the same one, or the session's log
    // goes somewhere nobody is looking.
    if !crate::config::path_is_default() {
        command.arg("--config").arg(crate::config::path());
    }
    // SAFETY: the unsafe here is `pre_exec` below — its closure runs between
    // fork and exec and calls only dup2 and fcntl, both async-signal-safe.
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
        .arg("--keeper-backend")
        .arg(backend)
        .arg("--keeper-start")
        .arg(start)
        .arg("--keeper-account-fd")
        .arg("5")
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
                if libc::dup2(account_fd, 5) < 0 || libc::fcntl(5, libc::F_SETFD, 0) < 0 {
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

    drop(account_copy);
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

/// An exclusive claim on one account's session lifecycle.
///
/// Held across "does this user have a session?" and "then make one", which
/// have to be one step and were two. Two connections for the same account
/// arriving before either keeper published its record both saw no session and
/// both created one: two desktops for one person, two keepers, and — before
/// the cookie file became per display — the second one's cookie overwriting
/// the first's, so reconnecting to the first failed with "holds no cookie".
///
/// Keyed by uid rather than by the name as typed, so `Alice` and `alice`
/// cannot end up on either side of the same lock.
///
/// Worker and starting keeper share the same flock. A worker timeout cannot
/// release the keeper's claim; publication (or keeper death) ends the claim.
pub(crate) struct AccountLock {
    /// Held purely for its `flock`; closing it releases the claim.
    _file: std::fs::File,
}

impl AccountLock {
    /// Adopt the worker's same open file description, preserving its flock.
    pub(crate) fn adopt(fd: std::os::fd::RawFd) -> anyhow::Result<Self> {
        use std::os::fd::FromRawFd as _;
        anyhow::ensure!(fd >= 0, "invalid account lock descriptor");
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        anyhow::ensure!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } >= 0,
            "account lock CLOEXEC: {}", std::io::Error::last_os_error());
        Ok(Self { _file: file })
    }

    fn acquire(base: &Path, user: &str) -> anyhow::Result<Self> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let uid = privilege::lookup_user(user)
            .with_context(|| format!("look up {user}"))?
            .uid;
        let path = base.join(format!("account-{uid}.lock"));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        // Blocking: the wait is one session start, and giving up would mean
        // creating the second desktop this exists to prevent.
        // SAFETY: a valid open fd.
        let held = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        anyhow::ensure!(held == 0, "lock {}: {}", path.display(), std::io::Error::last_os_error());
        Ok(Self { _file: file })
    }
}

/// The user's session, creating one if they have none.
///
/// The lookup and the creation happen under one per-account lock, so a second
/// connection for the same person either finds the session the first one made
/// or waits for it — never starts a second.
pub(crate) fn attach_or_create(
    base: &Path,
    user: &str,
    password: &str,
    range: RangeInclusive<u16>,
    size: (u16, u16),
    spec: &KeeperSpec<'_>,
) -> anyhow::Result<registry::SessionRecord> {
    let account = AccountLock::acquire(base, user)?;
    if let Some(existing) = attach_live(base, user, range.clone()) {
        // One account, one session. Switching `session.backend` while a
        // session runs must not quietly start a second desktop of the other
        // kind, nor serve this one through the wrong path.
        anyhow::ensure!(
            existing.backend == spec.backend,
            "{user} already has a running {} (slot {}), and this login would be served a {} \
             — log out of it first, or set session.backend back",
            described(&existing.backend),
            existing.display,
            described(spec.backend),
        );
        tracing::info!(user, display = existing.display, "attached to the existing session");
        return Ok(existing);
    }
    create(base, user, password, range, size, spec, &account)
}

/// A case's name as an operator reads it, for messages about sessions.
fn described(backend: &str) -> &str {
    backends::by_id(backend).map_or(backend, |case| case.describe())
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
                bus: None,
                backend: backends::x11::ID.to_owned(),
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

    #[test]
    fn account_claim_survives_worker_timeout_until_keeper_publishes() {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::process::CommandExt as _;
        use std::io::Read as _;
        const CHILD: &str = "LINRDP_TEST_ACCOUNT_KEEPER";
        if let Some(base) = std::env::var_os(CHILD) {
            let base = std::path::PathBuf::from(base);
            let account = AccountLock::adopt(5).unwrap();
            let flags = unsafe { libc::fcntl(5, libc::F_GETFD) };
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
            std::fs::write(base.join("ready"), b"ready").unwrap();
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            let user = std::env::var("LINRDP_TEST_ACCOUNT_USER").unwrap();
            registry::write_record(&base, &registry::SessionRecord {
                user, display: 51000, runtime_dir: "fixture".into(), xauthority: "fixture".into(), locked: false, logind_id: None, bus: None,
                backend: backends::x11::ID.to_owned(),
            }).unwrap();
            drop(account);
            return;
        }
        let base = temp_base("late-keeper");
        let user = unsafe { std::ffi::CStr::from_ptr((*libc::getpwuid(libc::getuid())).pw_name).to_string_lossy().into_owned() };
        for publish in [true, false] {
            let _ = std::fs::remove_file(base.join("ready"));
            let _ = registry::forget_record(&base, 51000);
            let account = AccountLock::acquire(&base, &user).unwrap();
            let lease = display_alloc::allocate(&base, 51000..=51000).unwrap();
            let raw = unsafe { libc::fcntl(account._file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
            assert!(raw >= 0);
            let copy = unsafe { std::fs::File::from_raw_fd(raw) };
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "session::tests::account_claim_survives_worker_timeout_until_keeper_publishes"])
                .env(CHILD, &base).env("LINRDP_TEST_ACCOUNT_USER", &user)
                .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null());
            unsafe { command.pre_exec(move || {
                if libc::dup2(raw, 5) < 0 || libc::fcntl(5, libc::F_SETFD, 0) < 0 { return Err(std::io::Error::last_os_error()); }
                Ok(())
            }); }
            let mut child = command.spawn().unwrap();
            drop(copy);
            let deadline = std::time::Instant::now() + core::time::Duration::from_secs(5);
            while !base.join("ready").exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(core::time::Duration::from_millis(10));
            }
            assert!(keeper_main::wait_for_record(&base, 51000, &user, core::time::Duration::from_millis(1)).is_err());
            drop(account); // Worker exits after timeout; child retains the same claim.
            let probe = std::fs::OpenOptions::new().read(true).write(true)
                .open(base.join(format!("account-{}.lock", unsafe { libc::getuid() }))).unwrap();
            assert_ne!(unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0,
                "another worker must not start a second session while keeper is pending");
            if publish {
                drop(child.stdin.take());
                assert!(child.wait().unwrap().success());
                assert_eq!(attach_live(&base, &user, 51000..=51000).unwrap().display, 51000);
            } else {
                child.kill().unwrap(); child.wait().unwrap();
                assert!(registry::read_one(&base, 51000).is_none());
            }
            assert_eq!(unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0,
                "publication or keeper death must release the account claim");
            drop(probe); drop(lease);
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    /// Two logins for one account must not become two desktops.
    ///
    /// Regression scenario: `attach_live` and `create` were separate steps, so
    /// two connections arriving before either keeper published its record both
    /// saw no session and both made one. The lock makes them one step; this
    /// exercises the lock itself, because starting two real keepers needs X,
    /// PAM and root.
    #[test]
    fn one_account_creates_one_session_at_a_time() {
        let base = temp_base("acctlock");
        let account = {
            // SAFETY: getpwuid is read into an owned value immediately.
            unsafe {
                let pw = libc::getpwuid(libc::getuid());
                assert!(!pw.is_null(), "this uid has an account");
                std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
            }
        };

        let inside = std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let overlapped = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let (base, user) = (base.clone(), account.clone());
                let (inside, overlapped) = (inside.clone(), overlapped.clone());
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        let _guard = AccountLock::acquire(&base, &user).expect("lock");
                        if inside.fetch_add(1, core::sync::atomic::Ordering::SeqCst) != 0 {
                            overlapped.store(true, core::sync::atomic::Ordering::SeqCst);
                        }
                        std::thread::yield_now();
                        inside.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker");
        }
        assert!(
            !overlapped.load(core::sync::atomic::Ordering::SeqCst),
            "two logins were inside one account's attach-or-create at once, which is how \
             that account ends up with two desktops"
        );

        // Different accounts must not wait for each other. Skipped when the
        // tests run as root, where "another account" would be the same one and
        // this would deadlock on itself.
        if account != "root" {
            let _mine = AccountLock::acquire(&base, &account).expect("lock");
            AccountLock::acquire(&base, "root").expect("another account is not blocked");
        }
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

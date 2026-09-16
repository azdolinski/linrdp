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
}

/// Run as the session keeper. Returns only when the session is over.
pub(crate) fn run(args: &KeeperArgs) -> anyhow::Result<()> {
    let mut password = String::new();
    std::io::stdin()
        .read_to_string(&mut password)
        .context("read the session password from stdin")?;
    let password = password.trim_end_matches(['\n', '\r']).to_owned();

    let ids = privilege::lookup_user(&args.user)?;

    // Claim the display here, in the process that will hold it for the
    // session's life. The kernel releases the flock when this process dies,
    // so the claim and the session end together — which is the invariant the
    // worker could not provide.
    let lease = display_alloc::allocate(&args.state_dir, args.display..=args.display)
        .with_context(|| format!("claim display :{}", args.display))?;

    let (mut pam, env) = crate::pam::LibPamSession::open(&args.user, &password)
        .map_err(|e| anyhow::anyhow!("open a PAM session for {}: {e}", args.user))?;
    drop(password);

    let runtime_dir = env
        .iter()
        .find(|(k, _)| k == "XDG_RUNTIME_DIR")
        .map(|(_, v)| v.clone())
        .context("PAM gave no XDG_RUNTIME_DIR — is pam_systemd.so in /etc/pam.d/linrdp?")?;

    let xauthority = xauth::write_cookie(&runtime_dir, args.display, &ids)?;
    let rec = registry::SessionRecord {
        user: args.user.clone(),
        display: args.display,
        runtime_dir,
        xauthority: xauthority.to_string_lossy().into_owned(),
        // The user is authenticating right now; they are about to look at it.
        locked: false,
    };

    let x_log = args.state_dir.join(format!("display-{}.log", args.display));
    let x_cmd = keeper::xvfb_command(args.display, &rec.xauthority, args.size);
    let env_pairs = keeper::session_env(&rec, &ids);
    let x_pid = keeper::spawn_child(&x_cmd, &env_pairs, &ids, &x_log)
        .with_context(|| format!("start the X server for {} on :{}", args.user, args.display))?;

    // Only now is the display real. Publishing the record earlier is what let
    // a failed start masquerade as a healthy session.
    keeper::wait_for_display(args.display, core::time::Duration::from_secs(10)).inspect_err(|_| {
        // SAFETY: a pid this process created and has not reaped.
        unsafe { libc::kill(x_pid, libc::SIGTERM) };
    })?;

    if !args.session_exec.is_empty() {
        let desktop_log = args.state_dir.join(format!("display-{}.desktop.log", args.display));
        let desktop = split_exec(&args.session_exec);
        match keeper::spawn_child(&desktop, &env_pairs, &ids, &desktop_log) {
            Ok(pid) => tracing::info!(
                user = %args.user,
                display = args.display,
                exec = %args.session_exec,
                pid,
                "desktop session started"
            ),
            // A missing desktop is a degraded session, not a failed one: the
            // X server is up and the user gets a bare display rather than a
            // refused login.
            Err(error) => tracing::error!(
                user = %args.user,
                display = args.display,
                %error,
                "desktop session failed to start — serving a bare X server"
            ),
        }
    }

    lease.record_owner(&args.user)?;
    registry::write_record(&args.state_dir, &rec)?;
    tracing::info!(user = %args.user, display = args.display, "session ready");

    // The session lasts as long as its X server.
    let mut status = 0;
    // SAFETY: waiting on our own child.
    unsafe { libc::waitpid(x_pid, &mut status, 0) };
    tracing::info!(user = %args.user, display = args.display, "X server exited — ending the session");

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

/// Wait for a keeper to publish its session record.
pub(crate) fn wait_for_record(
    base: &Path,
    display: u16,
    timeout: core::time::Duration,
) -> anyhow::Result<registry::SessionRecord> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(rec) = registry::read_one(base, display) {
            return Ok(rec);
        }
        std::thread::sleep(core::time::Duration::from_millis(50));
    }
    anyhow::bail!("the session keeper for :{display} did not become ready within {timeout:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

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

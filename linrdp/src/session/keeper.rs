//! Building the desktop's command line and environment.
//!
//! The keeper process owns a session: the PAM handle, the display lock and
//! the desktop processes. It outlives every connection, which is what makes
//! a reconnect land on the same desktop.

use anyhow::Context as _;

use super::privilege::UserIds;
use super::registry::SessionRecord;

#[derive(Debug)]
pub(crate) struct DesktopCommand {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
}

/// The X server for one session.
///
/// `-auth` and the absence of `-ac` are the whole security boundary of the
/// session: without them any local user can read the screen and type into it.
pub(crate) fn xvfb_command(display: u16, xauthority: &str, size: (u16, u16)) -> DesktopCommand {
    let (w, h) = size;
    DesktopCommand {
        program: "Xvfb".to_owned(),
        args: vec![
            format!(":{display}"),
            "-screen".to_owned(),
            "0".to_owned(),
            format!("{w}x{h}x24"),
            "-auth".to_owned(),
            xauthority.to_owned(),
            "-nolisten".to_owned(),
            "tcp".to_owned(),
            "+extension".to_owned(),
            "DAMAGE".to_owned(),
            "+extension".to_owned(),
            "MIT-SHM".to_owned(),
            "+extension".to_owned(),
            "RANDR".to_owned(),
            "+extension".to_owned(),
            "XFIXES".to_owned(),
            "+extension".to_owned(),
            "XTEST".to_owned(),
        ],
    }
}

/// Environment for the desktop and for the worker that serves it.
///
/// PATH is included because a session environment without one breaks
/// anything that shells out, and a desktop shells out constantly.
///
/// It is NOT the cause of the "XKB: Failed to compile keymap" start failure
/// seen once here: driving this exact spawn path with and without PATH, the
/// X server came up either way. That cause is still unidentified, so do not
/// read this line as having fixed it.
pub(crate) fn session_env(rec: &SessionRecord, user: &UserIds) -> Vec<(String, String)> {
    let path = std::env::var("PATH")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned());
    vec![
        ("PATH".to_owned(), path),
        ("DISPLAY".to_owned(), format!(":{}", rec.display)),
        ("XAUTHORITY".to_owned(), rec.xauthority.clone()),
        ("XDG_RUNTIME_DIR".to_owned(), rec.runtime_dir.clone()),
        ("HOME".to_owned(), user.home.clone()),
        ("USER".to_owned(), user.name.clone()),
        ("LOGNAME".to_owned(), user.name.clone()),
    ]
}


/// Restore SIGCHLD to its default disposition, between fork and exec.
///
/// An ignored SIGCHLD survives `execve` — handlers are reset by an exec,
/// ignores are not — and the supervisor sets SIGCHLD to SIG_IGN so it never
/// accumulates zombie workers. Every descendant inherited that ignore,
/// including the X server: it runs `xkbcomp` through `Popen`/`Pclose` and
/// reads its exit status with `waitpid`. Under SIG_IGN the kernel reaps the
/// child first, that `waitpid` fails with ECHILD, the server concludes the
/// keymap never compiled, and dies:
///
/// ```text
/// XKB: Failed to compile keymap
/// Fatal server error: Failed to activate virtual core keyboard: 2
/// ```
///
/// Reproduced exactly, same Xvfb command line both ways: SIGCHLD default, the
/// server runs; SIGCHLD ignored, that log appears byte for byte. The same
/// inherited ignore also made the worker's `wait()` on the keeper fail with
/// ECHILD, so a keeper that started perfectly was reported as a failure.
///
/// So every exec of a foreign program goes through here. A process we did not
/// write may wait on its own children, and inheriting our reaping policy is
/// not ours to impose.
///
/// Async-signal-safe: `signal` is on the list, and nothing between here and
/// the exec is waiting on a child of its own.
pub(crate) fn restore_default_sigchld() {
    // SAFETY: async-signal-safe, and this runs in a freshly forked child
    // whose only remaining act is to exec.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
}

/// Point the grandchild's stdin at /dev/null and its output at `log`.
///
/// Async-signal-safe: only open/dup2/close between fork and exec.
fn redirect_stdio(log: &std::ffi::CStr) {
    // SAFETY: plain open/dup2/close on descriptors this process owns; all are
    // async-signal-safe and none allocate.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            libc::dup2(null, 0);
            if null > 2 {
                libc::close(null);
            }
        }
        let fd = libc::open(log.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND, 0o600);
        if fd >= 0 {
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                libc::close(fd);
            }
        }
    }
}

/// Find `program` on PATH, or accept it as-is when it is already a path.
fn resolve_program(program: &str) -> Option<String> {
    if program.contains('/') {
        return std::path::Path::new(program).is_file().then(|| program.to_owned());
    }
    std::env::var("PATH")
        .unwrap_or_else(|_| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned())
        .split(':')
        .map(|dir| std::path::Path::new(dir).join(program))
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.to_string_lossy().into_owned())
}

/// Clear what a killed X server left behind on this display number.
///
/// An X server writes `/tmp/.X<n>-lock` and `/tmp/.X11-unix/X<n>`, and a
/// SIGKILL leaves both. The next server on that number then dies with
/// "Could not create server lock file" and the number is unusable until
/// somebody notices — a display leak with no owner.
///
/// Safe because of what the caller already holds: the display was allocated
/// under a `flock`, so no other linrdp session owns this number, and the
/// socket is only removed when nothing answers on it. A live server is never
/// touched.
pub(crate) fn clear_stale_display(display: u16) {
    let socket = format!("/tmp/.X11-unix/X{display}");
    if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
        return; // somebody is serving this number; leave it completely alone
    }
    for path in [format!("/tmp/.X{display}-lock"), socket] {
        if std::path::Path::new(&path).exists() {
            match std::fs::remove_file(&path) {
                Ok(()) => tracing::info!(path, "removed a dead X server's leftovers"),
                Err(error) => tracing::warn!(path, %error, "could not remove a dead X server's leftovers"),
            }
        }
    }
}

/// Wait until an X server on `display` actually accepts connections.
///
/// Connecting, not just looking: a server killed with SIGKILL leaves its
/// socket file behind, and a stale one satisfies an existence check instantly.
/// That is how a caller ended up talking to a display whose server had not
/// started yet ("Connection refused"), and how a keeper could have adopted a
/// foreign server that happened to hold the number.
///
/// The grandchild is detached, so its exec failure cannot be waited for; a
/// socket that accepts is the only evidence available that the desktop is
/// real.
pub(crate) fn wait_for_display(display: u16, timeout: core::time::Duration) -> anyhow::Result<()> {
    let socket = format!("/tmp/.X11-unix/X{display}");
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            return Ok(());
        }
        std::thread::sleep(core::time::Duration::from_millis(50));
    }
    anyhow::bail!("X server for :{display} did not start within {timeout:?}")
}

/// Start `cmd` as a direct child, running as `user`, and return its pid.
///
/// Used by the keeper, which stays alive to supervise what it starts — so
/// unlike [`spawn_detached`] the child is reapable and its death is
/// observable, which is what lets the keeper end the session when the X
/// server exits.
pub(crate) fn spawn_child(
    cmd: &DesktopCommand,
    env: &[(String, String)],
    user: &UserIds,
    log_path: &std::path::Path,
) -> anyhow::Result<i32> {
    let resolved = resolve_program(&cmd.program)
        .with_context(|| format!("{} not found in PATH", cmd.program))?;
    let program = std::ffi::CString::new(resolved.as_str()).context("program name NUL")?;
    let mut argv_owned = vec![program.clone()];
    for a in &cmd.args {
        argv_owned.push(std::ffi::CString::new(a.as_str()).context("argument NUL")?);
    }
    let mut envp_owned = Vec::with_capacity(env.len());
    for (k, v) in env {
        envp_owned.push(std::ffi::CString::new(format!("{k}={v}")).context("env NUL")?);
    }
    let log_c = std::ffi::CString::new(log_path.as_os_str().as_encoded_bytes()).context("log path NUL")?;

    // SAFETY: the keeper is single-threaded, so the child inherits a
    // consistent address space.
    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            restore_default_sigchld();
            redirect_stdio(&log_c);
            if crate::session::privilege::drop_to(user).is_err() {
                // SAFETY: _exit is async-signal-safe and never returns.
                unsafe { libc::_exit(1) };
            }
            let mut argv: Vec<*const std::ffi::c_char> = argv_owned.iter().map(|a| a.as_ptr()).collect();
            argv.push(std::ptr::null());
            let mut envp: Vec<*const std::ffi::c_char> = envp_owned.iter().map(|e| e.as_ptr()).collect();
            envp.push(std::ptr::null());
            // SAFETY: NUL-terminated argv/envp built above; execve only
            // returns on failure.
            unsafe {
                libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(1)
            }
        }
        pid => Ok(pid),
    }
}

/// Start `cmd` as a detached child of init, running as `user`.
///
/// Double-fork: the intermediate child exits immediately, so the grandchild
/// is re-parented to init and survives the worker that created it. That is
/// what makes the desktop outlive the connection.
///
/// The privilege drop happens in the grandchild, after `setsid`, and any
/// failure there `_exit`s rather than returning — a child that failed to
/// become the session user must never go on to exec the desktop as root.
pub(crate) fn spawn_detached(
    cmd: &DesktopCommand,
    env: &[(String, String)],
    user: &UserIds,
    log_path: &std::path::Path,
) -> anyhow::Result<()> {
    // execve does NOT search PATH — a bare "Xvfb" fails with ENOENT in the
    // grandchild, where nothing can report it. Resolve here, where the error
    // still has somewhere to go.
    let resolved = resolve_program(&cmd.program)
        .with_context(|| format!("{} not found in PATH", cmd.program))?;
    let program = std::ffi::CString::new(resolved.as_str()).context("program name NUL")?;
    let mut argv_owned = vec![program.clone()];
    for a in &cmd.args {
        argv_owned.push(std::ffi::CString::new(a.as_str()).context("argument NUL")?);
    }
    let mut envp_owned = Vec::with_capacity(env.len());
    for (k, v) in env {
        envp_owned.push(std::ffi::CString::new(format!("{k}={v}")).context("env NUL")?);
    }
    let log_c = std::ffi::CString::new(log_path.as_os_str().as_encoded_bytes()).context("log path NUL")?;

    // SAFETY: fork from a context the caller guarantees is single-threaded
    // (the worker does this before starting its runtime).
    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            // Intermediate child: detach into a new session, fork again, exit.
            // SAFETY: setsid on a fresh child always succeeds.
            unsafe { libc::setsid() };
            // SAFETY: same single-threaded reasoning as above.
            match unsafe { libc::fork() } {
                // Only _exit here: the normal exit path would run atexit
                // handlers and flush buffers this forked copy shares with
                // the parent.
                //
                // SAFETY: _exit is async-signal-safe and never returns.
                -1 => unsafe { libc::_exit(1) },
                0 => {
                    // Grandchild. Give it somewhere to complain first: it is
                    // detached, so without this its stdout and stderr die with
                    // the worker and a desktop that fails to start does so in
                    // complete silence — which is exactly how a failed Xvfb
                    // first looked like a working session.
                    restore_default_sigchld();
                    redirect_stdio(&log_c);
                    // Become the user, then become the desktop.
                    if crate::session::privilege::drop_to(user).is_err() {
                        // SAFETY: as above.
                        unsafe { libc::_exit(1) };
                    }
                    let mut argv: Vec<*const std::ffi::c_char> =
                        argv_owned.iter().map(|a| a.as_ptr()).collect();
                    argv.push(std::ptr::null());
                    let mut envp: Vec<*const std::ffi::c_char> =
                        envp_owned.iter().map(|e| e.as_ptr()).collect();
                    envp.push(std::ptr::null());
                    // SAFETY: NUL-terminated argv and envp built above;
                    // execve only returns on failure.
                    unsafe {
                        libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr());
                        libc::_exit(1)
                    }
                }
                // SAFETY: as above.
                _ => unsafe { libc::_exit(0) },
            }
        }
        pid => {
            // Reap the intermediate child so it does not linger as a zombie;
            // the grandchild belongs to init by then.
            let mut status = 0;
            // SAFETY: waiting on our own direct child.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::privilege::UserIds;
    use crate::session::registry::SessionRecord;

    #[test]
    fn xvfb_is_never_started_with_access_control_off() {
        let cmd = xvfb_command(42, "/run/user/1000/linrdp/Xauthority", (2880, 1800));
        assert_eq!(cmd.program, "Xvfb");
        assert!(
            !cmd.args.iter().any(|a| a == "-ac"),
            "-ac disables X access control: any local user could screenshot the \
             session and inject input. Never emit it. Got {:?}",
            cmd.args
        );
        assert!(cmd.args.iter().any(|a| a == ":42"), "display must be passed");
        let auth = cmd.args.windows(2).find(|w| w[0] == "-auth").expect("-auth is mandatory");
        assert_eq!(auth[1], "/run/user/1000/linrdp/Xauthority");
        assert!(
            cmd.args.iter().any(|a| a.starts_with("2880x1800x")),
            "screen geometry must be applied, got {:?}",
            cmd.args
        );
    }

    /// A child that restored the default disposition can reap its own
    /// children again.
    ///
    /// Regression: the supervisor ignores SIGCHLD, that ignore survives exec,
    /// and the X server reads `xkbcomp`'s exit status with `waitpid`. Under an
    /// inherited SIG_IGN the call returned ECHILD, the server reported
    /// "XKB: Failed to compile keymap" and refused to start — every session
    /// died before its desktop existed.
    ///
    /// Run inside a forked child so the test never touches the disposition of
    /// the process running the suite.
    #[test]
    fn a_restored_sigchld_lets_the_child_wait_for_its_own_children() {
        // SAFETY: the child does nothing but async-signal-safe calls
        // (signal, fork, waitpid, _exit) before exiting.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // SAFETY: as above.
            unsafe {
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                restore_default_sigchld();
                let grandchild = libc::fork();
                if grandchild == 0 {
                    libc::_exit(7);
                }
                let mut status = 0;
                let reaped = libc::waitpid(grandchild, &mut status, 0);
                // Reaped the right child, with the status it chose: proof the
                // kernel did not collect it behind our back.
                let ok = reaped == grandchild && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 7;
                libc::_exit(i32::from(!ok));
            }
        }
        let mut status = 0;
        // SAFETY: waiting on our own direct child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "after restoring the default disposition a child must still be reapable by hand"
        );
    }

    #[test]
    fn the_session_env_points_at_the_users_own_runtime_dir() {
        let rec = SessionRecord {
            user: "alice".to_owned(),
            display: 42,
            runtime_dir: "/run/user/1001".to_owned(),
            xauthority: "/run/user/1001/linrdp/Xauthority".to_owned(),
            locked: false,
        };
        let user = UserIds { uid: 1001, gid: 1001, name: "alice".to_owned(), home: "/home/alice".to_owned() };

        let env = session_env(&rec, &user);
        let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());

        assert_eq!(get("DISPLAY"), Some(":42"));
        assert_eq!(get("XAUTHORITY"), Some("/run/user/1001/linrdp/Xauthority"));
        assert_eq!(get("XDG_RUNTIME_DIR"), Some("/run/user/1001"));
        assert_eq!(get("HOME"), Some("/home/alice"));
        assert_eq!(get("USER"), Some("alice"));
        // Without PATH the X server cannot run xkbcomp and dies before the
        // display exists.
        assert!(
            get("PATH").is_some_and(|p| p.contains("/usr/bin")),
            "PATH must be present: the X server shells out to xkbcomp"
        );
        assert!(
            get("XAUTHORITY").is_some_and(|p| p.starts_with("/run/user/")),
            "the cookie must never be pointed at /tmp or a home directory"
        );
    }
}

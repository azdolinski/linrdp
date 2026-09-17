//! The supervisor: accept, fork, reap. It never speaks RDP.
//!
//! Forking before any protocol runs is what removes the routing problem.
//! The child learns which desktop to serve from its own CredSSP exchange,
//! not from the client-supplied X.224 `mstshash` cookie — that field is
//! unauthenticated and must never decide whose desktop someone reaches.

use std::net::SocketAddr;
use std::ops::RangeInclusive;

use anyhow::Context as _;

/// Parse `--display-range LOW-HIGH`.
pub(crate) fn parse_display_range(spec: &str) -> anyhow::Result<RangeInclusive<u16>> {
    let Some((low, high)) = spec.split_once('-') else {
        anyhow::bail!("--display-range expects LOW-HIGH, e.g. 10-99");
    };
    let low: u16 = low.trim().parse().context("--display-range LOW")?;
    let high: u16 = high.trim().parse().context("--display-range HIGH")?;
    anyhow::ensure!(low >= 1, "--display-range must start at 1 or above (:0 is a physical seat)");
    anyhow::ensure!(low <= high, "--display-range expects LOW-HIGH with LOW <= HIGH");
    Ok(low..=high)
}

/// Accept connections and fork a worker for each.
///
/// A blocking listener deliberately: the supervisor has no async work, and
/// `fork` in a multi-threaded tokio runtime is a footgun — only the calling
/// thread survives in the child, so any runtime state is poisoned.
pub(crate) fn run(bind: SocketAddr, worker_argv: &[String]) -> anyhow::Result<()> {
    let listener = std::net::TcpListener::bind(bind).with_context(|| format!("bind {bind}"))?;
    tracing::info!(%bind, "supervisor listening — forking a worker per connection");

    // Reap children without blocking: a worker that exits must not become a
    // zombie, and the supervisor never waits on a specific child.
    //
    // This disposition belongs to the supervisor ALONE. An ignored SIGCHLD is
    // inherited across fork *and* across exec, so every worker, keeper, X
    // server and desktop process would otherwise inherit auto-reaping and see
    // its own `waitpid` calls fail with ECHILD. Each forked child restores the
    // default before exec — see `session::keeper::restore_default_sigchld`,
    // which documents what that cost us.
    //
    // SAFETY: setting SIGCHLD to SIG_IGN is async-signal-safe and documented
    // on Linux to auto-reap.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };

    loop {
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "accept failed");
                continue;
            }
        };

        // SAFETY: the supervisor is single-threaded here (no tokio runtime),
        // so the child inherits a consistent address space.
        match unsafe { libc::fork() } {
            -1 => tracing::error!(error = %std::io::Error::last_os_error(), "fork failed"),
            0 => {
                crate::session::keeper::restore_default_sigchld();
                exec_worker(stream, worker_argv);
                // exec_worker only returns on failure.
                std::process::exit(1);
            }
            pid => {
                tracing::debug!(%peer, pid, "forked worker");
                drop(stream); // the child owns it now
            }
        }
    }
}

/// The path the supervisor should exec for each worker.
///
/// `/proc/self/exe` — which is what `current_exe` reads — keeps pointing at
/// the *inode* this process was started from. Replace the binary in place
/// (`install`, a package upgrade) and the link becomes
/// `/usr/local/bin/linrdp (deleted)`, which `current_exe` hands back verbatim,
/// suffix and all. `execv` on that fails with ENOENT, so every worker died
/// between fork and its first line of code: connections were reset with
/// nothing anywhere saying why, until the service happened to be restarted.
///
/// Stripping the suffix leaves the path the operator installed to, so a
/// running supervisor picks up an upgraded binary on the next connection
/// instead of breaking on it.
fn worker_program(exe: &std::path::Path) -> std::path::PathBuf {
    let raw = exe.as_os_str().as_encoded_bytes();
    match raw.strip_suffix(b" (deleted)") {
        // SAFETY: the bytes came from an OsStr and are a prefix of it, so they
        // are still whatever encoding the platform uses for paths.
        Some(trimmed) => std::path::PathBuf::from(unsafe {
            std::ffi::OsString::from_encoded_bytes_unchecked(trimmed.to_vec())
        }),
        None => exe.to_path_buf(),
    }
}

/// Move `stream` to fd 3 and exec the worker with `--serve-fd 3`.
fn exec_worker(stream: std::net::TcpStream, argv: &[String]) {
    use std::os::fd::IntoRawFd as _;

    let fd = stream.into_raw_fd();
    // SAFETY: dup2 onto a fd the child does not otherwise use; dup2 clears
    // CLOEXEC on the copy, which is what lets it survive the exec.
    if unsafe { libc::dup2(fd, 3) } < 0 {
        tracing::error!(error = %std::io::Error::last_os_error(), "worker: cannot place the socket on fd 3");
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(exe) => worker_program(&exe),
        Err(error) => {
            tracing::error!(%error, "worker: cannot locate the linrdp binary");
            return;
        }
    };
    let Ok(exe_c) = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes()) else {
        tracing::error!(path = %exe.display(), "worker: binary path contains a NUL");
        return;
    };

    let mut args: Vec<std::ffi::CString> = vec![exe_c.clone()];
    for a in argv {
        if let Ok(c) = std::ffi::CString::new(a.as_str()) {
            args.push(c);
        }
    }
    for literal in ["--serve-fd", "3"] {
        if let Ok(c) = std::ffi::CString::new(literal) {
            args.push(c);
        }
    }

    let mut ptrs: Vec<*const std::ffi::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: NUL-terminated argv built above; execv only returns on failure.
    unsafe { libc::execv(exe_c.as_ptr(), ptrs.as_ptr()) };
    // Only reachable on failure, and it must never be silent again: this is
    // the process that was about to become the whole connection.
    tracing::error!(
        program = %exe.display(),
        error = %std::io::Error::last_os_error(),
        "worker: exec failed — the connection is being dropped"
    );
}

#[cfg(test)]
mod tests {
    use super::*;


    /// A binary replaced underneath a running supervisor.
    ///
    /// Regression: `install` over `/usr/local/bin/linrdp` unlinks the old
    /// inode, so `/proc/self/exe` — and therefore `current_exe` — reads
    /// `/usr/local/bin/linrdp (deleted)`. `execv` on that returns ENOENT and
    /// every worker died before its first line of code: connections reset,
    /// nothing in the log but "forked worker".
    #[test]
    fn a_replaced_binary_is_exec_ed_at_its_real_path() {
        assert_eq!(
            worker_program(std::path::Path::new("/usr/local/bin/linrdp (deleted)")),
            std::path::Path::new("/usr/local/bin/linrdp"),
            "the suffix the kernel adds is not part of the path"
        );
    }

    /// And a path that merely looks like one is left alone.
    #[test]
    fn an_ordinary_path_is_untouched() {
        for path in ["/usr/local/bin/linrdp", "/opt/my (deleted) tools/linrdp", "linrdp"] {
            assert_eq!(worker_program(std::path::Path::new(path)), std::path::Path::new(path));
        }
    }

    #[test]
    fn a_valid_range_parses() {
        let range = parse_display_range("10-99").expect("valid");
        assert_eq!(*range.start(), 10);
        assert_eq!(*range.end(), 99);
    }

    #[test]
    fn an_inverted_range_is_rejected() {
        let err = parse_display_range("99-10").expect_err("inverted");
        assert!(err.to_string().contains("LOW-HIGH"), "got: {err}");
    }

    #[test]
    fn display_zero_is_rejected() {
        let err = parse_display_range("0-9").expect_err("zero");
        assert!(err.to_string().contains("must start at 1"), "got: {err}");
    }

    #[test]
    fn garbage_is_rejected() {
        parse_display_range("ten to ninety").expect_err("not a range");
        parse_display_range("10").expect_err("missing the dash");
    }
}

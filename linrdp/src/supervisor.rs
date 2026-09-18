//! The supervisor: bind, accept, fork, reap. It never speaks RDP.
//!
//! Forking before any protocol runs is what removes the routing problem.
//! The child learns which desktop to serve from its own CredSSP exchange,
//! not from the client-supplied X.224 `mstshash` cookie — that field is
//! unauthenticated and must never decide whose desktop someone reaches.
//!
//! One process owns every listener the configuration names. It used to own
//! exactly one, which is why serving a second port meant a second systemd unit
//! with a second copy of every setting in its `ExecStart`.

use core::time::Duration;
use std::net::TcpListener;
use std::os::fd::AsRawFd as _;

use anyhow::Context as _;

use crate::config::{self, Config};

/// A listening socket and the configuration line that produced it.
#[derive(Debug)]
pub(crate) struct Bound {
    listener: TcpListener,
    /// The `bind` literal from the file, handed to the worker verbatim. Not a
    /// re-formatted `SocketAddr`: `0.0.0.0:3389`, `[::]:3389` and
    /// `[::ffff:0.0.0.0]:3389` can name one socket, and `Display` hands back a
    /// spelling the operator never wrote, which the worker would then fail to
    /// find in the very file it came from.
    bind: String,
}

/// Bind every listener the configuration names, or none of them.
///
/// A partial start is worse than no start. The shape this replaces is one port
/// for every client and one for the PAM-free logon screen; if the first fails
/// and the second succeeds, the process is *healthy*, so `Restart=on-failure`
/// never fires and monitoring stays green while the port everybody uses is
/// dead. Exiting hands both of those back for free.
///
/// Every failure is reported, not just the first: an operator with two typos
/// should learn both in one run.
pub(crate) fn bind_all(config: &Config) -> anyhow::Result<Vec<Bound>> {
    let mut bound = Vec::new();
    let mut failures = Vec::new();

    for listener in &config.listeners {
        match TcpListener::bind(listener.bind.as_str()) {
            Ok(socket) => bound.push(Bound {
                listener: socket,
                bind: listener.bind.clone(),
            }),
            Err(error) => failures.push(format!("{}: {error}", listener.bind)),
        }
    }

    if !failures.is_empty() {
        // The listening socket is what stops two supervisors, so this is where
        // that shows up — as "address already in use", which describes the
        // symptom and not the cause. Name the process holding it.
        let held_by = match crate::daemon::running() {
            Some(pid) => format!("\n  another linrdp supervisor is running (pid {pid})"),
            None => String::new(),
        };
        // `bound` is dropped on the way out, so nothing stays half-open.
        anyhow::bail!(
            "cannot bind {} of {} listeners, so none of them were kept:\n  - {}{held_by}",
            failures.len(),
            config.listeners.len(),
            failures.join("\n  - ")
        );
    }

    Ok(bound)
}

/// Accept on every listener and fork a worker for each connection.
///
/// One thread, `poll`, and no async runtime: `fork` in a multi-threaded tokio
/// runtime is a footgun — only the calling thread survives in the child, so
/// any runtime state is poisoned. That constraint is why this is a hand-rolled
/// poll loop rather than anything built on mio.
pub(crate) fn run(mut live: Vec<Bound>) -> anyhow::Result<()> {
    anyhow::ensure!(!live.is_empty(), "no listeners to accept on");

    for bound in &live {
        // Not an optimisation. A connection reset between `poll` reporting
        // POLLIN and `accept` running leaves `accept` blocking (see the BUGS
        // section of select(2)) — with one listener that only stalled itself,
        // with several it stalls every other port in this same thread.
        bound
            .listener
            .set_nonblocking(true)
            .with_context(|| format!("make {} non-blocking", bound.bind))?;
        tracing::info!(bind = %bound.bind, "listening");
    }

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
    // It also keeps a finished worker from waking `poll`, which is why this
    // loop needs no child bookkeeping at all. Anyone who later wants per-
    // listener worker counts will need a real SIGCHLD handler, and with it the
    // EINTR that is handled below.
    //
    // SAFETY: setting SIGCHLD to SIG_IGN is async-signal-safe and documented
    // on Linux to auto-reap.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };

    loop {
        let mut fds: Vec<libc::pollfd> = live
            .iter()
            .map(|bound| libc::pollfd {
                fd: bound.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let count = libc::nfds_t::try_from(fds.len()).expect("a handful of listeners");

        // SAFETY: `fds` holds `count` initialised pollfd values for the whole
        // call, and nothing else touches it meanwhile.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), count, -1) };

        if ready < 0 {
            let error = std::io::Error::last_os_error();
            // SIGCHLD is ignored, but SIGWINCH, SIGHUP and the SIGCONT after a
            // debugger's SIGSTOP all land here. Exiting on those would mean a
            // server that dies when somebody attaches strace to it.
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // A permanent poll error would otherwise spin, filling the log at
            // the speed of the disk.
            tracing::error!(%error, "poll failed — retrying");
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }

        let mut dead = Vec::new();
        for (index, pollfd) in fds.iter().enumerate() {
            match verdict(pollfd.revents) {
                Verdict::Dead => dead.push(index),
                Verdict::Ready => accept_all(&live[index]),
                Verdict::Idle => {}
            }
        }

        // A listening TCP socket does not die on its own; this is here to stop
        // a bug in our own descriptor handling from becoming a busy loop that
        // reports the same dead fd forever.
        for index in dead.into_iter().rev() {
            let gone = live.remove(index);
            tracing::error!(
                bind = %gone.bind,
                "listening socket became unusable — this address is no longer served"
            );
        }
        anyhow::ensure!(
            !live.is_empty(),
            "every listening socket is gone; there is nothing left to accept on"
        );
    }
}

/// What one listener's `revents` means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Somebody is waiting.
    Ready,
    /// Nothing happened on this one.
    Idle,
    /// The descriptor is no longer a listening socket. It has to leave the
    /// set: `poll` reports an error condition again immediately, so a loop
    /// that only logged it would spin at the speed of the disk.
    Dead,
}

fn verdict(revents: i16) -> Verdict {
    if revents & (libc::POLLNVAL | libc::POLLERR | libc::POLLHUP) != 0 {
        Verdict::Dead
    } else if revents & libc::POLLIN != 0 {
        Verdict::Ready
    } else {
        Verdict::Idle
    }
}

/// Take every connection this listener has ready.
///
/// Level-triggered poll would report the socket again, but draining keeps one
/// busy port from having to wait a full poll cycle per connection while a
/// quiet one is checked.
fn accept_all(bound: &Bound) {
    loop {
        match bound.listener.accept() {
            Ok((stream, peer)) => {
                // SAFETY: the supervisor is single-threaded here (no tokio
                // runtime), so the child inherits a consistent address space.
                match unsafe { libc::fork() } {
                    -1 => tracing::error!(
                        error = %std::io::Error::last_os_error(),
                        bind = %bound.bind,
                        "fork failed"
                    ),
                    0 => {
                        crate::session::keeper::restore_default_sigchld();
                        exec_worker(stream, &worker_argv(&bound.bind));
                        // exec_worker only returns on failure.
                        std::process::exit(1);
                    }
                    pid => {
                        tracing::debug!(%peer, pid, bind = %bound.bind, "forked worker");
                        drop(stream); // the child owns it now
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                tracing::warn!(bind = %bound.bind, %error, "accept failed");
                return;
            }
        }
    }
}

/// Everything a worker is told, which is only which listener it is serving.
///
/// No setting appears here. A worker reads the same file the supervisor read
/// and looks its listener up by this string, so there is no second place a
/// value could come from and no flag that could silently outrank the file.
fn worker_argv(bind: &str) -> Vec<String> {
    let mut argv = vec!["--listener".to_owned(), bind.to_owned()];
    if !config::path_is_default() {
        argv.push("--config".to_owned());
        argv.push(config::path().display().to_string());
    }
    // The one thing a worker is told that the file does not say, and it says
    // nothing about what is served — only how loudly. `linrdp debug` is worth
    // little if the interesting half, which is the session, keeps logging at
    // the level the machine uses every day.
    if let Some(filter) = crate::logging::override_filter() {
        argv.push("--log-level".to_owned());
        argv.push(filter.to_owned());
    }
    argv
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
        Some(trimmed) => {
            // SAFETY: the bytes came from an OsStr and are a prefix of it, so
            // they are still whatever encoding the platform uses for paths.
            let trimmed = unsafe { std::ffi::OsString::from_encoded_bytes_unchecked(trimmed.to_vec()) };
            std::path::PathBuf::from(trimmed)
        }
        None => exe.to_path_buf(),
    }
}

/// Move `stream` to fd 3 and exec the worker with `--serve-fd 3`.
fn exec_worker(stream: std::net::TcpStream, argv: &[String]) {
    use std::os::fd::IntoRawFd as _;

    let fd = stream.into_raw_fd();
    // SAFETY: dup2 onto a descriptor the child does not otherwise use.
    if unsafe { libc::dup2(fd, 3) } < 0 {
        tracing::error!(error = %std::io::Error::last_os_error(), "worker: cannot place the socket on fd 3");
        return;
    }
    // dup2 clears FD_CLOEXEC on the copy, which is what lets the socket
    // survive the exec — except when oldfd == newfd, where POSIX says dup2
    // does nothing at all, close-on-exec included. With a single listener the
    // accepted socket could never land on fd 3; with several it can, and the
    // worker would then have been exec'd onto a descriptor closed out from
    // under it: EBADF, connection dropped, nothing in the log.
    //
    // SAFETY: fd 3 is the descriptor just established above.
    if unsafe { libc::fcntl(3, libc::F_SETFD, 0) } < 0 {
        tracing::error!(error = %std::io::Error::last_os_error(), "worker: cannot clear close-on-exec on fd 3");
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

    let mut cstrings: Vec<std::ffi::CString> = vec![exe_c.clone()];
    for arg in argv {
        if let Ok(c) = std::ffi::CString::new(arg.as_str()) {
            cstrings.push(c);
        }
    }
    for literal in ["--serve-fd", "3"] {
        if let Ok(c) = std::ffi::CString::new(literal) {
            cstrings.push(c);
        }
    }

    let mut ptrs: Vec<*const core::ffi::c_char> = cstrings.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(core::ptr::null());
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

    fn config_with(binds: &[&str]) -> Config {
        let listeners = binds
            .iter()
            .map(|bind| format!("  - bind: {bind}\n    auth: both\n"))
            .collect::<String>();
        serde_norway::from_str(&format!("listeners:\n{listeners}")).expect("parses")
    }

    /// An error condition on a listening socket has to take it out of the
    /// set. `poll` reports the same condition on the next call and every call
    /// after it, so a loop that logged and carried on would spin — filling
    /// /var/log/linrdp at the speed of the disk while serving nobody.
    #[test]
    fn a_broken_listener_leaves_the_set_rather_than_being_polled_again() {
        for condition in [libc::POLLNVAL, libc::POLLERR, libc::POLLHUP] {
            assert_eq!(verdict(condition), Verdict::Dead, "revents {condition:#x}");
        }
        // Even alongside readable data: the socket is going away either way.
        assert_eq!(verdict(libc::POLLIN | libc::POLLERR), Verdict::Dead);
    }

    #[test]
    fn a_readable_listener_is_accepted_on_and_a_quiet_one_is_left_alone() {
        assert_eq!(verdict(libc::POLLIN), Verdict::Ready);
        assert_eq!(verdict(0), Verdict::Idle);
    }

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

    /// The worker finds its settings by matching this string against the file,
    /// so it has to be the string the file contains — not `SocketAddr`'s idea
    /// of how to write the same address.
    #[test]
    fn the_listener_argument_is_the_bind_literal_verbatim() {
        assert_eq!(
            worker_argv("[::1]:3389"),
            vec!["--listener".to_owned(), "[::1]:3389".to_owned()]
        );
    }

    /// Nothing that decides *what is served* reaches a worker through argv. A
    /// setting smuggled in here would outrank the configuration file silently,
    /// which is the whole arrangement this replaces.
    ///
    /// `--log-level` is the one thing that does travel, and it is not an
    /// exception to that rule: it changes how loud the worker is, never which
    /// address, which authentication or which features it serves.
    #[test]
    fn a_worker_is_told_nothing_but_which_listener_it_serves() {
        let argv = worker_argv("0.0.0.0:3389");
        for flag in [
            "--auth",
            "--bind-addr",
            "--usb",
            "--console",
            "--fixed-size",
            "--display-range",
        ] {
            assert!(
                !argv.iter().any(|a| a == flag),
                "`{flag}` reached a worker through argv"
            );
        }
    }

    /// One unusable address takes the whole start down, and leaves nothing
    /// bound behind it. A half-started supervisor looks healthy to systemd, so
    /// `Restart=on-failure` would never fire on the port that is missing.
    #[test]
    fn one_unbindable_listener_refuses_the_whole_start() {
        let occupied = TcpListener::bind("127.0.0.1:0").expect("a port to steal");
        let taken = occupied.local_addr().expect("addr").to_string();
        let free = {
            let probe = TcpListener::bind("127.0.0.1:0").expect("a free port");
            probe.local_addr().expect("addr").to_string()
        };

        let error = bind_all(&config_with(&[&free, &taken])).expect_err("refused");
        assert!(format!("{error:#}").contains(&taken), "got: {error:#}");

        TcpListener::bind(free.as_str()).expect("the first port was not left bound");
    }

    /// Two typos, one restart.
    #[test]
    fn every_bind_failure_is_reported_not_just_the_first() {
        let first = TcpListener::bind("127.0.0.1:0").expect("port");
        let second = TcpListener::bind("127.0.0.1:0").expect("port");
        let a = first.local_addr().expect("addr").to_string();
        let b = second.local_addr().expect("addr").to_string();

        let error = format!("{:#}", bind_all(&config_with(&[&a, &b])).expect_err("refused"));
        assert!(error.contains(&a) && error.contains(&b), "got: {error}");
        assert!(error.contains("cannot bind 2 of 2"), "got: {error}");
    }

    #[test]
    fn a_configuration_that_binds_cleanly_yields_one_socket_per_listener() {
        let ports: Vec<String> = core::iter::repeat_with(|| {
            let probe = TcpListener::bind("127.0.0.1:0").expect("port");
            probe.local_addr().expect("addr").to_string()
        })
        .take(2)
        .collect();
        let refs: Vec<&str> = ports.iter().map(String::as_str).collect();
        let bound = bind_all(&config_with(&refs)).expect("both bind");
        assert_eq!(bound.len(), 2);
        assert_eq!(bound[0].bind, ports[0]);
    }
}

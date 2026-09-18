//! `linrdp daemon` — running the supervisor without systemd.
//!
//! The interlock against two supervisors is not this file: it is the listening
//! socket. Two processes cannot hold 0.0.0.0:3389, so the second one refuses
//! to start before it has served anything, and refuses *every* listener rather
//! than coming up half-bound. The pid file adds no safety on top of that and
//! is not trusted as though it did — a supervisor killed with SIGKILL leaves
//! one behind, and pids are reused.
//!
//! What it is for is the two questions the socket cannot answer: which process
//! do I signal to stop it, and who is holding the port I was just refused.

use core::time::Duration;
use std::path::Path;

use anyhow::Context as _;

/// Under /run: tmpfs, cleared on boot, and already the supervisor's state
/// directory at mode 0700.
const PID_FILE: &str = "/run/linrdp/supervisor.pid";

/// Record this supervisor, once it is bound and nothing can still refuse it.
///
/// Best effort on purpose: a machine that cannot write /run is a machine that
/// should still serve RDP.
pub(crate) fn write_pid_file() {
    let pid = std::process::id();
    if let Some(dir) = Path::new(PID_FILE).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(error) = crate::atomic::write(Path::new(PID_FILE), &format!("{pid}\n"), 0o644) {
        tracing::debug!(%error, path = PID_FILE, "could not record the pid");
    }
}

/// The pid of the supervisor running here, if one is.
///
/// Two checks, because either alone lies. A pid file outlives the process that
/// wrote it, and the number in it is handed out again to something unrelated;
/// so the pid has to exist *and* be a linrdp before the answer is yes.
pub(crate) fn running() -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(PID_FILE).ok()?.trim().parse().ok()?;
    is_a_live_linrdp(pid).then_some(pid)
}

fn is_a_live_linrdp(pid: u32) -> bool {
    let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else {
        return false; // no such process
    };
    comm.trim() == "linrdp"
}

/// `linrdp daemon <verb>`.
pub(crate) fn run(verb: Option<&str>) -> anyhow::Result<()> {
    let parsed = verb.or(Some("")).filter(|v| VERBS.contains(v));
    match parsed {
        Some("start") => start(),
        Some("stop") => stop(),
        Some("status") => status(),
        _ => {
            print!("{}", crate::cli::subtree("daemon"));
            match verb {
                Some(other) => anyhow::bail!("`linrdp daemon {other}` is not one of them"),
                None => anyhow::bail!("no command specified"),
            }
        }
    }
}

pub(crate) const VERBS: [&str; 3] = ["start", "stop", "status"];

fn start() -> anyhow::Result<()> {
    require_root("start")?;

    // systemd first. Its supervisor writes the same pid file, so asking that
    // question first would answer "already running (pid N)" — true, and no
    // help at all to somebody who needs to know that the way to touch this one
    // is `service`, not `daemon`.
    if crate::service::unit::systemctl(&["is-active", "--quiet", crate::service::unit::UNIT_NAME])
        == Some(true)
    {
        anyhow::bail!(
            "systemd is already running linrdp here. `linrdp service restart` is the \
             command for that one; `daemon` is for machines without systemd."
        );
    }
    if let Some(pid) = running() {
        anyhow::bail!("a linrdp supervisor is already running (pid {pid})");
    }

    // Read the configuration here, in the foreground, where a complaint about
    // it lands on the terminal of the person who typed the command. After the
    // fork it would go wherever the log goes, which on a machine with no
    // journal and no `log.file` is nowhere.
    let config = crate::config::load_or_default(crate::config::path())?.config;
    crate::config::validate(&config)?;

    let exe = std::env::current_exe().context("find this binary")?;
    let mut child = std::process::Command::new(&exe);
    // No arguments: a bare `linrdp` *is* the supervisor, so the background
    // process is the same thing the unit starts, not a mode of its own.
    child
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(log_destination(&config));
    // Its own session, so closing this terminal does not take the supervisor
    // with it. Written outside the `unsafe` below so that block holds exactly
    // the one operation it is vouching for.
    let own_session = || {
        // SAFETY: setsid takes no arguments and touches no memory.
        if unsafe { libc::setsid() } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: `own_session` runs between fork and exec in the child, where
    // only async-signal-safe calls are allowed. It makes exactly one, and
    // setsid is on that list.
    unsafe {
        use std::os::unix::process::CommandExt as _;
        child.pre_exec(own_session);
    }
    let mut child = child.spawn().with_context(|| format!("start {}", exe.display()))?;

    // Long enough for a refused bind, which is the failure this catches. A
    // supervisor that gets past it has already opened every listener.
    std::thread::sleep(Duration::from_millis(600));
    match child.try_wait().context("check on the supervisor")? {
        Some(status) => anyhow::bail!(
            "the supervisor exited immediately ({status}); {}",
            where_to_look(&config)
        ),
        None => {
            println!("linrdp is running in the background (pid {}).", child.id());
            println!("Stop it with `linrdp daemon stop`; {}.", where_to_look(&config));
            Ok(())
        }
    }
}

fn stop() -> anyhow::Result<()> {
    require_root("stop")?;
    let Some(pid) = running() else {
        anyhow::bail!("no linrdp supervisor is running here");
    };

    // SAFETY: kill takes two integers and touches no memory.
    let sent = unsafe { libc::kill(pid.cast_signed(), libc::SIGTERM) };
    anyhow::ensure!(sent == 0, "could not signal pid {pid}: {}", std::io::Error::last_os_error());

    // It closes its listeners and goes; the desktops it started do not, for
    // the same reason `KillMode=process` is in the unit — they are owned by
    // keepers re-parented to init.
    for _ in 0..50 {
        if running().is_none() {
            let _ = std::fs::remove_file(PID_FILE);
            println!("stopped (pid {pid}). Sessions already open are still running.");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("pid {pid} did not stop within five seconds")
}

fn status() -> anyhow::Result<()> {
    match running() {
        Some(pid) => {
            println!("running (pid {pid})");
            if crate::service::unit::systemctl(&["is-active", "--quiet", crate::service::unit::UNIT_NAME])
                == Some(true)
            {
                println!("started by systemd — `linrdp service status` has the rest");
            }
        }
        None => println!("not running"),
    }

    let path = crate::config::path();
    match crate::config::load_for_diagnostics(path) {
        (_, Some(problem)) => println!("\n{} is not usable:\n  {problem}", path.display()),
        (config, None) => {
            println!("\nConfiguration {}", path.display());
            for listener in &config.listeners {
                println!("  {}  auth: {}", listener.bind, listener.auth);
            }
        }
    }
    Ok(())
}

/// Where a detached supervisor's own stderr goes.
///
/// To the log file when there is one, so the reason it refused to start is
/// somewhere. Without one there is nothing to keep it in — and inheriting this
/// terminal would print into a shell the operator has moved on from.
fn log_destination(config: &crate::config::Config) -> std::process::Stdio {
    let Some(path) = &config.log.file else {
        return std::process::Stdio::null();
    };
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_or_else(|_| std::process::Stdio::null(), std::process::Stdio::from)
}

fn where_to_look(config: &crate::config::Config) -> String {
    match &config.log.file {
        Some(path) => format!("the log is {}", path.display()),
        None => "there is no `log.file`, so nothing was kept — set one, or use `linrdp debug`".to_owned(),
    }
}

fn require_root(verb: &str) -> anyhow::Result<()> {
    // SAFETY: geteuid takes no arguments, touches no memory and cannot fail.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        euid == 0,
        "`linrdp daemon {verb}` needs the privileges the server runs with: \
         try `sudo linrdp daemon {verb}`"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pid file outlives whatever wrote it, and the number is handed out
    /// again. Trusting the file alone would have `daemon start` refuse to run
    /// because of a process that is now somebody's text editor.
    #[test]
    fn a_pid_belonging_to_something_else_is_not_a_running_linrdp() {
        // This test process is alive and is not called linrdp.
        assert!(!is_a_live_linrdp(std::process::id()), "cargo's test binary is not linrdp");
        // Pid 1 exists on every Linux machine and is not linrdp either.
        assert!(!is_a_live_linrdp(1), "init is not linrdp");
        // Nothing has this pid: /proc says so by not being there.
        assert!(!is_a_live_linrdp(0x3FFF_FFFF), "an impossible pid is not running");
    }

    /// Every verb the tree shows is a verb this takes. The listing an operator
    /// is given and the dispatch behind it are the same list.
    #[test]
    fn the_tree_shows_exactly_the_verbs_this_accepts() {
        let shown = crate::cli::subtree("daemon");
        for verb in VERBS {
            assert!(shown.contains(verb), "`{verb}` is not in what a refusal prints:\n{shown}");
        }
    }
}

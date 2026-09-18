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

/// A supervisor found running on this machine, and how it looks from outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Running {
    pub(crate) pid: u32,
    pub(crate) health: Health,
}

/// What could be established about it without talking to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Health {
    /// It holds the listening sockets for these ports, in the order the
    /// configuration names them. This is the process that will refuse your
    /// bind, and this is exactly what it is holding.
    Serving(Vec<u16>),
    /// Process state `T` or `t`: stopped by a signal or under a debugger. It
    /// keeps every socket it had and will never accept another connection —
    /// alive by every cheaper test, and serving nobody.
    Stopped,
    /// Alive, and a supervisor, but none of the configured ports is on its
    /// descriptors. Either it is still starting, or it is on its way out.
    NotListening,
    /// Its descriptors could not be read. /proc/<pid>/fd is readable by the
    /// process's own user and by root, so this is what a non-root `status`
    /// sees — "I could not tell", which is not the same as "nothing".
    Unknown,
}

impl Health {
    /// The sentence that follows "linrdp is already running (pid N)".
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Serving(ports) => {
                let list: Vec<String> = ports.iter().map(u16::to_string).collect();
                let plural = if ports.len() == 1 { "port" } else { "ports" };
                format!("serving {plural} {}", list.join(", "))
            }
            Self::Stopped => {
                "STOPPED by a signal — it still holds the ports and will never accept a \
                 connection. `kill -CONT <pid>` resumes it; `kill <pid>` ends it"
                    .to_owned()
            }
            Self::NotListening => "not listening on any configured port — starting, or stopping".to_owned(),
            Self::Unknown => "cannot see its sockets from here; try as root".to_owned(),
        }
    }
}

/// The supervisor running here, if there is one.
///
/// Four questions, because each of the cheap ones alone lies:
///
/// 1. Is the pid alive? A pid file outlives the process that wrote it.
/// 2. Is it *this* program, invoked as a supervisor? Pids are handed out
///    again, and a reused one is often one of linrdp's own workers or keepers
///    — which share the name and would pass a `comm` check.
/// 3. Is it a zombie? An exited process with an unreaped parent is in /proc,
///    answers a signal-0, and serves nothing.
/// 4. Does it hold one of the ports? That is the question the caller actually
///    has, and the only one whose answer is not a proxy for it.
///
/// None of this is the interlock against two servers — the listening socket
/// is, and it needs no cooperation from anybody. This is here so the refusal
/// can say which process, and in what state, rather than "address in use".
pub(crate) fn look(ports: &[u16]) -> Option<Running> {
    let pid: u32 = std::fs::read_to_string(PID_FILE).ok()?.trim().parse().ok()?;
    look_at(pid, ports)
}

fn look_at(pid: u32, ports: &[u16]) -> Option<Running> {
    if !is_a_supervisor(pid) {
        return None;
    }
    let health = match state_of(pid) {
        // Exited, waiting to be reaped. It holds nothing.
        Some('Z') => return None,
        Some('T' | 't') => Health::Stopped,
        _ => match socket_inodes(pid) {
            None => Health::Unknown,
            Some(held) => {
                let listening = listening_on(ports);
                // In the configuration's order, not the kernel's: the file
                // reads 3389 then 3390, and so should the answer.
                let mine: Vec<u16> = ports
                    .iter()
                    .filter(|port| {
                        listening
                            .iter()
                            .any(|(listening_port, inode)| listening_port == *port && held.contains(inode))
                    })
                    .copied()
                    .collect();
                if mine.is_empty() {
                    Health::NotListening
                } else {
                    Health::Serving(mine)
                }
            }
        },
    };
    Some(Running { pid, health })
}

/// Whether `pid` is this program, started as a supervisor.
///
/// The name alone is not enough: every worker, keeper and greeter linrdp forks
/// is also called `linrdp`, so a reused pid lands on one of them more often
/// than on anything else. What separates them is the argv — a supervisor is
/// `linrdp` or `linrdp debug`, and never carries any of the flags below.
fn is_a_supervisor(pid: u32) -> bool {
    let Some(argv) = cmdline(pid) else {
        return false;
    };
    let Some(program) = argv.first() else {
        return false;
    };
    if !std::path::Path::new(program)
        .file_name()
        .is_some_and(|name| name == "linrdp")
    {
        return false;
    }
    !argv
        .iter()
        .any(|arg| ["--listener", "--serve-fd", "--keeper", "--capture-credential"].contains(&arg.as_str()))
}

fn cmdline(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        raw.split('\0')
            .filter(|arg| !arg.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// The process state letter from /proc/<pid>/stat.
fn state_of(pid: u32) -> Option<char> {
    state_in(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Field three of a stat line, parsed the only way that is safe.
///
/// Field two is the executable name in parentheses, and it is the raw name: it
/// can contain spaces and it can contain parentheses. Splitting on whitespace
/// and taking the third field is the classic way to read the wrong character.
/// The *last* `)` is the end of that field, whatever is inside it.
fn state_in(stat: &str) -> Option<char> {
    stat[stat.rfind(')')? + 1..].split_whitespace().next()?.chars().next()
}

/// The inode of every socket `pid` has open, or `None` if that cannot be read.
fn socket_inodes(pid: u32) -> Option<std::collections::HashSet<u64>> {
    let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    Some(
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .filter_map(|target| {
                target
                    .to_str()?
                    .strip_prefix("socket:[")?
                    .strip_suffix(']')?
                    .parse::<u64>()
                    .ok()
            })
            .collect(),
    )
}

/// `(port, inode)` for every socket on this machine listening on one of
/// `ports`, from /proc/net/tcp and its v6 twin.
fn listening_on(ports: &[u16]) -> Vec<(u16, u64)> {
    let mut found = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(body) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in body.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // local_address, st, ..., inode — the layout is fixed, but a
            // kernel that prints fewer columns must not panic the server.
            let (Some(local), Some(state), Some(inode)) = (fields.get(1), fields.get(3), fields.get(9)) else {
                continue;
            };
            if *state != "0A" {
                continue; // 0A is TCP_LISTEN; everything else is a connection
            }
            let Some(port) = local.rsplit(':').next().and_then(|hex| u16::from_str_radix(hex, 16).ok()) else {
                continue;
            };
            if ports.contains(&port) {
                if let Ok(inode) = inode.parse::<u64>() {
                    found.push((port, inode));
                }
            }
        }
    }
    found
}

/// The ports a configuration asks for, for [`look`].
pub(crate) fn ports_of(config: &crate::config::Config) -> Vec<u16> {
    config
        .listeners
        .iter()
        .filter_map(|listener| listener.bind.rsplit(':').next()?.parse().ok())
        .collect()
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

    // Read the configuration here, in the foreground, where a complaint about
    // it lands on the terminal of the person who typed the command. After the
    // fork it would go wherever the log goes, which on a machine with no
    // journal and no `log.file` is nowhere. It also names the ports, which is
    // what makes the check below more than a guess.
    let config = crate::config::load_or_default(crate::config::path())?.config;
    crate::config::validate(&config)?;

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
    if let Some(found) = look(&ports_of(&config)) {
        anyhow::bail!("{}", already_running(&found));
    }

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
    let ports = crate::config::load_for_diagnostics(crate::config::path()).0;
    let Some(found) = look(&ports_of(&ports)) else {
        anyhow::bail!("no linrdp supervisor is running here");
    };
    let pid = found.pid;

    // SAFETY: kill takes two integers and touches no memory.
    let sent = unsafe { libc::kill(pid.cast_signed(), libc::SIGTERM) };
    anyhow::ensure!(sent == 0, "could not signal pid {pid}: {}", std::io::Error::last_os_error());

    // It closes its listeners and goes; the desktops it started do not, for
    // the same reason `KillMode=process` is in the unit — they are owned by
    // keepers re-parented to init.
    for _ in 0..50 {
        if look(&ports_of(&ports)).is_none() {
            let _ = std::fs::remove_file(PID_FILE);
            println!("stopped (pid {pid}). Sessions already open are still running.");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("pid {pid} did not stop within five seconds")
}

fn status() -> anyhow::Result<()> {
    let ports = ports_of(&crate::config::load_for_diagnostics(crate::config::path()).0);
    match look(&ports) {
        Some(found) => {
            println!("running (pid {}, {})", found.pid, found.health.describe());
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

/// What to say to somebody who asked for a second server.
///
/// One sentence, first, naming the process — because the alternative is what
/// this replaces: two "address already in use" lines and the useful fact
/// underneath them, where it reads like a footnote to a failure rather than
/// the reason nothing was attempted.
pub(crate) fn already_running(found: &Running) -> String {
    format!(
        "linrdp is already running (pid {}, {}) — nothing was started.\n\
         Stop it with `linrdp daemon stop`, or `linrdp service stop` if systemd started it.",
        found.pid,
        found.health.describe()
    )
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
    /// again — often to one of linrdp's own workers or keepers, which carry
    /// the same name. Trusting the pid, or even the name, would have a start
    /// refused because of a process that is now somebody's text editor.
    #[test]
    fn a_pid_belonging_to_something_else_is_not_a_supervisor() {
        // This test process is alive and is not linrdp.
        assert!(!is_a_supervisor(std::process::id()), "cargo's test binary is not linrdp");
        // Pid 1 exists on every Linux machine and is not linrdp either.
        assert!(!is_a_supervisor(1), "init is not linrdp");
        // Nothing has this pid: /proc says so by not being there.
        assert!(!is_a_supervisor(0x3FFF_FFFF), "an impossible pid is not running");
    }

    /// The question the caller actually has is "is that process holding my
    /// port", and this is the only check that answers it rather than standing
    /// in for it. Asked with a socket this very process is listening on, so
    /// the answer is known before it is asked.
    #[test]
    fn a_process_is_found_by_the_port_it_is_listening_on() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port of our own");
        let port = listener.local_addr().expect("bound").port();
        let me = std::process::id();

        let held = socket_inodes(me).expect("our own descriptors are readable");
        let listening = listening_on(&[port]);
        assert!(!listening.is_empty(), "the kernel does not list our listening socket");
        assert!(
            listening.iter().any(|(_, inode)| held.contains(inode)),
            "the socket we are listening on is not among ours"
        );

        // Ours specifically, not "nothing at all": the suite runs in parallel
        // and an ephemeral port freed here can be handed to another test
        // before this line runs. The inode cannot be handed to anybody.
        drop(listener);
        assert!(
            listening_on(&[port]).iter().all(|(_, inode)| !held.contains(inode)),
            "a closed socket is still reported as listening"
        );
    }

    /// Field two of a stat line is the executable name in parentheses, and it
    /// is the raw name: it may contain spaces and parentheses. Taking the
    /// third whitespace-separated field is the classic way to read the wrong
    /// character and call a running process stopped.
    #[test]
    fn the_process_state_survives_an_executable_with_a_silly_name() {
        assert_eq!(state_in("42 (linrdp) S 1 42 42 0 -1"), Some('S'));
        assert_eq!(state_in("42 (a b) c) T 1 42"), Some('T'), "the LAST paren ends the name");
        assert_eq!(state_in("42 (evil S name) Z 1"), Some('Z'), "not the one inside the name");
        assert_eq!(state_in("nonsense"), None);
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

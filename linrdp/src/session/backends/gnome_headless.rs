//! A GNOME session of its own for an RDP login — the GNOME counterpart of the
//! per-user X session, and the case `auto` prefers wherever GNOME Shell can be
//! started.
//!
//! GNOME 49+ has no X11 session, so on such a machine the per-user desktop is
//! a headless GNOME Shell: `gnome-shell --headless` with no monitor at all,
//! given a virtual one at the client's size whenever a client connects
//! (`RecordVirtual`, see `wayland::mutter`). It is the arrangement
//! gnome-remote-desktop uses for its own remote logins.
//!
//! One account may already be logged in at the console. Two GNOME Shells
//! cannot share a session bus — both would claim `org.gnome.Shell` and
//! Mutter's names — so every headless session gets a private `dbus-daemon`,
//! and apps it starts are told which Wayland display is theirs through that
//! bus's activation environment. Measured on GNOME 50: both sessions run side
//! by side, and an app activated in the remote one opens there, not on the
//! console.
//!
//! How the processes are started is a case of its own ([`Launcher`]):
//! directly, in the keeper's PAM session, when GNOME is installed where
//! linrdp is; or on the host through `host-spawn`, when linrdp runs in a
//! distrobox/toolbox/apx container and GNOME is the host's.

// Without the `wayland` feature there is no GNOME case to start these
// sessions with; only the launcher is still probed, for `linrdp doctor`.
#![cfg_attr(
    not(feature = "wayland"),
    expect(dead_code, reason = "sessions are laid out and started only by the GNOME case")
)]

use std::path::{Path, PathBuf};

use crate::session::keeper::DesktopCommand;
use crate::session::privilege::UserIds;

pub(crate) const ID: &str = "gnome-headless";

/// How a headless GNOME session is started on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Launcher {
    /// `gnome-shell` is installed where linrdp runs; the keeper starts it as
    /// the user, inside the PAM session it opened — a logind session of its
    /// own, which polkit and the session's lock need.
    Native,
    /// linrdp runs in a container and GNOME is the host's: the keeper starts
    /// it through `host-spawn` (Flatpak's HostCommand on the host's session
    /// bus). No logind session of its own can be made from a rootless
    /// container, so polkit prompts do not reach this session.
    Host,
}

impl Launcher {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Host => "host",
        }
    }

    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw {
            "native" => Some(Self::Native),
            "host" => Some(Self::Host),
            _ => None,
        }
    }
}

const HOST_ROOT: &str = "/run/host";
const HOST_SPAWN: &str = "host-spawn";

/// Which launcher this machine offers, if any. `in_container` and `exists`
/// are the probes, passed in so the choice is testable.
pub(crate) fn choose_launcher(in_container: bool, exists: &dyn Fn(&str) -> bool) -> Option<Launcher> {
    if exists("gnome-shell") {
        return Some(Launcher::Native);
    }
    if in_container && exists(&format!("{HOST_ROOT}/usr/bin/gnome-shell")) && exists(HOST_SPAWN) {
        return Some(Launcher::Host);
    }
    None
}

/// [`choose_launcher`] for this machine.
pub(crate) fn launcher() -> Option<Launcher> {
    let in_container = Path::new("/run/.containerenv").exists() || Path::new("/.dockerenv").exists();
    choose_launcher(in_container, &crate::session::detect::program_exists)
}

/// Where one headless session's sockets are, as the session sees them and as
/// linrdp does. They differ only in a container, where the host's
/// `/run/user/<uid>` is `/run/host/run/user/<uid>` from here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    /// `XDG_RUNTIME_DIR` inside the session.
    pub(crate) session_runtime: String,
    /// The same directory, reached from linrdp.
    pub(crate) local_runtime: String,
    /// The private bus, as the session addresses it.
    pub(crate) session_bus: String,
    /// The private bus, as linrdp reaches it.
    pub(crate) local_bus: String,
    /// The session's Wayland display name.
    pub(crate) wayland: String,
}

pub(crate) fn layout(launcher: Launcher, pam_runtime: &str, uid: u32, slot: u16) -> Layout {
    let (session_runtime, local_runtime) = match launcher {
        Launcher::Native => (pam_runtime.to_owned(), pam_runtime.to_owned()),
        Launcher::Host => (format!("/run/user/{uid}"), format!("{HOST_ROOT}/run/user/{uid}")),
    };
    let bus = format!("linrdp-session-{slot}.bus");
    Layout {
        session_bus: format!("{session_runtime}/{bus}"),
        local_bus: format!("{local_runtime}/{bus}"),
        session_runtime,
        local_runtime,
        wayland: format!("linrdp-{slot}"),
    }
}

pub(crate) fn dbus_command(layout: &Layout) -> DesktopCommand {
    DesktopCommand {
        program: "dbus-daemon".to_owned(),
        args: vec![
            "--session".to_owned(),
            "--nofork".to_owned(),
            format!("--address=unix:path={}", layout.session_bus),
        ],
    }
}

/// No `--virtual-monitor`: the monitor is created per connection at the
/// client's size, and goes away with it.
pub(crate) fn shell_command(layout: &Layout) -> DesktopCommand {
    DesktopCommand {
        program: "gnome-shell".to_owned(),
        args: vec!["--headless".to_owned(), format!("--wayland-display={}", layout.wayland)],
    }
}

/// The environment the session's processes start with.
pub(crate) fn session_env(layout: &Layout, user: &UserIds, logind_id: Option<&str>) -> Vec<(String, String)> {
    let mut env = vec![
        ("PATH".to_owned(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned()),
        ("HOME".to_owned(), user.home.clone()),
        ("USER".to_owned(), user.name.clone()),
        ("LOGNAME".to_owned(), user.name.clone()),
        ("XDG_RUNTIME_DIR".to_owned(), layout.session_runtime.clone()),
        ("DBUS_SESSION_BUS_ADDRESS".to_owned(), format!("unix:path={}", layout.session_bus)),
        ("XDG_SESSION_TYPE".to_owned(), "wayland".to_owned()),
        ("XDG_SESSION_CLASS".to_owned(), "user".to_owned()),
        ("XDG_CURRENT_DESKTOP".to_owned(), "GNOME".to_owned()),
        ("XDG_SESSION_DESKTOP".to_owned(), "gnome".to_owned()),
    ];
    if let Some(id) = logind_id {
        env.push(("XDG_SESSION_ID".to_owned(), id.to_owned()));
    }
    env
}

/// What the private bus hands to every service it activates — the apps
/// among them must open on this session's display, not the console's.
pub(crate) fn activation_env(layout: &Layout) -> Vec<(String, String)> {
    vec![
        ("WAYLAND_DISPLAY".to_owned(), layout.wayland.clone()),
        ("XDG_SESSION_TYPE".to_owned(), "wayland".to_owned()),
        ("XDG_CURRENT_DESKTOP".to_owned(), "GNOME".to_owned()),
        ("XDG_SESSION_DESKTOP".to_owned(), "gnome".to_owned()),
        // An inherited DISPLAY would be the console's X server.
        ("DISPLAY".to_owned(), String::new()),
    ]
}

/// The command as the keeper runs it, and the environment it runs with.
///
/// Natively that is the command itself. Through the host it is `host-spawn
/// -no-pty env K=V… program args…`: host-spawn passes on only the variables it
/// is told to, so `env` carries the session's own, while host-spawn itself is
/// pointed at the host's session bus, where HostCommand lives.
pub(crate) fn launch(
    launcher: Launcher,
    command: &DesktopCommand,
    env: &[(String, String)],
    uid: u32,
) -> (DesktopCommand, Vec<(String, String)>) {
    match launcher {
        Launcher::Native => (
            DesktopCommand {
                program: command.program.clone(),
                args: command.args.clone(),
            },
            env.to_vec(),
        ),
        Launcher::Host => {
            let mut args = vec!["-no-pty".to_owned(), "env".to_owned()];
            args.extend(env.iter().map(|(k, v)| format!("{k}={v}")));
            args.push(command.program.clone());
            args.extend(command.args.iter().cloned());
            let host_runtime = format!("{HOST_ROOT}/run/user/{uid}");
            let spawn_env = vec![
                ("PATH".to_owned(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned()),
                ("DBUS_SESSION_BUS_ADDRESS".to_owned(), format!("unix:path={host_runtime}/bus")),
                ("XDG_RUNTIME_DIR".to_owned(), host_runtime),
            ];
            (
                DesktopCommand {
                    program: HOST_SPAWN.to_owned(),
                    args,
                },
                spawn_env,
            )
        }
    }
}

/// Wait until `path` exists, or `timeout` passes.
pub(crate) fn wait_for_socket(path: &Path, timeout: core::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(core::time::Duration::from_millis(50));
    }
    path.exists()
}

/// The local bus path as a `PathBuf`, for the Mutter client.
pub(crate) fn local_bus(layout: &Layout) -> PathBuf {
    PathBuf::from(&layout.local_bus)
}

/// The case itself; the rest of this module is how its sessions are laid out
/// and started.
#[cfg(feature = "wayland")]
pub(crate) struct GnomeHeadless;

#[cfg(feature = "wayland")]
impl super::DesktopBackend for GnomeHeadless {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "per-user headless GNOME session"
    }

    fn serves(&self) -> super::Serves {
        super::Serves::OwnSession
    }

    fn choice(&self) -> Option<super::BackendChoice> {
        Some(super::BackendChoice::Gnome)
    }

    fn probe(&self, login: &super::Login<'_>) -> Result<super::Binder, String> {
        let launcher = launcher().ok_or_else(|| {
            "no GNOME Shell can be started here (neither installed alongside linrdp, nor on the host of \
             the container it runs in)"
                .to_owned()
        })?;
        // The same account may also be logged in at the console; binding
        // locks that session, so it is looked for now.
        let console = super::gnome_console::find(login.user);
        Ok(Box::new(move |login: &super::Login<'_>| bind(login, launcher, console.as_ref())))
    }

    fn serve_session(&self, keeper: crate::session::keeper_main::Keeper<'_>) -> anyhow::Result<()> {
        let launcher = Launcher::parse(&keeper.args.start).ok_or_else(|| {
            anyhow::anyhow!("a headless GNOME session is started natively or on the host, not `{}`", keeper.args.start)
        })?;
        serve(keeper, launcher)
    }
}

/// Attach this worker to `login`'s own headless GNOME session, starting one
/// if there is none — the GNOME counterpart of the X case.
///
/// If the same account is logged in at the console, that session is locked:
/// one person, one place in use, and the desk shows that it is in use
/// elsewhere — the way Windows locks a console whose user signs in remotely.
#[cfg(feature = "wayland")]
fn bind(
    login: &super::Login<'_>,
    launcher: Launcher,
    console: Option<&crate::wayland::mutter::GnomeSession>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;

    use crate::wayland::mutter;

    let user = login.user;
    // `session.fixed_size` pins the virtual monitor too.
    let size = login.fixed_size.unwrap_or(login.client_size);
    let rec = crate::session::attach_or_create(
        login.state_dir,
        user,
        login.password,
        login.range.clone(),
        size,
        &crate::session::KeeperSpec {
            backend: ID,
            // A shell takes longer to come up than an X server: it is a whole
            // desktop.
            ready_within: core::time::Duration::from_secs(75),
            start: &|| launcher.as_str().to_owned(),
        },
    )?;
    anyhow::ensure!(
        rec.user == user,
        "the session in slot {} belongs to {}, not to {user} — refusing to bind",
        rec.display,
        rec.user
    );
    let bus = rec.bus.clone().context("the session record names no bus")?;
    let ids = crate::session::privilege::lookup_user(user)?;
    let target = mutter::GnomeSession {
        uid: ids.uid,
        gid: ids.gid,
        runtime_dir: PathBuf::from(&rec.runtime_dir),
        bus: PathBuf::from(bus),
    };
    mutter::attach(user, &target, mutter::AttachOptions::remote(size), size)?;
    crate::session::gate::bind_compositor("gnome", user, &rec.runtime_dir, size)?;
    if rec.locked {
        let _ = crate::session::registry::set_locked(login.state_dir, rec.display, false);
    }
    *login.bound.lock().unwrap_or_else(|p| p.into_inner()) = Some(crate::session::router::BoundSession {
        display: rec.display,
        logind_id: rec.logind_id.clone(),
    });
    if let Some(console) = console {
        mutter::lock_session(console);
    }
    tracing::info!(user, slot = rec.display, "routed to the user's GNOME session");
    Ok(())
}

/// Run a headless GNOME session for as long as it lives.
///
/// The same shape as the X case: start it, publish the record only once it
/// answers, then wait for either half to die and tear the other down. The
/// halves here are the private bus and the shell on it.
#[cfg(feature = "wayland")]
fn serve(keeper: crate::session::keeper_main::Keeper<'_>, launcher: Launcher) -> anyhow::Result<()> {
    use anyhow::Context as _;

    use crate::session::keeper_main::end_session;
    use crate::session::{keeper, registry};

    let crate::session::keeper_main::Keeper {
        args,
        ids,
        runtime_dir,
        logind_id,
        mut pam,
        lease,
        account,
    } = keeper;

    let layout = layout(launcher, &runtime_dir, ids.uid, args.display);
    // A socket left by a session that died hard would make the new bus fail
    // to bind, and — worse — make the wait below succeed at once.
    let _ = std::fs::remove_file(&layout.local_bus);
    let env = session_env(&layout, &ids, logind_id.as_deref());

    let fail = |pids: &[i32], pam: &mut crate::pam::LibPamSession, error: anyhow::Error| {
        for &pid in pids {
            end_session(pid);
        }
        let _ = std::fs::remove_file(&layout.local_bus);
        let _ = pam.close();
        Err(error)
    };

    let bus_log = args.state_dir.join(format!("display-{}.bus.log", args.display));
    let (bus_cmd, bus_env) = launch(launcher, &dbus_command(&layout), &env, ids.uid);
    let bus_pid = keeper::spawn_child(&bus_cmd, &bus_env, &ids, &bus_log)
        .with_context(|| format!("start the session bus for {}", args.user))?;
    if !wait_for_socket(&local_bus(&layout), core::time::Duration::from_secs(10)) {
        return fail(
            &[bus_pid],
            &mut pam,
            anyhow::anyhow!("the session bus never appeared at {} — see {}", layout.local_bus, bus_log.display()),
        );
    }

    // The account's keyring, relayed onto the session's bus before anything
    // there can ask for it. Losing it costs saved passwords, not the session,
    // so a failure is logged and the session goes on.
    let bridge_pid = match std::env::current_exe() {
        Ok(exe) => {
            let bridge = DesktopCommand {
                program: exe.to_string_lossy().into_owned(),
                args: vec![
                    "--secrets-bridge".to_owned(),
                    "--from".to_owned(),
                    layout.local_bus.clone(),
                    "--to".to_owned(),
                    format!("{}/bus", layout.local_runtime),
                ],
            };
            let log = args.state_dir.join(format!("display-{}.secrets.log", args.display));
            keeper::spawn_child(&bridge, &[], &ids, &log)
                .inspect_err(|error| tracing::warn!(%error, "no Secret Service in the session"))
                .ok()
        }
        Err(error) => {
            tracing::warn!(%error, "no Secret Service in the session");
            None
        }
    };

    let shell_log = args.state_dir.join(format!("display-{}.desktop.log", args.display));
    let (shell_cmd, shell_env) = launch(launcher, &shell_command(&layout), &env, ids.uid);
    let shell_pid = match keeper::spawn_child(&shell_cmd, &shell_env, &ids, &shell_log) {
        Ok(pid) => pid,
        Err(error) => return fail(&[bus_pid], &mut pam, error.context("start gnome-shell")),
    };

    // Published only once Mutter answers: a record for a shell that never
    // came up is the black screen the X case learned to refuse.
    if let Err(error) = crate::wayland::mutter::prepare_headless(
        ids.uid,
        ids.gid,
        &local_bus(&layout),
        &activation_env(&layout),
        core::time::Duration::from_secs(60),
    ) {
        return fail(
            &[shell_pid, bus_pid],
            &mut pam,
            error.context(format!("gnome-shell did not come up — see {}", shell_log.display())),
        );
    }

    let rec = registry::SessionRecord {
        user: args.user.clone(),
        display: args.display,
        runtime_dir: layout.local_runtime.clone(),
        xauthority: String::new(),
        locked: false,
        logind_id,
        bus: Some(layout.local_bus.clone()),
        backend: ID.to_owned(),
    };
    lease.record_owner(&args.user)?;
    registry::write_record(&args.state_dir, &rec)?;
    drop(account);
    tracing::info!(
        user = %args.user,
        slot = args.display,
        launcher = launcher.as_str(),
        bus = %layout.local_bus,
        wayland = %layout.wayland,
        "headless GNOME session ready"
    );

    let ended_by = loop {
        let mut status = 0;
        // SAFETY: waiting on our own children.
        let dead = unsafe { libc::waitpid(-1, &mut status, 0) };
        if dead == shell_pid {
            break "gnome-shell exited (logout)";
        }
        if dead == bus_pid {
            break "the session bus exited";
        }
        if dead == -1 {
            break "no children left";
        }
    };
    tracing::info!(user = %args.user, slot = args.display, ended_by, "GNOME session over — tearing it down");
    end_session(shell_pid);
    end_session(bus_pid);
    if let Some(pid) = bridge_pid {
        end_session(pid);
    }
    let _ = std::fs::remove_file(&layout.local_bus);
    let _ = registry::forget_record(&args.state_dir, args.display);
    let _ = pam.close();
    drop(lease);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> UserIds {
        UserIds {
            uid: 1000,
            gid: 1000,
            name: "artur".to_owned(),
            home: "/home/artur".to_owned(),
        }
    }

    #[test]
    fn gnome_where_linrdp_runs_is_started_directly() {
        let everything = |_: &str| true;
        assert_eq!(choose_launcher(false, &everything), Some(Launcher::Native));
        assert_eq!(choose_launcher(true, &everything), Some(Launcher::Native));
    }

    /// Vanilla OS: linrdp in an apx container, GNOME only on the host.
    #[test]
    fn gnome_on_the_host_of_a_container_is_started_through_it() {
        let host_only = |p: &str| p == "/run/host/usr/bin/gnome-shell" || p == "host-spawn";
        assert_eq!(choose_launcher(true, &host_only), Some(Launcher::Host));
        assert_eq!(choose_launcher(false, &host_only), None, "no /run/host outside a container");
        let no_spawn = |p: &str| p == "/run/host/usr/bin/gnome-shell";
        assert_eq!(choose_launcher(true, &no_spawn), None, "without host-spawn there is no way over");
    }

    #[test]
    fn a_container_session_is_laid_out_on_the_host() {
        let l = layout(Launcher::Host, "/run/user/1000", 1000, 12);
        assert_eq!(l.session_bus, "/run/user/1000/linrdp-session-12.bus");
        assert_eq!(l.local_bus, "/run/host/run/user/1000/linrdp-session-12.bus");
        assert_eq!(l.wayland, "linrdp-12");
    }

    #[test]
    fn a_native_session_is_laid_out_in_its_runtime_dir() {
        let l = layout(Launcher::Native, "/run/user/1001", 1001, 10);
        assert_eq!(l.session_bus, l.local_bus);
        assert_eq!(l.local_bus, "/run/user/1001/linrdp-session-10.bus");
    }

    /// The shell must be on the private bus: on the user's own bus it would
    /// fight the console's shell for org.gnome.Shell.
    #[test]
    fn the_shell_runs_on_the_private_bus_with_no_fixed_monitor() {
        let l = layout(Launcher::Native, "/run/user/1000", 1000, 10);
        let env = session_env(&l, &ids(), Some("c7"));
        assert!(env.contains(&(
            "DBUS_SESSION_BUS_ADDRESS".to_owned(),
            "unix:path=/run/user/1000/linrdp-session-10.bus".to_owned()
        )));
        assert!(env.contains(&("XDG_SESSION_ID".to_owned(), "c7".to_owned())));
        let shell = shell_command(&l);
        assert!(shell.args.contains(&"--headless".to_owned()));
        assert!(!shell.args.iter().any(|a| a.starts_with("--virtual-monitor")));
    }

    #[test]
    fn through_the_host_the_session_env_travels_on_the_command_line() {
        let l = layout(Launcher::Host, "/run/user/1000", 1000, 10);
        let env = session_env(&l, &ids(), None);
        let (cmd, spawn_env) = launch(Launcher::Host, &shell_command(&l), &env, 1000);
        assert_eq!(cmd.program, "host-spawn");
        assert_eq!(&cmd.args[..2], ["-no-pty", "env"]);
        assert!(cmd.args.contains(&"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/linrdp-session-10.bus".to_owned()));
        assert_eq!(cmd.args[cmd.args.len() - 2], "--headless");
        // host-spawn itself talks to the host's bus, reached through /run/host.
        assert!(spawn_env.contains(&(
            "DBUS_SESSION_BUS_ADDRESS".to_owned(),
            "unix:path=/run/host/run/user/1000/bus".to_owned()
        )));
    }

    #[test]
    fn apps_are_pointed_at_the_sessions_display() {
        let l = layout(Launcher::Native, "/run/user/1000", 1000, 10);
        let env = activation_env(&l);
        assert!(env.contains(&("WAYLAND_DISPLAY".to_owned(), "linrdp-10".to_owned())));
        assert!(env.contains(&("DISPLAY".to_owned(), String::new())));
    }
}

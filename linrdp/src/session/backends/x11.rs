//! The per-user X session: an X server (Xvfb, or Xorg) linrdp starts for the
//! account, with the desktop from `/usr/share/xsessions` on it — what every
//! X11 distribution serves (Debian with XFCE, Arch with anything X11).

use anyhow::Context as _;

use super::{BackendChoice, Binder, DesktopBackend, Login, Serves};
use crate::session::keeper_main::{Keeper, end_session};
use crate::session::router::BoundSession;
use crate::session::{detect, gate, keeper, registry, xauth};

pub(crate) const ID: &str = "x11";

pub(crate) struct X11Session;

impl DesktopBackend for X11Session {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "per-user X session (Xvfb/Xorg)"
    }

    fn serves(&self) -> Serves {
        Serves::OwnSession
    }

    fn choice(&self) -> Option<BackendChoice> {
        Some(BackendChoice::X11)
    }

    fn probe(&self, _login: &Login<'_>) -> Result<Binder, String> {
        if !x_server_installed() {
            return Err("no X server (Xvfb or Xorg) is installed".to_owned());
        }
        Ok(Box::new(bind))
    }

    fn serve_session(&self, keeper: Keeper<'_>) -> anyhow::Result<()> {
        serve(keeper)
    }
}

/// Whether an X server linrdp can start sessions on is installed.
pub(crate) fn x_server_installed() -> bool {
    ["Xvfb", "Xorg"].iter().any(|b| detect::program_exists(b))
}

/// Attach this worker to `login`'s own X session, starting one if there is
/// none.
fn bind(login: &Login<'_>) -> anyhow::Result<()> {
    let user = login.user;
    // A session's X server is created at the LARGEST desktop we serve, not at
    // this client's size: `-screen 0 WxH` is also Xvfb's RandR maximum and
    // cannot grow afterwards, so a session born at one client's size could
    // never fit the next one. The capture path scales the screen down to
    // `client_size` when it connects. `session.fixed_size` still wins when the
    // operator pinned a geometry.
    let size = login.fixed_size.unwrap_or(crate::session::SESSION_SCREEN_MAX);
    let rec = crate::session::attach_or_create(
        login.state_dir,
        user,
        login.password,
        login.range.clone(),
        size,
        &crate::session::KeeperSpec {
            backend: ID,
            ready_within: core::time::Duration::from_secs(20),
            start: &desktop_exec,
        },
    )?;

    // The record must name the account that just authenticated. Session
    // creation races used to make this untrue: two logins could probe the
    // same display number, and the loser then read the winner's record and
    // bound to a desktop that was not its own.
    anyhow::ensure!(
        rec.user == user,
        "the session on :{} belongs to {}, not to {user} — refusing to bind",
        rec.display,
        rec.user
    );

    // The gate, not the environment, is what the capture and input paths
    // trust. Binding also sets the environment for the subsystems that start
    // later and read it (clipboard, selection owner).
    gate::bind(&rec.user, rec.display, &rec.xauthority, &rec.runtime_dir, login.client_size)?;
    // The user just proved who they are, so the desktop is theirs to see.
    // Unlocking is recorded rather than assumed, so a later disconnect — or a
    // supervisor restart — can put it back.
    if rec.locked {
        crate::session::unlock(login.state_dir, &rec)?;
    }
    *login.bound.lock().unwrap_or_else(|p| p.into_inner()) = Some(BoundSession {
        display: rec.display,
        logind_id: rec.logind_id.clone(),
    });
    tracing::info!(user, display = rec.display, "routed to the user's desktop");
    Ok(())
}

/// The desktop a new X session gets: the first runnable entry in
/// `/usr/share/xsessions`, as its `Exec=` line. Empty — a bare X server —
/// when there is none, which the log says.
fn desktop_exec() -> String {
    let exec = detect::choose_session(&detect::desktop_sessions(), None)
        .map(|s| s.exec.clone())
        .unwrap_or_default();
    if exec.is_empty() {
        tracing::warn!(
            "no runnable desktop session found — the user will get a bare X server. \
             Run `linrdp doctor` to see why."
        );
    }
    exec
}

/// Run an X session for as long as it lives: the X server, then the desktop
/// on it, the record published only once both are up.
fn serve(keeper: Keeper<'_>) -> anyhow::Result<()> {
    let Keeper {
        args,
        ids,
        runtime_dir,
        logind_id,
        mut pam,
        lease,
        account,
    } = keeper;

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
        bus: None,
        backend: ID.to_owned(),
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
    if !args.start.is_empty() {
        let desktop_log = args.state_dir.join(format!("display-{}.desktop.log", args.display));
        let desktop = split_exec(&args.start);
        match keeper::spawn_child(&desktop, &env_pairs, &ids, &desktop_log) {
            Ok(pid) => {
                desktop_pid = Some(pid);
                tracing::info!(
                    user = %args.user,
                    display = args.display,
                    exec = %args.start,
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
    drop(account); // A reconnect can now find the published session.
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

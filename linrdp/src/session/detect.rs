//! What this machine can actually do.
//!
//! linrdp does not only run on Debian with XFCE. The desktop session it
//! starts, whether a lock screen can be drawn at all, and whether per-user
//! sessions are possible depend on what is installed — so nothing here is
//! assumed, everything is probed.
//!
//! A declared session is not a runnable one: this box ships
//! `xfce-wayland.desktop` while having no Wayland compositor binary at all.
//! Launching it would fail at runtime with nothing useful to say, so
//! [`DesktopSession::runnable`] is resolved from the executable, not from the
//! file's existence.
//!
//! Parsing and selection are pure functions over entries, so the awkward
//! cases can be tested without installing a desktop.

use std::path::{Path, PathBuf};

/// X11 or Wayland.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionKind {
    X11,
    Wayland,
}

/// One entry from `/usr/share/xsessions` or `/usr/share/wayland-sessions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DesktopSession {
    /// The `.desktop` basename, e.g. `xfce`.
    pub(crate) id: String,
    /// `Name=` — what a human calls it.
    pub(crate) name: String,
    /// `Exec=` — the command that starts the session.
    pub(crate) exec: String,
    pub(crate) kind: SessionKind,
    /// Whether the command actually exists on this machine.
    pub(crate) runnable: bool,
}

/// Parse a `.desktop` session entry. `None` when it carries no `Exec`.
///
/// `TryExec`, when present, is the freedesktop-blessed way to say "this entry
/// is only valid if that binary exists", so it wins over `Exec` for the
/// runnable check.
pub(crate) fn parse_session_entry(
    id: &str,
    body: &str,
    kind: SessionKind,
    exists: &dyn Fn(&str) -> bool,
) -> Option<DesktopSession> {
    let field = |key: &str| -> Option<String> {
        let prefix = format!("{key}=");
        body.lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix(&prefix))
            .map(|v| v.trim().to_owned())
    };

    let exec = field("Exec")?;
    if exec.is_empty() {
        return None;
    }
    let probe = field("TryExec").unwrap_or_else(|| {
        // The first word of Exec is the program; the rest are arguments.
        exec.split_whitespace().next().unwrap_or_default().to_owned()
    });

    Some(DesktopSession {
        id: id.to_owned(),
        name: field("Name").unwrap_or_else(|| id.to_owned()),
        exec,
        kind,
        runnable: !probe.is_empty() && exists(&probe),
    })
}

/// Pick the session to start.
///
/// Only runnable entries are considered. X11 wins over Wayland because linrdp
/// captures an X display; a Wayland session is reported by `doctor` but is not
/// something this capture path can serve yet. A caller-supplied preference
/// (`--session-id`) beats both, so an operator can always override the guess.
pub(crate) fn choose_session<'a>(
    sessions: &'a [DesktopSession],
    preferred_id: Option<&str>,
) -> Option<&'a DesktopSession> {
    if let Some(id) = preferred_id {
        return sessions.iter().find(|s| s.id == id && s.runnable);
    }
    sessions
        .iter()
        .find(|s| s.runnable && s.kind == SessionKind::X11)
}

/// Everything linrdp probed about this machine.
#[derive(Debug, Clone)]
pub(crate) struct Capabilities {
    pub(crate) distro: String,
    pub(crate) logind: bool,
    pub(crate) pam_service: bool,
    pub(crate) x_servers: Vec<String>,
    pub(crate) sessions: Vec<DesktopSession>,
    pub(crate) lockers: Vec<String>,
}

/// A single human-readable conclusion, worst first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Multi-session cannot work at all.
    Blocker(String),
    /// It will work, but something useful is missing.
    Warning(String),
    /// Confirmation that a requirement is met.
    Ok(String),
}

/// Turn probed capabilities into conclusions. Pure, so every awkward
/// combination is testable without installing anything.
pub(crate) fn verdicts(caps: &Capabilities) -> Vec<Verdict> {
    let mut out = Vec::new();

    if caps.x_servers.is_empty() {
        out.push(Verdict::Blocker(
            "no X server found (Xvfb or Xorg) — a per-user session cannot be started".to_owned(),
        ));
    } else {
        out.push(Verdict::Ok(format!("X server: {}", caps.x_servers.join(", "))));
    }

    match choose_session(&caps.sessions, None) {
        Some(session) => out.push(Verdict::Ok(format!(
            "desktop session: {} ({})",
            session.name, session.id
        ))),
        None => {
            let declared_but_broken: Vec<&DesktopSession> =
                caps.sessions.iter().filter(|s| !s.runnable).collect();
            if declared_but_broken.is_empty() {
                out.push(Verdict::Blocker(
                    "no desktop session found in /usr/share/xsessions — sessions will be a bare X server".to_owned(),
                ));
            } else {
                let names: Vec<&str> = declared_but_broken.iter().map(|s| s.id.as_str()).collect();
                out.push(Verdict::Blocker(format!(
                    "no runnable desktop session: {} declared but their programs are missing",
                    names.join(", ")
                )));
            }
        }
    }

    if !caps.pam_service {
        out.push(Verdict::Blocker(
            "/etc/pam.d/linrdp is missing — PAM cannot open a session, so no per-user desktop can start".to_owned(),
        ));
    } else {
        out.push(Verdict::Ok("PAM service: /etc/pam.d/linrdp".to_owned()));
    }

    if caps.logind {
        out.push(Verdict::Ok("logind: available".to_owned()));
    } else {
        out.push(Verdict::Warning(
            "logind not detected — sessions will not be registered and XDG_RUNTIME_DIR may be missing".to_owned(),
        ));
    }

    if caps.lockers.is_empty() {
        out.push(Verdict::Warning(
            "no screen locker found — a disconnected session can be marked locked, but nothing will draw a lock screen".to_owned(),
        ));
    } else {
        out.push(Verdict::Ok(format!("screen locker: {}", caps.lockers.join(", "))));
    }

    // Report Wayland separately: seeing it listed but unused is otherwise
    // baffling for anyone whose desktop is Wayland-first.
    let wayland: Vec<&DesktopSession> = caps
        .sessions
        .iter()
        .filter(|s| s.kind == SessionKind::Wayland)
        .collect();
    if !wayland.is_empty() && choose_session(&caps.sessions, None).is_some_and(|s| s.kind == SessionKind::X11) {
        let names: Vec<&str> = wayland.iter().map(|s| s.id.as_str()).collect();
        out.push(Verdict::Warning(format!(
            "Wayland session(s) present ({}) but linrdp captures X11, so an X11 session was chosen",
            names.join(", ")
        )));
    }

    out
}

/// Read the session entries under `dir`.
fn read_sessions(dir: &Path, kind: SessionKind, exists: &dyn Fn(&str) -> bool) -> Vec<DesktopSession> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "desktop") {
            continue;
        }
        let Some(id) = path.file_stem().map(|s| s.to_string_lossy().into_owned()) else {
            continue;
        };
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(session) = parse_session_entry(&id, &body, kind, exists) {
            out.push(session);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Is `program` on PATH (or a path that exists)?
pub(crate) fn program_exists(program: &str) -> bool {
    if program.contains('/') {
        return Path::new(program).is_file();
    }
    std::env::var("PATH")
        .unwrap_or_else(|_| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned())
        .split(':')
        .any(|dir| PathBuf::from(dir).join(program).is_file())
}

/// Probe this machine.
pub(crate) fn probe() -> Capabilities {
    let exists: &dyn Fn(&str) -> bool = &program_exists;

    let distro = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|body| {
            body.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_owned())
        })
        .unwrap_or_else(|| "unknown".to_owned());

    let mut sessions = read_sessions(Path::new("/usr/share/xsessions"), SessionKind::X11, exists);
    sessions.extend(read_sessions(
        Path::new("/usr/share/wayland-sessions"),
        SessionKind::Wayland,
        exists,
    ));

    Capabilities {
        distro,
        // The seat directory exists exactly when logind is running.
        logind: Path::new("/run/systemd/seats").exists() || Path::new("/run/systemd/sessions").exists(),
        pam_service: Path::new("/etc/pam.d/linrdp").is_file(),
        x_servers: ["Xvfb", "Xorg"]
            .iter()
            .filter(|b| program_exists(b))
            .map(|b| (*b).to_owned())
            .collect(),
        sessions,
        lockers: [
            "light-locker",
            "xfce4-screensaver",
            "xscreensaver",
            "gnome-screensaver",
            "xsecurelock",
            "i3lock",
            "swaylock",
        ]
        .iter()
        .filter(|b| program_exists(b))
        .map(|b| (*b).to_owned())
        .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nothing_exists(_: &str) -> bool {
        false
    }
    fn everything_exists(_: &str) -> bool {
        true
    }

    const XFCE: &str = "[Desktop Entry]\nName=Xfce Session\nExec=startxfce4\nType=Application\n";

    #[test]
    fn a_session_entry_is_parsed() {
        let s = parse_session_entry("xfce", XFCE, SessionKind::X11, &everything_exists).expect("parsed");
        assert_eq!(s.id, "xfce");
        assert_eq!(s.name, "Xfce Session");
        assert_eq!(s.exec, "startxfce4");
        assert_eq!(s.kind, SessionKind::X11);
        assert!(s.runnable);
    }

    /// The case this machine actually has: a declared Wayland session whose
    /// compositor is not installed. Launching it would fail at runtime with
    /// nothing useful to say, so it must be marked unrunnable here.
    #[test]
    fn a_declared_session_without_its_program_is_not_runnable() {
        let s = parse_session_entry("xfce-wayland", XFCE, SessionKind::Wayland, &nothing_exists).expect("parsed");
        assert!(!s.runnable, "a session whose Exec does not exist must not be offered");
    }

    /// TryExec is the freedesktop way of saying "only valid if this exists",
    /// so it decides runnability even when Exec names something else.
    #[test]
    fn try_exec_decides_runnability() {
        let body = "[Desktop Entry]\nName=Thing\nTryExec=/opt/thing/bin/thing\nExec=thing --session\n";
        let only_tryexec = |p: &str| p == "/opt/thing/bin/thing";
        let s = parse_session_entry("thing", body, SessionKind::X11, &only_tryexec).expect("parsed");
        assert!(s.runnable);
        assert_eq!(s.exec, "thing --session", "Exec is still what gets run");
    }

    #[test]
    fn an_entry_without_exec_is_skipped() {
        let body = "[Desktop Entry]\nName=Broken\nType=Application\n";
        assert!(parse_session_entry("broken", body, SessionKind::X11, &everything_exists).is_none());
    }

    fn session(id: &str, kind: SessionKind, runnable: bool) -> DesktopSession {
        DesktopSession {
            id: id.to_owned(),
            name: id.to_owned(),
            exec: id.to_owned(),
            kind,
            runnable,
        }
    }

    #[test]
    fn an_x11_session_is_preferred_over_wayland() {
        let sessions = vec![
            session("gnome-wayland", SessionKind::Wayland, true),
            session("xfce", SessionKind::X11, true),
        ];
        assert_eq!(choose_session(&sessions, None).map(|s| s.id.as_str()), Some("xfce"));
    }

    #[test]
    fn an_unrunnable_session_is_never_chosen() {
        let sessions = vec![session("xfce", SessionKind::X11, false)];
        assert!(choose_session(&sessions, None).is_none());
        assert!(
            choose_session(&sessions, Some("xfce")).is_none(),
            "an explicit preference must not override a missing program"
        );
    }

    #[test]
    fn an_explicit_preference_wins() {
        let sessions = vec![
            session("xfce", SessionKind::X11, true),
            session("openbox", SessionKind::X11, true),
        ];
        assert_eq!(
            choose_session(&sessions, Some("openbox")).map(|s| s.id.as_str()),
            Some("openbox")
        );
    }

    fn caps(sessions: Vec<DesktopSession>, x: &[&str], lockers: &[&str], pam: bool) -> Capabilities {
        Capabilities {
            distro: "Test Linux".to_owned(),
            logind: true,
            pam_service: pam,
            x_servers: x.iter().map(|s| (*s).to_owned()).collect(),
            sessions,
            lockers: lockers.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn a_missing_x_server_blocks() {
        let v = verdicts(&caps(vec![session("xfce", SessionKind::X11, true)], &[], &["light-locker"], true));
        assert!(
            v.iter().any(|x| matches!(x, Verdict::Blocker(m) if m.contains("no X server"))),
            "got {v:?}"
        );
    }

    /// The diagnosis an operator actually needs: the session is declared, so
    /// "no desktop found" would be wrong and misleading.
    #[test]
    fn a_declared_but_unrunnable_session_says_so() {
        let v = verdicts(&caps(
            vec![session("xfce-wayland", SessionKind::Wayland, false)],
            &["Xvfb"],
            &["light-locker"],
            true,
        ));
        assert!(
            v.iter().any(|x| matches!(x, Verdict::Blocker(m)
                if m.contains("declared but their programs are missing") && m.contains("xfce-wayland"))),
            "got {v:?}"
        );
    }

    #[test]
    fn a_missing_pam_service_blocks() {
        let v = verdicts(&caps(
            vec![session("xfce", SessionKind::X11, true)],
            &["Xvfb"],
            &["light-locker"],
            false,
        ));
        assert!(
            v.iter().any(|x| matches!(x, Verdict::Blocker(m) if m.contains("/etc/pam.d/linrdp"))),
            "got {v:?}"
        );
    }

    /// Without a locker the lock state is bookkeeping only — say so rather
    /// than letting someone believe the desktop is protected.
    #[test]
    fn a_missing_locker_warns_that_the_lock_is_invisible() {
        let v = verdicts(&caps(
            vec![session("xfce", SessionKind::X11, true)],
            &["Xvfb"],
            &[],
            true,
        ));
        assert!(
            v.iter().any(|x| matches!(x, Verdict::Warning(m) if m.contains("nothing will draw a lock screen"))),
            "got {v:?}"
        );
    }

    #[test]
    fn a_healthy_machine_has_no_blockers() {
        let v = verdicts(&caps(
            vec![session("xfce", SessionKind::X11, true)],
            &["Xvfb", "Xorg"],
            &["light-locker"],
            true,
        ));
        assert!(!v.iter().any(|x| matches!(x, Verdict::Blocker(_))), "got {v:?}");
    }
}

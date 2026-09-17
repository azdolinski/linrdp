//! `linrdp doctor` — what this machine is, and what linrdp may do on it.
//!
//! The report is built before it is drawn. [`Report`] is a plain value derived
//! from the probe, so what the report *says* can be tested without a terminal,
//! and drawing it is a separate step that decides nothing.
//!
//! The drawing borrows cliclack's theme — the Rust port of clack's look — but
//! not its output functions: those write to stderr with no way to redirect,
//! and a diagnostic report is precisely the thing people send to a file or a
//! pager. Every `format_*` on the [`Theme`] trait returns a `String`, so the
//! theme renders and we choose the stream.

use std::path::Path;

use cliclack::{Theme, ThemeState};
use console::Style;

use crate::sam;
use crate::session::detect::{self, Capabilities, SessionKind, Verdict};

/// One `key  value` line inside a section.
struct Fact {
    key: &'static str,
    value: String,
}

/// One row of the desktop-session table.
struct SessionRow {
    id: String,
    kind: &'static str,
    /// `chosen`, `runnable` or `MISSING` — the session that would start says
    /// so here, which is why no confirmation of it is needed further down.
    status: &'static str,
    exec: String,
}

/// Something that wants the operator's attention. A met requirement is not a
/// finding: it is already visible as a fact above.
enum Finding {
    Blocker(String),
    Warning(String),
}

/// What `doctor` has to say, before anything decides how to draw it.
struct Report {
    system: Vec<Fact>,
    authentication: Vec<Fact>,
    /// Header of the session table; names the session that would start.
    sessions_title: String,
    sessions: Vec<SessionRow>,
    findings: Vec<Finding>,
}

impl Report {
    fn blockers(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| matches!(f, Finding::Blocker(_)))
            .count()
    }
}

/// Turn the probe into the report. Pure, so every awkward machine can be
/// tested without being one.
fn build(
    caps: &Capabilities,
    accounts: &[String],
    sam_path: &Path,
    pam_capture: bool,
    auth_mode: Option<&str>,
) -> Report {
    // `--auth system` takes credentials from the client and checks them against
    // /etc/shadow itself, so it neither needs nor uses a captured password.
    let capture_needed = auth_mode != Some("system");
    let list = |items: &[String]| {
        if items.is_empty() {
            "none".to_owned()
        } else {
            items.join(", ")
        }
    };

    let system = vec![
        Fact { key: "distribution", value: caps.distro.clone() },
        Fact { key: "X servers", value: list(&caps.x_servers) },
        Fact { key: "logind", value: if caps.logind { "yes" } else { "no" }.to_owned() },
        Fact {
            key: "PAM service",
            value: if caps.pam_service { "/etc/pam.d/linrdp" } else { "missing" }.to_owned(),
        },
        Fact { key: "lockers", value: list(&caps.lockers) },
    ];

    let authentication = vec![
        Fact {
            key: "default",
            value: "system password (/etc/shadow + PAM); `--auth nla` uses the SAM".to_owned(),
        },
        Fact {
            key: "NLA accounts",
            value: if accounts.is_empty() {
                format!("none provisioned in {}", sam_path.display())
            } else {
                accounts.join(", ")
            },
        },
        Fact {
            key: "PAM capture",
            value: match (pam_capture, capture_needed) {
                (true, _) => "wired".to_owned(),
                (false, false) => "not wired (`--auth system` does not need it)".to_owned(),
                (false, true) => "NOT wired".to_owned(),
            },
        },
    ];

    let chosen = detect::choose_session(&caps.sessions, None);
    let sessions_title = match chosen {
        Some(session) => format!("desktop sessions (starting {})", session.name),
        None => "desktop sessions".to_owned(),
    };
    let sessions = caps
        .sessions
        .iter()
        .map(|session| SessionRow {
            id: session.id.clone(),
            kind: match session.kind {
                SessionKind::X11 => "x11",
                SessionKind::Wayland => "wayland",
            },
            status: if chosen.is_some_and(|c| c.id == session.id) {
                "chosen"
            } else if session.runnable {
                "runnable"
            } else {
                "MISSING"
            },
            exec: session.exec.clone(),
        })
        .collect();

    // A met requirement is dropped: every one of them restates a fact printed
    // a few lines above, and burying two warnings in five confirmations is how
    // the old report managed to hide what was wrong with the machine.
    let mut findings: Vec<Finding> = detect::verdicts(caps)
        .into_iter()
        .filter_map(|verdict| match verdict {
            Verdict::Blocker(message) => Some(Finding::Blocker(message)),
            Verdict::Warning(message) => Some(Finding::Warning(message)),
            Verdict::Ok(_) => None,
        })
        .collect();

    // Not part of `verdicts`, which reports what the *machine* can do: this is
    // about how the machine is wired, and it is the difference between "NLA
    // works" and "every login is denied as invalid username".
    if !pam_capture && capture_needed {
        findings.push(Finding::Blocker(
            "PAM credential capture is NOT wired, and this machine runs the default `--auth \
             nla`. NLA cannot verify an /etc/shadow hash, so linrdp has to learn each account's \
             system password from the system's own authentication: install deploy/pam-capture \
             into the PAM stack. The alternative, if you would rather not touch PAM, is `--auth \
             system` — it stores nothing, but only works with clients that send credentials \
             without NLA (FreeRDP, Remmina; mstsc does not)."
                .to_owned(),
        ));
    }
    if accounts.is_empty() {
        findings.push(Finding::Warning(
            "no account's password has been captured yet — authenticate once on this machine \
             (su -, ssh, console login) and the next RDP login will work"
                .to_owned(),
        ));
    }

    // Worst first. The probes run in whatever order reads well in `verdicts`,
    // which is not the order in which someone fixes a machine.
    findings.sort_by_key(|finding| match finding {
        Finding::Blocker(_) => 0,
        Finding::Warning(_) => 1,
    });

    Report { system, authentication, sessions_title, sessions, findings }
}

/// A `key  value` block, keys aligned, ready to be hung off a gutter.
fn facts_block(title: &str, facts: &[Fact]) -> String {
    let width = facts.iter().map(|fact| fact.key.chars().count()).max().unwrap_or(0);
    let mut block = title.to_owned();
    for fact in facts {
        block.push_str(&format!("\n{key:<width$}  {value}", key = fact.key, value = fact.value));
    }
    block
}

/// The session table. Columns are measured, not guessed, so a long session id
/// does not shunt every other column out of line.
fn sessions_block(title: &str, rows: &[SessionRow]) -> String {
    if rows.is_empty() {
        return format!("{title}\n(none found in /usr/share/xsessions or /usr/share/wayland-sessions)");
    }

    let width = |f: &dyn Fn(&SessionRow) -> usize| rows.iter().map(f).max().unwrap_or(0);
    let id_width = width(&|row| row.id.chars().count());
    let kind_width = width(&|row| row.kind.chars().count());
    let status_width = width(&|row| row.status.chars().count());

    let mut block = title.to_owned();
    for row in rows {
        // Pad before styling: the escape sequences would otherwise be counted
        // as part of the column's width.
        let status = format!("{:<status_width$}", row.status);
        let status = match row.status {
            "chosen" => Style::new().green().apply_to(status),
            "MISSING" => Style::new().red().apply_to(status),
            _ => Style::new().apply_to(status),
        };
        block.push_str(&format!(
            "\n{id:<id_width$}  {kind:<kind_width$}  {status}  {exec}",
            id = row.id,
            kind = row.kind,
            exec = row.exec,
        ));
    }
    block
}

/// clack's own look, unmodified: every [`Theme`] method has a default body, so
/// an empty impl *is* the theme.
struct DoctorTheme;
impl Theme for DoctorTheme {}

/// Draw the report. Nothing here decides anything — it only chooses symbols.
fn render(report: &Report, theme: &dyn Theme) -> String {
    // A section header wears the same symbol a submitted prompt does, which is
    // what makes the block read as one thing hanging off the gutter.
    let section = theme.state_symbol(&ThemeState::Submit);

    let mut out = theme.format_intro("linrdp doctor");
    out.push_str(&theme.format_log(&facts_block("system", &report.system), &section));
    out.push_str(&theme.format_log(&facts_block("authentication", &report.authentication), &section));
    out.push_str(&theme.format_log(&sessions_block(&report.sessions_title, &report.sessions), &section));

    for finding in &report.findings {
        let (symbol, message) = match finding {
            Finding::Blocker(message) => (theme.error_symbol(), message),
            Finding::Warning(message) => (theme.warning_symbol(), message),
        };
        // 3 = the symbol and the two spaces after it, which every wrapped line
        // has to clear to sit under the first one.
        out.push_str(&theme.format_log(&cliclack::termwrap(message, 3), &symbol));
    }

    let blockers = report.blockers();
    if blockers == 0 {
        out.push_str(&theme.format_outro("Per-user sessions can run on this machine."));
    } else {
        out.push_str(&theme.format_outro_cancel(&format!(
            "{blockers} blocker(s): per-user sessions cannot run until these are fixed."
        )));
    }
    out
}

/// Whether the PAM stack calls linrdp on every successful authentication.
///
/// Without it linrdp never sees a password, and NLA — which must know the
/// secret to compute the expected NTLM response — denies every login.
fn pam_capture_wired() -> bool {
    const CANDIDATES: [&str; 4] = [
        "/etc/pam.d/common-auth",
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ];
    CANDIDATES.iter().any(|path| {
        std::fs::read_to_string(path).is_ok_and(|body| {
            body.lines()
                .any(|line| !line.trim_start().starts_with('#') && line.contains("--capture-credential"))
        })
    })
}

/// The `--auth` mode this machine is configured to run, when it can be told.
///
/// `doctor` runs as its own process and cannot see a running server's flags,
/// so it asks systemd what the unit is set to start. Without systemd, or
/// without the unit, the answer is unknown and the caller assumes the
/// default. Only used to decide how loudly to report a missing PAM capture:
/// required for `nla`, meaningless for `system`.
fn configured_auth_mode() -> Option<String> {
    let out = std::process::Command::new("systemctl")
        .args(["show", "linrdp", "--property=ExecStart", "--value"])
        .output()
        .ok()?;
    let exec = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || exec.trim().is_empty() {
        return None;
    }
    // ExecStart renders as a struct; the argv is in there verbatim, so a
    // window search over the tokens is enough and needs no parser.
    let tokens: Vec<&str> = exec.split_whitespace().collect();
    tokens
        .windows(2)
        .find(|pair| pair[0] == "--auth")
        .map(|pair| pair[1].trim_end_matches(&['"', '\''][..]).to_owned())
}

/// Probe this machine and print the report on stdout.
pub(crate) fn run() -> anyhow::Result<()> {
    let caps = detect::probe();
    let accounts = sam::account_names();
    let auth_mode = configured_auth_mode();
    let report = build(
        &caps,
        &accounts,
        &sam::sam_path(),
        pam_capture_wired(),
        auth_mode.as_deref(),
    );
    print!("{}", render(&report, &DoctorTheme));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::detect::DesktopSession;

    fn session(id: &str, kind: SessionKind, runnable: bool) -> DesktopSession {
        DesktopSession {
            id: id.to_owned(),
            name: format!("{id} Session"),
            exec: format!("start{id}"),
            kind,
            runnable,
        }
    }

    /// A machine with everything in place.
    fn healthy(sessions: Vec<DesktopSession>) -> Capabilities {
        Capabilities {
            distro: "Debian GNU/Linux 13 (trixie)".to_owned(),
            logind: true,
            pam_service: true,
            x_servers: vec!["Xvfb".to_owned(), "Xorg".to_owned()],
            sessions,
            lockers: vec!["light-locker".to_owned()],
        }
    }

    fn accounts() -> Vec<String> {
        vec!["user".to_owned()]
    }

    fn sam() -> &'static Path {
        Path::new("/var/lib/linrdp/sam")
    }

    /// The old report restated every met requirement ("ok logind: available")
    /// directly under the facts that already said so. A finding is now only
    /// what the operator has to do something about, so a healthy machine ends
    /// with nothing listed at all.
    #[test]
    fn met_requirements_do_not_become_findings() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(&caps, &accounts(), sam(), true, None);
        assert!(
            report.findings.is_empty(),
            "a healthy machine has nothing for the operator to read"
        );
        assert_eq!(report.blockers(), 0);
    }

    /// Which session would actually start is the one thing the table could not
    /// say before, and it is why the confirmation of it can be dropped.
    #[test]
    fn the_session_that_would_start_is_marked_chosen() {
        let caps = healthy(vec![
            session("xfce-wayland", SessionKind::Wayland, true),
            session("xfce", SessionKind::X11, true),
            session("lightdm-xsession", SessionKind::X11, false),
        ]);
        let report = build(&caps, &accounts(), sam(), true, None);

        let status = |id: &str| {
            report
                .sessions
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.status)
                .expect("row present")
        };
        assert_eq!(status("xfce"), "chosen", "X11 wins, because linrdp captures X11");
        assert_eq!(status("xfce-wayland"), "runnable");
        assert_eq!(status("lightdm-xsession"), "MISSING");
        assert!(
            report.sessions_title.contains("xfce Session"),
            "the header names the session that starts, got {:?}",
            report.sessions_title
        );
    }

    /// Without the PAM hook linrdp never learns a password, so every NLA login
    /// is denied as an invalid username. That is a blocker, and the fact row
    /// has to say so too — the fact block is where people look first.
    #[test]
    fn an_unwired_pam_capture_is_a_blocker() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(&caps, &accounts(), sam(), false, None);

        assert_eq!(report.blockers(), 1);
        let capture = report
            .authentication
            .iter()
            .find(|f| f.key == "PAM capture")
            .expect("the capture fact is reported");
        assert_eq!(capture.value, "NOT wired");
    }

    /// `--auth system` checks the client's credentials against /etc/shadow
    /// itself, so it never reads a captured password. Calling the missing
    /// capture a blocker there tells the operator to fix what they chose.
    #[test]
    fn auth_system_does_not_need_the_pam_capture() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(&caps, &accounts(), sam(), false, Some("system"));

        assert_eq!(report.blockers(), 0, "the mode in use needs no capture");
        let capture = report
            .authentication
            .iter()
            .find(|f| f.key == "PAM capture")
            .expect("the capture fact is reported");
        assert_eq!(capture.value, "not wired (`--auth system` does not need it)");
    }

    /// An empty SAM is the normal state of a fresh install: the hook is wired
    /// and the first `su -` fills it. Nothing is broken, so nothing may claim
    /// sessions cannot run.
    #[test]
    fn no_captured_password_yet_is_a_warning_not_a_blocker() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(&caps, &[], sam(), true, None);

        assert_eq!(report.blockers(), 0);
        assert!(
            matches!(report.findings.as_slice(), [Finding::Warning(_)]),
            "one warning, no blocker"
        );
    }

    /// The footer is the one line everybody reads, so a blocked machine has to
    /// be told apart from a working one there and not only in the list above.
    #[test]
    fn a_blocked_machine_says_so_in_the_footer() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);

        let blocked = render(&build(&caps, &accounts(), sam(), false, None), &DoctorTheme);
        assert!(
            blocked.contains("1 blocker(s): per-user sessions cannot run"),
            "got {blocked}"
        );

        let working = render(&build(&caps, &accounts(), sam(), true, None), &DoctorTheme);
        assert!(
            working.contains("Per-user sessions can run on this machine."),
            "got {working}"
        );
    }

    /// What stops the machine working has to be read before what merely
    /// degrades it, whatever order the probes happened to run in.
    #[test]
    fn blockers_are_listed_before_warnings() {
        let mut caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        caps.x_servers.clear();
        caps.lockers.clear();
        let report = build(&caps, &[], sam(), true, None);

        assert!(report.blockers() >= 1);
        let first_warning = report
            .findings
            .iter()
            .position(|f| matches!(f, Finding::Warning(_)))
            .expect("this machine has warnings");
        let last_blocker = report
            .findings
            .iter()
            .rposition(|f| matches!(f, Finding::Blocker(_)))
            .expect("this machine has blockers");
        assert!(last_blocker < first_warning, "every blocker comes first");
    }
}

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

use std::path::{Path, PathBuf};

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

/// Wrap a finding for the terminal, leaving anything indented alone.
///
/// A finding that ends in commands is only worth printing if the commands
/// survive being copied out of it, and wrapping breaks a path down the
/// middle — `/etc/systemd/user/` on one line and the rest of the filename on
/// the next, which is a mistake waiting to be pasted. So prose wraps and
/// indented lines go through at whatever length they are: a command that
/// scrolls is still a command.
fn wrap_finding(message: &str, padding: u16) -> String {
    message
        .split('\n')
        .map(|line| {
            if line.starts_with("    ") {
                line.to_owned()
            } else {
                cliclack::termwrap(line, padding)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
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
        out.push_str(&theme.format_log(&wrap_finding(message, 3), &symbol));
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
    auth_mode_of("linrdp")
}

/// The `--auth` mode one unit is set to start, when it can be told.
fn auth_mode_of(unit: &str) -> Option<String> {
    let out = std::process::Command::new("systemctl")
        .args(["show", unit, "--property=ExecStart", "--value"])
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

// ---------------------------------------------------------------------------
// `linrdp doctor <account>` — will this account work on this machine?
//
// The machine report above answers "may linrdp run here". It cannot answer
// "why does this account have no sound", because everything that decides that
// is per-account: which runtime directory the session gets, whether systemd
// will start a sound server for that uid at all, whether the account's
// password is even usable. Measured here first: a root desktop has no audio
// because `pulseaudio.socket` carries `ConditionUser=!root`, which no amount
// of reading the machine report would have revealed.
// ---------------------------------------------------------------------------

/// One linrdp listener and the authentication it is configured to offer.
///
/// There is rarely only one. This machine runs two — NLA on 3389 and the
/// server-drawn logon screen on 3390 — and they want different things from an
/// account: NLA has to know the password to compute the expected response,
/// while the logon screen hands what you type straight to PAM and needs
/// nothing stored. A report that looked at one unit would tell someone
/// logging in through the greeter that their account was not ready, which is
/// what the first draft of this did.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthListener {
    unit: String,
    /// `both`, `nla`, `system` or `greeter`.
    mode: String,
}

impl AuthListener {
    /// Whether this listener needs a captured system password.
    ///
    /// Only the modes that offer NLA do. `system` checks the client's own
    /// credentials against `/etc/shadow`, and `greeter` never asks the client
    /// for credentials at all.
    fn needs_capture(&self) -> bool {
        matches!(self.mode.as_str(), "both" | "nla")
    }
}

/// Whether systemd would start a sound server for an account at all.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SoundServerPolicy {
    /// Nothing in the unit stands in this account's way.
    Startable,
    /// A `ConditionUser=` excludes this account. Carries the condition
    /// verbatim, so the report quotes the machine rather than paraphrasing it.
    Excluded(String),
    /// No `pulseaudio.socket` on the unit search path: this machine may use
    /// PipeWire, or have no sound server at all.
    NoUnit,
    /// A condition this code does not evaluate. Said plainly, because a
    /// guessed verdict on an account's audio is worse than no verdict.
    Unevaluated(String),
}

/// Everything `doctor <account>` needs, gathered before any of it is judged.
///
/// Separated from the judging for the same reason [`Report`] is: an account
/// that is locked, or absent, or root, can then be described in a test
/// without the machine having to have one.
struct AccountProbe {
    name: String,
    /// `None` when NSS does not know this account.
    ids: Option<crate::session::privilege::UserIds>,
    home_exists: bool,
    password: crate::auth::PasswordState,
    /// Whether this account's system password has been captured, which is
    /// what NLA needs to compute the expected response.
    captured: bool,
    /// Present only while the account has a logind session.
    runtime_dir_exists: bool,
    sound_policy: SoundServerPolicy,
    sound_socket_exists: bool,
    cookie_exists: bool,
    /// The display of this account's live linrdp session, if it has one.
    live_display: Option<u16>,
    /// Every linrdp listener on this machine, and what it asks of an account.
    listeners: Vec<AuthListener>,
}

/// What `doctor <account>` has to say.
struct AccountReport {
    account: String,
    identity: Vec<Fact>,
    authentication: Vec<Fact>,
    audio: Vec<Fact>,
    findings: Vec<Finding>,
}

impl AccountReport {
    fn blockers(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| matches!(f, Finding::Blocker(_)))
            .count()
    }
}

/// systemd's search path for user units, lowest precedence last.
const USER_UNIT_DIRS: [&str; 3] = ["/etc/systemd/user", "/run/systemd/user", "/usr/lib/systemd/user"];

/// The effective `ConditionUser=` of a systemd user unit.
///
/// Conditions are a list: each assignment appends, and an empty assignment
/// clears everything accumulated so far. That is how a drop-in lifts one —
/// `[Unit]` with a bare `ConditionUser=` — so an implementation that only
/// read the shipped unit would report a condition the operator had already
/// removed.
fn effective_condition_user(unit: Option<&str>, dropins: &[String]) -> Vec<String> {
    let mut conditions = Vec::new();
    for body in unit.into_iter().chain(dropins.iter().map(String::as_str)) {
        for line in body.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some(value) = line.strip_prefix("ConditionUser=") else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                conditions.clear();
            } else {
                conditions.push(value.to_owned());
            }
        }
    }
    conditions
}

/// Read a user unit and its drop-ins off the search path.
///
/// `None` for the unit body means no such unit exists anywhere.
fn read_user_unit(unit: &str) -> (Option<String>, Vec<String>) {
    // The unit itself: the first directory that has one wins outright.
    let body = USER_UNIT_DIRS
        .iter()
        .find_map(|dir| std::fs::read_to_string(Path::new(dir).join(unit)).ok());

    // Drop-ins: every directory contributes, and within one they apply in
    // name order.
    let mut dropins = Vec::new();
    for dir in USER_UNIT_DIRS.iter().rev() {
        let path = Path::new(dir).join(format!("{unit}.d"));
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        let mut files: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "conf"))
            .collect();
        files.sort();
        dropins.extend(files.iter().filter_map(|path| std::fs::read_to_string(path).ok()));
    }
    (body, dropins)
}

/// Whether these conditions let this account have a sound server.
///
/// Only the forms that actually appear in the shipped units are evaluated —
/// a name, a uid, either of those negated. Anything else (`@system`, a range)
/// is reported as unevaluated rather than guessed at.
fn sound_server_policy(conditions: &[String], uid: u32, name: &str) -> SoundServerPolicy {
    for condition in conditions {
        let (negated, subject) = match condition.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, condition.as_str()),
        };
        let matches = match subject.parse::<u32>() {
            Ok(wanted) => wanted == uid,
            Err(_) => subject == name,
        };
        let satisfied = matches != negated;
        if !satisfied {
            // A condition that names something we did understand, and that
            // this account fails.
            if subject.parse::<u32>().is_ok() || subject == name || negated {
                return SoundServerPolicy::Excluded(condition.clone());
            }
            return SoundServerPolicy::Unevaluated(condition.clone());
        }
    }
    SoundServerPolicy::Startable
}

/// Gather the account's facts from this machine.
fn probe_account(name: &str) -> AccountProbe {
    let ids = crate::session::privilege::lookup_user(name).ok();
    let (unit, dropins) = read_user_unit("pulseaudio.socket");
    let conditions = effective_condition_user(unit.as_deref(), &dropins);

    let sound_policy = match (&unit, &ids) {
        (None, _) => SoundServerPolicy::NoUnit,
        (Some(_), Some(ids)) => sound_server_policy(&conditions, ids.uid, name),
        // Without an account there is nothing to evaluate the condition
        // against, and the report will have said so far more loudly.
        (Some(_), None) => SoundServerPolicy::Startable,
    };

    let runtime_dir = ids.as_ref().map(|ids| PathBuf::from(format!("/run/user/{}", ids.uid)));
    AccountProbe {
        name: name.to_owned(),
        home_exists: ids.as_ref().is_some_and(|ids| Path::new(&ids.home).is_dir()),
        password: crate::auth::password_state(name),
        captured: sam::account_names().iter().any(|account| account == name),
        runtime_dir_exists: runtime_dir.as_ref().is_some_and(|dir| dir.is_dir()),
        sound_socket_exists: runtime_dir
            .as_ref()
            .is_some_and(|dir| dir.join("pulse").join("native").exists()),
        cookie_exists: ids
            .as_ref()
            .is_some_and(|ids| Path::new(&ids.home).join(".config/pulse/cookie").exists()),
        // The same default range the supervisor uses when none is given.
        live_display: crate::session::registry::find(
            Path::new(crate::session::runtime_dir::STATE_DIR),
            name,
            10..=99,
        )
        .map(|record| record.display),
        sound_policy,
        listeners: configured_listeners(),
        ids,
    }
}

/// Every linrdp listener systemd knows about, with the authentication it
/// offers.
///
/// `doctor` runs as its own process and cannot see a running server's flags,
/// so it asks systemd what each unit is set to start. A unit with no `--auth`
/// runs the default, which is `both`.
fn configured_listeners() -> Vec<AuthListener> {
    let Ok(out) = std::process::Command::new("systemctl")
        .args(["list-units", "--type=service", "--all", "--no-legend", "--plain", "linrdp*.service"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| unit.ends_with(".service"))
        .map(|unit| AuthListener {
            mode: auth_mode_of(unit).unwrap_or_else(|| "both".to_owned()),
            unit: unit.to_owned(),
        })
        .collect()
}

/// Turn the account probe into its report. Pure, as [`build`] is.
fn build_account(probe: &AccountProbe) -> AccountReport {
    let mut findings = Vec::new();

    // Nothing else is worth reporting about an account that does not exist:
    // every later fact would be a statement about a user who is not there.
    let Some(ids) = &probe.ids else {
        return AccountReport {
            account: probe.name.clone(),
            identity: vec![Fact { key: "account", value: "NOT FOUND in NSS".to_owned() }],
            authentication: Vec::new(),
            audio: Vec::new(),
            findings: vec![Finding::Blocker(format!(
                "there is no account called {} on this machine — NSS does not resolve it, so no \
                 login as {} can ever succeed. Check the spelling, or `getent passwd {}` to see \
                 what the name service actually returns.",
                probe.name, probe.name, probe.name
            ))],
        };
    };

    let runtime_dir = format!("/run/user/{}", ids.uid);
    let identity = vec![
        Fact { key: "uid / gid", value: format!("{} / {}", ids.uid, ids.gid) },
        Fact {
            key: "home",
            value: format!("{}{}", ids.home, if probe.home_exists { "" } else { "  (MISSING)" }),
        },
        Fact {
            key: "runtime dir",
            value: format!(
                "{runtime_dir}{}",
                if probe.runtime_dir_exists { "" } else { "  (absent — no logind session right now)" }
            ),
        },
        Fact {
            key: "linrdp session",
            value: match probe.live_display {
                Some(display) => format!("live on :{display}"),
                None => "none running".to_owned(),
            },
        },
    ];

    // Capture matters only where NLA is actually offered. A machine that only
    // runs the greeter port stores nothing and needs nothing stored.
    let needing: Vec<&AuthListener> = probe.listeners.iter().filter(|l| l.needs_capture()).collect();
    let capture_needed = !needing.is_empty();
    let authentication = vec![
        Fact {
            key: "listeners",
            value: if probe.listeners.is_empty() {
                "none found (systemd knows no linrdp*.service)".to_owned()
            } else {
                probe
                    .listeners
                    .iter()
                    .map(|l| format!("{} (--auth {})", l.unit, l.mode))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        },
        Fact {
            key: "/etc/shadow",
            value: match probe.password {
                crate::auth::PasswordState::Set => "usable password hash".to_owned(),
                crate::auth::PasswordState::Locked => "LOCKED".to_owned(),
                crate::auth::PasswordState::Empty => "EMPTY password field".to_owned(),
                crate::auth::PasswordState::Absent => "not present (NSS-only account)".to_owned(),
                crate::auth::PasswordState::Unreadable => "unreadable (run doctor as root)".to_owned(),
            },
        },
        Fact {
            key: "password captured",
            value: match (probe.captured, capture_needed) {
                (true, _) => "yes — NLA can authenticate this account".to_owned(),
                (false, false) => "no (`--auth system` does not need it)".to_owned(),
                (false, true) => "NOT yet".to_owned(),
            },
        },
    ];

    let socket = format!("{runtime_dir}/pulse/native");
    let audio = vec![
        Fact {
            key: "sound server",
            value: match &probe.sound_policy {
                SoundServerPolicy::Startable => "pulseaudio.socket may start for this account".to_owned(),
                SoundServerPolicy::Excluded(condition) => {
                    format!("EXCLUDED by pulseaudio.socket's ConditionUser={condition}")
                }
                SoundServerPolicy::NoUnit => "no pulseaudio.socket on this machine".to_owned(),
                SoundServerPolicy::Unevaluated(condition) => {
                    format!("ConditionUser={condition} — not evaluated here")
                }
            },
        },
        Fact {
            key: "socket",
            value: format!("{socket}{}", if probe.sound_socket_exists { "" } else { "  (absent)" }),
        },
        Fact {
            key: "cookie",
            value: format!(
                "{}/.config/pulse/cookie{}",
                ids.home,
                if probe.cookie_exists { "" } else { "  (absent)" }
            ),
        },
    ];

    // Authentication first: an account that cannot log in has no audio problem
    // worth discussing yet.
    match probe.password {
        crate::auth::PasswordState::Locked => findings.push(Finding::Blocker(format!(
            "{}'s password is locked in /etc/shadow, so PAM refuses every password it is offered \
             and no RDP login can succeed whatever else is configured. `sudo passwd -u {}` \
             unlocks it (an account with no password set needs `sudo passwd {}` instead).",
            probe.name, probe.name, probe.name
        ))),
        crate::auth::PasswordState::Empty => findings.push(Finding::Blocker(format!(
            "{}'s password field in /etc/shadow is empty, which PAM refuses by default. Set one \
             with `sudo passwd {}`.",
            probe.name, probe.name
        ))),
        crate::auth::PasswordState::Absent => findings.push(Finding::Warning(format!(
            "{} is not in /etc/shadow, so it comes from somewhere else in NSS (LDAP, SSSD). \
             That works — PAM decides — but this report cannot tell you whether the password is \
             usable.",
            probe.name
        ))),
        crate::auth::PasswordState::Unreadable => findings.push(Finding::Warning(
            "/etc/shadow could not be read, so nothing here describes the account's password. \
             Run `sudo linrdp doctor` for that part."
                .to_owned(),
        )),
        crate::auth::PasswordState::Set => {}
    }

    if !probe.home_exists {
        findings.push(Finding::Blocker(format!(
            "{}'s home directory {} does not exist. The desktop starts in it and PulseAudio keeps \
             its authentication cookie there, so both fail. Create it owned by the account: \
             `sudo mkdir -p {} && sudo chown {}:{} {}`.",
            probe.name, ids.home, ids.home, ids.uid, ids.gid, ids.home
        )));
    }

    if !probe.captured && capture_needed {
        let units: Vec<&str> = needing.iter().map(|l| l.unit.as_str()).collect();
        let greeters: Vec<&str> = probe
            .listeners
            .iter()
            .filter(|l| !l.needs_capture())
            .map(|l| l.unit.as_str())
            .collect();
        findings.push(Finding::Warning(format!(
            "no password captured for {} yet, so {} cannot let this account in: NLA must know the \
             secret to compute the expected NTLM response, and it cannot verify an /etc/shadow \
             hash. Authenticate once as {} by any other means — `su - {}`, ssh, a console login — \
             and the PAM capture records it for the next RDP login. Nothing needs to be \
             provisioned in linrdp; the system password is the only one it uses.{}",
            probe.name,
            units.join(" or "),
            probe.name,
            probe.name,
            if greeters.is_empty() {
                String::new()
            } else {
                format!(
                    " This does not affect {} — the server-drawn logon screen hands what you type \
                     straight to PAM and needs nothing stored.",
                    greeters.join(" or ")
                )
            }
        )));
    }

    match &probe.sound_policy {
        SoundServerPolicy::Excluded(condition) => findings.push(Finding::Blocker(format!(
            "{} will never have audio as things stand: systemd's pulseaudio.socket carries \
             ConditionUser={condition}, which excludes this account, so no sound server is ever \
             started for uid {} and there is nothing for linrdp to capture. PulseAudio itself \
             runs fine for this account — it is the unit's condition that stops it. To lift it \
             (this is the distribution's own policy, so it is your call):\n\
             \n    cd /etc/systemd/user && sudo mkdir -p pulseaudio.{{socket,service}}.d\
             \n    printf '[Unit]\\nConditionUser=\\n' | sudo tee pulseaudio.{{socket,service}}.d/allow-root.conf\
             \n    sudo systemctl --user -M {}@ daemon-reload\
             \n    sudo systemctl --user -M {}@ start pulseaudio.socket\n\
             \nThe simpler answer is to serve desktops from an ordinary account instead.",
            probe.name, ids.uid, probe.name, probe.name
        ))),
        SoundServerPolicy::NoUnit => findings.push(Finding::Warning(
            "no pulseaudio.socket on this machine's user-unit path. If this host uses PipeWire, \
             linrdp's capture path does not speak to it yet and there will be no audio."
                .to_owned(),
        )),
        SoundServerPolicy::Unevaluated(condition) => findings.push(Finding::Warning(format!(
            "pulseaudio.socket carries ConditionUser={condition}, which this report does not \
             evaluate. Ask systemd directly: `systemctl --user -M {}@ status pulseaudio.socket`.",
            probe.name
        ))),
        SoundServerPolicy::Startable => {
            // A missing socket only means something once the account is
            // actually logged in — before that there is no runtime dir for a
            // daemon to listen in, and saying so would be noise.
            if probe.runtime_dir_exists && !probe.sound_socket_exists {
                findings.push(Finding::Warning(format!(
                    "{} has a session but no sound server listening at {socket}. The unit permits \
                     it, so something stopped it starting: `systemctl --user -M {}@ status \
                     pulseaudio.socket` says what.",
                    probe.name, probe.name
                )));
            }
            if !probe.cookie_exists {
                findings.push(Finding::Warning(format!(
                    "no PulseAudio cookie at {}/.config/pulse/cookie. linrdp authenticates to the \
                     account's daemon with it — the worker is root and the daemon is not, so the \
                     daemon's own credential check cannot pass. The cookie is written when the \
                     daemon first starts, so this usually clears itself on the next login.",
                    ids.home
                )));
            }
        }
    }

    findings.sort_by_key(|finding| match finding {
        Finding::Blocker(_) => 0,
        Finding::Warning(_) => 1,
    });

    AccountReport {
        account: probe.name.clone(),
        identity,
        authentication,
        audio,
        findings,
    }
}

/// Draw the account report. Decides nothing, as [`render`] decides nothing.
fn render_account(report: &AccountReport, theme: &dyn Theme) -> String {
    let section = theme.state_symbol(&ThemeState::Submit);

    let mut out = theme.format_intro(&format!("linrdp doctor {}", report.account));
    out.push_str(&theme.format_log(&facts_block("identity", &report.identity), &section));
    if !report.authentication.is_empty() {
        out.push_str(&theme.format_log(&facts_block("authentication", &report.authentication), &section));
    }
    if !report.audio.is_empty() {
        out.push_str(&theme.format_log(&facts_block("audio", &report.audio), &section));
    }

    for finding in &report.findings {
        let (symbol, message) = match finding {
            Finding::Blocker(message) => (theme.error_symbol(), message),
            Finding::Warning(message) => (theme.warning_symbol(), message),
        };
        out.push_str(&theme.format_log(&wrap_finding(message, 3), &symbol));
    }

    let blockers = report.blockers();
    if blockers == 0 {
        out.push_str(&theme.format_outro(&format!(
            "{} can log in and be served on this machine. `linrdp doctor` reports the machine itself.",
            report.account
        )));
    } else {
        out.push_str(&theme.format_outro_cancel(&format!(
            "{blockers} blocker(s) for {}: see above. `linrdp doctor` reports the machine itself.",
            report.account
        )));
    }
    out
}

/// Probe one account and print its report on stdout.
pub(crate) fn run_account(name: &str) -> anyhow::Result<()> {
    let probe = probe_account(name);
    print!("{}", render_account(&build_account(&probe), &DoctorTheme));
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

    // -----------------------------------------------------------------------
    // `doctor <account>`
    // -----------------------------------------------------------------------

    fn ids(uid: u32, home: &str) -> crate::session::privilege::UserIds {
        crate::session::privilege::UserIds {
            uid,
            gid: uid,
            name: "someone".to_owned(),
            home: home.to_owned(),
        }
    }

    fn account(name: &str, uid: u32) -> AccountProbe {
        AccountProbe {
            name: name.to_owned(),
            ids: Some(ids(uid, &format!("/home/{name}"))),
            home_exists: true,
            password: crate::auth::PasswordState::Set,
            captured: true,
            runtime_dir_exists: true,
            sound_policy: SoundServerPolicy::Startable,
            sound_socket_exists: true,
            cookie_exists: true,
            live_display: None,
            listeners: vec![AuthListener { unit: "linrdp-alt-port.service".to_owned(), mode: "greeter".to_owned() }],
        }
    }

    fn blockers(report: &AccountReport) -> Vec<&str> {
        report
            .findings
            .iter()
            .filter_map(|f| match f {
                Finding::Blocker(m) => Some(m.as_str()),
                Finding::Warning(_) => None,
            })
            .collect()
    }

    fn warnings(report: &AccountReport) -> Vec<&str> {
        report
            .findings
            .iter()
            .filter_map(|f| match f {
                Finding::Warning(m) => Some(m.as_str()),
                Finding::Blocker(_) => None,
            })
            .collect()
    }

    /// A healthy account is reported as healthy. A doctor that finds fault
    /// with everything is a doctor nobody reads.
    #[test]
    fn an_account_that_can_be_served_has_no_findings() {
        let report = build_account(&account("rdptest", 1002));

        assert!(report.findings.is_empty(), "got {:?}", blockers(&report));
    }

    /// The condition that actually cost an evening: systemd will not start a
    /// sound server for uid 0, so a root desktop has no audio and never will
    /// until the condition is lifted.
    #[test]
    fn root_is_told_that_its_sound_server_is_excluded_and_how_to_lift_it() {
        let mut probe = account("root", 0);
        probe.sound_policy = SoundServerPolicy::Excluded("!root".to_owned());

        let report = build_account(&probe);
        let found = blockers(&report).join("\n");
        assert!(found.contains("ConditionUser=!root"), "got {found}");
        assert!(found.contains("/etc/systemd/user"), "the fix is spelled out: {found}");
        assert!(found.contains("allow-root.conf"), "the drop-in is named: {found}");
        assert!(found.contains("ordinary account"), "the simpler answer is offered too: {found}");
    }

    /// The real condition text, parsed from the units as shipped on this
    /// machine — not a string invented by the test.
    #[test]
    fn the_shipped_condition_excludes_root_and_nobody_else() {
        let conditions = effective_condition_user(Some("[Unit]\nConditionUser=!root\n"), &[]);

        assert_eq!(
            sound_server_policy(&conditions, 0, "root"),
            SoundServerPolicy::Excluded("!root".to_owned())
        );
        assert_eq!(sound_server_policy(&conditions, 1002, "rdptest"), SoundServerPolicy::Startable);
    }

    /// A drop-in with a bare `ConditionUser=` clears the condition, which is
    /// exactly how an operator lifts it. Reading only the shipped unit would
    /// keep reporting a blocker they had already fixed.
    #[test]
    fn a_dropin_that_clears_the_condition_is_honoured() {
        let conditions = effective_condition_user(
            Some("[Unit]\nConditionUser=!root\n"),
            &["[Unit]\nConditionUser=\n".to_owned()],
        );

        assert!(conditions.is_empty());
        assert_eq!(sound_server_policy(&conditions, 0, "root"), SoundServerPolicy::Startable);
    }

    /// Commented-out settings are not settings.
    #[test]
    fn a_commented_condition_is_not_a_condition() {
        let conditions = effective_condition_user(Some("[Unit]\n#ConditionUser=!root\n"), &[]);

        assert!(conditions.is_empty(), "got {conditions:?}");
    }

    /// A locked password beats every other consideration: no login of any
    /// kind can succeed, so it is reported as a blocker with the one command
    /// that fixes it.
    #[test]
    fn a_locked_password_is_a_blocker_with_the_command_to_unlock_it() {
        let mut probe = account("rdptest", 1002);
        probe.password = crate::auth::PasswordState::Locked;

        let found = blockers(&build_account(&probe)).join("\n");
        assert!(found.contains("locked"), "got {found}");
        assert!(found.contains("passwd -u rdptest"), "got {found}");
    }

    /// An unknown account ends the report there. Describing the home
    /// directory of a user who does not exist would be noise dressed as
    /// diagnosis.
    #[test]
    fn an_unknown_account_is_one_blocker_and_nothing_else() {
        let mut probe = account("ghost", 1234);
        probe.ids = None;

        let report = build_account(&probe);
        assert_eq!(report.findings.len(), 1);
        assert!(report.audio.is_empty(), "nothing is claimed about a user who is not there");
        assert!(blockers(&report)[0].contains("getent passwd ghost"), "got {:?}", blockers(&report));
    }

    /// A missing socket means nothing before the account has logged in —
    /// there is no runtime directory for a daemon to listen in. Reporting it
    /// then would be a warning nobody can act on.
    #[test]
    fn a_missing_socket_is_only_reported_once_the_account_has_a_session() {
        let mut probe = account("rdptest", 1002);
        probe.runtime_dir_exists = false;
        probe.sound_socket_exists = false;
        assert!(warnings(&build_account(&probe)).is_empty());

        probe.runtime_dir_exists = true;
        let found = warnings(&build_account(&probe)).join("\n");
        assert!(found.contains("no sound server listening"), "got {found}");
    }

    /// `--auth system` verifies the client's own credentials against
    /// /etc/shadow, so it needs no captured password and must not be nagged
    /// about one.
    #[test]
    fn auth_system_does_not_need_a_captured_password_for_the_account() {
        let mut probe = account("rdptest", 1002);
        probe.captured = false;

        probe.listeners = vec![AuthListener { unit: "linrdp.service".to_owned(), mode: "system".to_owned() }];
        assert!(warnings(&build_account(&probe)).is_empty());

        probe.listeners = vec![AuthListener { unit: "linrdp.service".to_owned(), mode: "nla".to_owned() }];
        let found = warnings(&build_account(&probe)).join("\n");
        assert!(found.contains("su - rdptest"), "got {found}");
        assert!(
            !found.contains("set-password"),
            "linrdp must never offer to provision a password of its own: {found}"
        );
    }

    /// The shadow classifier, over the shapes a real shadow file holds.
    #[test]
    fn shadow_fields_are_classified_by_shape() {
        use crate::auth::PasswordState;
        let shadow = concat!(
            "alice:$6$salt$hash:20000:0:99999:7:::\n",
            "bob:!:20000:0:99999:7:::\n",
            "carol:!!:20000:0:99999:7:::\n",
            "dave:*:20000:0:99999:7:::\n",
            "erin::20000:0:99999:7:::\n",
        );

        assert_eq!(crate::auth::classify_shadow_for_test(shadow, "alice"), PasswordState::Set);
        assert_eq!(crate::auth::classify_shadow_for_test(shadow, "bob"), PasswordState::Locked);
        assert_eq!(crate::auth::classify_shadow_for_test(shadow, "carol"), PasswordState::Locked);
        assert_eq!(crate::auth::classify_shadow_for_test(shadow, "dave"), PasswordState::Locked);
        assert_eq!(crate::auth::classify_shadow_for_test(shadow, "erin"), PasswordState::Empty);
        assert_eq!(crate::auth::classify_shadow_for_test(shadow, "frank"), PasswordState::Absent);
    }
}

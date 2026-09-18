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

/// One line of the `linrdp` block. Unlike a [`Fact`], a value here can be a
/// live state rather than a description of the machine, and the one that is —
/// whether anything is serving right now — is drawn in colour, for the same
/// reason the session that would start is: it is what the eye goes looking
/// for.
struct Status {
    key: &'static str,
    value: String,
    /// Draw the value green. Reserved for a state somebody wants to see, so
    /// that a report with nothing green in it is a report worth reading.
    good: bool,
}

/// What this binary is, and what the machine has done with it. Probed by the
/// caller, like everything else in this report, so that the report itself
/// stays a value.
struct Installation {
    version: String,
    build: String,
    /// Whether there is a systemd here to have a unit at all. A machine
    /// without one is not missing anything — `linrdp daemon` is how it runs
    /// the server — and telling it to run `service install` would be telling
    /// it to run something that cannot work.
    systemd: bool,
    unit_installed: bool,
    /// What is serving right now, whichever way it was started.
    serving: Option<Serving>,
}

/// How the running server was started. Not interchangeable: the command that
/// stops one does not stop the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serving {
    Unit,
    Daemon { pid: u32 },
}

/// Something that wants the operator's attention. A met requirement is not a
/// finding: it is already visible as a fact above.
enum Finding {
    Blocker(String),
    Warning(String),
}

/// What `doctor` has to say, before anything decides how to draw it.
struct Report {
    /// What this binary is, and what the machine has done with it.
    linrdp: Vec<Status>,
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
/// What the configuration contributes to the machine report.
#[derive(Debug, Default)]
struct ConfiguredService {
    listeners: Vec<AuthListener>,
    /// `false` when there is no file at all — the listeners below are then the
    /// built-in defaults, and saying "0.0.0.0:3389" without saying that would
    /// read as a deliberate choice somebody made.
    present: bool,
    /// Why the file could not be read, when it exists and is wrong.
    problem: Option<String>,
}

fn build(
    caps: &Capabilities,
    accounts: &[String],
    sam_path: &Path,
    pam_capture: bool,
    service: &ConfiguredService,
    installation: &Installation,
) -> Report {
    let listeners = service.listeners.as_slice();
    let config_problem = service.problem.as_deref();
    // Capture is needed if ANY listener offers NLA. The old test was one
    // unit's `--auth`, which on a machine running `system` on one port and
    // `both` on another reported whichever unit happened to be named `linrdp`
    // — and told the operator to fix nothing while half the server was
    // refusing logins.
    let capture_needed = listeners
        .iter()
        .any(|l| l.refuses_without_capture() || l.loses_nla_without_capture());
    let list = |items: &[String]| {
        if items.is_empty() {
            "none".to_owned()
        } else {
            items.join(", ")
        }
    };

    // What this binary is, and what the machine has done with it. It leads
    // the report because a report that does not say which linrdp produced it
    // cannot be acted on, and because "is it even running" is asked before
    // any question about the machine is.
    let linrdp = vec![
        Status { key: "version", value: installation.version.clone(), good: false },
        Status { key: "build", value: installation.build.clone(), good: false },
        Status {
            key: "service",
            // Each state names the command that changes it: "not installed"
            // on its own sends the operator back to the help to find out what
            // installs it.
            value: if !installation.systemd {
                "no systemd here — `sudo linrdp daemon start` runs it without one".to_owned()
            } else if installation.unit_installed {
                "installed".to_owned()
            } else {
                "not installed — `sudo linrdp service install` writes the unit".to_owned()
            },
            good: false,
        },
        Status {
            key: "started",
            value: match installation.serving {
                Some(Serving::Unit) => "yes".to_owned(),
                // Named, because the command that stops this one is not the
                // command that stops a unit.
                Some(Serving::Daemon { pid }) => format!("yes (linrdp daemon, pid {pid})"),
                None => "no".to_owned(),
            },
            good: installation.serving.is_some(),
        },
    ];

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
            value: "system password (/etc/shadow + PAM); `auth: nla` uses the SAM".to_owned(),
        },
        Fact {
            key: "listeners",
            value: {
                let list = listeners
                    .iter()
                    .map(|l| format!("{} (auth: {})", l.bind, l.mode))
                    .collect::<Vec<_>>()
                    .join(", ");
                match (listeners.is_empty(), service.present) {
                    (true, _) => "none configured".to_owned(),
                    (false, true) => list,
                    (false, false) => format!(
                        "{list} — built-in defaults; there is no {}",
                        crate::config::CONFIG_PATH
                    ),
                }
            },
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
                (false, false) => "not wired (no listener offers NLA)".to_owned(),
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
            "PAM credential capture is NOT wired, and a listener here offers NLA. NLA cannot \
             verify an /etc/shadow hash, so linrdp has to learn each account's system password \
             from the system's own authentication: `linrdp service install` wires that up. The \
             alternatives, if you would rather not touch PAM, are `auth: greeter` (the server \
             draws the logon form; every client works) and `auth: system` (nothing stored, but \
             only clients that send credentials without NLA — FreeRDP, Remmina; mstsc does \
             not)."
                .to_owned(),
        ));
    }

    // A configuration that does not load is not a detail of this report: it is
    // the reason the service is not running, and everything below it here is
    // describing defaults the machine is not actually using.
    if let Some(problem) = config_problem {
        findings.push(Finding::Blocker(format!(
            "the configuration cannot be read, so linrdp will not start — this report shows \
             the built-in defaults instead of what you configured. {problem}"
        )));
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

    Report { linrdp, system, authentication, sessions_title, sessions, findings }
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

/// The `linrdp` block: aligned like a fact block, but a value in it can be a
/// state rather than a description, and a state is worth a colour.
fn status_block(title: &str, rows: &[Status]) -> String {
    let width = rows.iter().map(|row| row.key.chars().count()).max().unwrap_or(0);
    let mut block = title.to_owned();
    for row in rows {
        // Green for what is up, and the terminal's own colour for what is
        // not. Not red: a service nobody has started yet is a state, and red
        // would say the machine is broken when nothing about it is.
        let value = if row.good {
            Style::new().green().apply_to(&row.value)
        } else {
            Style::new().apply_to(&row.value)
        };
        block.push_str(&format!("\n{key:<width$}  {value}", key = row.key));
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
    out.push_str(&theme.format_log(&status_block("linrdp", &report.linrdp), &section));
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

/// The listeners this machine is configured to serve, for the account report.
///
/// It used to ask systemd: `systemctl list-units linrdp*.service`, then
/// `systemctl show` on each and a window search over `ExecStart` for
/// `--auth`. That answered "what is this unit set to start", which is only
/// the same question as "how is this server configured" while the two happen
/// not to have drifted. The configuration file answers it directly.
fn configured_listeners() -> Vec<AuthListener> {
    crate::config::load_for_diagnostics(crate::config::path())
        .0
        .listeners
        .iter()
        .map(|listener| AuthListener { bind: listener.bind.clone(), mode: listener.auth })
        .collect()
}

/// What this binary is, and what the machine has done with it.
///
/// Asked of the machine rather than of the configuration: whether the unit
/// `service install` writes is there, whether systemd says it is up, and —
/// for the machines with no systemd at all, which is what `linrdp daemon`
/// exists for — whether a supervisor started by hand is answering.
fn probe_installation(config: &crate::config::Config) -> Installation {
    use crate::service::unit;

    // One call answers both halves: `None` is a machine with no systemctl to
    // run, `Some(false)` a systemd that has not been asked to start this.
    let active = unit::systemctl(&["is-active", "--quiet", unit::UNIT_NAME]);
    let serving = if active == Some(true) {
        Some(Serving::Unit)
    } else {
        crate::daemon::look(&crate::daemon::ports_of(config)).map(|found| Serving::Daemon { pid: found.pid })
    };

    Installation {
        version: crate::build_info::VERSION.to_owned(),
        build: crate::build_info::build(),
        systemd: active.is_some(),
        unit_installed: unit::path_in(Path::new(unit::UNIT_DIR), unit::UNIT_NAME).exists(),
        serving,
    }
}

/// Probe this machine and print the report on stdout.
pub(crate) fn run() -> anyhow::Result<()> {
    let caps = detect::probe();
    let accounts = sam::account_names();
    let (config, problem) = crate::config::load_for_diagnostics(crate::config::path());
    let service = ConfiguredService {
        listeners: config
            .listeners
            .iter()
            .map(|listener| AuthListener { bind: listener.bind.clone(), mode: listener.auth })
            .collect(),
        present: crate::config::path().exists(),
        problem,
    };
    let installation = probe_installation(&config);
    let report = build(
        &caps,
        &accounts,
        &sam::sam_path(),
        pam_capture_wired(),
        &service,
        &installation,
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
/// There is rarely only one. A typical machine runs two — NLA on 3389 and the
/// server-drawn logon screen on 3390 — and they want different things from an
/// account: NLA has to know the password to compute the expected response,
/// while the logon screen hands what you type straight to PAM and needs
/// nothing stored. A report that looked at one listener would tell someone
/// logging in through the greeter that their account was not ready, which is
/// what the first draft of this did.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthListener {
    /// The `bind` literal from the configuration — what the operator would
    /// search the file for.
    bind: String,
    mode: crate::config::Auth,
}

impl AuthListener {
    /// Whether a missing captured password shuts this listener's door.
    ///
    /// Only `nla` does. It advertises CredSSP alone, so a client that cannot
    /// complete it has nowhere else to go.
    fn refuses_without_capture(&self) -> bool {
        self.mode == crate::config::Auth::Nla
    }

    /// Whether a missing captured password costs this listener NLA but not
    /// the login.
    ///
    /// `both` advertises CredSSP *or* TLS. Traced on this machine: with no
    /// stored secret the NTLM exchange runs to the public-key step, the
    /// server computes its response from a session key derived from a
    /// password it does not have, the client rejects it and abandons
    /// CredSSP — then mstsc opens a second connection asking for plain
    /// `SSL`, sends the typed password in the Client Info PDU, and
    /// `ShadowValidator` checks it against `/etc/shadow`. The login
    /// succeeds. So this is a lost feature, not a locked door, and calling
    /// it a blocker told someone their account was broken while they were
    /// sitting in its desktop.
    fn loses_nla_without_capture(&self) -> bool {
        self.mode == crate::config::Auth::Both
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
        // The range the service is actually configured with — the third
        // independent copy of `10..=99` used to live right here, and a machine
        // whose sessions sat outside it reported every account as having no
        // live display at all.
        live_display: crate::session::registry::find(
            Path::new(crate::session::runtime_dir::STATE_DIR),
            name,
            crate::config::load_for_diagnostics(crate::config::path())
                .0
                .session
                .display_range
                .range(),
        )
        .map(|record| record.display),
        sound_policy,
        listeners: configured_listeners(),
        ids,
    }
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

    // Capture matters only where NLA is offered, and it matters differently:
    // `nla` has no other path, `both` falls back to TLS.
    let refusing: Vec<&str> = probe
        .listeners
        .iter()
        .filter(|l| l.refuses_without_capture())
        .map(|l| l.bind.as_str())
        .collect();
    let degrading: Vec<&str> = probe
        .listeners
        .iter()
        .filter(|l| l.loses_nla_without_capture())
        .map(|l| l.bind.as_str())
        .collect();
    let capture_needed = !refusing.is_empty() || !degrading.is_empty();
    let authentication = vec![
        Fact {
            key: "listeners",
            value: if probe.listeners.is_empty() {
                "none configured".to_owned()
            } else {
                probe
                    .listeners
                    .iter()
                    .map(|l| format!("{} (auth: {})", l.bind, l.mode))
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
                (false, false) => "no (no listener here offers NLA)".to_owned(),
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
        // How to get a password captured, which is the same sentence either
        // way. linrdp provisions nothing of its own: the system password is
        // the only one it ever uses.
        let remedy = format!(
            "Authenticate once as {} by any other means — `su - {}`, ssh, a console login — and \
             the PAM capture records it for the next RDP login.",
            probe.name, probe.name
        );

        if !refusing.is_empty() {
            findings.push(Finding::Blocker(format!(
                "no password captured for {} yet, and {} advertises CredSSP alone. NLA must know \
                 the secret to compute its half of the exchange and cannot verify an /etc/shadow \
                 hash, so this account has no way in on that listener at all. {remedy}",
                probe.name,
                refusing.join(" and ")
            )));
        }
        if !degrading.is_empty() {
            findings.push(Finding::Warning(format!(
                "no password captured for {} yet, so NLA cannot authenticate it on {}. The login \
                 still works: that listener advertises CredSSP *or* TLS, and a client that gives \
                 up on CredSSP reconnects over plain TLS, where the password it sends is checked \
                 against /etc/shadow. mstsc does exactly that — it opens a second connection — so \
                 what is actually lost is pre-authentication, not access. {remedy}",
                probe.name,
                degrading.join(" and ")
            )));
        }
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

    fn listeners(modes: &[crate::config::Auth]) -> Vec<AuthListener> {
        modes
            .iter()
            .enumerate()
            .map(|(n, mode)| AuthListener { bind: format!("0.0.0.0:{}", 3389 + n), mode: *mode })
            .collect()
    }

    fn service(modes: &[crate::config::Auth]) -> ConfiguredService {
        ConfiguredService { listeners: listeners(modes), present: true, problem: None }
    }

    /// A machine that has installed the service and is running it.
    fn installation() -> Installation {
        Installation {
            version: "0.1.0".to_owned(),
            build: "35a421b, release, 2026-09-18".to_owned(),
            systemd: true,
            unit_installed: true,
            serving: Some(Serving::Unit),
        }
    }

    fn linrdp_row<'a>(report: &'a Report, key: &str) -> &'a Status {
        report
            .linrdp
            .iter()
            .find(|row| row.key == key)
            .unwrap_or_else(|| panic!("the linrdp block has a `{key}` row"))
    }

    /// A healthy machine, so that a test about the block at the top is not
    /// also a test about the four sections under it.
    fn report_for(installation: &Installation) -> Report {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        build(
            &caps,
            &accounts(),
            sam(),
            true,
            &service(&[crate::config::Auth::Both]),
            installation,
        )
    }


    /// A version alone does not identify a binary — 0.1.0 has been every
    /// commit on this branch — so the report opens with what was actually
    /// built, which is the thing a bug report can then name.
    #[test]
    fn the_report_opens_with_the_version_and_the_build() {
        let report = report_for(&installation());
        assert_eq!(linrdp_row(&report, "version").value, "0.1.0");
        assert_eq!(linrdp_row(&report, "build").value, "35a421b, release, 2026-09-18");
    }

    /// "Is it actually running" is what this report is opened for often
    /// enough that the answer is the one thing in the block wearing a colour.
    #[test]
    fn a_service_systemd_has_started_is_the_one_green_thing_in_the_block() {
        let report = report_for(&installation());
        let started = linrdp_row(&report, "started");
        assert_eq!(started.value, "yes");
        assert!(started.good, "a running service is green");
        assert_eq!(linrdp_row(&report, "service").value, "installed");
        assert!(!linrdp_row(&report, "version").good, "a version is not a state");
    }

    /// Installed and stopped is a state, not a fault: nothing here is broken,
    /// it simply has not been started. So it says so in the terminal's own
    /// colour rather than in red.
    #[test]
    fn an_installed_service_that_is_not_running_says_no_without_colour() {
        let report = report_for(&Installation { serving: None, ..installation() });
        let started = linrdp_row(&report, "started");
        assert_eq!(started.value, "no");
        assert!(!started.good);
    }

    /// This report is read on machines where nothing has been installed yet,
    /// and "not installed" without the command that installs it sends the
    /// operator back to the help.
    #[test]
    fn a_machine_with_no_unit_is_told_what_writes_one() {
        let report = report_for(&Installation {
            unit_installed: false,
            serving: None,
            ..installation()
        });
        let value = &linrdp_row(&report, "service").value;
        assert!(value.starts_with("not installed"), "got {value:?}");
        assert!(value.contains("linrdp service install"), "and what writes one: {value:?}");
    }

    /// A container, a chroot, a distribution that does not use systemd: there
    /// is no unit to be missing, and `service install` is not the command
    /// that helps.
    #[test]
    fn a_machine_without_systemd_is_pointed_at_the_daemon_rather_than_the_unit() {
        let report = report_for(&Installation {
            systemd: false,
            unit_installed: false,
            serving: None,
            ..installation()
        });
        let value = &linrdp_row(&report, "service").value;
        assert!(value.contains("linrdp daemon"), "got {value:?}");
        assert!(!value.contains("service install"), "which is not the command here: {value:?}");
    }

    /// `linrdp daemon start` serves RDP as surely as the unit does. Saying
    /// "started no" beside a supervisor answering on 3389 would be the report
    /// contradicting the machine.
    #[test]
    fn a_supervisor_started_by_the_daemon_is_running_even_though_no_unit_is() {
        let report = report_for(&Installation {
            systemd: false,
            unit_installed: false,
            serving: Some(Serving::Daemon { pid: 4321 }),
            ..installation()
        });
        let started = linrdp_row(&report, "started");
        assert!(started.good, "something is serving: {:?}", started.value);
        assert!(started.value.starts_with("yes"), "got {:?}", started.value);
        assert!(started.value.contains("4321"), "and which process it is: {:?}", started.value);
    }

    /// First, because "what is this binary, and is it running" is asked
    /// before anything about the machine under it.
    #[test]
    fn the_linrdp_block_is_drawn_before_everything_it_reports_about() {
        let drawn = render(&report_for(&installation()), &DoctorTheme);
        let at = |needle: &str| drawn.find(needle).unwrap_or_else(|| panic!("{needle} is drawn"));
        assert!(at("version") < at("distribution"), "the block comes first:\n{drawn}");
        assert!(at("started") < at("logind"), "all of it, not just its head:\n{drawn}");
    }

    /// The old report restated every met requirement ("ok logind: available")
    /// directly under the facts that already said so. A finding is now only
    /// what the operator has to do something about, so a healthy machine ends
    /// with nothing listed at all.
    #[test]
    fn met_requirements_do_not_become_findings() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(&caps, &accounts(), sam(), true, &service(&[crate::config::Auth::Both]), &installation());
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
        let report = build(&caps, &accounts(), sam(), true, &service(&[crate::config::Auth::Both]), &installation());

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
        let report = build(&caps, &accounts(), sam(), false, &service(&[crate::config::Auth::Both]), &installation());

        assert_eq!(report.blockers(), 1);
        let capture = report
            .authentication
            .iter()
            .find(|f| f.key == "PAM capture")
            .expect("the capture fact is reported");
        assert_eq!(capture.value, "NOT wired");
    }

    /// `auth: system` checks the client's credentials against /etc/shadow
    /// itself, so it never reads a captured password. Calling the missing
    /// capture a blocker there tells the operator to fix what they chose.
    #[test]
    fn auth_system_does_not_need_the_pam_capture() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(&caps, &accounts(), sam(), false, &service(&[crate::config::Auth::System]), &installation());

        assert_eq!(report.blockers(), 0, "the mode in use needs no capture");
        let capture = report
            .authentication
            .iter()
            .find(|f| f.key == "PAM capture")
            .expect("the capture fact is reported");
        assert_eq!(capture.value, "not wired (no listener offers NLA)");
    }

    /// The listener list is what the file says, and it names each listener by
    /// the address the operator would search that file for — not by a systemd
    /// unit, which is what it used to report and which no longer exists.
    #[test]
    fn the_listeners_fact_comes_from_the_configuration() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(
            &caps,
            &accounts(),
            sam(),
            true,
            &service(&[crate::config::Auth::Both, crate::config::Auth::Greeter]),
            &installation(),
        );
        let fact = report
            .authentication
            .iter()
            .find(|f| f.key == "listeners")
            .expect("the listener fact is reported");
        assert_eq!(fact.value, "0.0.0.0:3389 (auth: both), 0.0.0.0:3390 (auth: greeter)");
    }

    /// One port that stores nothing does not excuse another that cannot work
    /// without a capture. The old report asked systemd for the `--auth` of the
    /// unit named `linrdp` and answered for the whole machine with it, so a
    /// machine serving `system` there and `nla` elsewhere was told it had
    /// nothing to fix while half of it refused every login.
    #[test]
    fn a_listener_that_needs_the_capture_is_not_excused_by_one_that_does_not() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(
            &caps,
            &accounts(),
            sam(),
            false,
            &service(&[crate::config::Auth::System, crate::config::Auth::Nla]),
            &installation(),
        );
        assert_eq!(report.blockers(), 1, "the nla listener still needs it");
    }

    /// Only when no listener offers NLA at all is the missing capture a
    /// non-event.
    #[test]
    fn a_machine_offering_no_nla_anywhere_needs_no_capture() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(
            &caps,
            &accounts(),
            sam(),
            false,
            &service(&[crate::config::Auth::System, crate::config::Auth::Greeter]),
            &installation(),
        );
        assert_eq!(report.blockers(), 0);
    }

    /// A configuration that does not load is why the service is not running,
    /// and it also means every other line of this report is describing
    /// defaults the machine is not using. Both halves have to be said.
    #[test]
    fn a_configuration_that_does_not_load_is_a_blocker() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(
            &caps,
            &accounts(),
            sam(),
            true,
            &ConfiguredService {
                listeners: listeners(&[crate::config::Auth::Both]),
                present: true,
                problem: Some("listeners[0].auth: unknown variant `greter`".to_owned()),
            },
            &installation(),
        );
        let blocker = report
            .findings
            .iter()
            .filter_map(|f| match f {
                Finding::Blocker(message) => Some(message.as_str()),
                Finding::Warning(_) => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(blocker.contains("will not start"), "got: {blocker}");
        assert!(blocker.contains("built-in defaults"), "it says what is being shown instead: {blocker}");
        assert!(blocker.contains("greter"), "it carries the parser's own words: {blocker}");
    }

    /// An empty SAM is the normal state of a fresh install: the hook is wired
    /// and the first `su -` fills it. Nothing is broken, so nothing may claim
    /// sessions cannot run.
    #[test]
    fn no_captured_password_yet_is_a_warning_not_a_blocker() {
        let caps = healthy(vec![session("xfce", SessionKind::X11, true)]);
        let report = build(&caps, &[], sam(), true, &service(&[crate::config::Auth::Both]), &installation());

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

        let blocked = render(
            &build(
                &caps,
                &accounts(),
                sam(),
                false,
                &service(&[crate::config::Auth::Both]),
                &installation(),
            ),
            &DoctorTheme,
        );
        assert!(
            blocked.contains("1 blocker(s): per-user sessions cannot run"),
            "got {blocked}"
        );

        let working = render(
            &build(
                &caps,
                &accounts(),
                sam(),
                true,
                &service(&[crate::config::Auth::Both]),
                &installation(),
            ),
            &DoctorTheme,
        );
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
        let report = build(&caps, &[], sam(), true, &service(&[crate::config::Auth::Both]), &installation());

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
            listeners: vec![AuthListener { bind: "0.0.0.0:3390".to_owned(), mode: crate::config::Auth::Greeter }],
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

    /// `auth: system` verifies the client's own credentials against
    /// /etc/shadow, so it needs no captured password and must not be nagged
    /// about one.
    #[test]
    fn auth_system_does_not_need_a_captured_password_for_the_account() {
        let mut probe = account("rdptest", 1002);
        probe.captured = false;

        let listener = |mode: crate::config::Auth| {
            vec![AuthListener { bind: "0.0.0.0:3389".to_owned(), mode }]
        };

        probe.listeners = listener(crate::config::Auth::System);
        assert!(build_account(&probe).findings.is_empty());

        probe.listeners = listener(crate::config::Auth::Greeter);
        assert!(build_account(&probe).findings.is_empty());

        probe.listeners = listener(crate::config::Auth::Nla);
        let found = blockers(&build_account(&probe)).join("\n");
        assert!(found.contains("su - rdptest"), "got {found}");
        assert!(
            !found.contains("set-password"),
            "linrdp must never offer to provision a password of its own: {found}"
        );
    }

    /// `auth: both` without a captured password is a lost feature, not a
    /// locked door: NLA fails, the client reconnects over TLS, and
    /// /etc/shadow lets it in. Traced on a real login — the first draft
    /// called this a blocker and told someone their account could not get in
    /// while they were sitting in its desktop.
    #[test]
    fn auth_both_without_a_capture_loses_nla_but_not_the_login() {
        let mut probe = account("user", 1000);
        probe.captured = false;
        probe.listeners = vec![AuthListener { bind: "0.0.0.0:3389".to_owned(), mode: crate::config::Auth::Both }];

        let report = build_account(&probe);
        assert!(blockers(&report).is_empty(), "not a blocker: {:?}", blockers(&report));

        let found = warnings(&report).join("\n");
        assert!(found.contains("login still works"), "got {found}");
        assert!(found.contains("/etc/shadow"), "it says what does let them in: {found}");
    }

    /// Both kinds of listener at once — the shape this deployment has. The
    /// blocker names only the listener that truly refuses.
    #[test]
    fn a_greeter_alongside_an_nla_listener_is_not_blamed_for_the_nla_listener() {
        let mut probe = account("rdptest", 1002);
        probe.captured = false;
        probe.listeners = vec![
            AuthListener { bind: "0.0.0.0:3389".to_owned(), mode: crate::config::Auth::Nla },
            AuthListener { bind: "0.0.0.0:3390".to_owned(), mode: crate::config::Auth::Greeter },
        ];

        let found = blockers(&build_account(&probe)).join("\n");
        assert!(found.contains("0.0.0.0:3389"), "got {found}");
        assert!(
            !found.contains("0.0.0.0:3390"),
            "the greeter port needs nothing stored and must not be named: {found}"
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

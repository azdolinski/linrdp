//! Which kind of desktop serves an authenticated account — and everything
//! that differs between the kinds.
//!
//! linrdp runs on many distributions, and "the desktop" is a different thing
//! on each of them: an Xvfb or Xorg session linrdp starts itself (Debian with
//! XFCE, Arch with anything X11), or a Wayland desktop that only its
//! compositor can share (GNOME 49+, which has no X11 session at all). Each of
//! those is one case here — a [`DesktopBackend`] in [`REGISTRY`] — and one
//! pure function, [`choose`], picks among them from what was probed. So a new
//! distribution or desktop is a new case and a new test row, never a special
//! branch somewhere else.
//!
//! The cases:
//!
//! | case             | module             | when                                                   | serves                                  |
//! |------------------|--------------------|--------------------------------------------------------|-----------------------------------------|
//! | `gnome-headless` | [`gnome_headless`] | GNOME Shell can be started (natively, or on the host)  | a GNOME session of the account's own    |
//! | `x11`            | [`x11`]            | an X server (Xvfb/Xorg) is installed                   | an X session of the account's own       |
//! | `gnome-console`  | `gnome_console`    | the client asks for the console (`mstsc /admin`) and   | the console's GNOME session itself      |
//! |                  |                    | the account is the one logged in at it                 |                                         |
//!
//! A login gets a session of its own, as on Windows Server; the console is
//! reached only by asking for it, and only by the account that is logged in
//! there — `/admin` from anyone else is refused, never answered with somebody
//! else's desktop. `session.backend` picks the kind of session of its own;
//! `auto` takes the first case in [`REGISTRY`] that can serve the login, and
//! GNOME comes first wherever it can be started, since that is the desktop
//! the machine was installed with. Configured console mode
//! (`session.console`) is separate: it serves one fixed X screen and never
//! routes per account.
//!
//! Adding a case:
//!
//! 1. a module here implementing [`DesktopBackend`]: `probe` says whether it
//!    can serve a login and returns how to bind it, and a case that starts
//!    sessions of its own runs them in the keeper through `serve_session`;
//! 2. if its desktop is reached through a compositor rather than an X
//!    display, an implementation of `wayland::compositor::CompositorDesktop`
//!    — the display, input, clipboard and lock paths then follow it as they
//!    are;
//! 3. one line in [`REGISTRY`], where its position is its `auto` preference;
//! 4. a [`BackendChoice`] value, if an operator may ask for it by name;
//! 5. what `linrdp doctor` should say about it (`session::detect`);
//! 6. a row in the scenario matrix below and in `docs/desktop-cases.md`.

#[cfg(feature = "wayland")]
pub(crate) mod gnome_console;
pub(crate) mod gnome_headless;
pub(crate) mod x11;

use core::ops::RangeInclusive;
use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use super::router::BoundSession;

/// `session.backend` in the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BackendChoice {
    /// Pick per account from what this machine and that account have.
    #[default]
    Auto,
    /// Always a per-user X session (Xvfb/Xorg).
    X11,
    /// Always a headless GNOME session of the account's own.
    Gnome,
}

impl BackendChoice {
    pub(crate) const ALL: [Self; 3] = [Self::Auto, Self::X11, Self::Gnome];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::X11 => "x11",
            Self::Gnome => "gnome",
        }
    }

    pub(crate) fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == raw.trim())
    }
}

impl fmt::Display for BackendChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which desktop a case serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Serves {
    /// A desktop of the account's own, started (or reattached to) by linrdp —
    /// what every ordinary login gets.
    OwnSession,
    /// The console's desktop, for the account logged in at it — only when the
    /// client asks for it (`mstsc /admin`).
    Console,
}

/// One verified login on its way to a desktop: everything probing and
/// binding it may need, so there is one of it.
pub(crate) struct Login<'a> {
    pub(crate) user: &'a str,
    pub(crate) password: &'a str,
    /// The desktop size the client negotiated.
    pub(crate) client_size: (u16, u16),
    /// `session.fixed_size`, when the operator pinned one.
    pub(crate) fixed_size: Option<(u16, u16)>,
    pub(crate) state_dir: &'a Path,
    /// The slots (X display numbers) sessions may occupy.
    pub(crate) range: RangeInclusive<u16>,
    /// Where binding records the session it bound, so the disconnect path
    /// can lock it.
    pub(crate) bound: &'a Mutex<Option<BoundSession>>,
}

/// How one login is bound to the desktop a probe found: decided by the probe,
/// carried out by the router once the case has been chosen.
pub(crate) type Binder = Box<dyn FnOnce(&Login<'_>) -> anyhow::Result<()>>;

/// One kind of desktop linrdp can serve a login.
///
/// Everything that differs between kinds lives behind this. The router, the
/// session gate, the display, input and clipboard paths, and the keeper's PAM
/// handling are the same code for every kind.
pub(crate) trait DesktopBackend: Sync {
    /// Its stable name: the keeper's `--keeper-backend`, the session record's
    /// `backend=`, and the log.
    fn id(&self) -> &'static str;

    /// What it serves, in an operator's words.
    fn describe(&self) -> &'static str;

    fn serves(&self) -> Serves;

    /// The `session.backend` value that asks for exactly this kind. `None`
    /// for the console, which is reached only by asking for it.
    fn choice(&self) -> Option<BackendChoice>;

    /// Whether this kind can serve `login` here, and if it can, how to bind
    /// it. `Err` says why not, in words a refusal can quote. Blocking: may
    /// look at the account's session bus.
    fn probe(&self, login: &Login<'_>) -> Result<Binder, String>;

    /// Run a session of this kind in the keeper, for as long as it lives:
    /// start it, publish its record once it answers, and tear it down when
    /// it ends. Only kinds that start sessions of their own have one.
    fn serve_session(&self, keeper: super::keeper_main::Keeper<'_>) -> anyhow::Result<()> {
        drop(keeper);
        anyhow::bail!("{} starts no sessions of its own", self.id())
    }
}

/// Every kind this build can serve, in the order `auto` prefers them.
pub(crate) static REGISTRY: &[&dyn DesktopBackend] = &[
    #[cfg(feature = "wayland")]
    &gnome_headless::GnomeHeadless,
    &x11::X11Session,
    #[cfg(feature = "wayland")]
    &gnome_console::GnomeConsole,
];

/// The kind called `id`, if this build has it.
pub(crate) fn by_id(id: &str) -> Option<&'static dyn DesktopBackend> {
    REGISTRY.iter().copied().find(|case| case.id() == id)
}

/// Choose the case for one login, probing no further than the choice needs:
/// a probe may talk to the account's session bus, and the first case that can
/// serve the login ends the search.
///
/// Pure over `probe`, so every combination a distribution can present is a
/// test row below — run against the real registry, its order and its
/// metadata.
pub(crate) fn choose<T>(
    registry: &[&'static dyn DesktopBackend],
    choice: BackendChoice,
    console_requested: bool,
    mut probe: impl FnMut(&'static dyn DesktopBackend) -> Result<T, String>,
) -> Result<(&'static dyn DesktopBackend, T), String> {
    let serving = |serves: Serves| registry.iter().copied().filter(move |case| case.serves() == serves);

    if console_requested {
        // Only ever the account's own console: /admin names a session that
        // exists, and it is not this account's unless this account is in it.
        let mut reasons = Vec::new();
        for case in serving(Serves::Console) {
            match probe(case) {
                Ok(found) => return Ok((case, found)),
                Err(reason) => reasons.push(reason),
            }
        }
        if reasons.is_empty() {
            reasons.push("this binary cannot serve the console".to_owned());
        }
        return Err(format!(
            "the client asked for the console session (/admin), and {} — connect without /admin for a \
             session of its own",
            reasons.join(", and ")
        ));
    }

    if choice == BackendChoice::Auto {
        let mut reasons = Vec::new();
        for case in serving(Serves::OwnSession) {
            match probe(case) {
                Ok(found) => return Ok((case, found)),
                Err(reason) => reasons.push(reason),
            }
        }
        if reasons.is_empty() {
            reasons.push("this binary serves no desktop of its own at all".to_owned());
        }
        return Err(reasons.join(", and "));
    }

    // An explicit choice is never second-guessed: it is served, or refused
    // with the reason — never quietly answered with another kind.
    let Some(case) = serving(Serves::OwnSession).find(|case| case.choice() == Some(choice)) else {
        return Err(format!("session.backend is {choice}, but this binary was built without support for it"));
    };
    probe(case)
        .map(|found| (case, found))
        .map_err(|reason| format!("session.backend is {choice}, but {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use gnome_headless::ID as GNOME;
    use x11::ID as X11;

    /// A machine and account that offer exactly the cases in `offered`.
    fn offering<'a>(offered: &'a [&'a str]) -> impl FnMut(&'static dyn DesktopBackend) -> Result<(), String> + 'a {
        move |case| {
            if offered.contains(&case.id()) {
                Ok(())
            } else {
                Err(format!("no {}", case.id()))
            }
        }
    }

    fn chosen(choice: BackendChoice, console_requested: bool, offered: &[&str]) -> Option<&'static str> {
        choose(REGISTRY, choice, console_requested, offering(offered))
            .ok()
            .map(|(case, ())| case.id())
    }

    /// The scenario matrix. One row per kind of machine and connection
    /// linrdp meets; a new distribution or desktop adds a row here first.
    #[cfg(feature = "wayland")]
    #[test]
    fn every_scenario_gets_the_case_it_calls_for() {
        use gnome_console::ID as CONSOLE;
        // (scenario, what the machine and account offer, /admin, expected case)
        let rows: &[(&str, &[&str], bool, Option<&str>)] = &[
            // Debian/Arch server with XFCE, no GNOME at all.
            ("x11 machine", &[X11], false, Some(X11)),
            // Vanilla OS / Fedora / Ubuntu GNOME, nobody at the console.
            ("gnome machine, empty console", &[GNOME], false, Some(GNOME)),
            // The same machine, the account also logged in at the console:
            // still a session of its own — the console is only for /admin.
            ("gnome machine, account at console", &[GNOME, CONSOLE], false, Some(GNOME)),
            // GNOME and Xvfb both installed: the machine's own desktop wins.
            ("gnome and xvfb", &[X11, GNOME], false, Some(GNOME)),
            // /admin by the account logged in at the console.
            ("/admin, same account", &[GNOME, CONSOLE], true, Some(CONSOLE)),
            // /admin by anyone else — zenek at the console, artur asking.
            ("/admin, other account", &[GNOME], true, None),
            ("/admin on an x11 machine", &[X11], true, None),
            // Nothing that can serve a desktop.
            ("nothing installed", &[], false, None),
        ];
        for (name, offered, console_requested, expected) in rows {
            assert_eq!(chosen(BackendChoice::Auto, *console_requested, offered), *expected, "scenario: {name}");
        }
    }

    /// A build without GNOME support still serves every X11 machine, and
    /// says why when GNOME is asked for.
    #[cfg(not(feature = "wayland"))]
    #[test]
    fn without_gnome_support_x11_serves_and_gnome_is_refused_with_the_reason() {
        assert_eq!(chosen(BackendChoice::Auto, false, &[X11, GNOME]), Some(X11));
        let reason = match choose(REGISTRY, BackendChoice::Gnome, false, offering(&[X11, GNOME])) {
            Ok((case, ())) => panic!("{} served a GNOME choice", case.id()),
            Err(reason) => reason,
        };
        assert!(reason.contains("built without"), "{reason}");
        let reason = match choose(REGISTRY, BackendChoice::Auto, true, offering(&[X11])) {
            Ok((case, ())) => panic!("{} served /admin", case.id()),
            Err(reason) => reason,
        };
        assert!(reason.contains("/admin") && reason.contains("cannot serve the console"), "{reason}");
    }

    #[test]
    fn an_explicit_choice_is_never_second_guessed() {
        assert_eq!(chosen(BackendChoice::X11, false, &[X11, GNOME]), Some(X11));
        assert_eq!(chosen(BackendChoice::Gnome, false, &[X11]), None);
        assert_eq!(chosen(BackendChoice::X11, false, &[GNOME]), None);
    }

    /// The refusal names the choice and quotes the case's own reason.
    #[test]
    fn an_explicit_choice_that_cannot_be_served_says_why() {
        let reason = match choose(REGISTRY, BackendChoice::X11, false, offering(&[GNOME])) {
            Ok((case, ())) => panic!("{} served an x11 choice", case.id()),
            Err(reason) => reason,
        };
        assert_eq!(reason, "session.backend is x11, but no x11");
    }

    /// The first case that can serve the login ends the search: a probe may
    /// talk to the account's session bus, and the ones after it are not
    /// needed. An explicit choice probes that case alone, and /admin only
    /// the cases that serve the console.
    #[test]
    fn probing_stops_at_the_first_case_that_can_serve() {
        let mut probed = Vec::new();
        let (case, ()) = choose(REGISTRY, BackendChoice::Auto, false, |case| {
            probed.push(case.id());
            Ok::<(), String>(())
        })
        .expect("a case");
        assert_eq!(probed, [case.id()], "only the first case is probed when it can serve");

        let mut probed = Vec::new();
        let _ = choose(REGISTRY, BackendChoice::X11, false, |case| {
            probed.push(case.id());
            Ok::<(), String>(())
        });
        assert_eq!(probed, [X11]);

        let mut probed = Vec::new();
        let _ = choose(REGISTRY, BackendChoice::Auto, true, |case| {
            probed.push(case.id());
            Err::<(), String>("no".to_owned())
        });
        assert!(
            probed.iter().all(|id| by_id(id).is_some_and(|case| case.serves() == Serves::Console)),
            "/admin probes only the console: {probed:?}"
        );
    }

    /// The real refusal, from the real console case: an account nobody is
    /// logged in as is never at the console.
    #[cfg(feature = "wayland")]
    #[test]
    fn admin_from_another_account_is_refused_with_the_reason() {
        let bound = Mutex::new(None);
        let login = Login {
            user: "linrdp-test-no-such-account",
            password: "",
            client_size: (1024, 768),
            fixed_size: None,
            state_dir: Path::new("/nonexistent"),
            range: 10..=20,
            bound: &bound,
        };
        let reason = match choose(REGISTRY, BackendChoice::Auto, true, |case| case.probe(&login)) {
            Ok((case, _)) => panic!("{} served /admin to an account that is not at the console", case.id()),
            Err(reason) => reason,
        };
        assert!(reason.contains("/admin") && reason.contains("not the one"), "{reason}");
    }

    /// Every case is known by one name, which the keeper and the session
    /// records use to find it again, and every explicit choice names one case.
    #[test]
    fn the_registry_names_each_case_once() {
        let mut ids: Vec<&str> = REGISTRY.iter().map(|case| case.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), REGISTRY.len(), "two cases share a name: {ids:?}");
        for case in REGISTRY {
            assert_eq!(by_id(case.id()).map(|found| found.describe()), Some(case.describe()));
            if let Some(choice) = case.choice() {
                assert_ne!(choice, BackendChoice::Auto, "{} claims `auto`", case.id());
                assert_eq!(case.serves(), Serves::OwnSession, "{} is chosen by name but serves the console", case.id());
                assert_eq!(
                    REGISTRY.iter().filter(|other| other.choice() == Some(choice)).count(),
                    1,
                    "session.backend: {choice} names more than one case"
                );
            }
        }
        assert!(by_id(X11).is_some(), "every build serves X11");
        assert!(by_id("wayland").is_none());
    }

    #[test]
    fn the_choice_round_trips_through_its_name() {
        for choice in BackendChoice::ALL {
            assert_eq!(BackendChoice::parse(choice.as_str()), Some(choice));
        }
        assert_eq!(BackendChoice::parse("wayland"), None);
    }
}
